from datetime import datetime, timedelta, timezone

import pytest

from app.audit.models import AuditLogEntry
from app.elections.models import Candidate, Division, Election
from app.extensions import db
from app.models import PendingAction, User
from app.admin.approval_service import request_action, approve_action


def make_user(email, role="delegate"):
    user = User(
        email=email,
        password_hash="test-password-hash",
        role=role,
        is_citizen=True,
        is_enrolled=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def test_self_approval_is_rejected(app):
    with app.app_context():
        requester = make_user("requester@example.com")
        target = make_user("voter@example.com", role="voter")

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target.id, "is_enrolled": False}]},
        )

        with pytest.raises(PermissionError, match="cannot approve"):
            approve_action(action.id, requester)

        db.session.refresh(action)
        db.session.refresh(target)
        assert action.status == "pending"
        assert target.is_enrolled is True


def test_expired_request_cannot_execute(app):
    with app.app_context():
        requester = make_user("requester@example.com")
        approver = make_user("approver@example.com")
        target = make_user("voter@example.com", role="voter")

        requested_at = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target.id, "is_enrolled": False}]},
            now=requested_at,
        )

        with pytest.raises(ValueError, match="approval window has expired"):
            approve_action(
                action.id,
                approver,
                now=requested_at + timedelta(minutes=15, seconds=1),
            )

        db.session.refresh(action)
        db.session.refresh(target)
        assert action.status == "expired"
        assert target.is_enrolled is True


def test_second_delegate_executes_bulk_change_once(app):
    with app.app_context():
        requester = make_user("requester@example.com")
        approver = make_user("approver@example.com")
        target = make_user("voter@example.com", role="voter")

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target.id, "is_enrolled": False}]},
        )

        approve_action(action.id, approver)

        db.session.refresh(action)
        db.session.refresh(target)
        assert action.status == "executed"
        assert action.requested_by_id != action.approved_by_id
        assert action.approved_by_id == approver.id
        assert action.executed_at is not None
        assert target.is_enrolled is False

        with pytest.raises(ValueError, match="already been processed"):
            approve_action(action.id, approver)

        logged_actions = db.session.execute(
            db.select(AuditLogEntry.action)
        ).scalars().all()

        assert "admin.action_requested" in logged_actions
        assert "admin.action_approved" in logged_actions


def test_candidate_exclusion_requires_second_delegate(app):
    with app.app_context():
        requester = make_user("requester@example.com")
        approver = make_user("approver@example.com")

        election = Election(
            name="Test election",
            chamber="house",
            created_by_id=requester.id,
        )
        db.session.add(election)
        db.session.commit()

        division = Division(
            election_id=election.id,
            name="Test division",
        )
        db.session.add(division)
        db.session.commit()

        candidate = Candidate(
            division_id=division.id,
            name="Test candidate",
            party="Example Party",
            position=1,
        )
        db.session.add(candidate)
        db.session.commit()

        action = request_action(
            requester,
            "candidate_exclusion",
            {"candidate_id": candidate.id},
        )

        assert candidate.is_excluded is False
        approve_action(action.id, approver)

        db.session.refresh(candidate)
        assert candidate.is_excluded is True

def _log_in_as(client, user):
    with client.session_transaction() as session:
        session["_user_id"] = str(user.id)
        session["_fresh"] = True


def test_delegate_can_request_and_approve_through_routes(app, client):
    # Create database records inside an application context.
    with app.app_context():
        requester = make_user("route-requester@example.com")
        approver = make_user("route-approver@example.com")
        target = make_user("route-voter@example.com", role="voter")

        requester_id = requester.id
        approver_id = approver.id
        target_id = target.id

    # IMPORTANT: HTTP requests are outside that application context.
    _log_in_as(client, requester)

    response = client.post(
        "/admin/actions",
        json={
            "action_type": "bulk_enrolment_change",
            "payload": {
                "changes": [
                    {"user_id": target_id, "is_enrolled": False}
                ]
            },
        },
    )

    assert response.status_code == 201, response.get_json()
    action_id = response.get_json()["id"]

    with app.app_context():
        saved_action = db.session.get(PendingAction, action_id)
        assert saved_action is not None
        assert saved_action.requested_by_id == requester_id
        assert requester_id != approver_id

    # A second client signs in as the other delegate.
    approver_client = app.test_client()
    _log_in_as(approver_client, approver)

    with approver_client.session_transaction() as session:
        assert session["_user_id"] == str(approver_id)

    response = approver_client.post(
        f"/admin/actions/{action_id}/approve"
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "executed"

def test_non_delegate_cannot_approve_action(app, client):
    with app.app_context():
        requester = make_user("approval-requester@example.com")
        voter = make_user("approval-voter@example.com", role="voter")
        target = make_user("approval-target@example.com", role="voter")

        # Save IDs before the application context closes.
        voter_id = voter.id
        target_id = target.id

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {
                "changes": [
                    {"user_id": target_id, "is_enrolled": False}
                ]
            },
        )
        action_id = action.id

    # Sign in as a voter, not a delegate.
    with client.session_transaction() as session:
        session["_user_id"] = str(voter_id)
        session["_fresh"] = True

    response = client.post(f"/admin/actions/{action_id}/approve")
    assert response.status_code == 403

    with app.app_context():
        saved_action = db.session.get(PendingAction, action_id)
        saved_target = db.session.get(User, target_id)

        assert saved_action.status == "pending"
        assert saved_target.is_enrolled is True

def test_non_delegate_cannot_request_action(app, client):
    with app.app_context():
        voter = make_user("request-voter@example.com", role="voter")
        target = make_user("request-target@example.com", role="voter")

        voter_id = voter.id
        target_id = target.id

    # Sign in as a voter, not a delegate.
    with client.session_transaction() as session:
        session["_user_id"] = str(voter_id)
        session["_fresh"] = True

    response = client.post(
        "/admin/actions",
        json={
            "action_type": "bulk_enrolment_change",
            "payload": {
                "changes": [
                    {"user_id": target_id, "is_enrolled": False}
                ]
            },
        },
    )

    assert response.status_code == 403

    with app.app_context():
        action = db.session.execute(
            db.select(PendingAction).where(
                PendingAction.requested_by_id == voter_id
            )
        ).scalar_one_or_none()

        assert action is None