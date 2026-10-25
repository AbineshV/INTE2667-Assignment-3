from datetime import datetime, timedelta, timezone

import pytest

from app.auth.passwords import hash_password
from app.audit.models import AuditLogEntry
from app.elections.models import Candidate, Division, Election
from app.extensions import db
from app.models import PendingAction, User
from app.admin.approval_service import request_action, approve_action


TEST_PASSWORD = "R8-test-password-123!"


def make_user(email, role="delegate", division="D01"):
    """Create a test user with an explicit division."""
    user = User(
        email=email,
        password_hash=hash_password(TEST_PASSWORD),
        role=role,
        division=division,
        is_citizen=True,
        is_enrolled=True,
    )
    db.session.add(user)
    db.session.commit()
    return user


def _log_in_as(client, email):
    """Log in through the application's real authentication route."""
    response = client.post(
        "/auth/login",
        data={
            "email": email,
            "password": TEST_PASSWORD,
        },
    )
    assert response.status_code == 302, (
        f"Login failed for {email}: HTTP {response.status_code}"
    )


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

        requested_at = datetime(
            2026, 1, 1, 10, 0, tzinfo=timezone.utc
        )

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target.id, "is_enrolled": False}]},
            now=requested_at,
        )

        with pytest.raises(
            ValueError, match="approval window has expired"
        ):
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

        action_id = action.id
        approver_id = approver.id
        requester_id = requester.id
        target_id = target.id

        approve_action(action_id, approver)

        db.session.refresh(action)
        db.session.refresh(target)

        assert action.status == "executed"
        assert requester_id != approver_id
        assert action.approved_by_id == approver_id
        assert action.executed_at is not None
        assert target.is_enrolled is False

        with pytest.raises(
            ValueError, match="already been processed"
        ):
            approve_action(action_id, approver)

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
            name="D01",
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


def test_delegate_can_request_and_approve_through_routes(app, client):
    requester_email = "route-requester@example.com"
    approver_email = "route-approver@example.com"
    target_email = "route-voter@example.com"

    with app.app_context():
        requester = make_user(requester_email)
        approver = make_user(approver_email)
        target = make_user(target_email, role="voter")

        requester_id = requester.id
        approver_id = approver.id
        target_id = target.id

    _log_in_as(client, requester_email)

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

    approver_client = app.test_client()
    _log_in_as(approver_client, approver_email)

    response = approver_client.post(
        f"/admin/actions/{action_id}/approve"
    )

    assert response.status_code == 200, response.get_json()
    assert response.get_json()["status"] == "executed"


def test_non_delegate_cannot_approve_action(app, client):
    requester_email = "approval-requester@example.com"
    voter_email = "approval-voter@example.com"

    with app.app_context():
        requester = make_user(requester_email)
        voter = make_user(voter_email, role="voter")
        target = make_user("approval-target@example.com", role="voter")

        voter_id = voter.id
        target_id = target.id

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target_id, "is_enrolled": False}]},
        )
        action_id = action.id

    _log_in_as(client, voter_email)

    response = client.post(f"/admin/actions/{action_id}/approve")
    assert response.status_code == 403

    with app.app_context():
        saved_action = db.session.get(PendingAction, action_id)
        saved_target = db.session.get(User, target_id)

        assert saved_action.status == "pending"
        assert saved_target.is_enrolled is True


def test_non_delegate_cannot_request_action(app, client):
    voter_email = "request-voter@example.com"

    with app.app_context():
        voter = make_user(voter_email, role="voter")
        target = make_user("request-target@example.com", role="voter")

        voter_id = voter.id
        target_id = target.id

    _log_in_as(client, voter_email)

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


def test_delegate_cannot_request_change_for_another_division(app):
    with app.app_context():
        requester = make_user(
            "cross-division-requester@example.com",
            division="D01",
        )
        target = make_user(
            "other-division-voter@example.com",
            role="voter",
            division="D02",
        )

        with pytest.raises(PermissionError, match="assigned division"):
            request_action(
                requester,
                "bulk_enrolment_change",
                {
                    "changes": [
                        {"user_id": target.id, "is_enrolled": False}
                    ]
                },
            )

        assert db.session.execute(
            db.select(PendingAction).where(
                PendingAction.requested_by_id == requester.id
            )
        ).scalar_one_or_none() is None

        db.session.refresh(target)
        assert target.is_enrolled is True


def test_delegate_cannot_approve_change_for_another_division(app):
    with app.app_context():
        requester = make_user(
            "same-division-requester@example.com",
            division="D01",
        )
        approver = make_user(
            "other-division-approver@example.com",
            division="D02",
        )
        target = make_user(
            "same-division-voter@example.com",
            role="voter",
            division="D01",
        )

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target.id, "is_enrolled": False}]},
        )
        action_id = action.id

        with pytest.raises(PermissionError, match="assigned division"):
            approve_action(action_id, approver)

        db.session.refresh(action)
        db.session.refresh(target)

        assert action.status == "pending"
        assert action.approved_by_id is None
        assert action.executed_at is None
        assert target.is_enrolled is True


def test_delegate_cannot_exclude_candidate_in_another_division(app):
    with app.app_context():
        requester = make_user(
            "candidate-requester@example.com",
            division="D01",
        )

        election = Election(
            name="Cross-division election",
            chamber="house",
            created_by_id=requester.id,
        )
        db.session.add(election)
        db.session.commit()

        division = Division(
            election_id=election.id,
            name="D02",
        )
        db.session.add(division)
        db.session.commit()

        candidate = Candidate(
            division_id=division.id,
            name="Other division candidate",
            party="Example Party",
            position=1,
        )
        db.session.add(candidate)
        db.session.commit()

        with pytest.raises(PermissionError, match="assigned division"):
            request_action(
                requester,
                "candidate_exclusion",
                {"candidate_id": candidate.id},
            )

        db.session.refresh(candidate)
        assert candidate.is_excluded is False


def test_delegate_cannot_move_user_to_another_division(app):
    with app.app_context():
        requester = make_user(
            "division-change-requester@example.com",
            division="D01",
        )
        target = make_user(
            "division-change-target@example.com",
            role="voter",
            division="D01",
        )

        with pytest.raises(
            PermissionError, match="outside their assigned division"
        ):
            request_action(
                requester,
                "bulk_enrolment_change",
                {
                    "changes": [
                        {
                            "user_id": target.id,
                            "division": "D02",
                        }
                    ]
                },
            )

        db.session.refresh(target)
        assert target.division == "D01"

def test_target_moved_to_another_division_before_approval_is_rejected(app):
    with app.app_context():
        requester = make_user(
            "stale-requester@example.com",
            division="D01",
        )
        approver = make_user(
            "stale-approver@example.com",
            division="D01",
        )
        target = make_user(
            "stale-target@example.com",
            role="voter",
            division="D01",
        )

        action = request_action(
            requester,
            "bulk_enrolment_change",
            {"changes": [{"user_id": target.id, "is_enrolled": False}]},
        )

        action_id = action.id
        target_id = target.id

        # Simulate reassignment after the request was created.
        target.division = "D02"
        db.session.commit()

        with pytest.raises(PermissionError, match="assigned division"):
            approve_action(action_id, approver)

        db.session.refresh(action)
        db.session.refresh(target)

        assert action.status == "pending"
        assert action.executed_at is None
        assert target.division == "D02"
        assert target.is_enrolled is True