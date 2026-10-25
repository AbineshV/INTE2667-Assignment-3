from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from app.audit import log_event
from app.elections.models import Candidate
from app.extensions import db
from app.models import PendingAction, User


APPROVAL_WINDOW = timedelta(minutes=15)

CANDIDATE_EXCLUSION = "candidate_exclusion"
BULK_ENROLMENT_CHANGE = "bulk_enrolment_change"


def _utc(value=None):
    value = value or datetime.now(timezone.utc)

    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _require_delegate(actor):
    """Require a delegate with an assigned division."""
    if actor is None or actor.role != "delegate":
        raise PermissionError(
            "Only delegates can request or approve actions."
        )

    if (
        not isinstance(actor.division, str)
        or not actor.division.strip()
    ):
        raise PermissionError(
            "Delegates must be assigned to a division."
        )


def _validate_payload(action_type, payload):
    """Validate the structure and values of a requested action."""
    if not isinstance(payload, dict):
        raise ValueError("Payload must be a dictionary.")

    if action_type == CANDIDATE_EXCLUSION:
        if set(payload) != {"candidate_id"}:
            raise ValueError(
                "Candidate exclusion requires candidate_id."
            )

        if (
            type(payload["candidate_id"]) is not int
            or payload["candidate_id"] < 1
        ):
            raise ValueError(
                "candidate_id must be a positive integer."
            )

    elif action_type == BULK_ENROLMENT_CHANGE:
        if set(payload) != {"changes"}:
            raise ValueError("Bulk changes require a changes list.")

        changes = payload["changes"]

        if (
            not isinstance(changes, list)
            or not 1 <= len(changes) <= 500
        ):
            raise ValueError(
                "Provide between 1 and 500 user changes."
            )

        seen_ids = set()
        allowed_fields = {
            "user_id",
            "is_citizen",
            "is_enrolled",
            "division",
        }

        for change in changes:
            if not isinstance(change, dict):
                raise ValueError(
                    "Each change must be a dictionary."
                )

            if (
                set(change) - allowed_fields
                or "user_id" not in change
            ):
                raise ValueError(
                    "A change contains an unsupported field."
                )

            user_id = change["user_id"]

            if type(user_id) is not int or user_id < 1:
                raise ValueError(
                    "user_id must be a positive integer."
                )

            if user_id in seen_ids:
                raise ValueError(
                    "A user may appear only once in a bulk change."
                )

            seen_ids.add(user_id)

            fields = set(change) - {"user_id"}

            if not fields:
                raise ValueError(
                    "Each change must update at least one field."
                )

            for field in ("is_citizen", "is_enrolled"):
                if field in change and type(change[field]) is not bool:
                    raise ValueError(
                        f"{field} must be true or false."
                    )

            if "division" in change:
                division = change["division"]

                if division is not None and (
                    not isinstance(division, str)
                    or not division.strip()
                    or len(division) > 100
                ):
                    raise ValueError(
                        "division must be a name of at most 100 characters."
                    )

    else:
        raise ValueError("Unsupported action type.")


def _check_targets(action_type, payload, actor):
    """
    Validate that targets exist and are within the delegate's division.

    This is called when an action is requested and again before it executes.
    """
    if action_type == CANDIDATE_EXCLUSION:
        candidate = db.session.get(
            Candidate,
            payload["candidate_id"],
        )

        if candidate is None:
            raise ValueError("Candidate not found.")

        if (
            candidate.division is None
            or candidate.division.name != actor.division
        ):
            raise PermissionError(
                "Delegates may only act on candidates "
                "in their assigned division."
            )

        if candidate.is_excluded:
            raise ValueError("Candidate is already excluded.")

    elif action_type == BULK_ENROLMENT_CHANGE:
        for change in payload["changes"]:
            user = db.session.get(User, change["user_id"])

            if user is None:
                raise ValueError(
                    f"User {change['user_id']} not found."
                )

            if user.division != actor.division:
                raise PermissionError(
                    "Delegates may only modify users "
                    "in their assigned division."
                )

            if (
                "division" in change
                and change["division"] != actor.division
            ):
                raise PermissionError(
                    "Delegates cannot move users outside "
                    "their assigned division."
                )


def request_action(actor, action_type, payload, now=None):
    """Create a pending action and record the request in the signed audit log."""
    _require_delegate(actor)
    _validate_payload(action_type, payload)
    _check_targets(action_type, payload, actor)

    pending = PendingAction(
        action_type=action_type,
        payload=payload,
        requested_by_id=actor.id,
        requested_at=_utc(now),
        status="pending",
    )

    try:
        db.session.add(pending)
        db.session.flush()

        log_event(
            actor=actor.email,
            action="admin.action_requested",
            target=f"pending_action:{pending.id}",
            details={
                "pending_action_id": pending.id,
                "action_type": action_type,
            },
        )

        return pending

    except Exception:
        db.session.rollback()
        raise


def _execute_action(action, actor):
    """Apply an approved action after rechecking the actor's permissions."""
    _check_targets(action.action_type, action.payload, actor)

    if action.action_type == CANDIDATE_EXCLUSION:
        candidate = db.session.get(
            Candidate,
            action.payload["candidate_id"],
        )

        candidate.is_excluded = True

    elif action.action_type == BULK_ENROLMENT_CHANGE:
        for change in action.payload["changes"]:
            user = db.session.get(User, change["user_id"])

            for field in ("is_citizen", "is_enrolled", "division"):
                if field in change:
                    setattr(user, field, change[field])


def approve_action(action_id, actor, now=None):
    """Approve and execute a pending action once, within the 15-minute window."""
    _require_delegate(actor)
    now = _utc(now)

    action = db.session.execute(
        db.select(PendingAction)
        .where(PendingAction.id == action_id)
        .with_for_update()
    ).scalar_one_or_none()

    if action is None:
        raise ValueError("Pending action not found.")

    if action.status != "pending" or action.executed_at is not None:
        raise ValueError("This action has already been processed.")

    if action.requested_by_id == actor.id:
        raise PermissionError(
            "You cannot approve your own request."
        )

    requested_at = _utc(action.requested_at)

    if now > requested_at + APPROVAL_WINDOW:
        action.status = "expired"

        try:
            log_event(
                actor=actor.email,
                action="admin.action_expired",
                target=f"pending_action:{action.id}",
                details={
                    "pending_action_id": action.id,
                    "action_type": action.action_type,
                },
            )

        except Exception:
            db.session.rollback()
            raise

        raise ValueError(
            "The 15-minute approval window has expired."
        )

    try:
        # Claim the pending action so it cannot be executed twice.
        result = db.session.execute(
            update(PendingAction)
            .where(
                PendingAction.id == action.id,
                PendingAction.status == "pending",
                PendingAction.executed_at.is_(None),
            )
            .values(status="executing"),
            execution_options={"synchronize_session": False},
        )

        if result.rowcount != 1:
            raise ValueError(
                "This action has already been processed."
            )

        action.status = "executing"

        # Revalidate targets against the approving delegate's division.
        _execute_action(action, actor)

        action.approved_by_id = actor.id
        action.approved_at = now
        action.executed_at = now
        action.status = "executed"

        # The audit logger commits the action, business changes and audit entry.
        log_event(
            actor=actor.email,
            action="admin.action_approved",
            target=f"pending_action:{action.id}",
            details={
                "pending_action_id": action.id,
                "action_type": action.action_type,
                "requested_by_id": action.requested_by_id,
            },
        )

        return action

    except Exception:
        db.session.rollback()
        raise