from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from app.admin.approval_service import approve_action, request_action
from app.extensions import db
from app.models import PendingAction

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
def index():
    return "Admin module coming soon."


def require_delegate():
    if not current_user.is_authenticated:
        abort(401)
    if current_user.role != "delegate":
        abort(403)


@bp.get("/actions")
@login_required
def list_actions():
    require_delegate()

    status = request.args.get("status", "pending")
    if status not in {
        "pending", "executing", "executed", "expired"
    }:
        return jsonify(error="Invalid status filter."), 400

    actions = db.session.execute(
        db.select(PendingAction)
        .where(PendingAction.status == status)
        .order_by(PendingAction.requested_at)
    ).scalars().all()

    return jsonify([
        {
            "id": action.id,
            "action_type": action.action_type,
            "payload": action.payload,
            "requested_by_id": action.requested_by_id,
            "requested_at": action.requested_at.isoformat(),
            "status": action.status,
        }
        for action in actions
    ])


@bp.post("/actions")
@login_required
def create_action():
    require_delegate()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Send a valid JSON object."), 400

    try:
        action = request_action(
            current_user,
            data.get("action_type"),
            data.get("payload"),
        )
    except PermissionError as error:
        return jsonify(error=str(error)), 403
    except ValueError as error:
        return jsonify(error=str(error)), 400

    return jsonify(
        id=action.id,
        action_type=action.action_type,
        status=action.status,
        requested_at=action.requested_at.isoformat(),
    ), 201


@bp.post("/actions/<int:action_id>/approve")
@login_required
def approve_pending_action(action_id):
    require_delegate()

    try:
        action = approve_action(action_id, current_user)
    except PermissionError as error:
        return jsonify(error=str(error)), 403
    except ValueError as error:
        status_code = 404 if str(error) == "Pending action not found." else 400
        return jsonify(error=str(error)), status_code

    return jsonify(
        id=action.id,
        action_type=action.action_type,
        status=action.status,
        approved_by_id=action.approved_by_id,
        executed_at=action.executed_at.isoformat(),
    ), 200