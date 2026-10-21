from flask import Blueprint

from app.access.permissions import require_roles

bp = Blueprint("enrolment", __name__, url_prefix="/enrolment")


@bp.route("/")
@require_roles("officer", "admin")
def index():
    return "Enrolment module coming soon."