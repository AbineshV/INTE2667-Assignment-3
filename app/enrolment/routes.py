from flask import Blueprint

from app.access.permissions import (
    require_division_access,
    require_roles,
)

bp = Blueprint("enrolment", __name__, url_prefix="/enrolment")


@bp.route("/")
@require_roles("officer", "admin")
def index():
    return "Enrolment module coming soon."


@bp.get("/divisions/<string:division>")
@require_division_access("officer", "admin")
def division_index(division):
    return f"Enrolment module for division {division} coming soon."