from flask import Blueprint

from app.access.permissions import require_roles

bp = Blueprint("results", __name__, url_prefix="/results")


@bp.route("/")
@require_roles("admin")
def index():
    return "Results module coming soon."