from flask import Blueprint

from app.access.permissions import require_roles

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
@require_roles("admin")
def index():
    return "Admin module coming soon."