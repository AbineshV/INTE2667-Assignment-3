from flask import Blueprint

from app.access.permissions import require_roles

bp = Blueprint("voting", __name__, url_prefix="/vote")


@bp.route("/")
@require_roles("voter")
def index():
    return "Voting module coming soon."