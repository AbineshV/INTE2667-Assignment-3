from flask import Blueprint

from app.access.permissions import public_endpoint, require_roles
from app.security.network_access import require_diplomatic_terminal_ip

bp = Blueprint("voting", __name__, url_prefix="/vote")


@bp.route("/")
@require_roles("voter")
def index():
    return "Voting module coming soon."


@bp.get("/diplomatic-terminal")
@public_endpoint
@require_diplomatic_terminal_ip
def diplomatic_terminal():
    return "Diplomatic terminal access permitted."