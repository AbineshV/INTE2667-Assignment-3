from flask import Blueprint

from app.security.network_access import require_diplomatic_terminal_ip

bp = Blueprint("voting", __name__, url_prefix="/vote")


@bp.route("/")
def index():
    return "Voting module coming soon."


@bp.get("/diplomatic-terminal")
@require_diplomatic_terminal_ip
def diplomatic_terminal():
    # Ballot functionality will be integrated by the voting subsystem.
    return "Diplomatic terminal access permitted."