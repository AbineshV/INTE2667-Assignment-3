from flask import Blueprint

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.route("/")
def index():
    return "Admin module coming soon."