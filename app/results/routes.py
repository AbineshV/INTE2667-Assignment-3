from flask import Blueprint

bp = Blueprint("results", __name__, url_prefix="/results")


@bp.route("/")
def index():
    return "Results module coming soon."