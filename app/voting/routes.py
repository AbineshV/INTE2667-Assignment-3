from flask import Blueprint

bp = Blueprint("voting", __name__, url_prefix="/vote")


@bp.route("/")
def index():
    return "Voting module coming soon."