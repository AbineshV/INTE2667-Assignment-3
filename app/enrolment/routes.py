from flask import Blueprint

bp = Blueprint("enrolment", __name__, url_prefix="/enrolment")


@bp.route("/")
def index():
    return "Enrolment module coming soon."