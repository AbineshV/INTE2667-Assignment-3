from flask import Blueprint, render_template, request

from app.ledger import lookup_tracking_code

from app.access.permissions import require_roles

bp = Blueprint("results", __name__, url_prefix="/results")


@bp.route("/")
@require_roles("admin")
def index():
    return "Results module coming soon."


# POST so the tracking code never appears in URLs or server logs
@bp.route("/track", methods=["GET", "POST"])
def track():
    result = None
    searched = False
    if request.method == "POST":
        searched = True
        result = lookup_tracking_code(request.form.get("tracking_code", ""))
    return render_template("results/track.html", result=result, searched=searched)
