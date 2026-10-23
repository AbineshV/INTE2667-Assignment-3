import json

from flask import Blueprint, abort, current_app, jsonify, render_template, request

from app.extensions import db
from app.ledger import lookup_tracking_code
from app.results.models import ResultPublication
from app.results.publication import (
    ALGORITHM, key_id, results_public_key_pem, verify_publication,
)

from app.access.permissions import require_roles

bp = Blueprint("results", __name__, url_prefix="/results")


def _publication_or_404(election_id):
    publication = db.session.execute(
        db.select(ResultPublication).filter_by(election_id=election_id)
    ).scalar_one_or_none()
    if publication is None:
        abort(404)
    return publication


@bp.route("/")
@require_roles("admin")
def index():
    publications = db.session.execute(
        db.select(ResultPublication).order_by(ResultPublication.id.desc())
    ).scalars().all()
    rows = [(p, json.loads(p.document)) for p in publications]
    return render_template("results/index.html", rows=rows)


@bp.route("/<int:election_id>")
def detail(election_id):
    publication = _publication_or_404(election_id)
    return render_template("results/detail.html", publication=publication,
                           data=json.loads(publication.document),
                           verification=verify_publication(publication))


@bp.route("/api/<int:election_id>")
def api_results(election_id):
    publication = _publication_or_404(election_id)
    # "document" is the exact signed string; verify it as-is, then parse it
    return jsonify({
        "document": publication.document,
        "signature": publication.signature,
        "algorithm": ALGORITHM,
        "key_id": publication.key_id,
    })


@bp.route("/api/public-key")
def api_public_key():
    return jsonify({
        "algorithm": ALGORITHM,
        "key_id": key_id(current_app.extensions["results_signing_key"].public_key()),
        "public_key_pem": results_public_key_pem(),
    })


# POST so the tracking code never appears in URLs or server logs
@bp.route("/track", methods=["GET", "POST"])
def track():
    result = None
    searched = False
    if request.method == "POST":
        searched = True
        result = lookup_tracking_code(request.form.get("tracking_code", ""))
    return render_template("results/track.html", result=result, searched=searched)
