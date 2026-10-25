"""
S3 – Voting routes (/vote).

Thin HTTP layer over app/voting/casting.py. The security properties (R9, R11,
R12) live in the service; these handlers validate input and shape responses.
"""

from flask import Blueprint, abort, jsonify, render_template, request
from flask_login import current_user

from app.access.permissions import public_endpoint, require_roles
from app.auth.eligibility import check_and_log_eligibility
from app.elections import verify_election
from app.elections.models import STATUS_LOCKED, Election
from app.extensions import db
from app.security.network_access import require_diplomatic_terminal_ip
from app.voting.casting import (
    AlreadyVotedError,
    BallotError,
    cast_ballot,
    find_by_tracking_code,
    has_voted,
)

bp = Blueprint("voting", __name__, url_prefix="/vote")


@bp.get("/diplomatic-terminal")
@public_endpoint
@require_diplomatic_terminal_ip
def diplomatic_terminal():
    """R7: diplomatic terminal access (IP-restricted public endpoint)."""
    return "Diplomatic terminal access permitted."


@bp.get("/")
@require_roles("voter")
def index():
    """List elections open for voting, and whether this voter has voted."""
    elections = db.session.execute(
        db.select(Election).where(Election.status == STATUS_LOCKED)
    ).scalars().all()

    result = []
    for election in elections:
        if not verify_election(election).ok:
            continue
        result.append({
            "election_id": election.id,
            "name": election.name,
            "chamber": election.chamber,
            "has_voted": has_voted(current_user.id, election.id),
        })

    # Browsers get the page with the site layout; API clients keep the JSON
    if request.accept_mimetypes.best_match(["application/json", "text/html"]) == "text/html":
        return render_template("voting/index.html", elections=result)
    return jsonify({"elections": result})


@bp.get("/<int:election_id>")
@require_roles("voter")
def ballot(election_id):
    """Show the ballot (candidates for the voter's division) for an election."""
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)
    if election.status != STATUS_LOCKED or not verify_election(election).ok:
        return jsonify({"error": "Election is not open for voting."}), 409

    division = None
    for div in election.divisions:
        if div.name == current_user.division:
            division = div
            break
    if division is None and election.divisions:
        division = election.divisions[0]
    if division is None:
        return jsonify({"error": "No division found for this election."}), 404

    candidates = [
        {"id": c.id, "name": c.name, "party": c.party, "position": c.position}
        for c in division.candidates if not c.is_excluded
    ]
    return jsonify({
        "election_id": election.id,
        "election_name": election.name,
        "chamber": election.chamber,
        "division": division.name,
        "has_voted": has_voted(current_user.id, election.id),
        "candidates": candidates,
    })


@bp.post("/<int:election_id>/cast")
@require_roles("voter")
def cast(election_id):
    """
    Cast a ranked-preference ballot.

    Body (JSON): {"preferences": [{"candidate_id": 3, "rank": 1}, ...]}
    Returns 201 + tracking_code, 409 if already voted / not open, 400 on bad input.
    """
    # R2: confirm the voter is eligible (enrolled citizen, 18+, has a division)
    # before accepting a ballot. Any refusal is written to the audit log.
    eligible, reason = check_and_log_eligibility(current_user)
    if not eligible:
        return jsonify({"error": "Not eligible to vote.", "reason": reason}), 403

    body = request.get_json(silent=True) or {}
    preferences = body.get("preferences", [])
    try:
        tracking_code = cast_ballot(
            voter_id=current_user.id,
            voter_division=current_user.division,
            election_id=election_id,
            preferences=preferences,
        )
    except AlreadyVotedError as exc:
        return jsonify({"error": str(exc)}), 409
    except BallotError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "message": "Vote cast successfully.",
        "tracking_code": tracking_code,
        "election_id": election_id,
    }), 201


@bp.get("/track/<code>")
@public_endpoint
def track(code):
    """Confirm a ballot is recorded by its tracking code. No contents revealed."""
    result = find_by_tracking_code(code)
    if result is None:
        return jsonify({"included": False}), 404
    return jsonify(result), 200
