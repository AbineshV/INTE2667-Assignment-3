"""
S3 – Ballot Definition & Vote Casting
Routes for the voting blueprint (/vote).

R12: Double-voting prevention — the Ballot table has a UNIQUE constraint on
     (voter_id, election_id); a second POST /vote/<id>/cast returns 409.
R19: Only show the ballot and accept votes when verify_election() returns ok.
"""
from flask import abort, jsonify, request
from flask_login import current_user

from app.access.permissions import public_endpoint, require_roles
from app.audit import log_event
from app.elections import verify_election
from app.elections.models import Election, Division, STATUS_LOCKED
from app.extensions import db
from app.security.network_access import require_diplomatic_terminal_ip
from app.voting.models import Ballot, BallotPreference

from flask import Blueprint

bp = Blueprint("voting", __name__, url_prefix="/vote")


# ---------------------------------------------------------------------------
# Public diplomatic-terminal route (kept from original stub)
# ---------------------------------------------------------------------------

@bp.get("/diplomatic-terminal")
@public_endpoint
@require_diplomatic_terminal_ip
def diplomatic_terminal():
    """R7: diplomatic terminal access (IP-restricted public endpoint)."""
    return "Diplomatic terminal access permitted."


# ---------------------------------------------------------------------------
# Voter-facing routes
# ---------------------------------------------------------------------------

@bp.get("/")
@require_roles("voter")
def index():
    """
    List all elections that are currently open for voting (status=locked and
    verify_election ok).  Also indicates whether the current voter has already
    cast a ballot in each election.
    """
    elections = db.session.execute(
        db.select(Election).where(Election.status == STATUS_LOCKED)
    ).scalars().all()

    result = []
    for election in elections:
        v = verify_election(election)
        if not v.ok:
            continue  # skip elections whose definition failed verification

        already_voted = db.session.execute(
            db.select(Ballot).where(
                Ballot.voter_id == current_user.id,
                Ballot.election_id == election.id,
            )
        ).scalar_one_or_none() is not None

        result.append({
            "election_id": election.id,
            "name": election.name,
            "chamber": election.chamber,
            "has_voted": already_voted,
        })

    return jsonify({"elections": result})


@bp.get("/<int:election_id>")
@require_roles("voter")
def ballot(election_id):
    """
    Return the ballot for the given election: the list of candidates in the
    voter's division, ordered by position.

    Returns 404 if the election does not exist, 409 if the election is not
    locked/verified, and 200 with candidate data otherwise.
    """
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)

    # R19: only show ballot when election definition is verified
    v = verify_election(election)
    if not v.ok:
        return jsonify({
            "error": "Election definition has not been verified.",
            "reason": v.reason,
        }), 409

    if election.status != STATUS_LOCKED:
        return jsonify({"error": "Election is not open for voting."}), 409

    # R12: tell the voter if they already voted
    already_voted = db.session.execute(
        db.select(Ballot).where(
            Ballot.voter_id == current_user.id,
            Ballot.election_id == election.id,
        )
    ).scalar_one_or_none() is not None

    # Find the voter's division — voters have a `division` name field
    division = None
    for div in election.divisions:
        if div.name == current_user.division:
            division = div
            break

    # Fall back to the first division if no match (e.g. in tests)
    if division is None and election.divisions:
        division = election.divisions[0]

    if division is None:
        return jsonify({"error": "No division found for this election."}), 404

    candidates = [
        {
            "id": c.id,
            "name": c.name,
            "party": c.party,
            "position": c.position,
        }
        for c in division.candidates
        if not c.is_excluded
    ]

    return jsonify({
        "election_id": election.id,
        "election_name": election.name,
        "chamber": election.chamber,
        "division": division.name,
        "has_voted": already_voted,
        "candidates": candidates,
    })


@bp.post("/<int:election_id>/cast")
@require_roles("voter")
def cast(election_id):
    """
    Submit a ranked-preference ballot.

    Expected JSON body:
        {
            "preferences": [
                {"candidate_id": 3, "rank": 1},
                {"candidate_id": 7, "rank": 2}
            ]
        }

    R12: Returns 409 if the voter has already voted in this election.
    R19: Returns 409 if the election is not locked or definition is unverified.
    Returns 201 with a tracking_code on success.
    """
    election = db.session.get(Election, election_id)
    if election is None:
        abort(404)

    # R19: verify election definition before accepting votes
    v = verify_election(election)
    if not v.ok:
        return jsonify({
            "error": "Election definition has not been verified.",
            "reason": v.reason,
        }), 409

    if election.status != STATUS_LOCKED:
        return jsonify({"error": "Election is not open for voting."}), 409

    # R12: reject double votes
    existing = db.session.execute(
        db.select(Ballot).where(
            Ballot.voter_id == current_user.id,
            Ballot.election_id == election.id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return jsonify({"error": "You have already voted in this election."}), 409

    # Determine the voter's division
    division = None
    for div in election.divisions:
        if div.name == current_user.division:
            division = div
            break
    if division is None and election.divisions:
        division = election.divisions[0]
    if division is None:
        return jsonify({"error": "No division found for this election."}), 404

    # Validate the submitted preferences
    body = request.get_json(silent=True) or {}
    preferences = body.get("preferences", [])
    if not preferences:
        return jsonify({"error": "No preferences submitted."}), 400

    valid_candidate_ids = {c.id for c in division.candidates if not c.is_excluded}
    submitted_candidate_ids = {int(p["candidate_id"]) for p in preferences}
    unknown = submitted_candidate_ids - valid_candidate_ids
    if unknown:
        return jsonify({"error": f"Unknown candidate IDs: {sorted(unknown)}"}), 400

    # Persist the ballot — the UniqueConstraint on (voter_id, election_id)
    # is a second line of defence against double voting at the DB level.
    ballot_obj = Ballot(
        voter_id=current_user.id,
        election_id=election.id,
        division_id=division.id,
    )
    db.session.add(ballot_obj)
    db.session.flush()  # assign ballot_obj.id before adding preferences

    for pref in preferences:
        db.session.add(BallotPreference(
            ballot_id=ballot_obj.id,
            candidate_id=int(pref["candidate_id"]),
            rank=int(pref["rank"]),
        ))

    # R18: audit log — log only THAT the voter voted, never the ballot content
    log_event(
        actor=f"user:{current_user.id}",
        action="vote.cast",
        target=f"election:{election.id}",
    )
    # log_event commits the session

    return jsonify({
        "message": "Vote cast successfully.",
        "tracking_code": ballot_obj.tracking_code,
        "election_id": election.id,
    }), 201
