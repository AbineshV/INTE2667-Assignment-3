"""
S3 – Secure ballot casting service (R9, R11, R12).

cast_ballot() is the one place a vote is recorded. In a single transaction it:

  1. (R12) refuses if this voter already has a VoteRecord for the election;
  2. (R9)  encrypts the ranked preferences into a sealed blob;
  3. (R11) stores that blob in an anonymous Ballot row with NO voter_id;
  4. (R12) writes a VoteRecord(voter, election) marker — the unique constraint
           is the real guard against a double vote under concurrency;
  5. logs participation to the audit trail (never the choices).

Because step 3 and step 4 write to different tables that share no column, the
system knows THAT the voter voted and WHAT the anonymous ballots say, but can
never join the two.
"""

import json
import secrets
from datetime import date

from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.audit import log_event
from app.elections import verify_election
from app.elections.models import Division, Election, STATUS_LOCKED
from app.extensions import db
from app.ledger import LedgerError, hash_tracking_code, stage_ballot
from app.ledger.chain import normalise_tracking_code
from app.voting.models import Ballot, VoteRecord

_MAX_ATTEMPTS = 5
# R11: ballot ids are random 62-bit integers, not sequential.
_BALLOT_ID_BITS = 62


class BallotError(Exception):
    """A ballot could not be accepted."""


class AlreadyVotedError(BallotError):
    """This voter has already voted in this election (R12)."""


class InvalidBallotError(BallotError):
    """The ballot's preferences are malformed (R13)."""


def _validate_preferences(preferences, valid_ids):
    """
    R13: a ballot's ranked preferences must be well formed.

    Each entry needs an integer candidate_id and rank. Across the ballot:
      * every candidate must be real and not excluded;
      * no candidate may appear twice;
      * the ranks must be 1..N with no gaps, ties or repeats (a complete,
        strictly ordered preference, as required for a formal House vote).
    """
    candidate_ids = []
    ranks = []
    for entry in preferences:
        try:
            cid = int(entry["candidate_id"])
            rank = int(entry["rank"])
        except (KeyError, TypeError, ValueError):
            raise InvalidBallotError("Each preference needs a candidate_id and a rank.")
        candidate_ids.append(cid)
        ranks.append(rank)

    if any(cid not in valid_ids for cid in candidate_ids):
        raise InvalidBallotError("Ballot references unknown or excluded candidates.")
    if len(set(candidate_ids)) != len(candidate_ids):
        raise InvalidBallotError("A candidate appears more than once on the ballot.")
    if sorted(ranks) != list(range(1, len(ranks) + 1)):
        raise InvalidBallotError("Ranks must be 1..N with no gaps, ties or repeats.")


def has_voted(voter_id, election_id) -> bool:
    return db.session.execute(
        db.select(VoteRecord).filter_by(voter_id=voter_id, election_id=election_id)
    ).scalar_one_or_none() is not None


def _sealing_key():
    return current_app.extensions["ballot_sealing_key"]


def _resolve_division(election, voter_division):
    for div in election.divisions:
        if div.name == voter_division:
            return div
    # Fall back to the first division (e.g. in tests / single-division setups)
    return election.divisions[0] if election.divisions else None


def cast_ballot(voter_id, voter_division, election_id, preferences):
    """
    Record one secure, anonymous ballot and return the voter's tracking code.

    `preferences` is the ranked list the voter submitted, e.g.
    [{"candidate_id": 3, "rank": 1}, {"candidate_id": 7, "rank": 2}].
    """
    election = db.session.get(Election, election_id)
    if election is None:
        raise BallotError("Unknown election.")

    # R19: only accept votes on a verified, locked ballot definition.
    if election.status != STATUS_LOCKED or not verify_election(election).ok:
        raise BallotError("This election is not open for voting.")

    division = _resolve_division(election, voter_division)
    if division is None:
        raise BallotError("No division found for this election.")

    if not preferences:
        raise BallotError("No preferences submitted.")

    # R13: the ranked preferences must be a well-formed, complete ordering.
    valid_ids = {c.id for c in division.candidates if not c.is_excluded}
    _validate_preferences(preferences, valid_ids)

    # R12: early, friendly rejection of a repeat vote.
    if has_voted(voter_id, election_id):
        raise AlreadyVotedError("You have already voted in this election.")

    # R9: seal the preferences before they are stored.
    plaintext = json.dumps(preferences, sort_keys=True, separators=(",", ":"))
    sealed = _sealing_key().encrypt(plaintext.encode("utf-8")).decode("ascii")

    for attempt in range(_MAX_ATTEMPTS):
        # R17: same transaction as the ballot; the ledger code is the receipt
        try:
            tracking_code = stage_ballot(election, division, sealed)
        except LedgerError as exc:
            db.session.rollback()
            raise BallotError(str(exc))

        # R11: the Ballot carries NO voter_id, a RANDOM (non-sequential) id so
        # its order can't be matched to a VoteRecord, and only the cast date.
        db.session.add(Ballot(
            id=secrets.randbits(_BALLOT_ID_BITS) + 1,
            election_id=election_id,
            division_id=division.id,
            chamber=election.chamber,
            sealed_ballot=sealed,
            tracking_code=hash_tracking_code(tracking_code),
            cast_date=date.today(),
        ))
        # R12: the marker that this voter has now voted.
        db.session.add(VoteRecord(voter_id=voter_id, election_id=election_id))

        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            # If the voter raced a second ballot in, the unique constraint fired.
            if has_voted(voter_id, election_id):
                raise AlreadyVotedError("You have already voted in this election.")
            if attempt == _MAX_ATTEMPTS - 1:
                raise
            continue

        # Participation only — never the choices.
        log_event(actor=f"user:{voter_id}", action="vote.cast",
                  target=f"election:{election_id}")
        return tracking_code


def find_by_tracking_code(code):
    """Confirm a ballot is recorded, by its tracking code. No contents returned."""
    code_hash = hash_tracking_code(code)
    if code_hash is None:
        return None
    ballot = db.session.execute(
        db.select(Ballot).filter_by(tracking_code=code_hash)
    ).scalar_one_or_none()
    if ballot is None:
        return None
    return {"tracking_code": normalise_tracking_code(code),
            "election_id": ballot.election_id,
            "cast_date": ballot.cast_date.isoformat(),
            "included": True}
