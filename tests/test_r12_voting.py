"""
S3 – Secure ballot tests (R9 encryption, R11 unlinkability, R12 one vote).

Each test targets a security property, not just the happy path:
  R12 - a voter cannot vote twice
  R9  - the stored ballot is encrypted, not plaintext
  R11 - nothing links a voter to their ballot
"""

import json

import pytest

from app import create_app, db
from app.config import TestingConfig
from app.elections.definition import sign_election
from app.elections.models import Candidate, Division, Election
from app.models import User
from app.auth.passwords import hash_password
from app.voting.casting import (
    AlreadyVotedError,
    cast_ballot,
    find_by_tracking_code,
    has_voted,
)
from app.voting.models import Ballot, VoteRecord


@pytest.fixture
def app():
    return create_app(TestingConfig)


@pytest.fixture
def setup(app):
    """A locked House election (two admin signatures) and one enrolled voter."""
    with app.app_context():
        a1 = User(email="a1@aec.gov.au", password_hash="x", role="admin")
        a2 = User(email="a2@aec.gov.au", password_hash="x", role="admin")
        voter = User(email="v@aec.gov.au", password_hash=hash_password("Pass@123"),
                     role="voter", is_citizen=True, is_enrolled=True,
                     division="Lalor")
        db.session.add_all([a1, a2, voter])
        db.session.commit()

        election = Election(name="2026 House", chamber="house", created_by_id=a1.id)
        division = Division(name="Lalor")
        division.candidates = [
            Candidate(name="A. Candidate", party="Ind", position=1),
            Candidate(name="B. Candidate", party="Ind", position=2),
        ]
        election.divisions.append(division)
        db.session.add(election)
        db.session.commit()

        sign_election(election, a1)
        sign_election(election, a2)  # locks it

        prefs = [{"candidate_id": c.id, "rank": i + 1}
                 for i, c in enumerate(division.candidates)]
        yield {"election_id": election.id, "voter_id": voter.id,
               "division": "Lalor", "preferences": prefs}


def _cast(s):
    return cast_ballot(s["voter_id"], s["division"], s["election_id"], s["preferences"])


# ---- R12: one vote per voter ---------------------------------------------- #
def test_vote_is_recorded(app, setup):
    with app.app_context():
        code = _cast(setup)
        assert len(code) == 32
        assert has_voted(setup["voter_id"], setup["election_id"]) is True


def test_voter_cannot_vote_twice(app, setup):
    with app.app_context():
        _cast(setup)
        with pytest.raises(AlreadyVotedError):
            _cast(setup)
        # only one ballot and one marker exist
        assert Ballot.query.count() == 1
        assert VoteRecord.query.count() == 1


# ---- R9: ballot is encrypted ---------------------------------------------- #
def test_ballot_is_encrypted_at_rest(app, setup):
    with app.app_context():
        _cast(setup)
        ballot = Ballot.query.first()
        plaintext = json.dumps(setup["preferences"], sort_keys=True,
                               separators=(",", ":"))
        assert plaintext not in ballot.sealed_ballot        # not stored in clear
        assert ballot.sealed_ballot.startswith("gAAAA")     # Fernet token


# ---- R11: voter cannot be linked to their ballot -------------------------- #
def test_ballot_has_no_voter_link(app, setup):
    with app.app_context():
        _cast(setup)
        ballot = Ballot.query.first()
        # The Ballot table must not carry a voter reference at all (R11).
        assert not hasattr(ballot, "voter_id")
        columns = {c.name for c in Ballot.__table__.columns}
        assert "voter_id" not in columns
        assert "user_id" not in columns


def test_marker_and_ballot_cannot_be_joined(app, setup):
    with app.app_context():
        _cast(setup)
        record = VoteRecord.query.first()
        ballot = Ballot.query.first()
        # The marker knows the voter but holds no ballot/content reference,
        # and the ballot holds no voter reference — so they can't be joined.
        record_cols = {c.name for c in VoteRecord.__table__.columns}
        assert "ballot_id" not in record_cols
        assert "tracking_code" not in record_cols
        assert "sealed_ballot" not in record_cols


# ---- receipt (verifiable inclusion, no contents) -------------------------- #
def test_tracking_code_confirms_inclusion_without_contents(app, setup):
    with app.app_context():
        code = _cast(setup)
        result = find_by_tracking_code(code)
        assert result["included"] is True
        assert "sealed_ballot" not in result
        assert find_by_tracking_code("NOPE") is None
