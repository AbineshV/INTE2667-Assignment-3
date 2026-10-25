"""
S3 – R2 eligibility integration, R11 hardening, R13 rank validation.

  R2  — the cast route refuses an ineligible voter (and logs it).
  R11 — ballots get random (non-sequential) ids and a date-only timestamp, so
        they can't be matched to a VoteRecord by id-order or by time.
  R13 — malformed ranked preferences are rejected.
"""

from datetime import date

import pytest

from app import create_app, db
from app.config import TestingConfig
from app.auth.passwords import hash_password
from app.elections.definition import sign_election
from app.elections.models import Candidate, Division, Election
from app.models import User
from app.voting.casting import InvalidBallotError, cast_ballot
from app.voting.models import Ballot, VoteRecord


@pytest.fixture
def app():
    return create_app(TestingConfig)


@pytest.fixture
def election(app):
    """A locked House election with two candidates in division 'Lalor'."""
    with app.app_context():
        a1 = User(email="a1@aec.gov.au", password_hash="x", role="admin")
        a2 = User(email="a2@aec.gov.au", password_hash="x", role="admin")
        db.session.add_all([a1, a2])
        db.session.commit()

        e = Election(name="2026 House", chamber="house", created_by_id=a1.id)
        d = Division(name="Lalor")
        d.candidates = [
            Candidate(name="A", party="Ind", position=1),
            Candidate(name="B", party="Ind", position=2),
        ]
        e.divisions.append(d)
        db.session.add(e)
        db.session.commit()
        sign_election(e, a1)
        sign_election(e, a2)
        yield {"election_id": e.id, "candidates": [c.id for c in d.candidates]}


def _good_prefs(cands):
    return [{"candidate_id": cands[0], "rank": 1},
            {"candidate_id": cands[1], "rank": 2}]


# ------------------------------------------------------------------ R2 ----- #
def _auth_client(app, **user_kwargs):
    """A logged-in voter via the real login flow (no MFA set up yet, so the
    password step logs them straight in)."""
    with app.app_context():
        u = User(email=user_kwargs.pop("email", "voter@aec.gov.au"),
                 password_hash=hash_password("Pass@123"), role="voter",
                 totp_secret=None, **user_kwargs)
        db.session.add(u)
        db.session.commit()
    client = app.test_client()
    client.post("/auth/login",
                data={"email": "voter@aec.gov.au", "password": "Pass@123"})
    return client


def test_ineligible_voter_is_refused_by_cast_route(app, election):
    # enrolled citizen but NO date_of_birth -> ineligible (R2)
    client = _auth_client(app, is_citizen=True, is_enrolled=True,
                          division="Lalor", date_of_birth=None)
    resp = client.post(f"/vote/{election['election_id']}/cast",
                       json={"preferences": _good_prefs(election["candidates"])})
    assert resp.status_code == 403
    assert resp.get_json()["reason"] == "NO_DOB"


def test_eligible_voter_is_accepted_by_cast_route(app, election):
    client = _auth_client(app, is_citizen=True, is_enrolled=True,
                          division="Lalor", date_of_birth=date(1990, 1, 1))
    resp = client.post(f"/vote/{election['election_id']}/cast",
                       json={"preferences": _good_prefs(election["candidates"])})
    assert resp.status_code == 201
    assert "tracking_code" in resp.get_json()


# ----------------------------------------------------------------- R11 ----- #
def test_ballot_ids_are_random_not_sequential(app, election):
    with app.app_context():
        for v in range(4):
            cast_ballot(1000 + v, "Lalor", election["election_id"],
                        _good_prefs(election["candidates"]))
        ids = [b.id for b in Ballot.query.all()]
        # not the sequence 1,2,3,4 and each is a large random number
        assert ids != [1, 2, 3, 4]
        assert all(i > 10 ** 6 for i in ids)


def test_ballot_stores_date_only_not_a_precise_time(app, election):
    with app.app_context():
        cast_ballot(2000, "Lalor", election["election_id"],
                    _good_prefs(election["candidates"]))
        ballot = Ballot.query.first()
        assert isinstance(ballot.cast_date, date)
        # Ballot has no precise timestamp column to correlate against a VoteRecord
        assert "cast_at" not in {c.name for c in Ballot.__table__.columns}


# ----------------------------------------------------------------- R13 ----- #
def test_duplicate_rank_is_rejected(app, election):
    with app.app_context():
        c = election["candidates"]
        bad = [{"candidate_id": c[0], "rank": 1}, {"candidate_id": c[1], "rank": 1}]
        with pytest.raises(InvalidBallotError):
            cast_ballot(3000, "Lalor", election["election_id"], bad)


def test_gap_in_ranks_is_rejected(app, election):
    with app.app_context():
        c = election["candidates"]
        bad = [{"candidate_id": c[0], "rank": 1}, {"candidate_id": c[1], "rank": 3}]
        with pytest.raises(InvalidBallotError):
            cast_ballot(3001, "Lalor", election["election_id"], bad)


def test_duplicate_candidate_is_rejected(app, election):
    with app.app_context():
        c = election["candidates"]
        bad = [{"candidate_id": c[0], "rank": 1}, {"candidate_id": c[0], "rank": 2}]
        with pytest.raises(InvalidBallotError):
            cast_ballot(3002, "Lalor", election["election_id"], bad)


def test_valid_ballot_is_accepted(app, election):
    with app.app_context():
        code = cast_ballot(3003, "Lalor", election["election_id"],
                           _good_prefs(election["candidates"]))
        assert isinstance(code, str)
