"""
S3 – R12: Double-voting prevention & ballot definition tests.
Tests for the voting blueprint: ballot display, vote casting, and the
database-level guard that rejects a second vote from the same voter.
"""
import pytest

from app.elections.models import Election, Division, Candidate, STATUS_LOCKED
from app.extensions import db
from app.voting.models import Ballot, BallotPreference


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_voter(app, email="voter@test.local", password="Pass@123",
                division="Division A"):
    """Create an enrolled voter and return an authenticated test client."""
    from app.models import User
    from app.auth.passwords import hash_password

    with app.app_context():
        if not db.session.execute(
            db.select(User).where(User.email == email)
        ).scalar_one_or_none():
            u = User(
                email=email,
                password_hash=hash_password(password),
                role="voter",
                is_citizen=True,
                is_enrolled=True,
                division=division,
            )
            db.session.add(u)
            db.session.commit()

    client = app.test_client()
    r = client.post("/auth/login", data={"email": email, "password": password})
    assert r.status_code == 302, f"Voter login failed: {r.status_code}"
    return client


def _make_admin(app, email="admin@test.local", password="Admin@123"):
    """Create an admin and return an authenticated test client."""
    from app.models import User
    from app.auth.passwords import hash_password

    with app.app_context():
        if not db.session.execute(
            db.select(User).where(User.email == email)
        ).scalar_one_or_none():
            u = User(
                email=email,
                password_hash=hash_password(password),
                role="admin",
                is_citizen=True,
                is_enrolled=True,
            )
            db.session.add(u)
            db.session.commit()

    client = app.test_client()
    r = client.post("/auth/login", data={"email": email, "password": password})
    assert r.status_code == 302, f"Admin login failed: {r.status_code}"
    return client


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def locked_election(app):
    """A LOCKED election with one division and two candidates.

    We properly sign it with two admins so that verify_election() returns ok=True,
    which the voting routes check before showing the ballot or accepting votes (R19).
    The app context is NOT held open across the yield so that _make_voter's own
    app_context calls don't create conflicting nested sessions.
    """
    from app.models import User
    from app.auth.passwords import hash_password
    from app.elections.definition import sign_election
    from app.elections.models import STATUS_DRAFT

    with app.app_context():
        def _get_or_create_admin(email):
            u = db.session.execute(
                db.select(User).where(User.email == email)
            ).scalar_one_or_none()
            if u is None:
                u = User(
                    email=email,
                    password_hash=hash_password("Pass@123"),
                    role="admin",
                    is_citizen=True,
                    is_enrolled=True,
                )
                db.session.add(u)
                db.session.flush()
            return u

        admin1 = _get_or_create_admin("creator@test.local")
        admin2 = _get_or_create_admin("creator2@test.local")

        # Create as DRAFT first (signing process will lock it)
        election = Election(
            name="Test Election",
            chamber="house",
            status=STATUS_DRAFT,
            created_by_id=admin1.id,
        )
        db.session.add(election)
        db.session.flush()

        div = Division(election_id=election.id, name="Division A")
        db.session.add(div)
        db.session.flush()

        c1 = Candidate(division_id=div.id, name="Alice",
                       party="Party A", position=1)
        c2 = Candidate(division_id=div.id, name="Bob",
                       party="Party B", position=2)
        db.session.add_all([c1, c2])
        db.session.commit()

        # Two admins sign → status becomes LOCKED automatically
        election = db.session.get(Election, election.id)
        sign_election(election, admin1)
        election = db.session.get(Election, election.id)
        sign_election(election, admin2)

        # Capture the ID so tests can re-query as needed.
        # Expunge the election from the session so it can be yielded
        # without holding an app context open (which would create a
        # conflicting scoped session when _make_voter pushes its own context).
        election = db.session.get(Election, election.id)
        db.session.expunge(election)
        election_id = election.id

    # Yield the detached election object (only .id is accessed by tests;
    # tests re-query inside their own app.app_context() blocks for anything else)
    yield election
    # No teardown — in-memory DB is discarded after each test.


@pytest.fixture
def draft_election(app):
    """A DRAFT election — cannot be voted on."""
    with app.app_context():
        from app.models import User
        from app.auth.passwords import hash_password

        creator = db.session.execute(
            db.select(User).where(User.role == "admin")
        ).scalar_one_or_none()
        if creator is None:
            creator = User(
                email="creator2@test.local",
                password_hash=hash_password("Pass@123"),
                role="admin",
                is_citizen=True,
                is_enrolled=True,
            )
            db.session.add(creator)
            db.session.flush()

        from app.elections.models import STATUS_DRAFT
        election = Election(
            name="Draft Election",
            chamber="senate",
            status=STATUS_DRAFT,
            created_by_id=creator.id,
        )
        db.session.add(election)
        db.session.commit()
        yield election


# ---------------------------------------------------------------------------
# Tests: ballot index
# ---------------------------------------------------------------------------

class TestVotingIndex:
    """GET /vote/ — list of elections available to the voter."""

    def test_index_requires_login(self, client):
        r = client.get("/vote/")
        assert r.status_code in (302, 401, 403)

    def test_index_returns_locked_elections(self, app, locked_election):
        voter = _make_voter(app)
        r = voter.get("/vote/")
        assert r.status_code == 200
        data = r.get_json()
        ids = [e["election_id"] for e in data["elections"]]
        assert locked_election.id in ids

    def test_index_excludes_draft_elections(self, app, draft_election):
        voter = _make_voter(app)
        r = voter.get("/vote/")
        assert r.status_code == 200
        data = r.get_json()
        ids = [e["election_id"] for e in data["elections"]]
        assert draft_election.id not in ids

    def test_index_shows_has_voted_false_before_voting(self, app, locked_election):
        voter = _make_voter(app)
        r = voter.get("/vote/")
        data = r.get_json()
        entry = next(e for e in data["elections"]
                     if e["election_id"] == locked_election.id)
        assert entry["has_voted"] is False

    def test_index_shows_has_voted_true_after_voting(self, app, locked_election):
        voter = _make_voter(app)
        with app.app_context():
            election = db.session.get(Election, locked_election.id)
            div = election.divisions[0]
            cands = div.candidates
        voter.post(f"/vote/{locked_election.id}/cast", json={
            "preferences": [
                {"candidate_id": cands[0].id, "rank": 1},
                {"candidate_id": cands[1].id, "rank": 2},
            ]
        })
        r = voter.get("/vote/")
        data = r.get_json()
        entry = next(e for e in data["elections"]
                     if e["election_id"] == locked_election.id)
        assert entry["has_voted"] is True


# ---------------------------------------------------------------------------
# Tests: ballot display
# ---------------------------------------------------------------------------

class TestBallotDisplay:
    """GET /vote/<election_id> — show the ballot."""

    def test_ballot_requires_login(self, client, locked_election):
        r = client.get(f"/vote/{locked_election.id}")
        assert r.status_code in (302, 401, 403)

    def test_ballot_404_for_unknown_election(self, app):
        voter = _make_voter(app)
        r = voter.get("/vote/99999")
        assert r.status_code == 404

    def test_ballot_returns_candidates(self, app, locked_election):
        voter = _make_voter(app)
        r = voter.get(f"/vote/{locked_election.id}")
        assert r.status_code == 200
        data = r.get_json()
        assert "candidates" in data
        names = {c["name"] for c in data["candidates"]}
        assert "Alice" in names
        assert "Bob" in names

    def test_ballot_shows_has_voted_false(self, app, locked_election):
        voter = _make_voter(app)
        r = voter.get(f"/vote/{locked_election.id}")
        data = r.get_json()
        assert data["has_voted"] is False

    def test_ballot_rejected_for_draft_election(self, app, draft_election):
        voter = _make_voter(app)
        r = voter.get(f"/vote/{draft_election.id}")
        assert r.status_code == 409


# ---------------------------------------------------------------------------
# Tests: vote casting (R12)
# ---------------------------------------------------------------------------

class TestVoteCasting:
    """POST /vote/<election_id>/cast — R12 and general vote submission."""

    def test_cast_requires_login(self, client, locked_election):
        r = client.post(f"/vote/{locked_election.id}/cast",
                        json={"preferences": []})
        assert r.status_code in (302, 401, 403)

    def test_cast_vote_returns_201_and_tracking_code(self, app, locked_election):
        voter = _make_voter(app)
        with app.app_context():
            cands = db.session.get(
                Election, locked_election.id
            ).divisions[0].candidates
        r = voter.post(f"/vote/{locked_election.id}/cast", json={
            "preferences": [
                {"candidate_id": cands[0].id, "rank": 1},
                {"candidate_id": cands[1].id, "rank": 2},
            ]
        })
        assert r.status_code == 201
        data = r.get_json()
        assert "tracking_code" in data
        assert len(data["tracking_code"]) == 64  # 32-byte hex

    def test_vote_recorded_in_database(self, app, locked_election):
        voter = _make_voter(app)
        with app.app_context():
            cands = db.session.get(
                Election, locked_election.id
            ).divisions[0].candidates
            voter_id = db.session.execute(
                db.select(__import__("app.models", fromlist=["User"]).User)
                .where(__import__("app.models", fromlist=["User"]).User.email == "voter@test.local")
            ).scalar_one().id

        voter.post(f"/vote/{locked_election.id}/cast", json={
            "preferences": [{"candidate_id": cands[0].id, "rank": 1}]
        })

        with app.app_context():
            ballot = db.session.execute(
                db.select(Ballot).where(
                    Ballot.voter_id == voter_id,
                    Ballot.election_id == locked_election.id,
                )
            ).scalar_one_or_none()
            assert ballot is not None
            assert len(ballot.preferences) == 1

    def test_r12_double_vote_rejected(self, app, locked_election):
        """R12: a second vote from the same voter must be rejected (409)."""
        voter = _make_voter(app)
        with app.app_context():
            cands = db.session.get(
                Election, locked_election.id
            ).divisions[0].candidates

        payload = {"preferences": [{"candidate_id": cands[0].id, "rank": 1}]}
        r1 = voter.post(f"/vote/{locked_election.id}/cast", json=payload)
        assert r1.status_code == 201

        r2 = voter.post(f"/vote/{locked_election.id}/cast", json=payload)
        assert r2.status_code == 409
        assert "already voted" in r2.get_json()["error"].lower()

    def test_cast_rejected_for_draft_election(self, app, draft_election):
        voter = _make_voter(app)
        r = voter.post(f"/vote/{draft_election.id}/cast",
                       json={"preferences": []})
        assert r.status_code in (404, 409)

    def test_cast_rejected_for_unknown_election(self, app):
        voter = _make_voter(app)
        r = voter.post("/vote/99999/cast", json={"preferences": []})
        assert r.status_code == 404

    def test_cast_rejected_for_invalid_candidate(self, app, locked_election):
        voter = _make_voter(app)
        r = voter.post(f"/vote/{locked_election.id}/cast", json={
            "preferences": [{"candidate_id": 99999, "rank": 1}]
        })
        assert r.status_code == 400

    def test_two_voters_can_each_vote_once(self, app, locked_election):
        """Two different voters can both cast ballots independently."""
        voter1 = _make_voter(app, email="voter1@test.local")
        voter2 = _make_voter(app, email="voter2@test.local")
        with app.app_context():
            cands = db.session.get(
                Election, locked_election.id
            ).divisions[0].candidates

        payload = {"preferences": [{"candidate_id": cands[0].id, "rank": 1}]}
        r1 = voter1.post(f"/vote/{locked_election.id}/cast", json=payload)
        r2 = voter2.post(f"/vote/{locked_election.id}/cast", json=payload)
        assert r1.status_code == 201
        assert r2.status_code == 201

    def test_tracking_codes_are_unique(self, app, locked_election):
        """Each ballot gets a unique tracking code."""
        voter1 = _make_voter(app, email="v1@test.local")
        voter2 = _make_voter(app, email="v2@test.local")
        with app.app_context():
            cands = db.session.get(
                Election, locked_election.id
            ).divisions[0].candidates

        payload = {"preferences": [{"candidate_id": cands[0].id, "rank": 1}]}
        tc1 = voter1.post(f"/vote/{locked_election.id}/cast",
                          json=payload).get_json()["tracking_code"]
        tc2 = voter2.post(f"/vote/{locked_election.id}/cast",
                          json=payload).get_json()["tracking_code"]
        assert tc1 != tc2
