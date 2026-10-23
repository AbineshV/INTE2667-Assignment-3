import hashlib

import pytest
from sqlalchemy import text

from app.elections import sign_election
from app.elections.models import Candidate, Division, Election
from app.extensions import db
from app.ledger import LedgerError, append_ballot, lookup_tracking_code, verify_ledger
from app.ledger.chain import GENESIS_HASH, normalise_tracking_code
from app.ledger.models import BallotLedgerEntry
from app.models import User


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def make_admin(email):
    user = User(email=email, password_hash="not-a-real-hash", role="admin")
    db.session.add(user)
    db.session.commit()
    return user


def make_election(name="2026 Federal Election", lock=True):
    first, second = make_admin(f"{name}-a1@example.com"), make_admin(f"{name}-a2@example.com")
    election = Election(name=name, chamber="house", created_by_id=first.id)
    division = Division(name="Melbourne")
    division.candidates = [Candidate(name="Alice", position=1), Candidate(name="Bob", position=2)]
    election.divisions.append(division)
    db.session.add(election)
    db.session.commit()
    if lock:
        sign_election(election, first)
        sign_election(election, second)
    return election


@pytest.fixture
def election(ctx):
    return make_election()


def cast(election, ciphertext):
    return append_ballot(election, election.divisions[0], ciphertext)


def entry(election, sequence):
    return db.session.execute(
        db.select(BallotLedgerEntry).filter_by(election_id=election.id, sequence=sequence)
    ).scalar_one()


def tamper(sql, **params):
    db.session.execute(text(sql), params)
    db.session.commit()
    db.session.expire_all()


# Appending ballots

def test_ballots_are_chained(election):
    for n in range(3):
        cast(election, f"ciphertext-{n}")
    assert entry(election, 1).prev_hash == GENESIS_HASH
    assert entry(election, 2).prev_hash == entry(election, 1).entry_hash
    assert entry(election, 3).prev_hash == entry(election, 2).entry_hash


def test_untouched_ledger_verifies(election):
    for n in range(3):
        cast(election, f"ciphertext-{n}")
    result = verify_ledger(election.id)
    assert result.ok
    assert result.entries_checked == 3
    assert result.head_hash == entry(election, 3).entry_hash


def test_each_ballot_gets_a_unique_tracking_code(election):
    codes = {cast(election, f"ciphertext-{n}") for n in range(20)}
    assert len(codes) == 20
    assert all(normalise_tracking_code(code) == code for code in codes)


def test_tracking_code_is_not_stored(election):
    code = cast(election, "ciphertext")
    row = entry(election, 1)
    assert code not in (row.tracking_hash, row.entry_hash, row.ciphertext)


def test_ledger_has_no_voter_or_time_columns():
    columns = set(BallotLedgerEntry.__table__.columns.keys())
    assert not {"voter_id", "user_id", "created_at", "timestamp"} & columns


def test_unlocked_election_is_refused(ctx):
    draft = make_election("Draft Election", lock=False)
    with pytest.raises(LedgerError, match="locked and verified"):
        cast(draft, "ciphertext")


def test_division_from_another_election_is_refused(election):
    other = make_election("Other Election")
    with pytest.raises(LedgerError, match="division"):
        append_ballot(election, other.divisions[0], "ciphertext")


@pytest.mark.parametrize("ciphertext", ["", None, 123, "x" * 20001])
def test_bad_ciphertext_is_refused(election, ciphertext):
    with pytest.raises(LedgerError):
        cast(election, ciphertext)


def test_each_election_has_its_own_chain(election):
    other = make_election("Other Election")
    cast(election, "a")
    cast(other, "b")
    assert entry(election, 1).prev_hash == GENESIS_HASH
    assert entry(other, 1).prev_hash == GENESIS_HASH
    assert verify_ledger(election.id).ok and verify_ledger(other.id).ok


# Tampering is detected

def test_edited_ciphertext_is_detected(election):
    for n in range(3):
        cast(election, f"ciphertext-{n}")
    tamper("UPDATE ballot_ledger SET ciphertext = 'forged' WHERE id = :id", id=entry(election, 2).id)
    result = verify_ledger(election.id)
    assert not result.ok
    assert result.failed_sequence == 2
    assert "modified" in result.reason


def test_recomputed_ciphertext_hash_is_detected(election):
    cast(election, "ciphertext")
    forged_hash = hashlib.sha256(b"forged").hexdigest()
    tamper("UPDATE ballot_ledger SET ciphertext = 'forged', ciphertext_hash = :h WHERE id = :id",
           h=forged_hash, id=entry(election, 1).id)
    result = verify_ledger(election.id)
    assert not result.ok
    assert "does not match its hash" in result.reason


def test_deleted_ballot_is_detected(election):
    for n in range(3):
        cast(election, f"ciphertext-{n}")
    tamper("DELETE FROM ballot_ledger WHERE id = :id", id=entry(election, 2).id)
    result = verify_ledger(election.id)
    assert not result.ok
    assert result.failed_sequence == 3
    assert "missing or out of order" in result.reason


def test_inserted_ballot_is_detected(election):
    cast(election, "ciphertext-1")
    first = entry(election, 1)
    tamper("INSERT INTO ballot_ledger (election_id, division_id, sequence, ciphertext, "
           "ciphertext_hash, tracking_hash, prev_hash, entry_hash) "
           "VALUES (:e, :d, 2, 'stuffed', :ch, :th, :p, :eh)",
           e=election.id, d=first.division_id, ch="a" * 64, th="b" * 64,
           p=first.entry_hash, eh="c" * 64)
    assert not verify_ledger(election.id).ok


def test_swapped_tracking_hash_is_detected(election):
    cast(election, "ciphertext-1")
    tamper("UPDATE ballot_ledger SET tracking_hash = :h WHERE id = :id",
           h="d" * 64, id=entry(election, 1).id)
    assert not verify_ledger(election.id).ok


# Tracking code lookup

def test_tracking_code_finds_the_ballot(election):
    cast(election, "first")
    code = cast(election, "second")
    result = lookup_tracking_code(code)
    assert result.sequence == 2
    assert result.ciphertext_hash == entry(election, 2).ciphertext_hash


def test_tracking_code_lookup_ignores_case_and_spaces(election):
    code = cast(election, "ciphertext")
    assert lookup_tracking_code(f"  {code.lower()} ") is not None


@pytest.mark.parametrize("code", ["", None, "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA",
                                  "' OR 1=1 --", "<script>alert(1)</script>", 42])
def test_unknown_or_malformed_code_finds_nothing(election, code):
    cast(election, "ciphertext")
    assert lookup_tracking_code(code) is None


# Tracking page

@pytest.fixture
def page_client(app):
    app.config["WTF_CSRF_ENABLED"] = False
    return app.test_client()


def test_track_page_loads(page_client):
    response = page_client.get("/results/track")
    assert response.status_code == 200
    assert b"Track your ballot" in response.data


def test_track_page_finds_ballot(app, page_client):
    with app.app_context():
        election = make_election()
        code = cast(election, "ciphertext")
    response = page_client.post("/results/track", data={"tracking_code": code})
    assert b"It is ballot 1 in the ledger" in response.data


def test_track_page_escapes_input(page_client):
    response = page_client.post("/results/track", data={"tracking_code": "<script>x</script>"})
    assert b"No ballot found" in response.data
    assert b"<script>x</script>" not in response.data


def test_track_page_requires_csrf_token(app):
    app.config["WTF_CSRF_ENABLED"] = True
    response = app.test_client().post("/results/track", data={"tracking_code": "x"})
    assert response.status_code == 400
