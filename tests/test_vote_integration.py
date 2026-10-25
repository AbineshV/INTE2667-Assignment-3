import itertools
from datetime import date

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text

from app.audit import verify_audit_log
from app.audit.models import AuditLogEntry
from app.elections import sign_election
from app.elections.models import Candidate, Division, Election
from app.extensions import db
from app.ledger import lookup_tracking_code, verify_ledger
from app.ledger.models import BallotLedgerEntry
from app.models import User
from app.results.cli import publish_results_command
from app.results.publication import verify_publication
from app.results.tally import TallyError, count_and_publish, count_first_preferences
from app.voting.casting import AlreadyVotedError, cast_ballot, find_by_tracking_code
from app.voting.keyshares import format_share, split_secret
from app.voting.models import Ballot


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


@pytest.fixture
def shares(app):
    key = Fernet.generate_key()
    app.extensions["ballot_sealing_key"] = Fernet(key)
    return [format_share(s) for s in split_secret(key, n=5, k=3)]


def make_user(email, role, division=None):
    user = User(email=email, password_hash="not-a-real-hash", role=role, division=division,
                is_citizen=True, is_enrolled=True, date_of_birth=date(1990, 1, 1))
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def election(ctx, shares):
    first, second = make_user("a1@example.com", "admin"), make_user("a2@example.com", "admin")
    election = Election(name="2026 Federal Election", chamber="house", created_by_id=first.id)
    for name in ("Melbourne", "Sydney"):
        division = Division(name=name)
        division.candidates = [Candidate(name=f"{name} A", position=1),
                               Candidate(name=f"{name} B", position=2),
                               Candidate(name=f"{name} C", position=3)]
        election.divisions.append(division)
    db.session.add(election)
    db.session.commit()
    sign_election(election, first)
    sign_election(election, second)
    return election


def vote(election, division_name, order, voter_number):
    division = next(d for d in election.divisions if d.name == division_name)
    voter = make_user(f"voter{voter_number}@example.com", "voter", division_name)
    prefs = [{"candidate_id": division.candidates[i].id, "rank": rank}
             for rank, i in enumerate(order, start=1)]
    return cast_ballot(voter.id, division_name, election.id, prefs)


def admin(email="a1@example.com"):
    return db.session.execute(db.select(User).filter_by(email=email)).scalar_one()


def cast_sample(election):
    return [vote(election, "Melbourne", (0, 1, 2), 1),
            vote(election, "Melbourne", (0, 2, 1), 2),
            vote(election, "Melbourne", (2, 0, 1), 3),
            vote(election, "Sydney", (1, 0, 2), 4)]


# Votes reach the ledger (R17)

def test_cast_vote_is_appended_to_ledger(election):
    codes = cast_sample(election)
    result = verify_ledger(election.id)
    assert result.ok
    assert result.entries_checked == len(codes)


def test_voter_code_works_on_ledger_and_voting_lookup(election):
    code = vote(election, "Melbourne", (0, 1, 2), 1)
    assert lookup_tracking_code(code).sequence == 1
    assert find_by_tracking_code(code)["included"] is True


def test_tracking_page_finds_real_vote(app, election):
    code = vote(election, "Melbourne", (0, 1, 2), 1)
    response = app.test_client().post("/results/track", data={"tracking_code": code})
    assert b"Your ballot has been recorded" in response.data


def test_ledger_and_ballot_hold_the_same_ciphertext(election):
    vote(election, "Melbourne", (0, 1, 2), 1)
    ballot = db.session.execute(db.select(Ballot)).scalar_one()
    entry = db.session.execute(db.select(BallotLedgerEntry)).scalar_one()
    assert ballot.sealed_ballot == entry.ciphertext


def test_plain_tracking_code_is_not_stored(election):
    code = vote(election, "Melbourne", (0, 1, 2), 1)
    ballot = db.session.execute(db.select(Ballot)).scalar_one()
    entry = db.session.execute(db.select(BallotLedgerEntry)).scalar_one()
    assert code not in (ballot.tracking_code, entry.tracking_hash)
    assert ballot.tracking_code == entry.tracking_hash


def test_rejected_second_vote_adds_nothing_to_ledger(election):
    division = election.divisions[0]
    voter = make_user("twice@example.com", "voter", "Melbourne")
    prefs = [{"candidate_id": c.id, "rank": i + 1} for i, c in enumerate(division.candidates)]
    cast_ballot(voter.id, "Melbourne", election.id, prefs)
    with pytest.raises(AlreadyVotedError):
        cast_ballot(voter.id, "Melbourne", election.id, prefs)
    assert db.session.query(BallotLedgerEntry).count() == 1
    assert db.session.query(Ballot).count() == 1


# Counting

def test_first_preferences_are_counted(election, shares):
    cast_sample(election)
    tallies = count_first_preferences(election, shares[:3])
    melbourne, sydney = election.divisions
    assert [tallies[melbourne.id][c.id] for c in melbourne.candidates] == [2, 0, 1]
    assert [tallies[sydney.id][c.id] for c in sydney.candidates] == [0, 1, 0]


def test_any_three_of_five_shares_can_count(election, shares):
    cast_sample(election)
    expected = count_first_preferences(election, shares[:3])
    for combo in itertools.combinations(shares, 3):
        assert count_first_preferences(election, list(combo)) == expected


def test_two_shares_cannot_count(election, shares):
    cast_sample(election)
    with pytest.raises(TallyError):
        count_first_preferences(election, shares[:2])


def test_shares_from_another_key_cannot_count(election):
    cast_sample(election)
    other = [format_share(s) for s in split_secret(Fernet.generate_key(), n=5, k=3)]
    with pytest.raises(TallyError, match="decrypted"):
        count_first_preferences(election, other[:3])


def test_ballot_missing_from_ledger_stops_count(election, shares):
    cast_sample(election)
    db.session.execute(text("DELETE FROM ballot_ledger WHERE sequence = 4"))
    db.session.commit()
    with pytest.raises(TallyError, match="do not match"):
        count_first_preferences(election, shares[:3])


def test_tampered_ledger_stops_count(election, shares):
    cast_sample(election)
    db.session.execute(text("UPDATE ballot_ledger SET ciphertext = 'forged' WHERE sequence = 2"))
    db.session.commit()
    db.session.expire_all()
    with pytest.raises(TallyError, match="ledger failed verification"):
        count_first_preferences(election, shares[:3])


# Publishing counted results (R20)

def test_count_and_publish_signs_real_results(election, shares):
    codes = cast_sample(election)
    publication = count_and_publish(election, admin(), shares[:3])
    assert verify_publication(publication).ok
    assert f'"ballots":{len(codes)}' in publication.document
    actions = db.session.execute(db.select(AuditLogEntry.action)).scalars().all()
    assert "results.counted" in actions and "results.published" in actions
    assert verify_audit_log().ok


def test_results_page_shows_counted_votes(app, election, shares):
    cast_sample(election)
    count_and_publish(election, admin(), shares[:3])
    page = app.test_client().get(f"/results/{election.id}").data
    assert b"Signature verified" in page
    assert b"Melbourne A" in page


def test_cli_publishes_results(app, election, shares, tmp_path):
    cast_sample(election)
    paths = []
    for i, share in enumerate(shares[:3]):
        path = tmp_path / f"share{i}.txt"
        path.write_text(share)
        paths += ["--share", str(path)]
    runner = app.test_cli_runner()

    result = runner.invoke(publish_results_command,
                           [str(election.id), "--admin", "a1@example.com", *paths])
    assert result.exit_code == 0, result.output
    assert "Published signed results" in result.output

    again = runner.invoke(publish_results_command,
                          [str(election.id), "--admin", "a1@example.com", *paths])
    assert again.exit_code != 0
    assert "already been published" in again.output
