import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text

from app.audit import verify_audit_log
from app.audit.models import AuditLogEntry
from app.elections import sign_election
from app.elections.models import Candidate, Division, Election
from app.extensions import db
from app.ledger import append_ballot
from app.models import User
from app.results.models import ResultPublication
from app.results.publication import (
    ResultsError, publish_results, verify_publication, verify_results,
)


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def make_user(email, role="admin"):
    user = User(email=email, password_hash="not-a-real-hash", role=role)
    db.session.add(user)
    db.session.commit()
    return user


def make_election(ballots=(3, 2)):
    first, second = make_user("a1@example.com"), make_user("a2@example.com")
    election = Election(name="2026 Federal Election", chamber="house", created_by_id=first.id)
    for name in ("Melbourne", "Sydney"):
        division = Division(name=name)
        division.candidates = [Candidate(name=f"{name} A", party="Party A", position=1),
                               Candidate(name=f"{name} B", position=2)]
        election.divisions.append(division)
    db.session.add(election)
    db.session.commit()
    sign_election(election, first)
    sign_election(election, second)
    for division, count in zip(election.divisions, ballots):
        for n in range(count):
            append_ballot(election, division, f"{division.name}-ciphertext-{n}")
    return election, first


def tallies_for(election, votes=((2, 1), (1, 1))):
    return {d.id: {c.id: v for c, v in zip(d.candidates, division_votes)}
            for d, division_votes in zip(election.divisions, votes)}


@pytest.fixture
def published(ctx):
    election, admin = make_election()
    return publish_results(election, admin, tallies_for(election))


# Publishing

def test_published_document_is_signed_and_verifies(published):
    assert verify_results(published.document, published.signature).ok
    assert verify_publication(published).ok


def test_document_binds_definition_and_ledger(published):
    data = json.loads(published.document)
    assert data["ledger"]["ballots"] == 5
    assert len(data["ledger"]["head_hash"]) == 64
    assert len(data["election"]["definition_hash"]) == 64
    assert [d["ballots"] for d in data["divisions"]] == [3, 2]


def test_publishing_is_audited(published):
    actions = db.session.execute(db.select(AuditLogEntry.action)).scalars().all()
    assert "results.published" in actions
    assert verify_audit_log().ok


def test_non_admin_cannot_publish(ctx):
    election, _ = make_election()
    with pytest.raises(ResultsError, match="Only an administrator"):
        publish_results(election, make_user("voter@example.com", "voter"), tallies_for(election))


def test_results_can_only_be_published_once(published):
    admin = db.session.get(User, published.published_by_id)
    with pytest.raises(ResultsError, match="already been published"):
        publish_results(published.election, admin, tallies_for(published.election))


def test_unlocked_election_cannot_publish(ctx):
    admin = make_user("solo@example.com")
    election = Election(name="Draft", chamber="house", created_by_id=admin.id)
    division = Division(name="Melbourne")
    division.candidates = [Candidate(name="A", position=1)]
    election.divisions.append(division)
    db.session.add(election)
    db.session.commit()
    with pytest.raises(ResultsError, match="definition failed verification"):
        publish_results(election, admin, {division.id: {division.candidates[0].id: 0}})


def test_tampered_ledger_blocks_publishing(ctx):
    election, admin = make_election()
    db.session.execute(text("UPDATE ballot_ledger SET ciphertext = 'forged' WHERE sequence = 1"))
    db.session.commit()
    db.session.expire_all()
    with pytest.raises(ResultsError, match="ledger failed verification"):
        publish_results(election, admin, tallies_for(election))


# Tally checks

def test_more_votes_than_ballots_is_refused(ctx):
    election, admin = make_election()
    with pytest.raises(ResultsError, match="more votes than ballots"):
        publish_results(election, admin, tallies_for(election, ((3, 1), (1, 1))))


def test_missing_division_is_refused(ctx):
    election, admin = make_election()
    tallies = tallies_for(election)
    tallies.pop(election.divisions[1].id)
    with pytest.raises(ResultsError, match="every division"):
        publish_results(election, admin, tallies)


def test_unknown_candidate_is_refused(ctx):
    election, admin = make_election()
    tallies = tallies_for(election)
    tallies[election.divisions[0].id][999] = 0
    with pytest.raises(ResultsError, match="every candidate"):
        publish_results(election, admin, tallies)


@pytest.mark.parametrize("bad", [-1, 1.5, "2", True, None])
def test_bad_vote_counts_are_refused(ctx, bad):
    election, admin = make_election()
    tallies = tallies_for(election)
    first = election.divisions[0]
    tallies[first.id][first.candidates[0].id] = bad
    with pytest.raises(ResultsError, match="whole numbers"):
        publish_results(election, admin, tallies)


@pytest.mark.parametrize("tallies", [None, [], {"abc": {}}, {"1; DROP TABLE": {}}])
def test_malformed_tallies_are_refused(ctx, tallies):
    election, admin = make_election()
    with pytest.raises(ResultsError):
        publish_results(election, admin, tallies)


# Tampering is detected

def test_edited_document_fails_signature(published):
    forged = published.document.replace('"votes":2', '"votes":9')
    assert forged != published.document
    assert not verify_results(forged, published.signature).ok


def test_wrong_key_fails(published):
    other = Ed25519PrivateKey.generate().public_key()
    assert not verify_results(published.document, published.signature, other).ok


def test_garbage_signature_fails(published):
    assert not verify_results(published.document, "not-hex").ok
    assert not verify_results(published.document, None).ok


def test_orm_edit_of_published_results_is_blocked(published):
    published.document = published.document.replace('"votes":2', '"votes":9')
    with pytest.raises(ResultsError, match="cannot be changed"):
        db.session.commit()
    db.session.rollback()


def test_orm_delete_of_published_results_is_blocked(published):
    db.session.delete(published)
    with pytest.raises(ResultsError, match="cannot be changed"):
        db.session.commit()
    db.session.rollback()


def test_raw_sql_edit_is_detected(published):
    forged = published.document.replace('"votes":2', '"votes":9')
    db.session.execute(text("UPDATE result_publications SET document = :d"), {"d": forged})
    db.session.commit()
    db.session.expire_all()
    publication = db.session.execute(db.select(ResultPublication)).scalar_one()
    assert not verify_publication(publication).ok


def test_ledger_changed_after_publishing_is_detected(published):
    db.session.execute(text("DELETE FROM ballot_ledger WHERE sequence = 5"))
    db.session.commit()
    db.session.expire_all()
    publication = db.session.execute(db.select(ResultPublication)).scalar_one()
    result = verify_publication(publication)
    assert not result.ok
    assert "ledger" in result.reason


def test_results_key_is_separate(app):
    keys = {app.extensions[name].public_key().public_bytes_raw()
            for name in ("audit_signing_key", "election_signing_key", "results_signing_key")}
    assert len(keys) == 3


# API and pages

def test_api_returns_document_that_verifies_with_published_key(app, client, published):
    election_id = published.election_id
    body = client.get(f"/results/api/{election_id}").get_json()
    key_body = client.get("/results/api/public-key").get_json()

    public_key = serialization.load_pem_public_key(key_body["public_key_pem"].encode())
    with app.app_context():
        assert verify_results(body["document"], body["signature"], public_key).ok
    assert body["algorithm"] == "Ed25519"
    assert body["key_id"] == key_body["key_id"]


def test_api_unknown_election_is_404(client):
    assert client.get("/results/api/12345").status_code == 404


def test_results_pages_show_verified_results(client, published):
    election_id = published.election_id
    assert b"2026 Federal Election" in client.get("/results/").data
    page = client.get(f"/results/{election_id}").data
    assert b"Signature verified" in page
    assert b"Melbourne A" in page


def test_results_page_shows_failure_after_tampering(app, client, published):
    election_id = published.election_id
    forged = published.document.replace('"votes":2', '"votes":9')
    db.session.execute(text("UPDATE result_publications SET document = :d"), {"d": forged})
    db.session.commit()
    assert b"Verification failed" in client.get(f"/results/{election_id}").data


def test_empty_results_page(client):
    assert b"No results have been published yet" in client.get("/results/").data
