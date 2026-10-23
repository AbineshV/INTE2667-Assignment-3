import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.audit import verify_audit_log
from app.audit.models import AuditLogEntry
from app.elections import ElectionError, definition_hash, sign_election, verify_election
from app.elections.models import (
    STATUS_AWAITING_SECOND, STATUS_DRAFT, STATUS_LOCKED, Candidate, Division, Election,
    ElectionSignature, Group,
)
from app.extensions import db
from app.models import User


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def make_user(email, role):
    user = User(email=email, password_hash="not-a-real-hash", role=role)
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def admins(ctx):
    return make_user("a1@example.com", "admin"), make_user("a2@example.com", "admin")


def make_house_election(creator):
    election = Election(name="2026 Federal Election", chamber="house", created_by_id=creator.id)
    division = Division(name="Melbourne")
    division.candidates = [
        Candidate(name="Alice Smith", party="Party A", position=1),
        Candidate(name="Bob Jones", party="Party B", position=2),
        Candidate(name="Cara Lee", party=None, position=3),
    ]
    election.divisions.append(division)
    db.session.add(election)
    db.session.commit()
    return election


def make_senate_election(creator):
    election = Election(name="2026 Senate", chamber="senate", created_by_id=creator.id)
    division = Division(name="Victoria")
    group_a = Group(label="A", name="Party A", position=1)
    group_b = Group(label="B", name="Party B", position=2)
    division.groups = [group_a, group_b]
    division.candidates = [
        Candidate(name="A One", position=1, group=group_a),
        Candidate(name="A Two", position=2, group=group_a),
        Candidate(name="B One", position=3, group=group_b),
        Candidate(name="Ungrouped", position=4),
    ]
    election.divisions.append(division)
    db.session.add(election)
    db.session.commit()
    return election


def locked_election(admins):
    election = make_house_election(admins[0])
    sign_election(election, admins[0])
    sign_election(election, admins[1])
    return election


# Dual signing

def test_new_election_is_draft_and_not_verified(admins):
    election = make_house_election(admins[0])
    assert election.status == STATUS_DRAFT
    assert not verify_election(election).ok


def test_one_signature_is_not_enough(admins):
    election = make_house_election(admins[0])
    sign_election(election, admins[0])
    assert election.status == STATUS_AWAITING_SECOND
    result = verify_election(election)
    assert not result.ok
    assert "not locked" in result.reason


def test_two_different_admins_lock_the_election(admins):
    election = locked_election(admins)
    assert election.status == STATUS_LOCKED
    assert election.locked_at is not None
    assert verify_election(election).ok


def test_senate_election_can_be_locked(admins):
    election = make_senate_election(admins[0])
    sign_election(election, admins[0])
    sign_election(election, admins[1])
    assert verify_election(election).ok


def test_same_admin_cannot_sign_twice(admins):
    election = make_house_election(admins[0])
    sign_election(election, admins[0])
    with pytest.raises(ElectionError, match="different administrator"):
        sign_election(election, admins[0])
    assert election.status == STATUS_AWAITING_SECOND


@pytest.mark.parametrize("role", ["voter", "auditor", "candidate"])
def test_non_admin_cannot_sign(admins, role):
    election = make_house_election(admins[0])
    with pytest.raises(ElectionError, match="Only an administrator"):
        sign_election(election, make_user(f"{role}@example.com", role))


def test_cannot_sign_locked_election(admins):
    election = locked_election(admins)
    third = make_user("a3@example.com", "admin")
    with pytest.raises(ElectionError, match="already locked"):
        sign_election(election, third)


def test_change_between_signatures_resets_first_signature(admins):
    election = make_house_election(admins[0])
    sign_election(election, admins[0])

    election.divisions[0].candidates[0].name = "Alice Smyth"
    db.session.commit()

    sign_election(election, admins[1])
    assert election.status == STATUS_AWAITING_SECOND
    assert [s.admin_id for s in election.signatures] == [admins[1].id]

    sign_election(election, admins[0])
    assert verify_election(election).ok


# Incomplete definitions

def test_election_without_divisions_cannot_be_signed(admins):
    election = Election(name="Empty", chamber="house", created_by_id=admins[0].id)
    db.session.add(election)
    db.session.commit()
    with pytest.raises(ElectionError, match="no divisions"):
        sign_election(election, admins[0])


def test_division_without_candidates_cannot_be_signed(admins):
    election = make_house_election(admins[0])
    election.divisions.append(Division(name="Empty Division"))
    db.session.commit()
    with pytest.raises(ElectionError, match="no candidates"):
        sign_election(election, admins[0])


def test_house_election_with_groups_cannot_be_signed(admins):
    election = make_house_election(admins[0])
    election.divisions[0].groups.append(Group(label="A", name="Party A", position=1))
    db.session.commit()
    with pytest.raises(ElectionError, match="above-the-line"):
        sign_election(election, admins[0])


# Locked definitions cannot change

def test_editing_candidate_after_lock_is_blocked(admins):
    election = locked_election(admins)
    election.divisions[0].candidates[0].name = "Mallory"
    with pytest.raises(ElectionError, match="locked"):
        db.session.commit()
    db.session.rollback()
    assert verify_election(election).ok


def test_adding_candidate_after_lock_is_blocked(admins):
    election = locked_election(admins)
    election.divisions[0].candidates.append(Candidate(name="Late Entry", position=4))
    with pytest.raises(ElectionError, match="locked"):
        db.session.commit()
    db.session.rollback()


def test_deleting_candidate_after_lock_is_blocked(admins):
    election = locked_election(admins)
    db.session.delete(election.divisions[0].candidates[0])
    with pytest.raises(ElectionError, match="locked"):
        db.session.commit()
    db.session.rollback()


def test_unlocking_is_blocked(admins):
    election = locked_election(admins)
    election.status = STATUS_DRAFT
    with pytest.raises(ElectionError, match="locked"):
        db.session.commit()
    db.session.rollback()


def test_removing_a_signature_is_blocked(admins):
    election = locked_election(admins)
    db.session.delete(election.signatures[0])
    with pytest.raises(ElectionError, match="locked"):
        db.session.commit()
    db.session.rollback()


def test_setting_locked_without_signatures_is_blocked(admins):
    election = make_house_election(admins[0])
    election.status = STATUS_LOCKED
    with pytest.raises(ElectionError, match="two administrator signatures"):
        db.session.commit()
    db.session.rollback()


def test_new_election_created_locked_is_blocked(admins):
    db.session.add(Election(name="Sneaky", chamber="house", created_by_id=admins[0].id,
                            status=STATUS_LOCKED))
    with pytest.raises(ElectionError):
        db.session.commit()
    db.session.rollback()


# Tampering that bypasses the ORM is still detected

def test_raw_sql_edit_after_lock_is_detected(admins):
    election = locked_election(admins)
    candidate_id = election.divisions[0].candidates[0].id
    db.session.execute(text("UPDATE candidates SET name = 'Mallory' WHERE id = :id"),
                       {"id": candidate_id})
    db.session.commit()
    db.session.expire_all()

    result = verify_election(db.session.get(Election, election.id))
    assert not result.ok
    assert "changed since it was signed" in result.reason


def test_forged_signature_is_detected(admins):
    election = locked_election(admins)
    db.session.execute(text("UPDATE election_signatures SET signature = :sig WHERE id = :id"),
                       {"sig": "00" * 64, "id": election.signatures[0].id})
    db.session.commit()
    db.session.expire_all()

    result = verify_election(db.session.get(Election, election.id))
    assert not result.ok
    assert "not valid" in result.reason


def test_database_rejects_same_admin_twice(admins):
    election = locked_election(admins)
    with pytest.raises(IntegrityError):
        db.session.execute(text("UPDATE election_signatures SET admin_id = :admin WHERE id = :id"),
                           {"admin": admins[0].id, "id": election.signatures[1].id})
    db.session.rollback()


def test_wrong_public_key_fails(admins):
    election = locked_election(admins)
    assert not verify_election(election, Ed25519PrivateKey.generate().public_key()).ok


def test_election_key_is_separate_from_audit_key(app):
    election_key = app.extensions["election_signing_key"].public_key().public_bytes_raw()
    audit_key = app.extensions["audit_signing_key"].public_key().public_bytes_raw()
    assert election_key != audit_key


# Hashing and audit trail

def test_hash_changes_when_definition_changes(admins):
    election = make_house_election(admins[0])
    before = definition_hash(election)
    election.divisions[0].candidates[1].party = "Party C"
    db.session.commit()
    assert definition_hash(election) != before


def test_signing_is_written_to_audit_log(admins):
    election = locked_election(admins)
    actions = db.session.execute(
        db.select(AuditLogEntry.action).filter_by(target=f"election:{election.id}")
        .order_by(AuditLogEntry.sequence)
    ).scalars().all()
    assert actions == ["election.signed", "election.signed", "election.locked"]
    assert verify_audit_log().ok


def test_signature_reset_is_audited(admins):
    election = make_house_election(admins[0])
    sign_election(election, admins[0])
    election.name = "Renamed"
    db.session.commit()
    sign_election(election, admins[1])
    actions = db.session.execute(db.select(AuditLogEntry.action)).scalars().all()
    assert "election.signatures_reset" in actions
    assert db.session.query(ElectionSignature).count() == 1
