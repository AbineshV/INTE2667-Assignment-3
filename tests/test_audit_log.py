import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import create_app
from app.audit import log_event, verify_audit_log
from app.audit.logger import GENESIS_HASH, compute_entry_hash
from app.audit.models import AuditLogEntry
from app.config import TestingConfig
from app.extensions import db


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def entry(sequence):
    return db.session.execute(
        db.select(AuditLogEntry).filter_by(sequence=sequence)
    ).scalar_one()


def write_three_events():
    log_event("user:1", "auth.login_success", target="user:1")
    log_event("admin:2", "admin.role_changed", target="user:3", details={"new_role": "auditor"})
    log_event("system", "election.opened", target="election:1")


# Writing entries

def test_entries_are_chained(ctx):
    write_three_events()
    first, second, third = entry(1), entry(2), entry(3)
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.entry_hash
    assert third.prev_hash == second.entry_hash


def test_entry_hash_covers_every_field(ctx):
    log_event("user:1", "auth.login_success", target="user:1", details={"ip": "10.0.0.1"})
    saved = entry(1)
    expected = compute_entry_hash(saved.sequence, saved.created_at, saved.actor, saved.action,
                                  saved.target, {"ip": "10.0.0.1"}, saved.prev_hash)
    assert saved.entry_hash == expected


def test_untouched_log_verifies(ctx):
    write_three_events()
    result = verify_audit_log()
    assert result.ok
    assert result.entries_checked == 3
    assert result.head_hash == entry(3).entry_hash


def test_empty_log_verifies(ctx):
    result = verify_audit_log()
    assert result.ok
    assert result.entries_checked == 0
    assert result.head_hash == GENESIS_HASH


# Tampering is detected

def test_edited_field_is_detected(ctx):
    write_three_events()
    entry(2).target = "user:99"
    db.session.commit()

    result = verify_audit_log()
    assert not result.ok
    assert result.failed_sequence == 2
    assert "modified" in result.reason


def test_edited_details_are_detected(ctx):
    write_three_events()
    entry(2).details = json.dumps({"new_role": "admin"})
    db.session.commit()

    result = verify_audit_log()
    assert not result.ok
    assert result.failed_sequence == 2


def test_recomputed_hash_without_key_is_detected(ctx):
    # Attacker recomputes the hash but cannot re-sign it
    write_three_events()
    row = entry(3)
    row.actor = "user:7"
    row.entry_hash = compute_entry_hash(row.sequence, row.created_at, row.actor, row.action,
                                        row.target, json.loads(row.details), row.prev_hash)
    db.session.commit()

    result = verify_audit_log()
    assert not result.ok
    assert result.failed_sequence == 3
    assert "Signature" in result.reason


def test_resigned_with_attacker_key_is_detected(ctx):
    write_three_events()
    attacker_key = Ed25519PrivateKey.generate()
    row = entry(3)
    row.actor = "user:7"
    row.entry_hash = compute_entry_hash(row.sequence, row.created_at, row.actor, row.action,
                                        row.target, json.loads(row.details), row.prev_hash)
    row.signature = attacker_key.sign(row.entry_hash.encode("ascii")).hex()
    db.session.commit()

    assert not verify_audit_log().ok


def test_deleted_entry_is_detected(ctx):
    write_three_events()
    db.session.delete(entry(2))
    db.session.commit()

    result = verify_audit_log()
    assert not result.ok
    assert result.failed_sequence == 3
    assert "missing or out of order" in result.reason


def test_broken_link_is_detected(ctx):
    write_three_events()
    entry(3).prev_hash = "f" * 64
    db.session.commit()

    result = verify_audit_log()
    assert not result.ok
    assert result.failed_sequence == 3
    assert "Link" in result.reason


def test_verifies_with_published_public_key(app, ctx):
    write_three_events()
    public_key = app.extensions["audit_signing_key"].public_key()
    assert verify_audit_log(public_key=public_key).ok
    assert not verify_audit_log(public_key=Ed25519PrivateKey.generate().public_key()).ok


# Input checks

@pytest.mark.parametrize("details", [
    {"password": "hunter2"},
    {"password_hash": "abc"},
    {"totp_code": "123456"},
    {"reset_token": "abc"},
    {"ballot": [1, 2, 3]},
    {"nested": {"preferences": [3, 1, 2]}},
])
def test_sensitive_details_are_refused(ctx, details):
    with pytest.raises(ValueError):
        log_event("user:1", "vote.cast", details=details)
    assert verify_audit_log().entries_checked == 0


@pytest.mark.parametrize("action", ["", "Login", "auth login", "auth.", "auth..x",
                                    "auth.login\nadmin.ok", "a" * 65, None])
def test_bad_action_names_are_refused(ctx, action):
    with pytest.raises(ValueError):
        log_event("user:1", action)


@pytest.mark.parametrize("actor", ["", "   ", None, "user:1\nadmin:1 granted", "x" * 256, 42])
def test_bad_actor_is_refused(ctx, actor):
    with pytest.raises(ValueError):
        log_event(actor, "auth.login_success")


def test_non_json_details_are_refused(ctx):
    with pytest.raises(ValueError):
        log_event("user:1", "auth.login_success", details={"when": object()})


def test_oversized_details_are_refused(ctx):
    with pytest.raises(ValueError):
        log_event("user:1", "auth.login_success", details={"note": "x" * 3000})


# Signing key storage

class FileKeyConfig(TestingConfig):
    TESTING = False


@pytest.fixture(autouse=True)
def election_key_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(FileKeyConfig, "ELECTION_SIGNING_KEY_PATH",
                        str(tmp_path / "election.pem"), raising=False)


def test_key_file_is_created_owner_only_and_reused(tmp_path):
    key_path = tmp_path / "keys" / "audit.pem"

    class Config(FileKeyConfig):
        AUDIT_SIGNING_KEY_PATH = str(key_path)

    first = create_app(Config)
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600

    second = create_app(Config)
    first_public = first.extensions["audit_signing_key"].public_key().public_bytes_raw()
    second_public = second.extensions["audit_signing_key"].public_key().public_bytes_raw()
    assert first_public == second_public


def test_encrypted_key_file_needs_passphrase(tmp_path, monkeypatch):
    key_path = tmp_path / "audit.pem"

    class Config(FileKeyConfig):
        AUDIT_SIGNING_KEY_PATH = str(key_path)

    monkeypatch.setenv("AUDIT_KEY_PASSPHRASE", "correct horse battery staple")
    create_app(Config)
    assert b"ENCRYPTED" in key_path.read_bytes()

    monkeypatch.delenv("AUDIT_KEY_PASSPHRASE")
    with pytest.raises(RuntimeError):
        create_app(Config)

    monkeypatch.setenv("AUDIT_KEY_PASSPHRASE", "wrong passphrase")
    with pytest.raises(RuntimeError):
        create_app(Config)
