import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from flask import current_app
from sqlalchemy.exc import IntegrityError

from app.audit.models import AuditLogEntry
from app.extensions import db

GENESIS_HASH = "0" * 64

# e.g. "auth.login_failed", "vote.cast"
_ACTION_PATTERN = re.compile(r"[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*")
# Blocks newlines so nobody can forge extra log lines
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

MAX_FIELD_LENGTH = 255
MAX_ACTION_LENGTH = 64
MAX_DETAILS_LENGTH = 2000

# Secrets and vote contents must never reach the log
FORBIDDEN_DETAIL_KEYS = ("password", "secret", "token", "totp", "otp",
                         "ballot", "preference", "vote_choice")

_MAX_APPEND_ATTEMPTS = 3


@dataclass(frozen=True)
class AuditVerification:
    ok: bool
    entries_checked: int
    failed_sequence: Optional[int] = None
    reason: str = ""
    head_hash: str = GENESIS_HASH


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_entry_hash(sequence, created_at, actor, action, target, details, prev_hash):
    payload = {
        "sequence": sequence,
        "created_at": created_at,
        "actor": actor,
        "action": action,
        "target": target,
        "details": details,
        "prev_hash": prev_hash,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _check_text(name, value, required):
    if value is None:
        if required:
            raise ValueError(f"{name} is required.")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string.")
    if required and not value.strip():
        raise ValueError(f"{name} must not be empty.")
    if len(value) > MAX_FIELD_LENGTH:
        raise ValueError(f"{name} is longer than {MAX_FIELD_LENGTH} characters.")
    if _CONTROL_CHARS.search(value):
        raise ValueError(f"{name} must not contain control characters.")
    return value


def _check_details(details):
    if details is None:
        return "{}"
    if not isinstance(details, dict):
        raise ValueError("details must be a dict.")

    def walk(value):
        if isinstance(value, dict):
            for key, inner in value.items():
                lowered = str(key).lower()
                if any(word in lowered for word in FORBIDDEN_DETAIL_KEYS):
                    raise ValueError(f"details must not contain sensitive field '{key}'.")
                walk(inner)
        elif isinstance(value, (list, tuple)):
            for inner in value:
                walk(inner)

    walk(details)
    try:
        encoded = _canonical_json(details)
    except (TypeError, ValueError) as error:
        raise ValueError("details must contain only JSON values.") from error
    if len(encoded) > MAX_DETAILS_LENGTH:
        raise ValueError(f"details is longer than {MAX_DETAILS_LENGTH} characters.")
    return encoded


def _signing_key():
    return current_app.extensions["audit_signing_key"]


def log_event(actor, action, target=None, details=None):
    # Appends one signed entry linked to the previous one, then commits
    actor = _check_text("actor", actor, required=True)
    target = _check_text("target", target, required=False)
    if not isinstance(action, str) or len(action) > MAX_ACTION_LENGTH \
            or not _ACTION_PATTERN.fullmatch(action):
        raise ValueError("action must be a lower-case dotted name such as 'auth.login_failed'.")
    details_json = _check_details(details)
    details_value = json.loads(details_json)

    for attempt in range(_MAX_APPEND_ATTEMPTS):
        last = db.session.execute(
            db.select(AuditLogEntry).order_by(AuditLogEntry.sequence.desc()).limit(1)
        ).scalar_one_or_none()
        sequence = last.sequence + 1 if last else 1
        prev_hash = last.entry_hash if last else GENESIS_HASH
        created_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")

        entry_hash = compute_entry_hash(sequence, created_at, actor, action,
                                        target, details_value, prev_hash)
        signature = _signing_key().sign(entry_hash.encode("ascii")).hex()

        entry = AuditLogEntry(
            sequence=sequence,
            created_at=created_at,
            actor=actor,
            action=action,
            target=target,
            details=details_json,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            signature=signature,
        )
        db.session.add(entry)
        try:
            db.session.commit()
            return entry
        except IntegrityError:
            # Another request took this sequence number first
            db.session.rollback()
            if attempt == _MAX_APPEND_ATTEMPTS - 1:
                raise


def verify_audit_log(public_key=None):
    # Checks sequence, links, hashes and signatures; stops at the first bad entry
    if public_key is None:
        public_key = _signing_key().public_key()

    entries = db.session.execute(
        db.select(AuditLogEntry).order_by(AuditLogEntry.sequence)
    ).scalars()

    expected_sequence = 1
    prev_hash = GENESIS_HASH
    checked = 0

    for entry in entries:
        def fail(reason):
            return AuditVerification(False, checked, entry.sequence, reason, prev_hash)

        if entry.sequence != expected_sequence:
            return fail(f"Expected entry {expected_sequence} but found {entry.sequence}; "
                        "an entry is missing or out of order.")
        if entry.prev_hash != prev_hash:
            return fail("Link to the previous entry is broken.")

        try:
            details_value = json.loads(entry.details)
        except (TypeError, ValueError):
            return fail("Details are not valid JSON.")

        recomputed = compute_entry_hash(entry.sequence, entry.created_at, entry.actor,
                                        entry.action, entry.target, details_value,
                                        entry.prev_hash)
        if recomputed != entry.entry_hash:
            return fail("Entry contents do not match its hash; it has been modified.")

        try:
            public_key.verify(bytes.fromhex(entry.signature), entry.entry_hash.encode("ascii"))
        except (InvalidSignature, ValueError):
            return fail("Signature is not valid for this entry.")

        prev_hash = entry.entry_hash
        expected_sequence += 1
        checked += 1

    return AuditVerification(True, checked, head_hash=prev_hash)
