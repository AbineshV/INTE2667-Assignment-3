import base64
import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from typing import Optional

from sqlalchemy.exc import IntegrityError

from app.elections import verify_election
from app.extensions import db
from app.ledger.models import BallotLedgerEntry

GENESIS_HASH = "0" * 64
MAX_CIPHERTEXT_LENGTH = 20000
TRACKING_CODE_BYTES = 15

# e.g. "K7QD-M2XA-..." : 24 base32 characters in groups of 4
_TRACKING_CODE_PATTERN = re.compile(r"[A-Z2-7]{4}(-[A-Z2-7]{4}){5}")
_MAX_APPEND_ATTEMPTS = 3


class LedgerError(Exception):
    pass


@dataclass(frozen=True)
class LedgerVerification:
    ok: bool
    entries_checked: int
    failed_sequence: Optional[int] = None
    reason: str = ""
    head_hash: str = GENESIS_HASH


@dataclass(frozen=True)
class TrackingResult:
    election_id: int
    sequence: int
    ciphertext_hash: str


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def new_tracking_code():
    raw = base64.b32encode(secrets.token_bytes(TRACKING_CODE_BYTES)).decode("ascii")
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def normalise_tracking_code(code):
    if not isinstance(code, str):
        return None
    cleaned = code.strip().upper().replace(" ", "")
    return cleaned if _TRACKING_CODE_PATTERN.fullmatch(cleaned) else None


def compute_entry_hash(election_id, sequence, ciphertext_hash, tracking_hash, prev_hash):
    payload = {
        "election_id": election_id,
        "sequence": sequence,
        "ciphertext_hash": ciphertext_hash,
        "tracking_hash": tracking_hash,
        "prev_hash": prev_hash,
    }
    return _sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _last_entry(election_id):
    return db.session.execute(
        db.select(BallotLedgerEntry).filter_by(election_id=election_id)
        .order_by(BallotLedgerEntry.sequence.desc()).limit(1)
    ).scalar_one_or_none()


def hash_tracking_code(code):
    normalised = normalise_tracking_code(code)
    return _sha256(normalised) if normalised else None


def stage_ballot(election, division, ciphertext):
    # Adds the entry without committing so callers can save it with their own rows
    if not verify_election(election).ok:
        raise LedgerError("Ballots can only be recorded for a locked and verified election.")
    if division is None or division.election_id != election.id:
        raise LedgerError("The division does not belong to this election.")
    if not isinstance(ciphertext, str) or not ciphertext:
        raise LedgerError("Ciphertext must be a non-empty string.")
    if len(ciphertext) > MAX_CIPHERTEXT_LENGTH:
        raise LedgerError("Ciphertext is too large.")

    ciphertext_hash = _sha256(ciphertext)
    code = new_tracking_code()
    tracking_hash = _sha256(code)
    last = _last_entry(election.id)
    sequence = last.sequence + 1 if last else 1
    prev_hash = last.entry_hash if last else GENESIS_HASH

    db.session.add(BallotLedgerEntry(
        election_id=election.id,
        division_id=division.id,
        sequence=sequence,
        ciphertext=ciphertext,
        ciphertext_hash=ciphertext_hash,
        tracking_hash=tracking_hash,
        prev_hash=prev_hash,
        entry_hash=compute_entry_hash(election.id, sequence, ciphertext_hash,
                                      tracking_hash, prev_hash),
    ))
    return code


def append_ballot(election, division, ciphertext):
    # Returns the tracking code; show it to the voter once, it is not stored
    for attempt in range(_MAX_APPEND_ATTEMPTS):
        code = stage_ballot(election, division, ciphertext)
        try:
            db.session.commit()
            return code
        except IntegrityError:
            # Another ballot took this sequence number first
            db.session.rollback()
            if attempt == _MAX_APPEND_ATTEMPTS - 1:
                raise


def verify_ledger(election_id):
    entries = db.session.execute(
        db.select(BallotLedgerEntry).filter_by(election_id=election_id)
        .order_by(BallotLedgerEntry.sequence)
    ).scalars()

    expected_sequence = 1
    prev_hash = GENESIS_HASH
    checked = 0

    for entry in entries:
        def fail(reason):
            return LedgerVerification(False, checked, entry.sequence, reason, prev_hash)

        if entry.sequence != expected_sequence:
            return fail(f"Expected ballot {expected_sequence} but found {entry.sequence}; "
                        "a ballot is missing or out of order.")
        if entry.prev_hash != prev_hash:
            return fail("Link to the previous ballot is broken.")
        if _sha256(entry.ciphertext) != entry.ciphertext_hash:
            return fail("Ballot ciphertext has been modified.")
        recomputed = compute_entry_hash(entry.election_id, entry.sequence, entry.ciphertext_hash,
                                        entry.tracking_hash, entry.prev_hash)
        if recomputed != entry.entry_hash:
            return fail("Ledger entry does not match its hash.")

        prev_hash = entry.entry_hash
        expected_sequence += 1
        checked += 1

    return LedgerVerification(True, checked, head_hash=prev_hash)


def lookup_tracking_code(code):
    normalised = normalise_tracking_code(code)
    if normalised is None:
        return None
    entry = db.session.execute(
        db.select(BallotLedgerEntry).filter_by(tracking_hash=_sha256(normalised))
    ).scalar_one_or_none()
    if entry is None:
        return None
    return TrackingResult(entry.election_id, entry.sequence, entry.ciphertext_hash)
