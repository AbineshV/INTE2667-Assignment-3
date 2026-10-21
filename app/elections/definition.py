import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from flask import current_app
from sqlalchemy import event, inspect, select
from sqlalchemy.orm import Session

from app.audit import log_event
from app.elections.models import (
    CHAMBERS, STATUS_AWAITING_SECOND, STATUS_LOCKED, Candidate, Division, Election,
    ElectionSignature, Group,
)
from app.extensions import db

ADMIN_ROLES = ("admin",)
REQUIRED_SIGNATURES = 2

# Set while sign_election is locking, so the guard lets that one change through
_SIGNING_FLAG = "election_signing"


class ElectionError(Exception):
    pass


@dataclass(frozen=True)
class ElectionVerification:
    ok: bool
    reason: str = ""
    definition_hash: str = ""


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def canonical_definition(election):
    divisions = []
    for division in sorted(election.divisions, key=lambda d: d.id):
        divisions.append({
            "id": division.id,
            "name": division.name,
            "groups": [
                {"id": g.id, "label": g.label, "name": g.name, "position": g.position,
                 "candidates": sorted(c.id for c in g.candidates)}
                for g in sorted(division.groups, key=lambda g: g.position)
            ],
            "candidates": [
                {"id": c.id, "name": c.name, "party": c.party, "position": c.position,
                 "group_id": c.group_id}
                for c in sorted(division.candidates, key=lambda c: c.position)
            ],
        })
    return {"id": election.id, "name": election.name, "chamber": election.chamber,
            "divisions": divisions}


def definition_hash(election):
    return hashlib.sha256(_canonical_json(canonical_definition(election)).encode("utf-8")).hexdigest()


def _signed_message(election_id, digest, admin_id, signed_at):
    return _canonical_json({"election_id": election_id, "definition_hash": digest,
                            "admin_id": admin_id, "signed_at": signed_at}).encode("utf-8")


def _signing_key():
    return current_app.extensions["election_signing_key"]


def _check_complete(election):
    if election.chamber not in CHAMBERS:
        raise ElectionError("Chamber must be 'house' or 'senate'.")
    if not election.divisions:
        raise ElectionError("The election has no divisions.")
    for division in election.divisions:
        if not division.candidates:
            raise ElectionError(f"Division '{division.name}' has no candidates.")
        if election.chamber == "house" and division.groups:
            raise ElectionError("House ballots do not have above-the-line groups.")
        for group in division.groups:
            if not group.candidates:
                raise ElectionError(f"Group {group.label} in '{division.name}' has no candidates.")


def sign_election(election, admin):
    # Each admin signs once; the second different admin locks the definition
    if admin is None or admin.role not in ADMIN_ROLES:
        raise ElectionError("Only an administrator can sign an election definition.")
    if election.is_locked:
        raise ElectionError("This election is already locked.")
    _check_complete(election)

    digest = definition_hash(election)

    stale = [s for s in election.signatures if s.definition_hash != digest]
    for signature in stale:
        election.signatures.remove(signature)

    if any(s.admin_id == admin.id for s in election.signatures):
        raise ElectionError("You have already signed this definition; a different "
                            "administrator must provide the second signature.")

    signed_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    signature = _signing_key().sign(_signed_message(election.id, digest, admin.id, signed_at))
    election.signatures.append(ElectionSignature(
        admin_id=admin.id, definition_hash=digest, signed_at=signed_at, signature=signature.hex(),
    ))

    if len(election.signatures) >= REQUIRED_SIGNATURES:
        election.status = STATUS_LOCKED
        election.locked_at = datetime.now(timezone.utc)
    else:
        election.status = STATUS_AWAITING_SECOND

    db.session.info[_SIGNING_FLAG] = True
    try:
        db.session.commit()
    finally:
        db.session.info.pop(_SIGNING_FLAG, None)

    actor = f"admin:{admin.id}"
    target = f"election:{election.id}"
    if stale:
        log_event(actor, "election.signatures_reset", target=target,
                  details={"removed": len(stale), "definition_hash": digest})
    log_event(actor, "election.signed", target=target,
              details={"definition_hash": digest, "signatures": len(election.signatures)})
    if election.is_locked:
        log_event(actor, "election.locked", target=target, details={"definition_hash": digest})
    return election


def verify_election(election, public_key=None):
    # Voting must only open when this returns ok
    if public_key is None:
        public_key = _signing_key().public_key()
    digest = definition_hash(election)

    if not election.is_locked:
        return ElectionVerification(False, "The election definition is not locked.", digest)

    signers = {s.admin_id for s in election.signatures}
    if len(signers) < REQUIRED_SIGNATURES:
        return ElectionVerification(
            False, f"Needs signatures from {REQUIRED_SIGNATURES} different administrators.", digest)

    for s in election.signatures:
        if s.definition_hash != digest:
            return ElectionVerification(False, "The definition has changed since it was signed.", digest)
        try:
            public_key.verify(bytes.fromhex(s.signature),
                              _signed_message(election.id, s.definition_hash, s.admin_id, s.signed_at))
        except (InvalidSignature, ValueError):
            return ElectionVerification(False, f"Signature from admin {s.admin_id} is not valid.", digest)

    return ElectionVerification(True, definition_hash=digest)


def _stored_status(session, election):
    # Read from the database; the in-memory value may already be changed or expired
    if not inspect(election).persistent:
        return None
    with session.no_autoflush:
        return session.execute(
            select(Election.status).where(Election.id == election.id)
        ).scalar_one_or_none()


def _election_of(obj):
    if isinstance(obj, Election):
        return obj
    if isinstance(obj, (ElectionSignature, Division)):
        return obj.election
    if isinstance(obj, (Group, Candidate)):
        return obj.division.election if obj.division else None
    return None


@event.listens_for(Session, "before_flush")
def _block_changes_to_locked_elections(session, flush_context, instances):
    signing = session.info.get(_SIGNING_FLAG, False)
    changed = list(session.new) + list(session.deleted) + \
        [obj for obj in session.dirty if session.is_modified(obj)]

    for obj in changed:
        election = _election_of(obj)
        if election is None:
            continue
        if _stored_status(session, election) == STATUS_LOCKED:
            raise ElectionError(f"Election {election.id} is locked and cannot be changed.")
        if election.status == STATUS_LOCKED and not signing:
            raise ElectionError("An election can only be locked by two administrator signatures.")
