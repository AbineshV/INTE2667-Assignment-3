import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from flask import current_app
from sqlalchemy import event, func
from sqlalchemy.orm import Session

from app.audit import log_event
from app.elections import verify_election
from app.extensions import db
from app.ledger import verify_ledger
from app.ledger.models import BallotLedgerEntry
from app.results.models import ResultPublication

ADMIN_ROLES = ("admin",)
ALGORITHM = "Ed25519"


class ResultsError(Exception):
    pass


@dataclass(frozen=True)
class ResultsVerification:
    ok: bool
    reason: str = ""


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _signing_key():
    return current_app.extensions["results_signing_key"]


def public_key_raw(public_key):
    return public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id(public_key):
    # Short fingerprint so clients can tell which key signed a document
    return hashlib.sha256(public_key_raw(public_key)).hexdigest()[:16]


def results_public_key_pem():
    return _signing_key().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _ballots_per_division(election_id):
    rows = db.session.execute(
        db.select(BallotLedgerEntry.division_id, func.count())
        .filter_by(election_id=election_id).group_by(BallotLedgerEntry.division_id)
    ).all()
    return dict(rows)


def _int_keys(mapping):
    try:
        return {int(k) for k in mapping}
    except (TypeError, ValueError) as error:
        raise ResultsError("Tally keys must be division and candidate ids.") from error


def _check_tallies(election, tallies, ballots):
    # tallies: {division_id: {candidate_id: votes}} covering every division and candidate
    if not isinstance(tallies, dict):
        raise ResultsError("Tallies must be a dict of divisions.")
    expected = {d.id: d for d in election.divisions}
    if _int_keys(tallies) != set(expected):
        raise ResultsError("Tallies must cover every division in the election, and only those.")

    divisions = []
    for division_id, division in sorted(expected.items()):
        counts = tallies.get(division_id, tallies.get(str(division_id)))
        if not isinstance(counts, dict):
            raise ResultsError(f"Tallies for '{division.name}' must be a dict of candidates.")
        candidate_ids = {c.id for c in division.candidates}
        if _int_keys(counts) != candidate_ids:
            raise ResultsError(f"Tallies for '{division.name}' must list every candidate exactly once.")

        rows, total = [], 0
        for candidate in division.candidates:
            votes = counts.get(candidate.id, counts.get(str(candidate.id)))
            if isinstance(votes, bool) or not isinstance(votes, int) or votes < 0:
                raise ResultsError("Vote counts must be whole numbers of zero or more.")
            total += votes
            rows.append({"id": candidate.id, "name": candidate.name,
                         "party": candidate.party, "votes": votes})

        if total > ballots.get(division_id, 0):
            raise ResultsError(f"'{division.name}' has more votes than ballots in the ledger.")
        divisions.append({"id": division.id, "name": division.name,
                          "ballots": ballots.get(division_id, 0), "candidates": rows})
    return divisions


def publish_results(election, admin, tallies):
    if admin is None or admin.role not in ADMIN_ROLES:
        raise ResultsError("Only an administrator can publish results.")
    if db.session.execute(db.select(ResultPublication).filter_by(election_id=election.id)).first():
        raise ResultsError("Results for this election have already been published.")

    definition = verify_election(election)
    if not definition.ok:
        raise ResultsError(f"Election definition failed verification: {definition.reason}")
    ledger = verify_ledger(election.id)
    if not ledger.ok:
        raise ResultsError(f"Ballot ledger failed verification: {ledger.reason}")

    divisions = _check_tallies(election, tallies, _ballots_per_division(election.id))
    published_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # Binds the results to the signed definition (R19) and the ballot ledger head (R17)
    document = _canonical_json({
        "election": {"id": election.id, "name": election.name, "chamber": election.chamber,
                     "definition_hash": definition.definition_hash},
        "ledger": {"ballots": ledger.entries_checked, "head_hash": ledger.head_hash},
        "divisions": divisions,
        "published_at": published_at,
        "published_by": admin.id,
    })
    private_key = _signing_key()
    publication = ResultPublication(
        election_id=election.id,
        published_by_id=admin.id,
        document=document,
        document_hash=_sha256(document),
        signature=private_key.sign(document.encode("utf-8")).hex(),
        key_id=key_id(private_key.public_key()),
    )
    db.session.add(publication)
    db.session.commit()

    log_event(f"admin:{admin.id}", "results.published", target=f"election:{election.id}",
              details={"document_hash": publication.document_hash})
    return publication


def verify_results(document, signature_hex, public_key=None):
    # What any client can do with the API response and the published public key
    if public_key is None:
        public_key = _signing_key().public_key()
    if not isinstance(document, str) or not isinstance(signature_hex, str):
        return ResultsVerification(False, "Document and signature must be strings.")
    try:
        public_key.verify(bytes.fromhex(signature_hex), document.encode("utf-8"))
    except (InvalidSignature, ValueError):
        return ResultsVerification(False, "Signature does not match the results document.")
    return ResultsVerification(True)


def verify_publication(publication):
    # Signature check plus a re-check that the definition and ledger have not changed since
    result = verify_results(publication.document, publication.signature)
    if not result.ok:
        return result
    data = json.loads(publication.document)
    definition = verify_election(publication.election)
    if not definition.ok or definition.definition_hash != data["election"]["definition_hash"]:
        return ResultsVerification(False, "Election definition no longer matches the results.")
    ledger = verify_ledger(publication.election_id)
    if not ledger.ok or ledger.head_hash != data["ledger"]["head_hash"]:
        return ResultsVerification(False, "Ballot ledger no longer matches the results.")
    return ResultsVerification(True)


@event.listens_for(Session, "before_flush")
def _block_changes_to_published_results(session, flush_context, instances):
    for obj in list(session.deleted) + list(session.dirty):
        if isinstance(obj, ResultPublication) and (obj in session.deleted or session.is_modified(obj)):
            raise ResultsError("Published results cannot be changed or deleted.")
