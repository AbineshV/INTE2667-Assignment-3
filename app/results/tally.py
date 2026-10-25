import json
from collections import Counter

from cryptography.fernet import InvalidToken
from sqlalchemy import func

from app.audit import log_event
from app.elections import verify_election
from app.extensions import db
from app.ledger import verify_ledger
from app.ledger.models import BallotLedgerEntry
from app.results.publication import publish_results
from app.voting.models import Ballot
from app.voting.sealing import reconstruct_sealing_key


class TallyError(Exception):
    pass


def _counts_by_division(model, election_id):
    rows = db.session.execute(
        db.select(model.division_id, func.count())
        .filter_by(election_id=election_id).group_by(model.division_id)
    ).all()
    return dict(rows)


def _first_preference(plaintext, candidate_ids):
    try:
        preferences = json.loads(plaintext)
        first = [int(p["candidate_id"]) for p in preferences if int(p["rank"]) == 1]
    except (ValueError, TypeError, KeyError):
        raise TallyError("A decrypted ballot is not in the expected format.")
    if len(first) != 1 or first[0] not in candidate_ids:
        raise TallyError("A decrypted ballot has no valid first preference.")
    return first[0]


def count_first_preferences(election, share_texts):
    # Returns {division_id: {candidate_id: votes}}
    if not verify_election(election).ok:
        raise TallyError("Election definition failed verification.")
    ledger = verify_ledger(election.id)
    if not ledger.ok:
        raise TallyError(f"Ballot ledger failed verification: {ledger.reason}")

    # Ballots table and ledger must match
    if _counts_by_division(Ballot, election.id) != _counts_by_division(BallotLedgerEntry, election.id):
        raise TallyError("The ballot table and the ledger do not match.")

    try:
        key = reconstruct_sealing_key(share_texts)
    except (ValueError, TypeError) as error:
        raise TallyError("Could not rebuild the ballot key from the shares given.") from error

    candidates = {d.id: {c.id for c in d.candidates} for d in election.divisions}
    counts = {division_id: Counter() for division_id in candidates}

    entries = db.session.execute(
        db.select(BallotLedgerEntry).filter_by(election_id=election.id)
        .order_by(BallotLedgerEntry.sequence)
    ).scalars()
    for entry in entries:
        try:
            plaintext = key.decrypt(entry.ciphertext.encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError) as error:
            raise TallyError("A ballot could not be decrypted with the shares given.") from error
        counts[entry.division_id][_first_preference(plaintext, candidates[entry.division_id])] += 1

    return {division_id: {cid: counts[division_id][cid] for cid in ids}
            for division_id, ids in candidates.items()}


def count_and_publish(election, admin, share_texts):
    tallies = count_first_preferences(election, share_texts)
    log_event(f"admin:{admin.id}", "results.counted", target=f"election:{election.id}",
              details={"votes_counted": sum(sum(c.values()) for c in tallies.values())})
    return publish_results(election, admin, tallies)
