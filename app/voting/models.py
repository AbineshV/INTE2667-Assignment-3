"""
S3 – Ballot Definition & Vote Casting
Models for recording that a voter cast a ballot (R12) and their preferences.

The Ballot table has a UNIQUE constraint on (voter_id, election_id) which is
the database-level guard against double voting (R12).  BallotPreference stores
the ranked choices without linking directly to the voter, so the tally can be
computed by S4 without knowing who voted for whom.
"""
import secrets
from datetime import datetime, timezone

from app.extensions import db


def _utc_now():
    return datetime.now(timezone.utc)


class Ballot(db.Model):
    """
    Records that voter cast a ballot in an election.  One row per
    (voter, election) pair — the UniqueConstraint enforces R12.
    The tracking_code is a random token the voter can use to confirm
    their vote was counted without revealing which candidate they chose.
    """
    __tablename__ = "ballots"
    __table_args__ = (
        db.UniqueConstraint("voter_id", "election_id",
                            name="uq_ballot_voter_election"),
    )

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey("users.id"),
                         nullable=False, index=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"),
                            nullable=False, index=True)
    division_id = db.Column(db.Integer, db.ForeignKey("divisions.id"),
                            nullable=False)
    cast_at = db.Column(db.DateTime(timezone=True),
                        default=_utc_now, nullable=False)
    # 32-byte hex token shown to the voter as a receipt (R17 compatible)
    tracking_code = db.Column(db.String(64), unique=True, nullable=False,
                              default=lambda: secrets.token_hex(32))

    voter = db.relationship("User", foreign_keys=[voter_id])
    election = db.relationship("Election")
    division = db.relationship("Division")
    preferences = db.relationship("BallotPreference",
                                  cascade="all, delete-orphan",
                                  order_by="BallotPreference.rank")

    def __repr__(self):
        return f"<Ballot voter={self.voter_id} election={self.election_id}>"


class BallotPreference(db.Model):
    """
    One row per candidate preference on a ballot.
    rank=1 is the voter's first choice, rank=2 second, etc.
    Not linked directly to the voter — only to the anonymous Ballot id.
    """
    __tablename__ = "ballot_preferences"
    __table_args__ = (
        db.UniqueConstraint("ballot_id", "rank",
                            name="uq_preference_ballot_rank"),
        db.UniqueConstraint("ballot_id", "candidate_id",
                            name="uq_preference_ballot_candidate"),
    )

    id = db.Column(db.Integer, primary_key=True)
    ballot_id = db.Column(db.Integer, db.ForeignKey("ballots.id"),
                          nullable=False, index=True)
    candidate_id = db.Column(db.Integer, db.ForeignKey("candidates.id"),
                             nullable=False)
    rank = db.Column(db.Integer, nullable=False)

    ballot = db.relationship("Ballot", back_populates="preferences")
    candidate = db.relationship("Candidate")

    def __repr__(self):
        return (f"<BallotPreference ballot={self.ballot_id} "
                f"candidate={self.candidate_id} rank={self.rank}>")
