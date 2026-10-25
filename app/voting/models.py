"""
S3 – Secure ballot storage (R9, R11, R12).

The central security idea is SEPARATION:

  Ballot      - the anonymous, ENCRYPTED vote. Has NO voter_id. (R9, R11)
  VoteRecord  - marks only THAT a voter voted in an election. Has NO ballot
                content. (R12)

The two tables share no column, so:
  * R9  — ballot preferences are sealed (encrypted) before storage.
  * R11 — nothing in the Ballot table links back to a voter, so no one can
          tell how a given person voted.
  * R12 — the UNIQUE (voter_id, election_id) on VoteRecord blocks a second
          vote, without that record revealing any choices.
"""

from datetime import datetime, timezone

from app.extensions import db


def _utc_now():
    return datetime.now(timezone.utc)


class Ballot(db.Model):
    """
    One cast ballot. ANONYMOUS by design — there is deliberately no voter_id
    column here (R11). The ranked preferences are encrypted into
    `sealed_ballot` (R9); the plaintext choices are never stored.
    """
    __tablename__ = "ballots"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"),
                            nullable=False, index=True)
    division_id = db.Column(db.Integer, db.ForeignKey("divisions.id"),
                            nullable=False)
    chamber = db.Column(db.String(10), nullable=False)  # "house" or "senate"

    # R9: the voter's ranked preferences, encrypted. Opaque bytes to the DB.
    sealed_ballot = db.Column(db.Text, nullable=False)

    # Receipt the voter keeps to confirm inclusion, without revealing choices.
    tracking_code = db.Column(db.String(64), unique=True, nullable=False,
                              index=True)

    cast_at = db.Column(db.DateTime(timezone=True),
                        default=_utc_now, nullable=False)

    election = db.relationship("Election")
    division = db.relationship("Division")

    def __repr__(self):
        return f"<Ballot {self.tracking_code} election={self.election_id}>"


class VoteRecord(db.Model):
    """
    Marks that one voter has voted in one election (R12).

    Holds NO ballot content and does not reference any Ballot row, so it cannot
    be used to find out how the voter voted. A dedicated (voter, election)
    marker is used rather than a single `has_voted` flag on User because the
    platform runs several elections at once (House and Senate), which one
    boolean cannot represent.
    """
    __tablename__ = "vote_records"
    __table_args__ = (
        db.UniqueConstraint("voter_id", "election_id",
                            name="uq_vote_voter_election"),
    )

    id = db.Column(db.Integer, primary_key=True)
    voter_id = db.Column(db.Integer, db.ForeignKey("users.id"),
                         nullable=False, index=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"),
                            nullable=False, index=True)
    voted_at = db.Column(db.DateTime(timezone=True),
                         default=_utc_now, nullable=False)

    def __repr__(self):
        return f"<VoteRecord voter={self.voter_id} election={self.election_id}>"
