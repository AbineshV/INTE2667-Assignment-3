from app.extensions import db


# R17: no voter id and no timestamp, so a ballot cannot be linked back to a voter (R11)
class BallotLedgerEntry(db.Model):
    __tablename__ = "ballot_ledger"
    __table_args__ = (db.UniqueConstraint("election_id", "sequence"),)

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False, index=True)
    division_id = db.Column(db.Integer, db.ForeignKey("divisions.id"), nullable=False)
    sequence = db.Column(db.Integer, nullable=False)

    ciphertext = db.Column(db.Text, nullable=False)
    ciphertext_hash = db.Column(db.String(64), nullable=False)

    # Only the hash is stored; the voter keeps the code itself
    tracking_hash = db.Column(db.String(64), nullable=False, unique=True)

    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)

    def __repr__(self):
        return f"<BallotLedgerEntry election={self.election_id} seq={self.sequence}>"
