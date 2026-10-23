from app.extensions import db


# R20: one signed, immutable results document per election
class ResultPublication(db.Model):
    __tablename__ = "result_publications"

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False, unique=True)
    published_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    # The exact canonical JSON that was signed
    document = db.Column(db.Text, nullable=False)
    document_hash = db.Column(db.String(64), nullable=False)
    signature = db.Column(db.String(128), nullable=False)
    key_id = db.Column(db.String(16), nullable=False)

    election = db.relationship("Election")
