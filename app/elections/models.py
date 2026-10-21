from datetime import datetime, timezone

from app.extensions import db

CHAMBERS = ("house", "senate")

STATUS_DRAFT = "draft"
STATUS_AWAITING_SECOND = "awaiting_second_signature"
STATUS_LOCKED = "locked"


def utc_now():
    return datetime.now(timezone.utc)


class Election(db.Model):
    __tablename__ = "elections"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    chamber = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(30), nullable=False, default=STATUS_DRAFT)
    created_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)
    locked_at = db.Column(db.DateTime(timezone=True), nullable=True)

    divisions = db.relationship("Division", back_populates="election",
                                cascade="all, delete-orphan", order_by="Division.id")
    signatures = db.relationship("ElectionSignature", back_populates="election",
                                 cascade="all, delete-orphan", order_by="ElectionSignature.id")

    @property
    def is_locked(self):
        return self.status == STATUS_LOCKED

    def __repr__(self):
        return f"<Election {self.id} {self.name} {self.status}>"


# House: an electoral division. Senate: a state or territory.
class Division(db.Model):
    __tablename__ = "divisions"
    __table_args__ = (db.UniqueConstraint("election_id", "name"),)

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)

    election = db.relationship("Election", back_populates="divisions")
    groups = db.relationship("Group", back_populates="division",
                             cascade="all, delete-orphan", order_by="Group.position")
    candidates = db.relationship("Candidate", back_populates="division",
                                 cascade="all, delete-orphan", order_by="Candidate.position")


# Senate above-the-line group
class Group(db.Model):
    __tablename__ = "candidate_groups"
    __table_args__ = (db.UniqueConstraint("division_id", "label"),)

    id = db.Column(db.Integer, primary_key=True)
    division_id = db.Column(db.Integer, db.ForeignKey("divisions.id"), nullable=False)
    label = db.Column(db.String(5), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    position = db.Column(db.Integer, nullable=False)

    division = db.relationship("Division", back_populates="groups")
    candidates = db.relationship("Candidate", back_populates="group",
                                 order_by="Candidate.position")


class Candidate(db.Model):
    __tablename__ = "candidates"
    __table_args__ = (db.UniqueConstraint("division_id", "position"),)

    id = db.Column(db.Integer, primary_key=True)
    division_id = db.Column(db.Integer, db.ForeignKey("divisions.id"), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey("candidate_groups.id"), nullable=True)
    name = db.Column(db.String(200), nullable=False)
    party = db.Column(db.String(200), nullable=True)
    position = db.Column(db.Integer, nullable=False)

    division = db.relationship("Division", back_populates="candidates")
    group = db.relationship("Group", back_populates="candidates")


class ElectionSignature(db.Model):
    __tablename__ = "election_signatures"
    __table_args__ = (db.UniqueConstraint("election_id", "admin_id"),)

    id = db.Column(db.Integer, primary_key=True)
    election_id = db.Column(db.Integer, db.ForeignKey("elections.id"), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    definition_hash = db.Column(db.String(64), nullable=False)
    signed_at = db.Column(db.String(32), nullable=False)
    signature = db.Column(db.String(128), nullable=False)

    election = db.relationship("Election", back_populates="signatures")
