from app.extensions import db


# R18: append-only, hash-chained and signed audit log
class AuditLogEntry(db.Model):
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    sequence = db.Column(db.Integer, unique=True, nullable=False, index=True)

    # ISO string so the hashed value is exactly what SQLite returns
    created_at = db.Column(db.String(32), nullable=False)

    actor = db.Column(db.String(255), nullable=False)
    action = db.Column(db.String(64), nullable=False, index=True)
    target = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=False, default="{}")

    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False, unique=True)
    signature = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f"<AuditLogEntry {self.sequence} {self.action}>"
