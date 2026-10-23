from datetime import datetime, timezone

from flask_login import UserMixin

from app.extensions import db, login_manager


def utc_now():
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # Access control (S2, R5) and division scoping (S2, R5)
    role = db.Column(db.String(20), nullable=False, default="voter")
    division = db.Column(db.String(100))

    # Eligibility (R2)
    date_of_birth = db.Column(db.Date)
    is_citizen = db.Column(db.Boolean, nullable=False, default=False)
    is_enrolled = db.Column(db.Boolean, nullable=False, default=False)

    # Multi-factor authentication (R1)
    totp_secret = db.Column(db.String(255), nullable=True)

    # Account lockout (R4)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"
class PendingAction(db.Model):
    """A sensitive administrative action awaiting a second delegate's approval."""
    __tablename__ = "pending_actions"

    id = db.Column(db.Integer, primary_key=True)
    action_type = db.Column(db.String(50), nullable=False)
    payload = db.Column(db.JSON, nullable=False)

    requested_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False
    )
    requested_at = db.Column(
        db.DateTime(timezone=True), default=utc_now, nullable=False
    )

    status = db.Column(db.String(20), nullable=False, default="pending")

    approved_by_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=True
    )
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    executed_at = db.Column(db.DateTime(timezone=True), nullable=True)

    requester = db.relationship("User", foreign_keys=[requested_by_id])
    approver = db.relationship("User", foreign_keys=[approved_by_id])
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))