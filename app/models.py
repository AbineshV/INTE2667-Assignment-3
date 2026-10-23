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
    totp_last_used_step = db.Column(db.Integer, nullable=True)

    # Account lockout (R4)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime(timezone=True), nullable=True)

    created_at = db.Column(db.DateTime(timezone=True), default=utc_now, nullable=False)

    def __repr__(self):
        return f"<User {self.email}>"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))