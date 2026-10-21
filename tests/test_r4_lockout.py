from datetime import timedelta
from types import SimpleNamespace

from app.auth.lockout import (
    LOCKOUT_MINUTES,
    MAX_FAILED_ATTEMPTS,
    as_utc,
    is_locked,
    record_failed_login,
    reset_failed_logins,
    utc_now,
)
from app.extensions import db
from app.models import User

GOOD_PASSWORD = "correct horse battery staple"
WRONG_PASSWORD = "not the right password"


def make_user():
    # A plain object with the two fields lockout.py uses; no database needed
    return SimpleNamespace(failed_login_count=0, locked_until=None)


# ---------- Unit tests: lockout rules ----------

def test_not_locked_before_max_attempts():
    user, now = make_user(), utc_now()
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        record_failed_login(user, now)
    assert user.failed_login_count == MAX_FAILED_ATTEMPTS - 1
    assert is_locked(user, now) is False


def test_locked_after_max_attempts():
    user, now = make_user(), utc_now()
    for _ in range(MAX_FAILED_ATTEMPTS):
        record_failed_login(user, now)
    assert is_locked(user, now) is True
    assert user.locked_until == now + timedelta(minutes=LOCKOUT_MINUTES)
    assert user.failed_login_count == 0          # fresh tries after the lock


def test_still_locked_just_before_expiry():
    user, now = make_user(), utc_now()
    for _ in range(MAX_FAILED_ATTEMPTS):
        record_failed_login(user, now)
    assert is_locked(user, now + timedelta(minutes=LOCKOUT_MINUTES - 1)) is True


def test_unlocked_after_lockout_period():
    user, now = make_user(), utc_now()
    for _ in range(MAX_FAILED_ATTEMPTS):
        record_failed_login(user, now)
    assert is_locked(user, now + timedelta(minutes=LOCKOUT_MINUTES + 1)) is False


def test_reset_clears_count_and_lock():
    user, now = make_user(), utc_now()
    for _ in range(MAX_FAILED_ATTEMPTS):
        record_failed_login(user, now)
    reset_failed_logins(user)
    assert user.failed_login_count == 0
    assert user.locked_until is None


def test_as_utc_handles_naive_datetime_from_sqlite():
    now = utc_now()
    naive = now.replace(tzinfo=None)             # what SQLite may give back
    assert as_utc(naive) == now
    assert as_utc(None) is None


# ---------- Route tests: login with lockout ----------

def register(client, email="voter@example.com"):
    return client.post("/auth/register", data={
        "email": email,
        "password": GOOD_PASSWORD,
        "confirm_password": GOOD_PASSWORD,
        "date_of_birth": "1990-05-01",
        "division": "Melbourne",
    })


def login(client, password, email="voter@example.com"):
    return client.post("/auth/login", data={"email": email, "password": password})


def test_correct_password_refused_while_locked(client):
    register(client)
    for _ in range(MAX_FAILED_ATTEMPTS):
        login(client, WRONG_PASSWORD)

    response = login(client, GOOD_PASSWORD)
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data   # same message, lock not revealed


def test_login_works_again_after_lock_expires(client, app):
    register(client)
    for _ in range(MAX_FAILED_ATTEMPTS):
        login(client, WRONG_PASSWORD)

    # Move the lock into the past instead of waiting 15 minutes
    with app.app_context():
        user = User.query.filter_by(email="voter@example.com").first()
        user.locked_until = utc_now() - timedelta(minutes=1)
        db.session.commit()

    response = login(client, GOOD_PASSWORD)
    assert response.status_code == 302


def test_successful_login_resets_failed_count(client, app):
    register(client)
    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        login(client, WRONG_PASSWORD)
    login(client, GOOD_PASSWORD)

    with app.app_context():
        user = User.query.filter_by(email="voter@example.com").first()
        assert user.failed_login_count == 0
        assert user.locked_until is None