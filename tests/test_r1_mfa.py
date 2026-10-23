import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest
from cryptography.fernet import InvalidToken

from app.auth.lockout import MAX_FAILED_ATTEMPTS
from app.auth.mfa import (
    check_code,
    current_step,
    decrypt_secret,
    encrypt_secret,
    generate_secret,
)
from app.extensions import db
from app.models import User

GOOD_PASSWORD = "correct horse battery staple"
EMAIL = "voter@example.com"
FIXED_NOW = datetime(2026, 1, 1, 12, 0, 15, tzinfo=timezone.utc)


# ---------- Helpers ----------

def register(client, email=EMAIL):
    return client.post("/auth/register", data={
        "email": email,
        "password": GOOD_PASSWORD,
        "confirm_password": GOOD_PASSWORD,
        "date_of_birth": "1990-05-01",
        "division": "Melbourne",
    })


def login(client, email=EMAIL, password=GOOD_PASSWORD):
    return client.post("/auth/login", data={"email": email, "password": password})


def make_mfa_user(client, app):
    """Register a user, give them MFA directly, and return the plain secret."""
    register(client)
    secret = generate_secret()
    with app.app_context():
        user = User.query.filter_by(email=EMAIL).first()
        user.totp_secret = encrypt_secret(secret)
        db.session.commit()
    return secret


def get_user(app):
    with app.app_context():
        return User.query.filter_by(email=EMAIL).first()


# ---------- Unit tests: mfa.py ----------

def test_secret_encryption_round_trip_and_tamper_detection(app):
    with app.app_context():
        secret = generate_secret()
        token = encrypt_secret(secret)
        assert token != secret
        assert decrypt_secret(token) == secret
        with pytest.raises(InvalidToken):
            decrypt_secret("not-a-valid-token")


def test_current_code_accepted_including_spaces():
    secret = generate_secret()
    code = pyotp.TOTP(secret).at(FIXED_NOW)
    spaced = code[:3] + " " + code[3:]
    assert check_code(secret, code, FIXED_NOW, None) == current_step(FIXED_NOW)
    assert check_code(secret, spaced, FIXED_NOW, None) == current_step(FIXED_NOW)


def test_one_window_drift_allowed_two_rejected():
    secret = generate_secret()
    totp = pyotp.TOTP(secret)
    assert check_code(secret, totp.at(FIXED_NOW - timedelta(seconds=30)), FIXED_NOW, None) is not None
    assert check_code(secret, totp.at(FIXED_NOW + timedelta(seconds=30)), FIXED_NOW, None) is not None
    assert check_code(secret, totp.at(FIXED_NOW - timedelta(seconds=60)), FIXED_NOW, None) is None


def test_reused_or_older_code_rejected():
    secret = generate_secret()
    totp = pyotp.TOTP(secret)
    code = totp.at(FIXED_NOW)
    step = check_code(secret, code, FIXED_NOW, None)
    assert check_code(secret, code, FIXED_NOW, step) is None                       # same code again
    older = totp.at(FIXED_NOW - timedelta(seconds=30))
    assert check_code(secret, older, FIXED_NOW, step) is None                      # earlier window


def test_badly_formatted_codes_rejected():
    secret = generate_secret()
    for bad in ["", "12345", "1234567", "abcdef", "12345a", "١٢٣٤٥٦", None]:
        assert check_code(secret, bad, FIXED_NOW, None) is None


# ---------- Route tests ----------

def test_setup_stores_secret_encrypted(client, app):
    register(client)
    login(client)                                  # no MFA yet, so this logs in
    client.get("/auth/mfa/setup")                  # creates the pending secret

    with client.session_transaction() as sess:
        pending = sess["pending_totp_secret"]
    with app.app_context():
        secret = decrypt_secret(pending)

    response = client.post("/auth/mfa/setup", data={"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 302

    with app.app_context():
        user = User.query.filter_by(email=EMAIL).first()
        assert user.totp_secret != secret          # stored encrypted, not plain
        assert decrypt_secret(user.totp_secret) == secret
        assert user.totp_last_used_step is not None
    with client.session_transaction() as sess:
        assert "pending_totp_secret" not in sess


def test_password_alone_does_not_log_in_mfa_user(client, app):
    make_mfa_user(client, app)
    response = login(client)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/mfa/verify")
    with client.session_transaction() as sess:
        assert "_user_id" not in sess
        assert "mfa_user_id" in sess


def test_correct_code_logs_in(client, app):
    secret = make_mfa_user(client, app)
    login(client)
    response = client.post("/auth/mfa/verify", data={"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/vote/")
    with client.session_transaction() as sess:
        assert "_user_id" in sess
        assert "mfa_user_id" not in sess
    assert get_user(app).totp_last_used_step is not None


def test_wrong_code_rejected_and_counted(client, app):
    make_mfa_user(client, app)
    login(client)
    response = client.post("/auth/mfa/verify", data={"code": "000000"})
    assert response.status_code == 401
    assert b"Invalid code" in response.data
    assert get_user(app).failed_login_count == 1


def test_verify_without_password_step_redirects_to_login(client):
    response = client.get("/auth/mfa/verify")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")


def test_verify_times_out_after_five_minutes(client, app):
    secret = make_mfa_user(client, app)
    login(client)
    with client.session_transaction() as sess:
        sess["mfa_started"] = int(time.time()) - 6 * 60

    response = client.post("/auth/mfa/verify", data={"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/auth/login")
    with client.session_transaction() as sess:
        assert "_user_id" not in sess
        assert "mfa_user_id" not in sess


def test_correct_code_refused_after_five_wrong_codes(client, app):
    secret = make_mfa_user(client, app)
    login(client)
    for _ in range(MAX_FAILED_ATTEMPTS):
        client.post("/auth/mfa/verify", data={"code": "000000"})

    response = client.post("/auth/mfa/verify", data={"code": pyotp.TOTP(secret).now()})
    assert response.status_code == 401
    with client.session_transaction() as sess:
        assert "_user_id" not in sess