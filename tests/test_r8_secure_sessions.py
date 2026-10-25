import time
from datetime import timedelta

from app.auth.passwords import hash_password
from app.config import Config
from app.extensions import db, login_manager
from app.models import User


TEST_PASSWORD = "R8-session-test-123!"


def _login_test_voter(app, client):
    """Create a test voter and authenticate through the actual login route."""
    email = "r8-session-voter@example.test"

    with app.app_context():
        user = User(
            email=email,
            password_hash=hash_password(TEST_PASSWORD),
            role="voter",
            division="D01",
            is_citizen=True,
            is_enrolled=True,
        )
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/auth/login",
        data={
            "email": email,
            "password": TEST_PASSWORD,
        },
    )

    assert response.status_code == 302
    return email


def test_secure_session_cookie_configuration(app):
    assert Config.SESSION_COOKIE_SECURE is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=30)
    assert app.config["SESSION_REFRESH_EACH_REQUEST"] is False


def test_flask_login_uses_strong_session_protection(app):
    assert app.config["SESSION_PROTECTION"] == "strong"
    assert login_manager.session_protection == "strong"


def test_idle_authenticated_session_expires(app, client):
    _login_test_voter(app, client)

    with client.session_transaction() as session:
        assert "last_activity" in session
        session["last_activity"] = int(time.time()) - 31 * 60

    response = client.get("/vote/")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    with client.session_transaction() as session:
        assert "_user_id" not in session
        assert "last_activity" not in session


def test_active_session_continues_and_refreshes_activity(app, client):
    _login_test_voter(app, client)

    old_activity = int(time.time()) - 60

    with client.session_transaction() as session:
        session["last_activity"] = old_activity

    response = client.get("/vote/")

    assert response.status_code == 200

    with client.session_transaction() as session:
        assert session["last_activity"] > old_activity
        assert session["_permanent"] is True


def test_authenticated_session_without_activity_timestamp_is_rejected(
    app, client
):
    _login_test_voter(app, client)

    with client.session_transaction() as session:
        session.pop("last_activity", None)

    response = client.get("/vote/")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    with client.session_transaction() as session:
        assert "_user_id" not in session

def test_session_with_future_activity_timestamp_is_rejected(app, client):
    _login_test_voter(app, client)

    with client.session_transaction() as session:
        session["last_activity"] = int(time.time()) + 3600

    response = client.get("/vote/")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]

    with client.session_transaction() as session:
        assert "_user_id" not in session
        assert "last_activity" not in session