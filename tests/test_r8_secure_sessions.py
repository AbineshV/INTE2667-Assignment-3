from datetime import timedelta

from app.config import Config
from app.extensions import login_manager


def test_secure_session_cookie_configuration(app):
    assert Config.SESSION_COOKIE_SECURE is True
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert app.config["PERMANENT_SESSION_LIFETIME"] == timedelta(minutes=30)
    assert app.config["SESSION_REFRESH_EACH_REQUEST"] is False


def test_flask_login_uses_strong_session_protection(app):
    assert app.config["SESSION_PROTECTION"] == "strong"
    assert login_manager.session_protection == "strong"