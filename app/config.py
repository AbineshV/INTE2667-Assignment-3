import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    TOTP_ENCRYPTION_KEY = os.environ.get("TOTP_ENCRYPTION_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///voting.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # R7: approved IP networks for diplomatic terminals.
    # Empty by default, so terminal access is denied until configured.
    DIPLOMATIC_TERMINAL_ALLOWED_CIDRS = [
        network.strip()
        for network in os.environ.get(
            "DIPLOMATIC_TERMINAL_ALLOWED_CIDRS", ""
        ).split(",")
        if network.strip()
    ]

    # R8: secure session settings.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "true").lower()
        in {"1", "true", "yes", "on"}
    )
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_REFRESH_EACH_REQUEST = False
    SESSION_PROTECTION = "strong"


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret-key-not-for-production"
    TOTP_ENCRYPTION_KEY = "oK0x1TxiLmebjISDzxsduFcVfnwrIjqubERvcNgHu0M="
    WTF_CSRF_ENABLED = False

    # Test client uses HTTP rather than HTTPS.
    SESSION_COOKIE_SECURE = False