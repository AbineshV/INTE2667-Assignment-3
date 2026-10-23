import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///voting.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TOTP_ENCRYPTION_KEY = os.environ.get("TOTP_ENCRYPTION_KEY")


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret-key-not-for-production"
    TOTP_ENCRYPTION_KEY = "UEQ9TmQrAo7bp9gznpp7FFXYuDp2xHWAc6lgR6EVTKU="