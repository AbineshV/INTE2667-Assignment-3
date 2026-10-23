# import os and load_dotenv
import os
from dotenv import load_dotenv

# call load_dotenv() so the values in .env are available
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///voting.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Comma-separated IPv4/IPv6 CIDRs authorised for diplomatic terminals.
    # Empty by default: all terminal requests are denied until configured.
    DIPLOMATIC_TERMINAL_ALLOWED_CIDRS = [
        network.strip()
        for network in os.environ.get(
            "DIPLOMATIC_TERMINAL_ALLOWED_CIDRS", ""
        ).split(",")
        if network.strip()
    ]
class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SECRET_KEY = "test-secret-key-not-for-production"
    WTF_CSRF_ENABLED = False