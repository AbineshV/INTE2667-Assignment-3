import base64
import hmac
import io

import pyotp
import qrcode
from cryptography.fernet import Fernet
from flask import current_app
from qrcode.image.svg import SvgPathImage

STEP_SECONDS = 30


def _fernet():
    key = current_app.config["TOTP_ENCRYPTION_KEY"]
    return Fernet(key.encode())


def generate_secret():
    return pyotp.random_base32()


def encrypt_secret(secret):
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token):
    return _fernet().decrypt(token.encode()).decode()


def current_step(now):
    return int(now.timestamp()) // STEP_SECONDS


def check_code(secret, code, now, last_used_step):
    code = (code or "").replace(" ", "")
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None

    totp = pyotp.TOTP(secret)
    for offset in (-1, 0, 1):  # allow 30 seconds of clock drift either way
        step = current_step(now) + offset
        expected = totp.at(step * STEP_SECONDS)
        if hmac.compare_digest(code, expected):
            if last_used_step is not None and step <= last_used_step:
                return None  # reused or older code
            return step
    return None


def qr_data_uri(uri):
    buffer = io.BytesIO()
    qrcode.make(uri, image_factory=SvgPathImage).save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode()
    return "data:image/svg+xml;base64," + encoded