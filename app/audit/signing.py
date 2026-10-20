import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DEFAULT_KEY_FILENAME = "audit_signing_key.pem"


def _passphrase():
    value = os.environ.get("AUDIT_KEY_PASSPHRASE")
    return value.encode() if value else None


def _load_key(path, passphrase):
    with open(path, "rb") as key_file:
        data = key_file.read()
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except (TypeError, ValueError) as error:
        raise RuntimeError(
            f"Could not load the audit signing key at {path}. "
            "Check AUDIT_KEY_PASSPHRASE is set correctly."
        ) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError(f"{path} is not an Ed25519 private key.")
    return key


def _create_key(path, passphrase):
    key = Ed25519PrivateKey.generate()
    if passphrase:
        encryption = serialization.BestAvailableEncryption(passphrase)
    else:
        encryption = serialization.NoEncryption()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Never overwrite an existing key; only the owner can read it
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as key_file:
        key_file.write(pem)
    return key


def load_signing_key(app):
    # Tests get a throwaway key; otherwise load or create instance/audit_signing_key.pem
    if app.config.get("TESTING"):
        return Ed25519PrivateKey.generate()

    path = app.config.get("AUDIT_SIGNING_KEY_PATH") or os.path.join(
        app.instance_path, DEFAULT_KEY_FILENAME
    )
    passphrase = _passphrase()
    if os.path.exists(path):
        return _load_key(path, passphrase)
    app.logger.warning("No audit signing key found, creating a new one at %s", path)
    return _create_key(path, passphrase)


def public_key_pem(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
