"""
S3 – Ballot sealing key (R9).

Ballots are encrypted at rest with Fernet (AES-128-CBC + HMAC). A throwaway key
under TESTING; otherwise a 0600 key file created once in the instance folder.

R10 note: in the full design this sealing key is not held whole on the server —
it is split into 5 Shamir shares, any 3 of which reconstruct it for the tally.
That is implemented separately; this module is the single point where the key
is obtained, so R10 slots in here without touching the casting logic.
"""

import os

from cryptography.fernet import Fernet

DEFAULT_KEY_FILENAME = "ballot_sealing_key.key"


def load_sealing_key(app, filename=DEFAULT_KEY_FILENAME,
                     config_key="BALLOT_SEALING_KEY_PATH") -> Fernet:
    if app.config.get("TESTING"):
        return Fernet(Fernet.generate_key())

    path = app.config.get(config_key) or os.path.join(app.instance_path, filename)
    if os.path.exists(path):
        with open(path, "rb") as key_file:
            return Fernet(key_file.read())

    app.logger.warning("No ballot sealing key found, creating a new one at %s", path)
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as key_file:
        key_file.write(key)
    return Fernet(key)
