from app.audit.signing import load_signing_key
from app.elections.definition import (
    ElectionError, ElectionVerification, canonical_definition, definition_hash, sign_election,
    verify_election,
)


def init_elections(app):
    # Separate key from the audit log
    app.extensions["election_signing_key"] = load_signing_key(
        app, filename="election_signing_key.pem", config_key="ELECTION_SIGNING_KEY_PATH"
    )


__all__ = ["ElectionError", "ElectionVerification", "canonical_definition", "definition_hash",
           "init_elections", "sign_election", "verify_election"]
