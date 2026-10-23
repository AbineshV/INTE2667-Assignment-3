from app.audit.signing import load_signing_key


def init_results(app):
    # Separate key from the audit log and election definitions
    app.extensions["results_signing_key"] = load_signing_key(
        app, filename="results_signing_key.pem", config_key="RESULTS_SIGNING_KEY_PATH"
    )
