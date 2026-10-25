from app.voting.sealing import load_sealing_key


def init_voting(app):
    # Load (or create) the ballot sealing key once at startup (R9).
    app.extensions["ballot_sealing_key"] = load_sealing_key(app)


__all__ = ["init_voting"]
