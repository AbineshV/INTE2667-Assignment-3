"""
S3 – Ballot sealing key (R9) protected by 3-of-5 key sharing (R10).

The sealing key that encrypts ballots is never written to disk as one file.
On first run it is generated, split into 5 Shamir shares (app/voting/keyshares.py),
and only the shares are stored — each one standing in for a share held by a
separate electoral official. Bringing the system up reconstructs the key from
any 3 shares (an "unseal" step); the same 3-of-5 reconstruction is what the
tally uses to decrypt ballots.

Under TESTING a throwaway in-memory key is used, so tests don't touch disk.

Prototype note: for a runnable demo the 5 share files live together in the
instance folder. In a real deployment the 5 shares are distributed to 5
officials and never co-located, so no single machine ever holds 3 at once
outside a supervised ceremony.
"""

import os

from cryptography.fernet import Fernet

from app.voting.keyshares import (
    combine_secret,
    format_share,
    parse_share,
    split_secret,
)

N_SHARES = 5
THRESHOLD = 3
SHARE_PREFIX = "ballot_key_share_"


def _share_paths(directory):
    return [os.path.join(directory, f"{SHARE_PREFIX}{i}.txt")
            for i in range(1, N_SHARES + 1)]


def _shares_dir(app, config_key):
    return app.config.get(config_key) or app.instance_path


def load_sealing_key(app, config_key="BALLOT_SHARES_DIR") -> Fernet:
    if app.config.get("TESTING"):
        return Fernet(Fernet.generate_key())

    directory = _shares_dir(app, config_key)
    paths = _share_paths(directory)
    present = [p for p in paths if os.path.exists(p)]

    # Already set up: reconstruct the key from any THRESHOLD shares.
    if len(present) >= THRESHOLD:
        shares = [parse_share(open(p).read()) for p in present[:THRESHOLD]]
        return Fernet(combine_secret(shares))

    # First run: generate the key, split it, store ONLY the shares.
    app.logger.warning("No ballot key shares found; generating a new 3-of-5 set "
                        "in %s", directory)
    key = Fernet.generate_key()
    shares = split_secret(key, n=N_SHARES, k=THRESHOLD)
    os.makedirs(directory, exist_ok=True)
    for share, path in zip(shares, paths):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(format_share(share))
    return Fernet(key)


def reconstruct_sealing_key(share_texts) -> Fernet:
    """
    Rebuild the sealing key from shares supplied as text (e.g. by officials at
    the tally). Needs at least THRESHOLD of them. Used by the results/tally code.
    """
    if len(share_texts) < THRESHOLD:
        raise ValueError(f"need at least {THRESHOLD} shares to reconstruct the key")
    shares = [parse_share(t) for t in share_texts]
    return Fernet(combine_secret(shares))
