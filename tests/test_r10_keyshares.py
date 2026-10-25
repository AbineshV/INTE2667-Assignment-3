"""
S3 – 3-of-5 key sharing tests (R10).

Proves the threshold property: any 3 of 5 shares rebuild the ballot key, 2 do
not, and the key is never persisted whole — only its shares.
"""

import itertools
import os
import types

from cryptography.fernet import Fernet

from app.voting.keyshares import (
    combine_secret,
    format_share,
    parse_share,
    split_secret,
)
from app.voting.sealing import (
    N_SHARES,
    THRESHOLD,
    load_sealing_key,
    reconstruct_sealing_key,
)


def _fake_app(tmp_dir):
    """Minimal stand-in for a Flask app (non-TESTING) for load_sealing_key."""
    return types.SimpleNamespace(
        config={"TESTING": False, "BALLOT_SHARES_DIR": str(tmp_dir)},
        instance_path=str(tmp_dir),
        logger=types.SimpleNamespace(warning=lambda *a, **k: None),
    )


# ---- core Shamir properties ----------------------------------------------- #
def test_any_three_of_five_reconstruct():
    secret = Fernet.generate_key()
    shares = split_secret(secret, n=5, k=3)
    assert len(shares) == 5
    for combo in itertools.combinations(shares, 3):
        assert combine_secret(list(combo)) == secret


def test_two_shares_do_not_reconstruct():
    secret = Fernet.generate_key()
    shares = split_secret(secret, n=5, k=3)
    for combo in itertools.combinations(shares, 2):
        assert combine_secret(list(combo)) != secret


def test_share_serialisation_round_trip():
    shares = split_secret(b"some-secret-bytes", n=5, k=3)
    text = format_share(shares[0])
    assert parse_share(text) == shares[0]


# ---- integration with the sealing key ------------------------------------- #
def test_first_run_stores_shares_not_the_key(tmp_path):
    app = _fake_app(tmp_path)
    key = load_sealing_key(app)

    files = os.listdir(tmp_path)
    share_files = [f for f in files if f.startswith("ballot_key_share_")]
    assert len(share_files) == N_SHARES          # 5 shares written
    # the whole key is never written as a single file
    assert not any("sealing_key" in f for f in files)
    # the key works
    assert key.decrypt(key.encrypt(b"ok")) == b"ok"


def test_restart_reconstructs_same_key_from_shares(tmp_path):
    app = _fake_app(tmp_path)
    key1 = load_sealing_key(app)             # first run: creates shares
    token = key1.encrypt(b'{"candidate_id":3,"rank":1}')

    key2 = load_sealing_key(app)             # restart: rebuilds from shares
    assert key2.decrypt(token) == b'{"candidate_id":3,"rank":1}'


def test_tally_reconstruct_from_three_official_shares(tmp_path):
    app = _fake_app(tmp_path)
    key = load_sealing_key(app)
    token = key.encrypt(b"secret ballot")

    # three officials bring their shares (as text) to the tally
    share_texts = [open(tmp_path / f"ballot_key_share_{i}.txt").read()
                   for i in (1, 3, 5)]
    rebuilt = reconstruct_sealing_key(share_texts)
    assert rebuilt.decrypt(token) == b"secret ballot"
    assert THRESHOLD == 3
