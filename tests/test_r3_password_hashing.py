from argon2 import PasswordHasher

from app.auth.passwords import (
    MAX_LENGTH,
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)

GOOD_PASSWORD = "correct horse battery staple"


def test_hash_is_argon2id_and_not_plaintext():
    hashed = hash_password(GOOD_PASSWORD)
    assert hashed.startswith("$argon2id$")
    assert GOOD_PASSWORD not in hashed


def test_same_password_gets_different_salts():
    assert hash_password(GOOD_PASSWORD) != hash_password(GOOD_PASSWORD)


def test_verify_correct_password_returns_true():
    hashed = hash_password(GOOD_PASSWORD)
    assert verify_password(hashed, GOOD_PASSWORD) is True


def test_verify_wrong_password_returns_false():
    hashed = hash_password(GOOD_PASSWORD)
    assert verify_password(hashed, "wrong password entirely") is False


def test_verify_garbled_hash_returns_false():
    assert verify_password("not-a-real-hash", GOOD_PASSWORD) is False


def test_needs_rehash_detects_weak_settings():
    assert needs_rehash(hash_password(GOOD_PASSWORD)) is False
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    assert needs_rehash(weak.hash(GOOD_PASSWORD)) is True


def test_validate_rejects_short_long_and_common():
    assert validate_password("short1")                  # too short
    assert validate_password("a" * (MAX_LENGTH + 1))    # too long
    assert validate_password("Password1234")            # common, any case


def test_validate_accepts_strong_password():
    assert validate_password(GOOD_PASSWORD) == []