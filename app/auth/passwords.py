from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# One hasher for the whole app; default settings use Argon2id
_hasher = PasswordHasher()

# Common passwords to reject (compared in lower case)
COMMON_PASSWORDS = frozenset({
    "password1234",
    "password12345",
    "123456789012",
    "qwertyuiop12",
    "iloveyou1234",
    "welcome12345",
    "letmein12345",
    "admin1234567",
})

MIN_LENGTH = 12
MAX_LENGTH = 128


def hash_password(plain):
    return _hasher.hash(plain)


def verify_password(stored_hash, plain):
    try:
        return _hasher.verify(stored_hash, plain)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash):
    return _hasher.check_needs_rehash(stored_hash)


def validate_password(plain):
    problems = []
    if len(plain) < MIN_LENGTH:
        problems.append(f"Password must be at least {MIN_LENGTH} characters long.")
    if len(plain) > MAX_LENGTH:
        problems.append(f"Password must be at most {MAX_LENGTH} characters long.")
    if plain.lower() in COMMON_PASSWORDS:
        problems.append("This password is too common. Choose a different one.")
    return problems