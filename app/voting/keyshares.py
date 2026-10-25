"""
S3 – Shamir's Secret Sharing for the ballot key (R10).

The ballot sealing key (R9) is never stored whole. It is split into 5 shares
handed to 5 electoral officials; any 3 of them can combine their shares to
reconstruct the key, but 2 shares reveal nothing about it. This is a k-of-n
threshold scheme (k=3, n=5) — the same idea HashiCorp Vault uses to "unseal".

Why it works: a secret byte s is hidden as the constant term of a random
degree-(k-1) polynomial over the finite field GF(2^8). Each share is that
polynomial evaluated at a distinct x (1..n). k points determine a degree-(k-1)
polynomial uniquely (Lagrange interpolation), so k shares recover s at x=0;
with only k-1 points every possible s is still equally likely, so fewer shares
leak nothing.

Arithmetic is in GF(2^8) with the AES reduction polynomial 0x11b, so every byte
operation stays within one byte and is exact (no rounding, unlike real numbers).
"""

import secrets

# --- GF(2^8) arithmetic ---------------------------------------------------- #

def _gf_mul(a, b):
    """Multiply two bytes in GF(2^8) (Russian-peasant, reduce by 0x11b)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        carry = a & 0x80
        a = (a << 1) & 0xFF
        if carry:
            a ^= 0x1B
        b >>= 1
    return p


# Exp/log tables with generator 0x03, for fast division.
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x = _gf_mul(_x, 0x03)
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gf_div(a, b):
    if b == 0:
        raise ZeroDivisionError("division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] - _LOG[b]) % 255]


def _gf_mul_fast(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 255]


# --- Shamir split / combine ------------------------------------------------ #

def split_secret(secret: bytes, n: int = 5, k: int = 3):
    """
    Split `secret` into `n` shares, any `k` of which can reconstruct it.
    Returns a list of (x, y_bytes) tuples, x = 1..n.
    """
    if not 2 <= k <= n <= 255:
        raise ValueError("require 2 <= k <= n <= 255")

    shares = [(x, bytearray(len(secret))) for x in range(1, n + 1)]
    for byte_index, s in enumerate(secret):
        # random polynomial: s + c1*x + ... + c_{k-1}*x^{k-1}
        coeffs = [s] + [secrets.randbelow(256) for _ in range(k - 1)]
        for x, ybytes in shares:
            acc = 0
            for power, coeff in enumerate(coeffs):
                term = coeff
                for _ in range(power):
                    term = _gf_mul_fast(term, x)
                acc ^= term
            ybytes[byte_index] = acc
    return [(x, bytes(ybytes)) for x, ybytes in shares]


def combine_secret(shares):
    """
    Reconstruct the secret from a list of (x, y_bytes) shares. Needs at least
    k shares; fewer (or wrong) shares simply yield the wrong bytes.
    """
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("shares must have distinct x values")
    length = len(shares[0][1])

    secret = bytearray(length)
    for byte_index in range(length):
        acc = 0
        for j, (xj, yj) in enumerate(shares):
            # Lagrange basis evaluated at x=0: prod_{m!=j} x_m / (x_j ^ x_m)
            num, den = 1, 1
            for m, (xm, _) in enumerate(shares):
                if m == j:
                    continue
                num = _gf_mul_fast(num, xm)
                den = _gf_mul_fast(den, xj ^ xm)
            basis = _gf_div(num, den)
            acc ^= _gf_mul_fast(yj[byte_index], basis)
        secret[byte_index] = acc
    return bytes(secret)


# --- Serialisation (so a share can be saved / handed to an official) ------- #

def format_share(share) -> str:
    """(x, y_bytes) -> 'x-hexbytes' text, safe to write to a file."""
    x, ybytes = share
    return f"{x}-{ybytes.hex()}"


def parse_share(text: str):
    """Inverse of format_share."""
    x_str, hex_str = text.strip().split("-", 1)
    return int(x_str), bytes.fromhex(hex_str)
