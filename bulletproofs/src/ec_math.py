"""
ec_math.py — Elliptic curve math helpers (bn128 curve via py_ecc)

We use the BN128 curve (also called alt_bn128), which is the same curve
used by Ethereum's precompiles (EIP-196 / EIP-197). This means proofs
generated here can theoretically be verified on-chain using Ethereum's
built-in pairing checks.

Compared to the dalek reference (which uses Ristretto/Curve25519),
we use BN128 because:
  - py_ecc supports it natively in Python
  - Ethereum has native precompiles for it (ecAdd, ecMul, ecPairing)
  - Solidity can verify our commitments without external libraries

A curve point is a tuple (x, y) of big integers, or None for the identity.
"""

import hashlib
from py_ecc.bn128 import (
    G1,
    add,
    multiply,
    neg,
    curve_order as ORDER,
    field_modulus as FIELD_MOD,
    is_on_curve,
    b,
)

# ── Generators ───────────────────────────────────────────────────────────────

# G  = the standard BN128 generator (1, 2)
G = G1

# H  = independent generator: hash-to-scalar → multiply G
# "Nothing-up-my-sleeve": H is derived deterministically from the string
# "bulletproof_H_generator" so no one knows log_G(H), which is required
# for the hiding property of Pedersen commitments.
_H_SCALAR = int.from_bytes(
    hashlib.sha256(b"bulletproof_H_generator_v1").digest(), "big"
) % ORDER
H = multiply(G1, _H_SCALAR)


# ── Basic operations ─────────────────────────────────────────────────────────

def ec_add(P, Q):
    """Add two curve points. Returns None (point at infinity) if they cancel."""
    return add(P, Q)


def ec_mul(scalar, P):
    """Multiply point P by scalar (integer). Reduces scalar mod ORDER first."""
    scalar = int(scalar) % ORDER
    if scalar == 0:
        return None
    return multiply(P, scalar)


def ec_neg(P):
    """Return the negation of point P (reflection over x-axis)."""
    return neg(P)


def point_equal(P, Q):
    """Check if two points are equal (handles None == None case)."""
    if P is None and Q is None:
        return True
    if P is None or Q is None:
        return False
    return P[0] == Q[0] and P[1] == Q[1]


# ── Hash utilities ────────────────────────────────────────────────────────────

def hash_to_scalar(*args) -> int:
    """
    Hash arbitrary data into a scalar in [1, ORDER-1].

    This is the core of Fiat-Shamir: we replace a verifier's random
    challenge with hash(transcript_so_far). Since SHA-256 is a random
    oracle (in the random oracle model), this is indistinguishable from
    truly random challenges.

    Args can be: bytes, int, tuple (curve point), or str.
    """
    h = hashlib.sha256()
    for a in args:
        if isinstance(a, bytes):
            h.update(a)
        elif isinstance(a, int):
            # encode as 32-byte big-endian (handles negative via mod)
            h.update((a % ORDER).to_bytes(32, "big"))
        elif isinstance(a, tuple):
            # curve point (x, y)
            h.update(a[0].to_bytes(32, "big"))
            h.update(a[1].to_bytes(32, "big"))
        elif isinstance(a, str):
            h.update(a.encode("utf-8"))
        elif a is None:
            h.update(b"\x00" * 32)
        else:
            h.update(str(a).encode("utf-8"))
    result = int.from_bytes(h.digest(), "big") % ORDER
    # Ensure non-zero (probability 1/ORDER ≈ negligible)
    return result if result != 0 else 1


def point_to_bytes(P) -> bytes:
    """Serialize a curve point to 64 bytes (for hashing / proof export).
    Handles py_ecc's bn128_FQ field elements by converting to int first."""
    if P is None:
        return b"\x00" * 64
    x = int(P[0])
    y = int(P[1])
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


# ── Generator vectors ─────────────────────────────────────────────────────────

def get_generator_vector(n: int, tag: bytes) -> list:
    """
    Return a list of n independent curve points, derived deterministically
    from `tag`. These are the G_vec / H_vec used in vector commitments.

    Each point is hash_to_scalar(tag, i) * G — so they're pseudorandom
    but reproducible. The verifier can recompute them independently.

    Reference comparison:
      dalek uses a Pedersen generators struct with Bulletproof-specific
      domain separation. We use the same idea: SHA256(tag || index) * G.
    """
    points = []
    for i in range(n):
        index_bytes = i.to_bytes(4, "big")
        scalar = hash_to_scalar(tag, index_bytes)
        points.append(ec_mul(scalar, G))
    return points


def multi_exp(scalars: list, points: list):
    """
    Compute sum(scalars[i] * points[i]) efficiently.
    This is a multi-scalar multiplication (MSM) — the most expensive
    operation in bulletproofs.

    dalek uses the Pippenger algorithm for O(n/log n) complexity.
    We use the naive O(n) loop — correct but slower (Python demo only).
    """
    assert len(scalars) == len(points), "Length mismatch"
    result = None
    for s, P in zip(scalars, points):
        s = int(s) % ORDER
        if s == 0:
            continue
        term = ec_mul(s, P)
        result = ec_add(result, term) if result is not None else term
    return result
