"""
pedersen.py — Pedersen commitments and vector Pedersen commitments

A Pedersen commitment to value v with blinding r is:
    C = v*G + r*H

Properties:
  - Hiding:   Given only C, no one can determine v (computationally)
  - Binding:  You cannot open C to two different values (computationally)
              (assuming discrete log is hard)

A Vector Pedersen Commitment to vector a = [a_0, ..., a_{n-1}] is:
    Com(a; r) = a_0*G_0 + a_1*G_1 + ... + a_{n-1}*G_{n-1} + r*H

This extends naturally to hiding an entire vector under one group element.

Reference comparison (dalek):
  dalek's PedersenGens holds G and H.
  dalek's BulletproofGens holds the G_vec and H_vec.
  We mirror this exactly with commit() and vector_commit().
"""

import secrets
from ec_math import G, H, ec_add, ec_mul, multi_exp, ORDER, get_generator_vector


# ── Scalar Pedersen commitment ─────────────────────────────────────────────

def commit(v: int, r: int = None) -> tuple:
    """
    Compute a Pedersen commitment to scalar value v.

    C = v*G + r*H

    Args:
        v: The secret value to commit to (must be in [0, ORDER))
        r: The blinding factor (random if not provided)

    Returns:
        (C, r)  where C is the commitment point and r is the blinding factor
                Keep r secret — it's the "key" to open the commitment.

    Example:
        C, r = commit(42)
        # C is a curve point, safe to publish
        # r must stay secret
    """
    if r is None:
        r = secrets.randbelow(ORDER - 1) + 1  # r in [1, ORDER-1]
    v = int(v) % ORDER
    r = int(r) % ORDER

    vG = ec_mul(v, G)   # v * G
    rH = ec_mul(r, H)   # r * H

    if vG is None:
        C = rH
    elif rH is None:
        C = vG
    else:
        C = ec_add(vG, rH)

    return C, r


def open_commit(C, v: int, r: int) -> bool:
    """
    Verify that commitment C was made to value v with blinding r.
    Returns True if C == v*G + r*H.
    """
    C_check, _ = commit(v, r)
    if C is None and C_check is None:
        return True
    if C is None or C_check is None:
        return False
    return C[0] == C_check[0] and C[1] == C_check[1]


# ── Vector Pedersen commitment ─────────────────────────────────────────────

def vector_commit(a_vec: list, G_vec: list, r: int = None) -> tuple:
    """
    Commit to a vector of scalars: Com(a; r) = sum(a_i * G_i) + r*H

    This is used in bulletproofs to commit to the bit-decomposition
    vectors a_L and a_R simultaneously.

    Args:
        a_vec: List of scalars [a_0, ..., a_{n-1}]
        G_vec: List of generator points [G_0, ..., G_{n-1}]
        r:     Blinding factor (random if not provided)

    Returns:
        (C, r) commitment point and blinding factor
    """
    assert len(a_vec) == len(G_vec), "Vector lengths must match"

    if r is None:
        r = secrets.randbelow(ORDER - 1) + 1

    # sum(a_i * G_i)
    C = multi_exp([int(a) % ORDER for a in a_vec], G_vec)

    # + r * H
    rH = ec_mul(r, H)
    if C is None:
        C = rH
    elif rH is not None:
        C = ec_add(C, rH)

    return C, r


def vector_commit_no_blinding(a_vec: list, G_vec: list):
    """
    Compute sum(a_i * G_i) without a blinding term.
    Used internally when the blinding is handled separately.
    """
    assert len(a_vec) == len(G_vec)
    result = multi_exp([int(a) % ORDER for a in a_vec], G_vec)
    return result


# ── Commitment arithmetic ──────────────────────────────────────────────────

def add_commitments(C1, C2):
    """
    Homomorphic addition of two commitments.

    If C1 = v1*G + r1*H  and  C2 = v2*G + r2*H
    then C1 + C2 = (v1+v2)*G + (r1+r2)*H

    This is the key homomorphic property of Pedersen commitments:
    you can add commitments without knowing the underlying values.
    """
    if C1 is None:
        return C2
    if C2 is None:
        return C1
    return ec_add(C1, C2)
