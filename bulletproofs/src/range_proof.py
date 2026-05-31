"""
range_proof.py — Bulletproof Range Proof

Proves that a committed value v lies in [0, 2^n_bits) without
revealing v. This is the main contribution of the Bulletproofs paper.

High-level idea:
  1. Write v in binary: v = b_0 + 2*b_1 + 4*b_2 + ... + 2^{n-1}*b_{n-1}
  2. Commit to bit vectors a_L (the bits) and a_R (the bits minus 1)
  3. Prove:  a_L ∘ a_R = 0   (each bit times (bit-1) = 0, so each is 0 or 1)
             <a_L, 2^n>  = v  (the bits reconstruct v)
  4. Use the inner product argument to compress (3) to O(log n) size

Reference comparison (dalek):
  dalek's RangeProof::prove() follows exactly this structure.
  Variable names here match the Bulletproofs paper (§4.2):
    a_L, a_R, s_L, s_R, A, S, T_1, T_2, t_hat, tau_x, mu

  Key simplification vs dalek:
    - dalek supports aggregated multi-range proofs (m commitments at once)
    - We implement single-range proofs only
    - dalek uses batch verification; we verify one proof at a time

Proof structure (what gets sent from prover to verifier):
  V       = commitment to v (1 curve point)
  A, S    = bit vector commitments (2 curve points)
  T_1, T_2 = polynomial commitments (2 curve points)
  tau_x   = blinding for t_hat (1 scalar)
  mu      = blinding for l, r vectors (1 scalar)
  t_hat   = inner product value (1 scalar)
  ipa     = inner product proof (2*log2(n) points + 2 scalars)

Total: 5 + 2*log2(n) group elements + 3 scalars
For n=8:  5 + 6 = 11 group elements + 3 scalars  (vs 8 naive)
For n=32: 5 + 10 = 15 group elements + 3 scalars (vs 32 naive)  ✓
"""

import secrets
from dataclasses import dataclass, field
from typing import Optional

from ec_math import (
    G, H, ec_add, ec_mul, multi_exp, ORDER,
    get_generator_vector, point_to_bytes,
)
from pedersen import commit, vector_commit_no_blinding
from transcript import Transcript
from inner_product import (
    inner_product, ipa_prove, ipa_verify,
    InnerProductProof, vec_add, vec_scale, hadamard,
)


# ── Helpers ───────────────────────────────────────────────────────────────

def int_to_bits(v: int, n: int) -> list:
    """
    Decompose v into n bits (little-endian).
    v = a_L[0] + 2*a_L[1] + 4*a_L[2] + ... + 2^{n-1}*a_L[n-1]

    Example: int_to_bits(6, 4) = [0, 1, 1, 0]
             6 = 0*1 + 1*2 + 1*4 + 0*8 ✓
    """
    assert 0 <= v < 2**n, f"Value {v} out of range [0, 2^{n})"
    return [(v >> i) & 1 for i in range(n)]


def power_vector(base: int, n: int) -> list:
    """
    Return [1, base, base^2, ..., base^{n-1}] mod ORDER.
    Used for y-powers and 2-powers in the proof.
    """
    result = []
    cur = 1
    for _ in range(n):
        result.append(cur)
        cur = (cur * base) % ORDER
    return result


def mod_inv(a: int) -> int:
    """Modular inverse of a mod ORDER (Fermat's little theorem)."""
    return pow(int(a) % ORDER, ORDER - 2, ORDER)


# ── Proof data structure ───────────────────────────────────────────────────

@dataclass
class RangeProof:
    """
    A complete Bulletproof range proof.

    All fields are what gets sent from prover to verifier.
    The verifier also needs V (the commitment) and n_bits (the range).
    """
    V:      object          # Pedersen commitment to v
    A:      object          # commitment to a_L, a_R
    S:      object          # commitment to s_L, s_R (blinding vectors)
    T_1:    object          # commitment to polynomial coefficient t_1
    T_2:    object          # commitment to polynomial coefficient t_2
    tau_x:  int             # blinding scalar for t_hat
    mu:     int             # blinding scalar for inner product
    t_hat:  int             # <l(x), r(x)> — the claimed inner product
    ipa:    InnerProductProof  # inner product argument (O(log n))
    n_bits: int             # bit-length of the range
    gamma:  int = field(default=0, repr=False)  # blinding for V (secret)

    def summary(self) -> str:
        """Human-readable proof summary."""
        n = self.n_bits
        ip_size = self.ipa.proof_size_elements
        return (
            f"RangeProof(n={n} bits, range=[0,{2**n}), "
            f"IPA rounds={len(self.ipa.L_vec)}, "
            f"total elements=5+{ip_size}={5+ip_size})"
        )

    def to_dict(self) -> dict:
        """Full serialization for export."""
        def pt(P):
            return (int(P[0]), int(P[1])) if P else None
        return {
            "V": pt(self.V), "A": pt(self.A), "S": pt(self.S),
            "T_1": pt(self.T_1), "T_2": pt(self.T_2),
            "tau_x": self.tau_x, "mu": self.mu, "t_hat": self.t_hat,
            "ipa": self.ipa.to_dict(),
            "n_bits": self.n_bits,
        }


# ── Prover ────────────────────────────────────────────────────────────────

def prove(v: int, n_bits: int = 8, gamma: int = None) -> RangeProof:
    """
    Generate a Bulletproof range proof for value v in [0, 2^n_bits).

    Args:
        v:      The secret value (must satisfy 0 <= v < 2^n_bits)
        n_bits: Bit-length of the range (8 → [0,255], 16 → [0,65535], etc.)
                Must be a power of 2 (4, 8, 16, 32, 64)
        gamma:  Blinding factor for V (random if not provided)

    Returns:
        RangeProof — send this to the verifier (keep gamma secret!)

    Raises:
        ValueError: if v is out of range or n_bits is not a power of 2
    """
    if not (0 <= v < 2**n_bits):
        raise ValueError(f"v={v} is not in [0, 2^{n_bits})={2**n_bits}")
    if n_bits <= 0 or (n_bits & (n_bits - 1)) != 0:
        raise ValueError(f"n_bits={n_bits} must be a power of 2 (4,8,16,32,...)")

    n = n_bits

    # ── Step 1: Commit to v ───────────────────────────────────────────
    # V = v*G + gamma*H
    if gamma is None:
        gamma = secrets.randbelow(ORDER - 1) + 1
    V, _ = commit(v, gamma)

    # ── Step 2: Bit decomposition ─────────────────────────────────────
    # a_L = bits of v (each 0 or 1)
    # a_R = a_L - 1   (each is 0 or -1 ≡ ORDER-1)
    # Key property: a_L[i] * a_R[i] = b*(b-1) = 0 for any bit b
    a_L = int_to_bits(v, n)
    a_R = [(ai - 1) % ORDER for ai in a_L]

    # Sanity check: inner product <a_L, a_R> should be 0
    # (all bits are 0 or 1, so a_L[i]*a_R[i] is always 0)
    assert inner_product(a_L, a_R) == 0, "Bug: bit decomposition failed"

    # ── Step 3: Generator vectors ─────────────────────────────────────
    G_vec = get_generator_vector(n, b"bulletproof_G_vec_v1")
    H_vec = get_generator_vector(n, b"bulletproof_H_vec_v1")

    # ── Step 4: Commit to a_L, a_R, s_L, s_R ────────────────────────
    # A = <a_L, G_vec> + <a_R, H_vec> + alpha*H
    alpha = secrets.randbelow(ORDER - 1) + 1
    A_base = ec_add(
        vector_commit_no_blinding(a_L, G_vec),
        vector_commit_no_blinding(a_R, H_vec),
    )
    A = ec_add(A_base, ec_mul(alpha, H)) if A_base else ec_mul(alpha, H)

    # s_L, s_R = random blinding vectors
    s_L = [secrets.randbelow(ORDER - 1) + 1 for _ in range(n)]
    s_R = [secrets.randbelow(ORDER - 1) + 1 for _ in range(n)]

    # S = <s_L, G_vec> + <s_R, H_vec> + rho*H
    rho = secrets.randbelow(ORDER - 1) + 1
    S_base = ec_add(
        vector_commit_no_blinding(s_L, G_vec),
        vector_commit_no_blinding(s_R, H_vec),
    )
    S = ec_add(S_base, ec_mul(rho, H)) if S_base else ec_mul(rho, H)

    # ── Step 5: Fiat-Shamir challenges y, z ──────────────────────────
    t = Transcript()
    t.append_point(b"V", V)
    t.append_point(b"A", A)
    t.append_point(b"S", S)

    y = t.get_challenge(b"y")   # challenge for weighting H_vec
    z = t.get_challenge(b"z")   # challenge for aggregating constraints

    # ── Step 6: Compute l(x) and r(x) polynomial vectors ─────────────
    # These encode the range proof constraints as a polynomial identity.
    #
    # l(X) = (a_L - z*1^n) + s_L*X
    # r(X) = y^n ∘ (a_R + z*1^n + s_R*X) + z^2 * 2^n
    #
    # The inner product <l(x), r(x)> = t(x) encodes all constraints:
    #   t_0: the constant term contains <a_L-z, y^n∘(a_R+z)> + z^2*<a_L,2^n>
    #        which is 0 iff all bits are valid AND they reconstruct v
    #   t_1: linear term (blinding)
    #   t_2: quadratic term (blinding)

    y_n = power_vector(y, n)           # [1, y, y^2, ..., y^{n-1}]
    z2 = (z * z) % ORDER
    two_n = power_vector(2, n)         # [1, 2, 4, ..., 2^{n-1}]

    # Compute t_1, t_2 (coefficients of t(X) = <l(X),r(X)>)
    # l(X) = l_0 + l_1*X  where l_0 = a_L - z, l_1 = s_L
    # r(X) = r_0 + r_1*X  where r_0 = y^n∘(a_R+z) + z^2*2^n, r_1 = y^n∘s_R
    l_0 = [(a_L[i] - z) % ORDER for i in range(n)]
    l_1 = s_L
    r_0 = [(y_n[i] * ((a_R[i] + z) % ORDER) + z2 * two_n[i]) % ORDER for i in range(n)]
    r_1 = [(y_n[i] * s_R[i]) % ORDER for i in range(n)]

    # t_1 = <l_0, r_1> + <l_1, r_0>   (cross terms)
    t_1 = (inner_product(l_0, r_1) + inner_product(l_1, r_0)) % ORDER
    # t_2 = <l_1, r_1>                 (quadratic term)
    t_2 = inner_product(l_1, r_1)

    # ── Step 7: Commit to t_1, t_2 ───────────────────────────────────
    tau_1 = secrets.randbelow(ORDER - 1) + 1
    tau_2 = secrets.randbelow(ORDER - 1) + 1
    T_1, _ = commit(t_1, tau_1)
    T_2, _ = commit(t_2, tau_2)

    # ── Step 8: Fiat-Shamir challenge x ──────────────────────────────
    t.append_point(b"T_1", T_1)
    t.append_point(b"T_2", T_2)
    x = t.get_challenge(b"x")

    # ── Step 9: Evaluate l(x), r(x), t_hat ───────────────────────────
    # l = l_0 + l_1*x
    l_vec = [(l_0[i] + l_1[i] * x) % ORDER for i in range(n)]
    # r = r_0 + r_1*x
    r_vec = [(r_0[i] + r_1[i] * x) % ORDER for i in range(n)]
    # t_hat = <l, r>
    t_hat = inner_product(l_vec, r_vec)

    # ── Step 10: Blinding factors ─────────────────────────────────────
    # tau_x = tau_2*x^2 + tau_1*x + z^2*gamma
    x2 = (x * x) % ORDER
    tau_x = (tau_2 * x2 + tau_1 * x + z2 * gamma) % ORDER

    # mu = alpha + rho*x
    mu = (alpha + rho * x) % ORDER

    # ── Step 11: Inner product argument ──────────────────────────────
    # We need to prove <l_vec, r_vec> = t_hat using the IPA.
    # The verifier will check this against the commitments.
    #
    # But we need to "re-weight" H_vec by y^{-n} first:
    #   P = <l_vec, G_vec> + <r_vec, H_vec_prime>  where H_vec' = y^{-i}*H_vec
    # This is a standard trick from the paper (§4.2, proof of t_hat).
    y_inv = mod_inv(y)
    y_inv_n = power_vector(y_inv, n)
    H_vec_prime = [ec_mul(y_inv_n[i], H_vec[i]) for i in range(n)]

    t.append_scalar(b"tau_x", tau_x)
    t.append_scalar(b"mu", mu)
    t.append_scalar(b"t_hat", t_hat)

    ipa = ipa_prove(l_vec, r_vec, G_vec, H_vec_prime, t)

    return RangeProof(
        V=V, A=A, S=S, T_1=T_1, T_2=T_2,
        tau_x=tau_x, mu=mu, t_hat=t_hat,
        ipa=ipa, n_bits=n_bits, gamma=gamma,
    )


# ── Verifier ─────────────────────────────────────────────────────────────

def verify(proof: RangeProof) -> bool:
    """
    Verify a Bulletproof range proof.

    The verifier:
      1. Recomputes all Fiat-Shamir challenges from the proof transcript
      2. Checks the polynomial identity t_hat = t(x) is consistent
      3. Verifies the inner product argument

    Args:
        proof: The RangeProof to verify

    Returns:
        True if the proof is valid (v is in range), False otherwise

    Note: This function does NOT take v or gamma as inputs — it only
    uses the public proof data. That's the whole point of a ZK proof!
    """
    n = proof.n_bits
    V, A, S = proof.V, proof.A, proof.S
    T_1, T_2 = proof.T_1, proof.T_2
    tau_x, mu, t_hat = proof.tau_x, proof.mu, proof.t_hat

    # ── Recompute generators (must match prover) ──────────────────────
    G_vec = get_generator_vector(n, b"bulletproof_G_vec_v1")
    H_vec = get_generator_vector(n, b"bulletproof_H_vec_v1")

    # ── Recompute challenges (Fiat-Shamir) ────────────────────────────
    t = Transcript()
    t.append_point(b"V", V)
    t.append_point(b"A", A)
    t.append_point(b"S", S)
    y = t.get_challenge(b"y")
    z = t.get_challenge(b"z")
    t.append_point(b"T_1", T_1)
    t.append_point(b"T_2", T_2)
    x = t.get_challenge(b"x")

    z2 = (z * z) % ORDER
    x2 = (x * x) % ORDER
    y_n = power_vector(y, n)
    two_n = power_vector(2, n)

    # ── Check 1: Polynomial identity ──────────────────────────────────
    # t_hat should equal t(x) = t_0 + t_1*x + t_2*x^2
    # where t_0 = delta(y,z) + z^2 * v
    #   delta(y,z) = (z - z^2) * <1^n, y^n> - z^3 * <1^n, 2^n>
    sum_y_n = sum(y_n) % ORDER
    sum_2_n = sum(two_n) % ORDER

    delta = (
        (z - z2) % ORDER * sum_y_n % ORDER
        - z2 * z % ORDER * sum_2_n % ORDER
    ) % ORDER

    # LHS: t_hat * G + tau_x * H  (commitment to t_hat)
    lhs_T = ec_add(ec_mul(t_hat, G), ec_mul(tau_x, H))

    # RHS: delta*G + x*T_1 + x^2*T_2 + z^2*V
    rhs_T = ec_add(
        ec_add(ec_mul(delta, G), ec_mul(x, T_1)),
        ec_add(ec_mul(x2, T_2), ec_mul(z2, V)),
    )

    if lhs_T is None or rhs_T is None or lhs_T[0] != rhs_T[0] or lhs_T[1] != rhs_T[1]:
        return False

    # ── Check 2: Inner product argument ──────────────────────────────
    # Compute the expected commitment P for the IPA verifier
    # P = -mu*H + A + x*S + sum(z*y^{-i}*H_i - z*G_i + z^2*2^i*y^{-i}*H_i)
    #
    # Simplified: P = A + x*S + <z^n∘G_vec_part, ...> (as in paper §4.2)

    y_inv = mod_inv(y)
    y_inv_n = power_vector(y_inv, n)
    H_vec_prime = [ec_mul(y_inv_n[i], H_vec[i]) for i in range(n)]

    # P = A + x*S
    P = ec_add(A, ec_mul(x, S))

    # Add generator offset terms
    # sum_i ( -z * G_i + (z*y^i + z^2*2^i) * H_i_prime )
    for i in range(n):
        # -z * G_i
        P = ec_add(P, ec_mul((-z) % ORDER, G_vec[i]))
        # (z * y_n[i] + z2 * two_n[i]) * H_i_prime
        coeff = (z * y_n[i] + z2 * two_n[i]) % ORDER
        P = ec_add(P, ec_mul(coeff, H_vec_prime[i]))

    # Remove blinding: P' = P - mu*H
    P = ec_add(P, ec_mul((-mu) % ORDER, H))

    # ── Verify IPA ────────────────────────────────────────────────────
    t.append_scalar(b"tau_x", tau_x)
    t.append_scalar(b"mu", mu)
    t.append_scalar(b"t_hat", t_hat)

    return ipa_verify(proof.ipa, P, t_hat, G_vec, H_vec_prime, t)
