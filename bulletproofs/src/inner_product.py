"""
inner_product.py — Inner Product Argument (IPA)

The key size-reduction trick in Bulletproofs.

Problem: We need to prove knowledge of vectors a, b such that:
    P = <a, G_vec> + <b, H_vec>   (vector commitment)
    c = <a, b>                     (inner product)

Naive approach: send all of a and b → O(n) proof size.

Bulletproof IPA: recursively "fold" the vectors in half each round:
    Round 1: n   elements → commitments L_1, R_1 + challenge x_1
    Round 2: n/2 elements → commitments L_2, R_2 + challenge x_2
    ...
    Round log2(n): 1 element → send final scalars a, b (2 elements)

Total proof size: 2*log2(n) curve points + 2 scalars = O(log n).

For n=64 bits: naive=128 elements, IPA=14 points + 2 scalars ✓

Reference comparison (dalek):
  dalek's InnerProductProof::create() does exactly this recursive fold.
  Our implementation mirrors the same structure with the same variable names
  (L_vec, R_vec, a, b) from the Bulletproofs paper (Bünz et al. 2018).

  Key difference: dalek uses Ristretto points; we use BN128.
  Key difference: dalek uses Merlin transcript; we use our Transcript class.
"""

import secrets
from ec_math import ec_add, ec_mul, multi_exp, ORDER, G, H , U
from transcript import Transcript


# ── Scalar helpers ────────────────────────────────────────────────────────

def inner_product(a: list, b: list) -> int:
    """
    Compute integer inner product <a, b> = sum(a_i * b_i) mod ORDER.
    This is the fundamental operation the whole protocol is about.
    """
    assert len(a) == len(b), f"Length mismatch: {len(a)} vs {len(b)}"
    result = 0
    for ai, bi in zip(a, b):
        result = (result + int(ai) * int(bi)) % ORDER
    return result


def hadamard(a: list, b: list) -> list:
    """Element-wise product: [a_0*b_0, a_1*b_1, ...]"""
    return [(int(ai) * int(bi)) % ORDER for ai, bi in zip(a, b)]


def vec_add(a: list, b: list) -> list:
    """Element-wise addition mod ORDER."""
    return [(int(ai) + int(bi)) % ORDER for ai, bi in zip(a, b)]


def vec_scale(a: list, s: int) -> list:
    """Scale every element: [s*a_0, s*a_1, ...]"""
    s = int(s) % ORDER
    return [(s * int(ai)) % ORDER for ai in a]


def halves(v: list) -> tuple:
    """Split vector into first and second halves."""
    n = len(v)
    assert n % 2 == 0, f"Vector length {n} must be even"
    mid = n // 2
    return v[:mid], v[mid:]


# ── Inner Product Proof ───────────────────────────────────────────────────

class InnerProductProof:
    """
    Proof that <a_vec, b_vec> = c, where a_vec and b_vec are committed.

    This is the O(log n) proof that replaces the naive O(n) approach.
    It works by recursively halving the vectors and committing to the
    cross-terms L and R at each step.

    Attributes:
        L_vec: List of curve points (one per round)
        R_vec: List of curve points (one per round)
        a:     Final scalar (single element after log2(n) rounds)
        b:     Final scalar (single element after log2(n) rounds)
    """

    def __init__(self, L_vec, R_vec, a_final: int, b_final: int):
        self.L_vec = L_vec      # length = log2(n)
        self.R_vec = R_vec      # length = log2(n)
        self.a = a_final        # single scalar
        self.b = b_final        # single scalar

    def to_dict(self) -> dict:
        """Serialize for export / display."""
        return {
            "L_vec": [(int(P[0]), int(P[1])) if P else None for P in self.L_vec],
            "R_vec": [(int(P[0]), int(P[1])) if P else None for P in self.R_vec],
            "a": self.a,
            "b": self.b,
            "rounds": len(self.L_vec),
        }

    @property
    def proof_size_elements(self) -> int:
        """Number of group elements + scalars in the proof."""
        return 2 * len(self.L_vec) + 2


def ipa_prove(
    a_vec: list,
    b_vec: list,
    G_vec: list,
    H_vec: list,
    transcript: Transcript,
) -> InnerProductProof:
    """
    Generate an inner product argument proving <a_vec, b_vec> = c.

    The prover knows a_vec and b_vec in full. The verifier only knows
    the commitments P = <a, G_vec> + <b, H_vec> + c * U and c = <a, b>.

    This is Figure 1 from the Bulletproofs paper (Bünz et al. 2018).

    Args:
        a_vec, b_vec: The secret witness vectors
        G_vec, H_vec: Public generator vectors (must match verifier's)
        transcript:   Running Fiat-Shamir transcript (already contains P)

    Returns:
        InnerProductProof with O(log n) elements
    """
    n = len(a_vec)
    assert n == len(b_vec) == len(G_vec) == len(H_vec)
    assert n > 0 and (n & (n - 1)) == 0, f"n={n} must be a power of 2"

    a = [int(x) % ORDER for x in a_vec]
    b = [int(x) % ORDER for x in b_vec]
    G = list(G_vec)
    H = list(H_vec)

    L_vec = []
    R_vec = []

    while n > 1:
        n //= 2

        # Split everything in half
        a_lo, a_hi = a[:n], a[n:]
        b_lo, b_hi = b[:n], b[n:]
        G_lo, G_hi = G[:n], G[n:]
        H_lo, H_hi = H[:n], H[n:]

        # L = <a_lo, G_hi> + <b_hi, H_lo> + c_L * U
        # (cross commitment: left half of a with right half of G)
        c_L = inner_product(a_lo, b_hi)
        L = multi_exp(a_lo, G_hi)
        tmp = multi_exp(b_hi, H_lo)
        if tmp is not None:
            L = ec_add(L, tmp) if L is not None else tmp

        L = ec_add(L, ec_mul(c_L, U))


        # R = <a_hi, G_lo> + <b_lo, H_hi> + c_R * U
        c_R = inner_product(a_hi, b_lo)
        R = multi_exp(a_hi, G_lo)
        tmp = multi_exp(b_lo, H_hi)
        if tmp is not None:
            R = ec_add(R, tmp) if R is not None else tmp

        R = ec_add(R, ec_mul(c_R, U))

        L_vec.append(L)
        R_vec.append(R)

        # Fiat-Shamir challenge
        transcript.append_point(b"L", L)
        transcript.append_point(b"R", R)
        x = transcript.get_challenge(b"x_ipa")
        x_inv = pow(x, ORDER - 2, ORDER)  # modular inverse

        # Fold: new vectors of length n (half)
        # a' = a_lo * x     + a_hi * x_inv
        # b' = b_lo * x_inv + b_hi * x
        # G' = G_lo * x_inv + G_hi * x     (inverse scaling on generators)
        # H' = H_lo * x     + H_hi * x_inv
        a = [(a_lo[i] * x + a_hi[i] * x_inv) % ORDER for i in range(n)]
        b = [(b_lo[i] * x_inv + b_hi[i] * x) % ORDER for i in range(n)]
        G = [
            ec_add(ec_mul(x_inv, G_lo[i]), ec_mul(x, G_hi[i]))
            for i in range(n)
        ]
        H = [
            ec_add(ec_mul(x, H_lo[i]), ec_mul(x_inv, H_hi[i]))
            for i in range(n)
        ]

    # After log2(n) rounds, a and b are single scalars
    return InnerProductProof(L_vec, R_vec, a[0], b[0])


def ipa_verify(
    proof: InnerProductProof,
    P_commit,          # commitment P = <a, G_vec> + <b, H_vec>
    c: int,            # claimed inner product value
    G_vec: list,
    H_vec: list,
    transcript: Transcript,
) -> bool:
    """
    Verify an inner product argument.

    The verifier recomputes the folded generators and checks that the
    final single-element "proof" is consistent with P and c.

    Returns True if the proof is valid, False otherwise.
    """
    n = len(G_vec)
    assert n == len(H_vec)
    assert n > 0 and (n & (n - 1)) == 0

    G = list(G_vec)
    H = list(H_vec)
    P = P_commit

    challenges = []

    for L, R in zip(proof.L_vec, proof.R_vec):
        transcript.append_point(b"L", L)
        transcript.append_point(b"R", R)
        x = transcript.get_challenge(b"x_ipa")
        x_inv = pow(x, ORDER - 2, ORDER)
        challenges.append((x, x_inv))

        x2 = (x * x) % ORDER
        x2_inv = (x_inv * x_inv) % ORDER

        # P' = x^2 * L + P + x^{-2} * R
        P = ec_add(
            ec_add(ec_mul(x2, L), P),
            ec_mul(x2_inv, R)
        )

        # Fold generators
        half = len(G) // 2
        G = [
            ec_add(ec_mul(x_inv, G[i]), ec_mul(x, G[i + half]))
            for i in range(half)
        ]
        H = [
            ec_add(ec_mul(x, H[i]), ec_mul(x_inv, H[i + half]))
            for i in range(half)
        ]

    # Final check: P_folded should equal a*G_folded + b*H_folded
    # The inner product c is verified indirectly through the range proof's
    # polynomial identity check (not here in the IPA itself).
    a, b = proof.a, proof.b

    expected = ec_add(ec_mul(a, G[0]), ec_mul(b, H[0]))
    expected = ec_add(expected, ec_mul((a * b) % ORDER, U))

    if expected is None or P is None:
        return expected is None and P is None

    return (int(expected[0]) == int(P[0]) and int(expected[1]) == int(P[1]))
