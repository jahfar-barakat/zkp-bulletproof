"""
tests/test_range_proof.py — Full test suite for the Bulletproof range proof.

Covers:
  - ec_math primitives (ecAdd, ecMul, multi_exp)
  - Pedersen commitment binding and homomorphism
  - Transcript determinism and challenge uniqueness
  - Inner Product Argument (prove + verify)
  - Range proof (prove + verify, edge cases, rejection)
  - Serialization round-trip
  - Solidity export correctness

Run:  cd bulletproofs && python -m pytest tests/ -v
  OR  cd bulletproofs && python tests/test_range_proof.py
"""

import sys, secrets, pytest
sys.path.insert(0, "src")
sys.path.insert(0, ".")

from ec_math import (
    G, H, ec_add, ec_mul, ORDER, multi_exp,
    get_generator_vector, hash_to_scalar, point_to_bytes
)
from pedersen import commit, open_commit, vector_commit, add_commitments
from transcript import Transcript
from inner_product import (
    inner_product, hadamard, vec_add, vec_scale,
    ipa_prove, ipa_verify, InnerProductProof
)
from range_proof import prove, verify, int_to_bits, power_vector


# ─────────────────────────────────────────────────────────────────────────────
# EC MATH
# ─────────────────────────────────────────────────────────────────────────────

class TestEcMath:
    def test_G_on_curve(self):
        """G should be a valid BN128 point."""
        assert G is not None
        assert G[0] == 1 and G[1] == 2

    def test_H_not_G(self):
        """H should be independent of G (nobody knows log_G(H))."""
        assert H != G
        assert H is not None

    def test_ec_mul_identity(self):
        """1 * G == G."""
        assert ec_mul(1, G) == G

    def test_ec_mul_zero(self):
        """0 * G == None (point at infinity)."""
        assert ec_mul(0, G) is None

    def test_ec_mul_order(self):
        """ORDER * G == None (point at infinity — additive group order)."""
        assert ec_mul(ORDER, G) is None

    def test_ec_add_commutativity(self):
        """P + Q == Q + P."""
        P = ec_mul(7, G)
        Q = ec_mul(13, G)
        assert ec_add(P, Q) == ec_add(Q, P)

    def test_ec_add_associativity(self):
        """(P + Q) + R == P + (Q + R)."""
        P = ec_mul(3, G)
        Q = ec_mul(5, G)
        R = ec_mul(7, G)
        lhs = ec_add(ec_add(P, Q), R)
        rhs = ec_add(P, ec_add(Q, R))
        assert lhs == rhs

    def test_scalar_linearity(self):
        """(a + b) * G == a*G + b*G."""
        a, b = 1234, 5678
        lhs = ec_mul((a + b) % ORDER, G)
        rhs = ec_add(ec_mul(a, G), ec_mul(b, G))
        assert lhs == rhs

    def test_multi_exp_correctness(self):
        """multi_exp([a,b], [G,G]) == (a+b)*G."""
        a, b = 99, 77
        result = multi_exp([a, b], [G, G])
        expected = ec_mul((a + b) % ORDER, G)
        assert result == expected

    def test_get_generator_vector_length(self):
        for n in [4, 8, 16]:
            vec = get_generator_vector(n, b"test_tag")
            assert len(vec) == n

    def test_get_generator_vector_independent(self):
        """Different tags produce different generators."""
        G0 = get_generator_vector(4, b"tag_one")[0]
        G1 = get_generator_vector(4, b"tag_two")[0]
        assert G0 != G1

    def test_point_to_bytes_length(self):
        """point_to_bytes should return 64 bytes for any point."""
        assert len(point_to_bytes(G)) == 64
        assert len(point_to_bytes(None)) == 64  # identity = 64 zero bytes


# ─────────────────────────────────────────────────────────────────────────────
# PEDERSEN COMMITMENTS
# ─────────────────────────────────────────────────────────────────────────────

class TestPedersen:
    def test_open_valid(self):
        """Commitment opens correctly."""
        v = 42
        C, r = commit(v)
        assert open_commit(C, v, r)

    def test_open_wrong_value(self):
        """Wrong value fails to open."""
        C, r = commit(42)
        assert not open_commit(C, 43, r)

    def test_open_wrong_blinding(self):
        """Wrong blinding factor fails to open."""
        C, r = commit(42)
        assert not open_commit(C, 42, r + 1)

    def test_hiding_randomness(self):
        """Two commitments to the same value look different."""
        C1, _ = commit(99)
        C2, _ = commit(99)
        # With overwhelming probability, different random r → different C
        assert C1 != C2

    def test_homomorphic_add(self):
        """C(v1,r1) + C(v2,r2) == C(v1+v2, r1+r2)."""
        v1, v2 = 30, 12
        C1, r1 = commit(v1)
        C2, r2 = commit(v2)
        C_sum  = add_commitments(C1, C2)
        r_sum  = (r1 + r2) % ORDER
        assert open_commit(C_sum, (v1 + v2) % ORDER, r_sum)

    def test_commit_deterministic_r(self):
        """Same (v, r) always gives the same commitment."""
        v, r = 7, 12345
        C1, _ = commit(v, r)
        C2, _ = commit(v, r)
        assert C1 == C2

    def test_vector_commit(self):
        """Vector commitment opens correctly."""
        n = 4
        a = [1, 0, 1, 0]
        G_vec = get_generator_vector(n, b"G_test")
        C, r = vector_commit(a, G_vec)
        # Manually check: C == sum(a_i * G_i) + r*H
        expected = multi_exp(a, G_vec)
        expected = ec_add(expected, ec_mul(r, H))
        assert C == expected


# ─────────────────────────────────────────────────────────────────────────────
# FIAT-SHAMIR TRANSCRIPT
# ─────────────────────────────────────────────────────────────────────────────

class TestTranscript:
    def test_challenge_nonzero(self):
        t = Transcript(b"test")
        c = t.get_challenge(b"x")
        assert 1 <= c < ORDER

    def test_challenges_differ(self):
        """Repeated challenges produce different values."""
        t = Transcript(b"test")
        c1 = t.get_challenge(b"y")
        c2 = t.get_challenge(b"z")
        assert c1 != c2

    def test_determinism(self):
        """Same inputs → same challenges."""
        def run():
            t = Transcript(b"determinism_test")
            t.append_point(b"P", G)
            t.append_scalar(b"v", 42)
            return t.get_challenge(b"x")
        assert run() == run()

    def test_point_changes_challenge(self):
        """Different points → different challenges."""
        t1 = Transcript(b"t")
        t1.append_point(b"P", G)
        c1 = t1.get_challenge(b"x")

        t2 = Transcript(b"t")
        t2.append_point(b"P", ec_mul(2, G))
        c2 = t2.get_challenge(b"x")

        assert c1 != c2

    def test_label_changes_challenge(self):
        """Different labels in the same transcript → different output."""
        t1 = Transcript(b"t")
        t2 = Transcript(b"t")
        c1 = t1.get_challenge(b"alpha")
        c2 = t2.get_challenge(b"beta")
        assert c1 != c2


# ─────────────────────────────────────────────────────────────────────────────
# INNER PRODUCT ARGUMENT
# ─────────────────────────────────────────────────────────────────────────────

class TestIPA:
    def _setup(self, n):
        a_vec = [secrets.randbelow(ORDER - 1) + 1 for _ in range(n)]
        b_vec = [secrets.randbelow(ORDER - 1) + 1 for _ in range(n)]
        G_vec = get_generator_vector(n, b"G_ipa_test")
        H_vec = get_generator_vector(n, b"H_ipa_test")
        c     = inner_product(a_vec, b_vec)
        # Commitment P = <a, G> + <b, H>
        P     = ec_add(multi_exp(a_vec, G_vec), multi_exp(b_vec, H_vec))
        return a_vec, b_vec, G_vec, H_vec, c, P

    def _prove_verify(self, n):
        a_vec, b_vec, G_vec, H_vec, c, P = self._setup(n)
        t = Transcript(b"ipa_test")
        t.append_point(b"P", P)
        proof = ipa_prove(a_vec, b_vec, G_vec, H_vec, t)

        t2 = Transcript(b"ipa_test")
        t2.append_point(b"P", P)
        return ipa_verify(proof, P, c, G_vec, H_vec, t2)

    def test_n4(self):   assert self._prove_verify(4)
    def test_n8(self):   assert self._prove_verify(8)
    def test_n16(self):  assert self._prove_verify(16)

    def test_proof_size_logarithmic(self):
        """IPA proof has 2*log2(n) points + 2 scalars."""
        for n in [4, 8, 16, 32]:
            a = [1] * n; b = [1] * n
            G_vec = get_generator_vector(n, b"G")
            H_vec = get_generator_vector(n, b"H")
            t = Transcript(b"size_test")
            t.append_point(b"P", G)
            proof = ipa_prove(a, b, G_vec, H_vec, t)
            import math
            assert len(proof.L_vec) == math.log2(n)
            assert proof.proof_size_elements == 2 * len(proof.L_vec) + 2

    def test_inner_product_zero(self):
        """IPA works when inner product is 0."""
        n = 4
        a = [2, 0, 0, 0]
        b = [0, 3, 5, 7]
        G_vec = get_generator_vector(n, b"G")
        H_vec = get_generator_vector(n, b"H")
        c = inner_product(a, b)
        assert c == 0
        P = ec_add(multi_exp(a, G_vec), multi_exp(b, H_vec))
        t = Transcript(b"zero_test")
        t.append_point(b"P", P)
        proof = ipa_prove(a, b, G_vec, H_vec, t)
        t2 = Transcript(b"zero_test")
        t2.append_point(b"P", P)
        assert ipa_verify(proof, P, c, G_vec, H_vec, t2)


# ─────────────────────────────────────────────────────────────────────────────
# RANGE PROOF
# ─────────────────────────────────────────────────────────────────────────────

class TestRangeProof:
    # ── Basic correctness ─────────────────────────────────────────────────
    def test_verify_midpoint(self):
        assert verify(prove(42, 8))

    def test_verify_zero(self):
        assert verify(prove(0, 8))

    def test_verify_max(self):
        assert verify(prove(255, 8))

    def test_verify_one(self):
        assert verify(prove(1, 8))

    def test_verify_4bit(self):
        assert verify(prove(7, 4))
        assert verify(prove(0, 4))
        assert verify(prove(15, 4))

    def test_verify_16bit(self):
        assert verify(prove(1000, 16))
        assert verify(prove(65535, 16))

    def test_verify_32bit(self):
        assert verify(prove(2**20, 32))

    # ── Out-of-range rejection (at prove time) ────────────────────────────
    def test_reject_above_range(self):
        with pytest.raises(ValueError):
            prove(256, 8)

    def test_reject_negative(self):
        with pytest.raises(ValueError):
            prove(-1, 8)

    def test_reject_exactly_2n(self):
        with pytest.raises(ValueError):
            prove(16, 4)

    def test_reject_invalid_nbits(self):
        with pytest.raises(ValueError):
            prove(5, 5)  # 5 is not a power of 2

    # ── Deterministic gamma ───────────────────────────────────────────────
    def test_fixed_gamma(self):
        """Fixing gamma makes V deterministic; proof still verifies."""
        gamma = 12345678
        p1 = prove(42, 8, gamma=gamma)
        p2 = prove(42, 8, gamma=gamma)
        assert p1.V == p2.V  # same V
        assert verify(p1)
        assert verify(p2)

    # ── Zero-knowledge: different proofs for same v ───────────────────────
    def test_zk_unlinkability(self):
        """Two proofs of the same value look completely different."""
        p1 = prove(42, 8)
        p2 = prove(42, 8)
        # V should differ (different random gamma)
        assert p1.V != p2.V
        # Both must still verify
        assert verify(p1) and verify(p2)

    # ── Tampered proof detection ──────────────────────────────────────────
    def test_tampered_t_hat_fails(self):
        """Changing t_hat should make verification fail."""
        p = prove(42, 8)
        p.t_hat = (p.t_hat + 1) % ORDER
        assert not verify(p)

    def test_tampered_tau_x_fails(self):
        """Changing tau_x should make verification fail."""
        p = prove(42, 8)
        p.tau_x = (p.tau_x + 1) % ORDER
        assert not verify(p)

    def test_tampered_V_fails(self):
        """Replacing V with a commitment to a different value must fail."""
        p = prove(42, 8)
        # Replace V with commitment to 100 (wrong value)
        V_wrong, _ = commit(100)
        p.V = V_wrong
        assert not verify(p)

    def test_tampered_ipa_a_fails(self):
        """Changing the IPA final scalar a should fail."""
        p = prove(42, 8)
        p.ipa.a = (p.ipa.a + 1) % ORDER
        assert not verify(p)

    # ── Serialization ─────────────────────────────────────────────────────
    def test_to_dict(self):
        """Proof serializes to dict without error."""
        p = prove(42, 8)
        d = p.to_dict()
        assert isinstance(d, dict)
        assert "V" in d and "t_hat" in d and "ipa" in d

    def test_summary(self):
        """Proof summary string is informative."""
        p = prove(42, 8)
        s = p.summary()
        assert "n=8" in s and "IPA" in s


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

class TestHelpers:
    def test_int_to_bits_known(self):
        assert int_to_bits(6, 4)  == [0, 1, 1, 0]
        assert int_to_bits(0, 4)  == [0, 0, 0, 0]
        assert int_to_bits(15, 4) == [1, 1, 1, 1]

    def test_int_to_bits_reconstruction(self):
        """Bits should reconstruct the original value."""
        for v in [0, 1, 42, 127, 255]:
            bits = int_to_bits(v, 8)
            reconstructed = sum(b * (2**i) for i, b in enumerate(bits))
            assert reconstructed == v

    def test_power_vector(self):
        v = power_vector(2, 4)
        assert v == [1, 2, 4, 8]

    def test_inner_product_basic(self):
        assert inner_product([1, 2, 3], [4, 5, 6]) == (4 + 10 + 18) % ORDER


# ─────────────────────────────────────────────────────────────────────────────
# SOLIDITY EXPORT
# ─────────────────────────────────────────────────────────────────────────────

class TestSolidityExport:
    def test_export_runs(self):
        from scripts.export_proof import export_for_solidity
        p = prove(42, 8)
        d = export_for_solidity(p)
        assert "P_final" in d
        assert "G_final" in d
        assert "H_final" in d
        assert "delta" in d

    def test_export_ipa_check(self):
        """Exported P_final, G_final, H_final must satisfy a*G+b*H == P."""
        from scripts.export_proof import export_for_solidity
        from py_ecc.bn128 import FQ
        p = prove(99, 8)
        d = export_for_solidity(p)
        # Reconstruct py_ecc points from exported [x, y] int pairs
        def to_point(pair):
            return (FQ(pair[0]), FQ(pair[1]))
        G_final = to_point(d["G_final"])
        H_final = to_point(d["H_final"])
        P_final = d["P_final"]   # keep as plain ints for comparison
        a = d["ipa_a"]
        b = d["ipa_b"]
        lhs = ec_add(ec_mul(a, G_final), ec_mul(b, H_final))
        assert int(lhs[0]) == P_final[0] and int(lhs[1]) == P_final[1]


# ─────────────────────────────────────────────────────────────────────────────
# MAIN (run without pytest)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import traceback

    suites = [
        TestEcMath, TestPedersen, TestTranscript,
        TestIPA, TestRangeProof, TestHelpers, TestSolidityExport
    ]

    total, passed, failed = 0, 0, 0
    failures = []

    for Suite in suites:
        instance = Suite()
        methods  = [m for m in dir(instance) if m.startswith("test_")]
        print(f"\n{Suite.__name__} ({len(methods)} tests)")
        for m in methods:
            total += 1
            try:
                getattr(instance, m)()
                print(f"  ✓  {m}")
                passed += 1
            except Exception as e:
                print(f"  ✗  {m}  →  {e}")
                failures.append((Suite.__name__, m, traceback.format_exc()))
                failed += 1

    print(f"\n{'='*50}")
    print(f"  Results: {passed}/{total} passed, {failed} failed")
    if failures:
        print("\nFailed tests:")
        for suite, method, tb in failures:
            print(f"\n  {suite}.{method}:")
            for line in tb.splitlines()[-3:]:
                print(f"    {line}")
    print("="*50)
    sys.exit(0 if failed == 0 else 1)
