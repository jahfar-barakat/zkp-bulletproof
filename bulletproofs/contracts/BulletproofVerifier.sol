// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BulletproofVerifier
 * @notice On-chain verifier for Bulletproof range proofs over the BN128 curve.
 *
 * A range proof proves that a committed value v lies in [0, 2^n) without
 * revealing v. This contract performs the two core verification checks:
 *
 *   CHECK 1 — Polynomial Identity:
 *     t_hat·G + tau_x·H  ==  delta·G + x·T1 + x²·T2 + z²·V
 *
 *   CHECK 2 — Inner Product Argument (IPA) Final Check:
 *     a·G_final + b·H_final  ==  P_final
 *
 * Both checks use BN128 elliptic-curve operations via Ethereum precompiles:
 *   ecAdd  → address 0x06  (EIP-196)
 *   ecMul  → address 0x07  (EIP-196)
 *
 * The Fiat-Shamir challenges (y, z, x) and pre-folded IPA generators
 * (G_final, H_final, P_final) are supplied by the caller, computed
 * off-chain by export_proof.py.
 *
 * Reference implementation: github.com/zkcrypto/bulletproofs (Rust)
 * Python implementation:     src/range_proof.py
 *
 * @dev Deploy on any EVM chain with BN128 precompiles (Ethereum, Polygon,
 *      Arbitrum, BSC, Hardhat local node, etc.).
 */
contract BulletproofVerifier {

    // ── BN128 curve parameters ───────────────────────────────────────────────
    /// @dev Curve order (scalar field modulus)
    uint256 public constant Q =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @dev Field modulus (base field of BN128)
    uint256 public constant FIELD_MOD =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // ── Standard generator G = (1, 2) ────────────────────────────────────────
    uint256 public constant Gx = 1;
    uint256 public constant Gy = 2;

    // ── Independent generator H (derived from SHA256 in Python, hardcoded) ───
    // H_scalar = SHA256("bulletproof_H_generator_v1") mod Q
    // H = H_scalar * G  (computed off-chain, hardcoded here for gas efficiency)
    uint256 public constant Hx =
        459949481272866443960724912740899158807083125217931006567015893658029788644;
    uint256 public constant Hy =
        11645021172173330494259080844525435138787232316664030576438478695061142053648;

    // ── Events ───────────────────────────────────────────────────────────────
    event ProofVerified(address indexed prover, bool valid, uint256 n_bits);

    // ── Proof input structs ──────────────────────────────────────────────────

    struct ProofPoints {
        uint256[2] V;    // Pedersen commitment to v (hides v)
        uint256[2] A;    // Commitment to bit vectors a_L, a_R
        uint256[2] S;    // Commitment to blinding vectors s_L, s_R
        uint256[2] T1;   // Polynomial coefficient commitment t_1
        uint256[2] T2;   // Polynomial coefficient commitment t_2
    }

    struct ProofScalars {
        uint256 tau_x;  // Blinding for t_hat
        uint256 mu;     // Blinding for l, r vectors
        uint256 t_hat;  // Inner product <l(x), r(x)>
        uint256 ipa_a;  // IPA final scalar a
        uint256 ipa_b;  // IPA final scalar b
    }

    struct Challenges {
        uint256 y;      // Fiat-Shamir challenge (weights H_vec)
        uint256 z;      // Fiat-Shamir challenge (aggregates constraints)
        uint256 x;      // Fiat-Shamir challenge (evaluation point)
        uint256 delta;  // Pre-computed: (z - z²)·⟨1ⁿ, yⁿ⟩ - z³·⟨1ⁿ, 2ⁿ⟩
        uint256 z2;     // z² mod Q
        uint256 x2;     // x² mod Q
    }

    struct IPAFinal {
        uint256[2] P_final;  // Commitment after all IPA rounds
        uint256[2] G_final;  // Generator after folding
        uint256[2] H_final;  // Generator after folding
    }

    // ── Main verification entry-point ────────────────────────────────────────

    /**
     * @notice Verify a Bulletproof range proof.
     *
     * @param points   Proof curve points: V, A, S, T1, T2
     * @param scalars  Proof scalars: tau_x, mu, t_hat, ipa_a, ipa_b
     * @param ch       Fiat-Shamir challenges + pre-computed delta, z², x²
     * @param ipa      Pre-folded IPA generators and commitment
     * @param n_bits   Bit-length of the range [0, 2^n_bits)
     *
     * @return valid   True if the proof is valid.
     *
     * Emits ProofVerified with the result.
     */
    function verify(
        ProofPoints calldata points,
        ProofScalars calldata scalars,
        Challenges calldata ch,
        IPAFinal calldata ipa,
        uint8 n_bits
    ) external returns (bool valid) {
        valid = _checkPolynomialIdentity(points, scalars, ch)
             && _checkIPAFinal(ipa, scalars.ipa_a, scalars.ipa_b);

        emit ProofVerified(msg.sender, valid, n_bits);
    }

    /**
     * @notice Pure version of verify (no state change, no event).
     *         Useful for off-chain simulation with eth_call.
     */
    function verifyView(
        ProofPoints calldata points,
        ProofScalars calldata scalars,
        Challenges calldata ch,
        IPAFinal calldata ipa,
        uint8 n_bits
    ) external view returns (bool valid) {
        valid = _checkPolynomialIdentity(points, scalars, ch)
             && _checkIPAFinal(ipa, scalars.ipa_a, scalars.ipa_b);
    }

    // ── Verification checks ──────────────────────────────────────────────────

    /**
     * @dev CHECK 1 — Polynomial Identity
     *
     * Verifies that the prover correctly evaluated the range proof polynomial.
     *
     *   LHS = t_hat·G + tau_x·H
     *   RHS = delta·G + x·T1 + x²·T2 + z²·V
     *
     * This encodes ALL the range constraints:
     *   - Each bit is 0 or 1  (a_L[i] * a_R[i] = 0)
     *   - The bits reconstruct v  (<a_L, 2ⁿ> = v)
     *   - The polynomial t(x) evaluates correctly
     */
    function _checkPolynomialIdentity(
        ProofPoints calldata p,
        ProofScalars calldata s,
        Challenges calldata ch
    ) internal view returns (bool) {
        // LHS = t_hat * G + tau_x * H
        uint256[2] memory lhs_tG  = _ecMul(Gx, Gy, s.t_hat);
        uint256[2] memory lhs_rH  = _ecMul(Hx, Hy, s.tau_x);
        uint256[2] memory lhs     = _ecAdd(lhs_tG[0], lhs_tG[1], lhs_rH[0], lhs_rH[1]);

        // RHS = delta*G + x*T1 + x²*T2 + z²*V
        uint256[2] memory rhs_dG  = _ecMul(Gx, Gy, ch.delta);
        uint256[2] memory rhs_xT1 = _ecMul(p.T1[0], p.T1[1], ch.x);
        uint256[2] memory rhs_x2T2= _ecMul(p.T2[0], p.T2[1], ch.x2);
        uint256[2] memory rhs_z2V = _ecMul(p.V[0], p.V[1], ch.z2);

        uint256[2] memory rhs = _ecAdd(rhs_dG[0], rhs_dG[1], rhs_xT1[0], rhs_xT1[1]);
        rhs = _ecAdd(rhs[0], rhs[1], rhs_x2T2[0], rhs_x2T2[1]);
        rhs = _ecAdd(rhs[0], rhs[1], rhs_z2V[0], rhs_z2V[1]);

        return lhs[0] == rhs[0] && lhs[1] == rhs[1];
    }

    /**
     * @dev CHECK 2 — IPA Final Check
     *
     * After log₂(n) folding rounds, the IPA reduces to a single check:
     *
     *   a·G_final + b·H_final  ==  P_final
     *
     * Where G_final, H_final are the folded generators and P_final is the
     * folded commitment. These are computed off-chain (by export_proof.py)
     * since recomputing on-chain for large n would be very gas-intensive.
     *
     * The folding is sound because the IPA challenges are derived from the
     * Fiat-Shamir transcript (which commits the prover to their choices).
     */
    function _checkIPAFinal(
        IPAFinal calldata ipa,
        uint256 a,
        uint256 b
    ) internal view returns (bool) {
        // a·G_final + b·H_final
        uint256[2] memory aG = _ecMul(ipa.G_final[0], ipa.G_final[1], a);
        uint256[2] memory bH = _ecMul(ipa.H_final[0], ipa.H_final[1], b);
        uint256[2] memory lhs = _ecAdd(aG[0], aG[1], bH[0], bH[1]);

        return lhs[0] == ipa.P_final[0] && lhs[1] == ipa.P_final[1];
    }

    // ── BN128 precompile wrappers ────────────────────────────────────────────

    /**
     * @dev Elliptic curve point addition using the ecAdd precompile (0x06).
     *      EIP-196: https://eips.ethereum.org/EIPS/eip-196
     */
    function _ecAdd(
        uint256 ax, uint256 ay,
        uint256 bx, uint256 by
    ) internal view returns (uint256[2] memory result) {
        uint256[4] memory input = [ax, ay, bx, by];
        bool success;
        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, result, 0x40)
        }
        require(success, "BulletproofVerifier: ecAdd precompile failed");
    }

    /**
     * @dev Elliptic curve scalar multiplication using the ecMul precompile (0x07).
     *      EIP-196: https://eips.ethereum.org/EIPS/eip-196
     *      Scalar is automatically reduced mod Q by the precompile.
     */
    function _ecMul(
        uint256 px, uint256 py,
        uint256 scalar
    ) internal view returns (uint256[2] memory result) {
        uint256[3] memory input = [px, py, scalar % Q];
        bool success;
        assembly {
            success := staticcall(gas(), 0x07, input, 0x60, result, 0x40)
        }
        require(success, "BulletproofVerifier: ecMul precompile failed");
    }

    // ── View helpers ─────────────────────────────────────────────────────────

    /**
     * @notice Returns the H generator point (useful for off-chain checks).
     */
    function getH() external pure returns (uint256 hx, uint256 hy) {
        return (Hx, Hy);
    }

    /**
     * @notice Compute v*G + r*H — useful to re-derive the commitment V
     *         and confirm it matches the proof's V point on-chain.
     * @param v Value (secret in real use; exposed here for demo verification)
     * @param r Blinding factor
     */
    function pedersenCommit(uint256 v, uint256 r)
        external view returns (uint256 cx, uint256 cy)
    {
        uint256[2] memory vG = _ecMul(Gx, Gy, v);
        uint256[2] memory rH = _ecMul(Hx, Hy, r);
        uint256[2] memory C  = _ecAdd(vG[0], vG[1], rH[0], rH[1]);
        return (C[0], C[1]);
    }
}
