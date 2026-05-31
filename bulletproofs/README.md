# Bulletproof Range Proof

> **Project 19 — Blockchain Privacy Technologies**
> Proves that a committed value lies in `[0, 2^n)` **without revealing the value**.

---

## What This Project Does

A **range proof** lets a prover convince a verifier that a hidden value `v` satisfies `0 ≤ v < 2^n`, without disclosing `v`. This is essential in confidential transactions (e.g. Monero, Zcash) where amounts must be non-negative but are kept secret.

**Bulletproofs** (Bünz et al., 2018) achieve this with a proof size of **O(log n)** group elements — a major improvement over older O(n) approaches.

---

## Reference Implementation

**Library:** [`github.com/zkcrypto/bulletproofs`](https://github.com/zkcrypto/bulletproofs)
**Language:** Rust
**Curve:** Ristretto255 (Curve25519-based)

### Setup (Reference — Rust)

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Clone and run the reference demo
git clone https://github.com/zkcrypto/bulletproofs
cd bulletproofs
cargo test                      # run all tests
cargo bench                     # optional: benchmarks

# Create a quick demo (save as examples/range_demo.rs, run with cargo run --example range_demo)
```

**Key difference vs this implementation:**

| Feature       | Reference (zkcrypto)    | This Implementation         |
|---------------|-------------------------|-----------------------------|
| Language      | Rust                    | Python 3                    |
| Curve         | Ristretto255            | BN128 (Ethereum-native)     |
| Transcript    | Merlin (STROBE-based)   | SHA-256 duplex              |
| Aggregation   | Multi-range proof        | Single range proof           |
| On-chain      | Not included            | Solidity verifier included  |

---

## Project Structure

```
bulletproofs-range-proof/
│
├── src/                        # Python implementation
│   ├── ec_math.py              # BN128 elliptic curve primitives
│   ├── pedersen.py             # Pedersen commitments
│   ├── transcript.py           # Fiat-Shamir transcript (hash-based challenges)
│   ├── inner_product.py        # Inner Product Argument (O(log n))
│   └── range_proof.py          # Main range proof (prove + verify)
│
├── contracts/
│   └── BulletproofVerifier.sol # Solidity on-chain verifier (BN128 precompiles)
│
├── scripts/
│   ├── export_proof.py         # Export proof → JSON for Solidity
│   └── call_verifier.js        # Hardhat: deploy + call verifier on-chain
│
├── tests/
│   └── test_range_proof.py     # Full test suite (54 tests)
│
├── demo.py                     # End-to-end demonstration
├── requirements.txt            # Python dependencies
├── package.json                # Node.js dependencies (Hardhat)
├── hardhat.config.js           # Hardhat configuration
└── README.md
```

---

## Installation

### Python (required for everything)

```bash
# Requires Python 3.9+
python --version

# Install dependencies
pip install -r requirements.txt
```

### Node.js (required for Solidity / on-chain verification)

```bash
# Requires Node.js 18+
node --version

# Install Hardhat and dependencies
npm install
```

---

## Running the Python Implementation

### Full Demo

```bash
# From project root:
python demo.py
```

Expected output:
```
════════════════════════════════════════════════════════════
  PART 1 — Basic Range Proof (n=8 bits, range [0, 256))
════════════════════════════════════════════════════════════
  ✓  Proof verified! v=42 is in [0, 256)  (prove=1.4s, verify=1.3s)
  •  Proof size: 11 group elements + 3 scalars  = ~800 bytes
  •  Naive approach for n=8: 256 bytes  →  ...
...
```

### Quick Single-Value Test

```bash
cd src
python3 -c "
from range_proof import prove, verify
proof = prove(42, n_bits=8)
print('Valid:', verify(proof))
print(proof.summary())
"
```

### Run All Tests

```bash
# Using pytest:
cd bulletproofs-range-proof
pytest tests/ -v

# Without pytest:
python tests/test_range_proof.py
```

---

## On-Chain Verification (Solidity)

The Solidity contract `BulletproofVerifier.sol` uses Ethereum's **BN128 precompiles**:
- `ecAdd` at address `0x06` (EIP-196)
- `ecMul` at address `0x07` (EIP-196)

### Step 1 — Generate and export a proof

```bash
# Prove that v=42 is in [0, 256), export to proof_export.json
python scripts/export_proof.py 42 8

# Or try different values:
python scripts/export_proof.py 100 8
python scripts/export_proof.py 1000 16
```

### Step 2 — Compile the Solidity contract

```bash
npx hardhat compile
```

### Step 3 — Start a local Hardhat node (in a separate terminal)

```bash
npx hardhat node
```

### Step 4 — Deploy and verify on-chain

```bash
npx hardhat run scripts/call_verifier.js --network hardhat
```

Expected output:
```
Loaded proof: v in [0, 256), n_bits=8
Deploying from: 0xf39Fd6...
BulletproofVerifier deployed at: 0x5FbDB2...

Calling verifyView()...

══════════════════════════════════════════════════
  On-chain verification result: ✓ VALID
  Proof range: [0, 256)
  n_bits: 8
══════════════════════════════════════════════════

Event ProofVerified:
  prover: 0xf39Fd6...
  valid:  true
  n_bits: 8

Gas used for verify(): 234502
```

---

## High-Level Protocol Overview

```
                    PROVER                               VERIFIER
                    ──────                               ────────
Secret: v ∈ [0,2ⁿ)
                    a_L = bits(v)
                    a_R = a_L − 1
                    A = <a_L,G> + <a_R,H> + α·H
                    S = <s_L,G> + <s_R,H> + ρ·H
                                        ─── A, S ───►
                                                     y,z ← hash(V,A,S)
                                        ◄── y, z ───
                    T₁, T₂ ← polynomial commitments
                                        ─── T₁,T₂ ──►
                                                     x ← hash(T₁,T₂)
                                        ◄── x ──────
                    l(x), r(x) ← evaluate vectors
                    t̂ = ⟨l,r⟩
                    τₓ, μ ← blinding scalars
                    IPA ← inner_product_prove(l,r)
                                        ─── τₓ,μ,t̂,IPA ──►
                                                     ① Check: t̂·G + τₓ·H = δ·G + x·T₁ + x²·T₂ + z²·V
                                                     ② Check: a·G_final + b·H_final = P_final
                                                     → ACCEPT if both pass
```

---

## Cryptographic Details

### Curve: BN128 (alt_bn128)
- Same curve used by Ethereum's `ecAdd`, `ecMul`, `ecPairing` precompiles
- Field modulus: `21888242871839275222246405745257275088696311157297823662689037894645226208583`
- Curve order: `21888242871839275222246405745257275088548364400416034343698204186575808495617`

### Pedersen Commitment
`C = v·G + r·H` where `H` is a hash-derived generator (nobody knows `log_G(H)`)

### Why BN128 instead of Ristretto?
Ethereum natively supports BN128 via precompiles → proofs can be verified on-chain cheaply.

### Security Assumptions
- Discrete Logarithm Problem (DLP) on BN128 is hard
- SHA-256 behaves as a random oracle (for Fiat-Shamir)
- The generators G, H, G_vec, H_vec are independent (no known discrete log relations)

---

## Sample Inputs/Outputs

```python
from src.range_proof import prove, verify

# Valid values
prove(0,   n_bits=8)   # ✓ minimum
prove(42,  n_bits=8)   # ✓ arbitrary valid value
prove(255, n_bits=8)   # ✓ maximum for n=8

# Rejected values (ValueError)
prove(256, n_bits=8)   # ✗ out of range
prove(-1,  n_bits=8)   # ✗ negative
prove(42,  n_bits=5)   # ✗ n_bits must be power of 2
```

Proof structure (n=8):
```
RangeProof(n=8 bits, range=[0,256), IPA rounds=3, total elements=5+8=13)
  V      = Pedersen commitment to v                    [1 point]
  A,S    = Bit vector commitments                      [2 points]
  T₁,T₂  = Polynomial commitments                     [2 points]
  IPA    = 3 rounds × (L,R) + (a,b)                   [6 points + 2 scalars]
  τₓ,μ,t̂ = Scalars                                   [3 scalars]
```

---

## Comparison: Reference vs This Implementation

For the same value `v=42, n=8`:

| Check                    | Reference (zkcrypto/Rust) | This Implementation (Python) |
|--------------------------|---------------------------|------------------------------|
| `verify(prove(42, 8))`   | `true`                    | `True`                       |
| `verify(prove(0, 8))`    | `true`                    | `True`                       |
| `verify(prove(255, 8))`  | `true`                    | `True`                       |
| `prove(256, 8)` → error  | `RangeProofError`         | `ValueError`                 |
| Proof size (n=8)         | ~675 bytes                | ~800 bytes                   |
| Proof size (n=32)        | ~1000 bytes               | ~1120 bytes                  |

Both correctly prove/reject the same values. Size difference is due to Ristretto (compressed 32B) vs BN128 (64B) points.

---

## Presentation Checklist

- [ ] Run `python demo.py` — shows all 5 parts including edge cases
- [ ] Run `python tests/test_range_proof.py` — shows 54/54 tests pass
- [ ] Run `python scripts/export_proof.py 42 8` — exports proof
- [ ] Run `npx hardhat run scripts/call_verifier.js --network hardhat` — on-chain verification
- [ ] Explain: what is a range proof and why it matters for privacy
- [ ] Explain: how Bulletproofs improve on naive proofs (O(log n) vs O(n))
- [ ] Explain: Fiat-Shamir transform (interactive → non-interactive)
- [ ] Compare with zkcrypto reference: same correctness, different curve

---

## References

- Bünz, B. et al. (2018). *Bulletproofs: Short Proofs for Confidential Transactions and More*. IEEE S&P 2018. [PDF](https://eprint.iacr.org/2017/1066.pdf)
- zkcrypto/bulletproofs (Rust reference): https://github.com/zkcrypto/bulletproofs
- EIP-196 (BN128 precompiles): https://eips.ethereum.org/EIPS/eip-196
- Pedersen, T.P. (1991). *Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing*. CRYPTO 1991.
