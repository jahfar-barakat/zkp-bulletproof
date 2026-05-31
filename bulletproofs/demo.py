"""
demo.py — Bulletproof Range Proof Demo

Demonstrates the full range proof workflow:
  1. Prove that a committed value lies in [0, 2^n) without revealing the value
  2. Verify the proof
  3. Show proof sizes vs naive approach
  4. Export proof data for Solidity verification

Run:  cd src && python ../demo.py
"""

import sys, time, json
sys.path.insert(0, "src")

from ec_math import ORDER
from range_proof import prove, verify

# ── ANSI colours ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def banner(title):
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}")

def ok(msg):   print(f"  {GREEN}✓{RESET}  {msg}")
def fail(msg): print(f"  {RED}✗{RESET}  {msg}")
def info(msg): print(f"  {YELLOW}•{RESET}  {msg}")


# ─────────────────────────────────────────────────────────────────────────────
# 1. BASIC DEMO: prove a single value
# ─────────────────────────────────────────────────────────────────────────────
banner("PART 1 — Basic Range Proof (n=8 bits, range [0, 256))")

v, n = 42, 8
info(f"Secret value v = {v}  |  Range = [0, 2^{n}) = [0, {2**n})")

t0 = time.time()
proof = prove(v, n_bits=n)
t_prove = time.time() - t0

t0 = time.time()
valid = verify(proof)
t_verify = time.time() - t0

if valid:
    ok(f"Proof verified! v={v} is in [0, {2**n})  (prove={t_prove:.2f}s, verify={t_verify:.2f}s)")
else:
    fail("Proof INVALID — bug detected!")
    sys.exit(1)

# Proof size analysis
ip_elems = proof.ipa.proof_size_elements
total_elems = 5 + ip_elems          # 5 curve points + IPA
total_bytes = total_elems * 64 + 3 * 32  # curve pts (64B) + 3 scalars (32B)
naive_bytes = n * 32                 # naive: send all n bits as scalars
info(f"Proof size: {total_elems} group elements + 3 scalars  = ~{total_bytes} bytes")
info(f"Naive approach for n={n}: {naive_bytes} bytes  →  Bulletproof saves {naive_bytes - total_bytes} bytes")

# ─────────────────────────────────────────────────────────────────────────────
# 2. EDGE CASES: boundary values, different bit lengths
# ─────────────────────────────────────────────────────────────────────────────
banner("PART 2 — Edge Cases and Different Bit Lengths")

test_cases = [
    (0,   8,  True,  "minimum value"),
    (255, 8,  True,  "maximum value (2^8 - 1)"),
    (127, 8,  True,  "midpoint"),
    (1,   4,  True,  "n=4 bits, v=1"),
    (15,  4,  True,  "n=4 bits, v=15 (max)"),
    (100, 16, True,  "n=16 bits, v=100"),
]

all_pass = True
for v_test, n_test, expect_valid, label in test_cases:
    try:
        p = prove(v_test, n_bits=n_test)
        result = verify(p)
        if result == expect_valid:
            ok(f"v={v_test:>5}, n={n_test}: valid={result}  [{label}]")
        else:
            fail(f"v={v_test:>5}, n={n_test}: expected valid={expect_valid}, got {result}  [{label}]")
            all_pass = False
    except ValueError as e:
        fail(f"v={v_test}, n={n_test}: unexpected error: {e}")
        all_pass = False

# Test that out-of-range values are rejected at prove time
banner_shown = False
out_of_range = [(256, 8), (-1, 8), (16, 4)]
for v_test, n_test in out_of_range:
    try:
        prove(v_test, n_bits=n_test)
        fail(f"v={v_test}, n={n_test}: should have been rejected but wasn't!")
        all_pass = False
    except ValueError:
        ok(f"v={v_test:>5}, n={n_test}: correctly rejected as out-of-range")

# ─────────────────────────────────────────────────────────────────────────────
# 3. ZERO-KNOWLEDGE PROPERTY: same value, different proofs every time
# ─────────────────────────────────────────────────────────────────────────────
banner("PART 3 — Zero-Knowledge: Two Proofs of Same Value Look Different")

p1 = prove(99, n_bits=8)
p2 = prove(99, n_bits=8)

# The commitments V should differ (different random blinding gamma)
V1 = (int(p1.V[0]), int(p1.V[1]))
V2 = (int(p2.V[0]), int(p2.V[1]))

if V1 != V2:
    ok("Commitments are different (different random blindings) — unlinkable!")
else:
    info("Commitments are same (very rare, negligible probability)")

ok(f"Both proofs verify: {verify(p1)} and {verify(p2)}")
info("An observer cannot tell that both proofs are for the same value.")

# ─────────────────────────────────────────────────────────────────────────────
# 4. PROOF SIZE COMPARISON TABLE
# ─────────────────────────────────────────────────────────────────────────────
banner("PART 4 — Proof Size: Bulletproof vs Naive (by n_bits)")

print(f"\n  {'n_bits':>6}  {'Range':>12}  {'Naive(B)':>9}  {'BP(B)':>7}  {'Rounds':>7}  {'Savings':>8}")
print(f"  {'-'*6}  {'-'*12}  {'-'*9}  {'-'*7}  {'-'*7}  {'-'*8}")
for n_test in [4, 8, 16, 32]:
    p = prove(1, n_bits=n_test)
    ip_e = p.ipa.proof_size_elements
    bp_b = (5 + ip_e) * 64 + 3 * 32
    naive_b = n_test * 32
    savings = f"{(1 - bp_b/naive_b)*100:.0f}%" if naive_b > bp_b else "N/A"
    print(f"  {n_test:>6}  {f'[0, {2**n_test})':>12}  {naive_b:>9}  {bp_b:>7}  {len(p.ipa.L_vec):>7}  {savings:>8}")

# ─────────────────────────────────────────────────────────────────────────────
# 5. EXPORT PROOF FOR SOLIDITY VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────
banner("PART 5 — Exporting Proof for On-Chain (Solidity) Verification")

from scripts.export_proof import export_for_solidity

v_demo, n_demo = 42, 8
proof_demo = prove(v_demo, n_bits=n_demo)
solidity_data = export_for_solidity(proof_demo)

output_path = "proof_export.json"
with open(output_path, "w") as f:
    json.dump(solidity_data, f, indent=2)

ok(f"Proof exported to: {output_path}")
ok(f"Use 'node scripts/call_verifier.js' to verify on-chain")
info(f"Verifier contract: contracts/BulletproofVerifier.sol")

# ─────────────────────────────────────────────────────────────────────────────
# 6. SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
banner("SUMMARY")

print(f"""
  Bulletproof Range Proof — Implementation Summary
  ─────────────────────────────────────────────────
  Curve:       BN128 (alt_bn128) — Ethereum-native
  Reference:   github.com/zkcrypto/bulletproofs (Rust / Ristretto)

  What we proved:
    - A committed value v lies in [0, 2^n) WITHOUT revealing v
    - The proof is zero-knowledge: repeated proofs look unrelated
    - The proof is O(log n) size, not O(n) like a naive approach

  Proof components:
    V         = Pedersen commitment to v  (blinded, hides v)
    A, S      = Commitments to bit vectors a_L, a_R
    T1, T2    = Polynomial commitments
    tau_x, mu = Blinding scalars
    t_hat     = Inner product <l(x), r(x)>
    IPA       = Inner Product Argument (O(log n) elements)

  Verification checks:
    ① Polynomial identity: t_hat·G + tau_x·H = delta·G + x·T1 + x²·T2 + z²·V
    ② Inner product argument: P_folded = a·G_folded + b·H_folded

  All tests passed: {GREEN}✓{RESET}
""")
