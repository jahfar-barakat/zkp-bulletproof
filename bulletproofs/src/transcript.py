"""
transcript.py — Fiat-Shamir transcript (non-interactive challenge generation)

In an interactive proof, the verifier sends fresh random challenges after
each prover message. The Fiat-Shamir heuristic replaces this by computing
challenges as hash(everything_the_prover_has_sent_so_far).

Because the hash function is a random oracle, the challenges are
unpredictable before the prover commits — so the prover cannot "cheat"
by choosing commitments that work for a specific challenge.

Reference comparison (dalek):
  dalek uses the Merlin transcript crate, which is a STROBE-based
  duplex construction. We use plain SHA-256 with domain-separated
  labels — same concept, simpler implementation.

  dalek call:   transcript.append_message(b"V", V.compress().as_bytes())
                let y = transcript.challenge_scalar(b"y")

  Our call:     transcript.append_point(b"V", V)
                y = transcript.get_challenge(b"y")
"""

import hashlib
from ec_math import ORDER, point_to_bytes


class Transcript:
    """
    A running hash of the entire prover-verifier interaction.

    Usage pattern:
        t = Transcript(b"range_proof_v1")
        t.append_point(b"V", commitment_V)
        t.append_point(b"A", commitment_A)
        y = t.get_challenge(b"y")        # first challenge
        z = t.get_challenge(b"z")        # second challenge (different!)
        t.append_point(b"T1", T1)
        x = t.get_challenge(b"x")        # third challenge
    """

    def __init__(self, label: bytes = b"bulletproof_range_proof_v1"):
        self._state = hashlib.sha256(label).digest()
        self._round = 0

    def _absorb(self, tag: bytes, data: bytes):
        """
        Mix tag + data into the running state.
        Using len-prefixed encoding prevents collisions between
        "tag=b'A', data=b'BC'" and "tag=b'AB', data=b'C'".
        """
        h = hashlib.sha256()
        h.update(self._state)
        h.update(len(tag).to_bytes(2, "big"))
        h.update(tag)
        h.update(len(data).to_bytes(4, "big"))
        h.update(data)
        self._state = h.digest()

    def append_point(self, label: bytes, point):
        """Add a curve point to the transcript."""
        self._absorb(label, point_to_bytes(point))

    def append_scalar(self, label: bytes, scalar: int):
        """Add a scalar (integer) to the transcript."""
        self._absorb(label, (int(scalar) % ORDER).to_bytes(32, "big"))

    def append_bytes(self, label: bytes, data: bytes):
        """Add raw bytes to the transcript."""
        self._absorb(label, data)

    def get_challenge(self, label: bytes) -> int:
        """
        Squeeze a challenge scalar from the current transcript state.

        Each call produces a DIFFERENT challenge even with the same label,
        because the round counter is mixed in.
        """
        self._round += 1
        h = hashlib.sha256()
        h.update(self._state)
        h.update(label)
        h.update(self._round.to_bytes(4, "big"))
        result = int.from_bytes(h.digest(), "big") % ORDER
        # Non-zero challenge (negligible probability of zero)
        if result == 0:
            result = 1
        # Also absorb the challenge back into state (makes it a duplex)
        self._absorb(b"challenge_feedback", result.to_bytes(32, "big"))
        return result
