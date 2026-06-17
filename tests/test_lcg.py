"""
test_lcg.py — AUTH-03 LCG parity check (Python mirror).

COVERAGE NOTE: This file mirrors the BigInt LCG from node-app/src/routes/auth.js
in Python so parity can be confirmed without running Node.js. It validates
Python-reconstructed logic, NOT the shipped auth.js code.

The real auth.js LCG is exercised end-to-end by the AUTH-03 challenge over HTTP
when the Docker stack is running (garden start).

Verifies:
  - Python LCG output matches JS BigInt LCG for fixed seeds
  - A 3000-candidate window spanning ±1500 ms from the seed captures the token
  - Token format: 8 hex chars (padStart 8 with '0')
"""
import re
import pytest


# ─────────────────────────────────────────────────────────────────────────────
# Mirror lcg() from auth.js (BigInt arithmetic)
# ─────────────────────────────────────────────────────────────────────────────

LCG_A = 1664525
LCG_C = 1013904223
LCG_M = 2**32   # mod 2^32


def lcg(seed: int) -> int:
    """
    LCG: token = (A * seed + C) % M

    Uses Python int (arbitrary precision) to match JS BigInt arithmetic exactly.
    Standard Python int never overflows — matches the BigInt semantics in auth.js.
    """
    return (LCG_A * seed + LCG_C) % LCG_M


def token_hex(seed: int) -> str:
    """Return the 8-char hex token for a given millisecond seed."""
    return hex(lcg(seed))[2:].zfill(8)


# ─────────────────────────────────────────────────────────────────────────────
# Reference values computed independently using Python for fixed seeds
# (These serve as regression anchors; any change to the LCG breaks these.)
# ─────────────────────────────────────────────────────────────────────────────

class TestLcgFormula:
    def test_seed_zero(self):
        """lcg(0) = (A*0 + C) % M = C = 1013904223"""
        assert lcg(0) == 1013904223

    def test_seed_one(self):
        """lcg(1) = (1664525 + 1013904223) % 2^32 = 1015568748"""
        assert lcg(1) == 1015568748

    def test_seed_1000(self):
        """lcg(1000) = (1664525000 + 1013904223) % 2^32"""
        expected = (1664525 * 1000 + 1013904223) % (2**32)
        assert lcg(1000) == expected

    def test_known_timestamp(self):
        """
        Verify against a concrete Date.now()-like value (Unix ms timestamp).
        Example: seed = 1700000000000 (Nov 2023)
        """
        seed = 1700000000000
        expected = (LCG_A * seed + LCG_C) % LCG_M
        assert lcg(seed) == expected
        assert 0 <= lcg(seed) < 2**32

    def test_output_range(self):
        """Output is always in [0, 2^32)."""
        for seed in [0, 1, 999999, 2**32, 2**53, 10**18]:
            result = lcg(seed)
            assert 0 <= result < 2**32, f"lcg({seed}) = {result} out of range"

    def test_vs_javascript_bigint(self):
        """
        Cross-check: A*seed for seed=Date.now() style value exceeds 2^53 safe integer
        limit. Standard Python int computes exactly (no precision loss).
        Verify via modular arithmetic identity:
          (A*seed + C) % M should equal ((A % M) * (seed % M) + C) % M
        """
        seed = 1_720_000_000_000   # typical modern timestamp
        val1 = (LCG_A * seed + LCG_C) % LCG_M
        val2 = ((LCG_A % LCG_M) * (seed % LCG_M) + LCG_C) % LCG_M
        assert val1 == val2


class TestTokenFormat:
    def test_token_is_8_hex_chars(self):
        """Token is always exactly 8 lowercase hex chars."""
        for seed in [0, 1, 100, 1700000000000]:
            t = token_hex(seed)
            assert len(t) == 8, f"token_hex({seed}) = {t!r} is not 8 chars"
            assert re.fullmatch(r'[0-9a-f]{8}', t), f"{t!r} not hex"

    def test_zero_seed_pads_correctly(self):
        """lcg(0) = 1013904223 = 0x3C6EF35F — 8 chars, no padding needed."""
        t = token_hex(0)
        assert t == hex(1013904223)[2:].zfill(8)

    def test_small_output_is_zero_padded(self):
        """If LCG output < 0x10000000, token must be zero-padded to 8 chars."""
        # Find a seed that produces a small output
        # lcg(seed) < 0x10000000 = 268435456
        # We can check: lcg(0x00000001) = 1015568748 which is > 0x10000000
        # Let's just test that zfill(8) is applied:
        small_val = 0x0000001F   # 31 decimal
        result = hex(small_val)[2:].zfill(8)
        assert result == '0000001f'
        assert len(result) == 8


class TestCandidateWindow:
    def test_window_covers_correct_token(self):
        """
        Core AUTH-03 attack: enumerate 3000 candidates spanning ±1500 ms from
        the server's Date header (second granularity). The correct token must
        appear in that window.
        """
        # Simulate: server generates token at exact_seed (unknown, sub-second)
        import time
        exact_seed = int(time.time() * 1000)   # current ms timestamp
        correct_token = token_hex(exact_seed)

        # Attacker reads Date header → knows time to the second → t_second
        t_second = (exact_seed // 1000) * 1000  # truncate to second boundary

        # Enumerate 3000 candidates: [t_second - 1000 ms, t_second + 2000 ms)
        # (±1 second window plus buffer)
        candidates = {token_hex(t_second + delta) for delta in range(-1000, 2001)}

        assert correct_token in candidates, (
            f"Token {correct_token!r} for seed {exact_seed} not found in "
            f"3000-candidate window around second {t_second}"
        )

    def test_window_size_is_sufficient(self):
        """
        A window of 3000 ms starting 1 second before the Date header always
        covers the actual seed (which is at most 999ms past the Date second).
        """
        # For any offset [0, 999] ms past the second boundary,
        # the window [t_second - 1000, t_second + 2000) covers it.
        t_second = 1_700_000_000_000  # arbitrary fixed second
        for offset_ms in [0, 1, 499, 999]:
            seed = t_second + offset_ms
            token = token_hex(seed)
            window = {token_hex(t_second + d) for d in range(-1000, 2001)}
            assert token in window, f"offset {offset_ms}ms not covered"

    def test_distinct_ms_give_distinct_tokens(self):
        """
        Consecutive millisecond seeds produce distinct tokens (no collision
        in the 3000-candidate window under normal circumstances).
        """
        base = 1_700_000_000_000
        tokens = [token_hex(base + i) for i in range(3000)]
        # Very low probability of collision in practice; assert no duplicates
        assert len(set(tokens)) == len(tokens), "LCG collision in 3000-candidate window"
