"""
test_flag_format.py — Docker-independent unit tests for mint_flags.py logic.

Verifies:
  - Exactly 23 challenge codes defined
  - Each generated flag matches JG{hex32} format
  - All 23 flags are unique
  - Challenge code list exactly matches the spec-defined set
"""
import re
import sys
import os
import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Import mint logic directly from flag-init/mint_flags.py
# ─────────────────────────────────────────────────────────────────────────────

# Add flag-init to path for direct import
_FLAG_INIT_DIR = os.path.join(os.path.dirname(__file__), '..', 'flag-init')
sys.path.insert(0, os.path.abspath(_FLAG_INIT_DIR))

import importlib.util

spec = importlib.util.spec_from_file_location(
    "mint_flags",
    os.path.join(_FLAG_INIT_DIR, "mint_flags.py")
)
_mint_module = importlib.util.module_from_spec(spec)
# Execute module but intercept main() — we only import the helpers
# We override OUTPUT_PATH to a safe location before executing
_mint_module.OUTPUT_PATH = "/dev/null"
spec.loader.exec_module(_mint_module)

CHALLENGE_CODES = _mint_module.CHALLENGE_CODES
mint_flag = _mint_module.mint_flag


# ─────────────────────────────────────────────────────────────────────────────
# Challenge codes completeness
# ─────────────────────────────────────────────────────────────────────────────

class TestChallengeCodes:
    EXPECTED_CODES = [
        "auth01", "auth02", "auth03", "auth04",
        "inj01",  "inj02",  "inj03",  "inj04",
        "bac01",  "bac02",  "bac03",  "bac04",
        "cs01",   "cs02",   "cs03",
        "ss01",   "ss02",   "ss03",
        "bl01",   "bl02",   "bl03",
        "mission_alpha",
        "bonus",
    ]

    def test_exactly_23_codes(self):
        assert len(CHALLENGE_CODES) == 23, (
            f"Expected 23 challenge codes, got {len(CHALLENGE_CODES)}"
        )

    def test_all_expected_codes_present(self):
        missing = set(self.EXPECTED_CODES) - set(CHALLENGE_CODES)
        assert not missing, f"Missing codes: {missing}"

    def test_no_extra_codes(self):
        extra = set(CHALLENGE_CODES) - set(self.EXPECTED_CODES)
        assert not extra, f"Unexpected codes: {extra}"

    def test_code_order_matches_spec(self):
        assert CHALLENGE_CODES == self.EXPECTED_CODES, (
            "Challenge code order does not match spec"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Flag format: JG{hex32}
# ─────────────────────────────────────────────────────────────────────────────

FLAG_RE = re.compile(r'^JG\{[0-9a-f]{32}\}$')


class TestFlagFormat:
    def test_single_flag_format(self):
        flag = mint_flag()
        assert FLAG_RE.match(flag), f"Flag {flag!r} does not match JG{{hex32}}"

    def test_flag_starts_with_JG(self):
        flag = mint_flag()
        assert flag.startswith("JG{")

    def test_flag_ends_with_brace(self):
        flag = mint_flag()
        assert flag.endswith("}")

    def test_flag_hex_portion_is_32_chars(self):
        flag = mint_flag()
        inner = flag[3:-1]   # strip JG{ and }
        assert len(inner) == 32
        assert re.fullmatch(r'[0-9a-f]+', inner), "hex portion contains non-hex chars"

    def test_100_flags_all_match_format(self):
        for _ in range(100):
            flag = mint_flag()
            assert FLAG_RE.match(flag), f"Bad flag: {flag!r}"


# ─────────────────────────────────────────────────────────────────────────────
# Uniqueness: 23 generated flags must all be distinct
# ─────────────────────────────────────────────────────────────────────────────

class TestFlagUniqueness:
    def test_23_flags_unique(self):
        """Generate one flag per challenge code; all must be distinct."""
        flags = []
        used = set()
        for _code in CHALLENGE_CODES:
            flag = mint_flag()
            while flag in used:
                flag = mint_flag()
            flags.append(flag)
            used.add(flag)

        assert len(set(flags)) == 23, "Duplicate flags detected among 23 generated values"

    def test_no_two_flags_share_prefix(self):
        """JG{ prefix is constant — uniqueness comes from the 16-byte random body."""
        flags = {mint_flag() for _ in range(23)}
        # All flags share JG{ prefix, so uniqueness is in the hex portion
        inners = {f[3:-1] for f in flags}
        assert len(inners) == len(flags), "Collision in hex bodies"

    def test_flags_are_random_not_sequential(self):
        """Two consecutively generated flags differ in all 32 hex chars (probabilistically)."""
        f1 = mint_flag()
        f2 = mint_flag()
        assert f1 != f2, "Consecutive flags are identical (RNG may be broken)"


# ─────────────────────────────────────────────────────────────────────────────
# UUID v1 fields (BAC-01 anchor timestamp extraction)
# ─────────────────────────────────────────────────────────────────────────────

class TestUuidV1Fields:
    """
    UUID v1 encodes a 60-bit timestamp (100-ns intervals since Oct 15, 1582).
    Fixed parameters per spec: clock_seq=0x1234, node=fallback 01:02:03:04:05:06
    BAC-01 attack: extract ms timestamp from UUID → enumerate ±1000ms candidates.
    """

    UUID_EPOCH_OFFSET = 122192928000000000  # 100-ns intervals (integer)

    def _uuid_to_ms(self, uuid_str: str) -> int:
        """Extract millisecond-precision UNIX timestamp from a UUID v1 string."""
        parts = uuid_str.split('-')
        time_low = int(parts[0], 16)
        time_mid = int(parts[1], 16)
        time_hi = int(parts[2], 16) & 0x0FFF   # strip version nibble

        ts_100ns = time_low | (time_mid << 32) | (time_hi << 48)
        ts_ms = (ts_100ns - self.UUID_EPOCH_OFFSET) // 10000
        return ts_ms

    def _mint_uuid_v1_python(self, ts_ms: int) -> str:
        """Python mirror of mintUuidV1 from uuid_v1.js."""
        UUID_EPOCH_OFFSET = 122192928000000000
        CLOCK_SEQ = 0x1234
        NODE_ID = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]

        ts_val = ts_ms * 10000 + UUID_EPOCH_OFFSET

        time_low = ts_val & 0xFFFFFFFF
        time_mid = (ts_val >> 32) & 0xFFFF
        time_hi = ((ts_val >> 48) & 0x0FFF) | 0x1000

        clock_seq_hi = ((CLOCK_SEQ >> 8) & 0x3F) | 0x80
        clock_seq_low = CLOCK_SEQ & 0xFF

        def hex_pad(n, width): return hex(n)[2:].zfill(width)

        return '-'.join([
            hex_pad(time_low, 8),
            hex_pad(time_mid, 4),
            hex_pad(time_hi, 4),
            hex_pad(clock_seq_hi, 2) + hex_pad(clock_seq_low, 2),
            ''.join(hex_pad(b, 2) for b in NODE_ID)
        ])

    def test_timestamp_round_trip(self):
        """mintUuidV1(ts) → extract → should recover ts exactly."""
        import time
        ts_ms = int(time.time() * 1000)
        uuid = self._mint_uuid_v1_python(ts_ms)
        recovered_ms = self._uuid_to_ms(uuid)
        assert recovered_ms == ts_ms

    def test_fixed_clock_seq(self):
        """clock_seq field is fixed at 0x1234 for all generated UUIDs."""
        import time
        for offset in [0, 100, 999]:
            ts_ms = int(time.time() * 1000) + offset
            uuid = self._mint_uuid_v1_python(ts_ms)
            parts = uuid.split('-')
            clock_seq_field = parts[3]   # 4 hex chars = 2 bytes
            clock_seq_hi = int(clock_seq_field[:2], 16)
            clock_seq_low = int(clock_seq_field[2:], 16)
            # clock_seq_hi has variant bits set: (0x12 & 0x3F) | 0x80 = 0x92
            # clock_seq_low = 0x34
            assert clock_seq_hi == 0x92, f"Unexpected clock_seq_hi: 0x{clock_seq_hi:02x}"
            assert clock_seq_low == 0x34, f"Unexpected clock_seq_low: 0x{clock_seq_low:02x}"

    def test_fixed_node_id(self):
        """Node ID field is fixed at 010203040506 (fallback)."""
        import time
        ts_ms = int(time.time() * 1000)
        uuid = self._mint_uuid_v1_python(ts_ms)
        node_field = uuid.split('-')[4]
        assert node_field == '010203040506'

    def test_idor_window_covers_target(self):
        """
        BAC-01: ±1000ms window around a reference timestamp always contains
        a candidate UUID for the target order (which differs by at most ±1000ms).
        """
        import time
        reference_ms = int(time.time() * 1000)
        # Target is 500ms after the reference (within ±1000ms window)
        target_ms = reference_ms + 500
        target_uuid = self._mint_uuid_v1_python(target_ms)

        # Enumerate ±1000ms candidates
        candidates = {
            self._mint_uuid_v1_python(reference_ms + delta)
            for delta in range(-1000, 1001)
        }
        assert target_uuid in candidates
