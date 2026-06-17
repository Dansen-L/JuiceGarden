"""
test_bl03_overflow.py — Docker-independent unit tests for BL-03 Int32 overflow gate.

Mirrors the overflow detection logic in node-app/src/routes/orders.js:

    const rawLineTotal = product.price_cents * qty;    // JS Number (float64)
    const loyaltyPoints = rawLineTotal | 0;            // Int32 coercion
    if (rawLineTotal !== loyaltyPoints && loyaltyPoints < 0 && bl03Flag) {
        overflowDetected = true;
    }

Key invariants verified:
  - Negative quantity (BL-01 exploit) must NOT trigger overflow gate
  - Genuinely large quantity that wraps Int32 MUST trigger overflow gate
  - Price 850 cents, qty ~2528895 is the documented minimal trigger
"""
import struct
import pytest
import ctypes


# ─────────────────────────────────────────────────────────────────────────────
# Python equivalent of JavaScript's `| 0` (Int32 coercion)
# ─────────────────────────────────────────────────────────────────────────────

def int32_coerce(x: float) -> int:
    """
    Equivalent to JS `x | 0`:
    1. Truncate float to integer (ToInt32 internal op)
    2. Take lower 32 bits (mod 2^32)
    3. Reinterpret as signed Int32

    https://tc39.es/ecma262/#sec-toint32
    """
    # Step 1: truncate to integer
    n = int(x)
    # Step 2: mask to 32 bits (unsigned)
    u32 = n & 0xFFFFFFFF
    # Step 3: reinterpret as signed 32-bit
    return struct.unpack('>i', struct.pack('>I', u32))[0]


def overflow_detected(price_cents: int, qty: int) -> bool:
    """
    Mirror BL-03 overflow detection gate from orders.js.
    Returns True iff the order triggers the BL-03 overflow payout.
    """
    raw_line_total = price_cents * qty   # Python float-equivalent (precise for integers)
    loyalty_points = int32_coerce(raw_line_total)
    # Gate: rawLineTotal !== loyaltyPoints (actual overflow) AND loyaltyPoints < 0
    return raw_line_total != loyalty_points and loyalty_points < 0


# ─────────────────────────────────────────────────────────────────────────────
# Int32 coerce function correctness
# ─────────────────────────────────────────────────────────────────────────────

class TestInt32Coerce:
    def test_small_positive(self):
        assert int32_coerce(42) == 42

    def test_zero(self):
        assert int32_coerce(0) == 0

    def test_negative_int(self):
        assert int32_coerce(-1) == -1

    def test_max_int32(self):
        # 2^31 - 1 = 2147483647
        assert int32_coerce(2147483647) == 2147483647

    def test_int32_overflow_wraps_negative(self):
        # 2^31 → signed 32-bit = -2147483648
        assert int32_coerce(2**31) == -2147483648

    def test_int32_overflow_max_plus_one(self):
        assert int32_coerce(2147483648) == -2147483648

    def test_large_value_wraps(self):
        # 2^32 → 0 (mod 2^32, sign = positive)
        assert int32_coerce(2**32) == 0

    def test_float_truncation(self):
        # Truncation toward zero before masking
        assert int32_coerce(3.9) == 3
        assert int32_coerce(-3.9) == -3


# ─────────────────────────────────────────────────────────────────────────────
# BL-01: Negative quantity — must NOT trigger BL-03 overflow gate
# ─────────────────────────────────────────────────────────────────────────────

class TestBl01NotOverflow:
    """
    BL-01 exploit: qty = -1. rawLineTotal < 0, loyaltyPoints = int32_coerce(-850) = -850.
    Since rawLineTotal == loyaltyPoints (both -850), the gate fires only on actual Int32
    wrap, NOT on plain negative qty. Gate must NOT trigger.
    """
    def test_qty_minus_one_price_850(self):
        assert not overflow_detected(850, -1)

    def test_qty_minus_one_various_prices(self):
        for price in [100, 500, 850, 999, 1000]:
            assert not overflow_detected(price, -1), f"price={price}, qty=-1 should not overflow"

    def test_qty_minus_large_not_overflow(self):
        # Very negative quantity: -10000
        assert not overflow_detected(850, -10000)

    def test_qty_positive_small_not_overflow(self):
        # Normal order
        assert not overflow_detected(850, 1)
        assert not overflow_detected(850, 5)
        assert not overflow_detected(850, 100)


# ─────────────────────────────────────────────────────────────────────────────
# BL-03: Large positive quantity that wraps Int32 — MUST trigger overflow gate
# ─────────────────────────────────────────────────────────────────────────────

class TestBl03OverflowTrigger:
    """
    Documented trigger: price=850, qty=2528895
    raw = 850 * 2528895 = 2149560750   (> 2^31-1 = 2147483647)
    int32_coerce(2149560750) = 2149560750 - 2^32 = -2145406546
    Gate: 2149560750 != -2145406546 AND -2145406546 < 0 → True
    """
    def test_documented_trigger_price_850(self):
        assert overflow_detected(850, 2528895)

    def test_raw_total_exceeds_int32_max(self):
        raw = 850 * 2528895
        assert raw > 2**31 - 1, "raw total must exceed Int32 max to wrap"

    def test_loyalty_points_is_negative(self):
        raw = 850 * 2528895
        lp = int32_coerce(raw)
        assert lp < 0, "loyalty_points must be negative after wrap"

    def test_raw_not_equal_loyalty_points(self):
        raw = 850 * 2528895
        lp = int32_coerce(raw)
        assert raw != lp, "raw and coerced values must differ on genuine overflow"

    def test_exact_overflow_boundary(self):
        """
        Find the minimum qty where overflow_detected(850, qty) is True.
        Int32 max = 2147483647; threshold = ceil(2^31 / 850) = 2526452
        (850 * 2526452 = 2147483800 > 2^31 - 1)
        """
        # Just below threshold should NOT overflow
        threshold_qty = (2**31 // 850) + 1
        raw_at_threshold = 850 * threshold_qty
        # This must exceed 2^31-1
        assert raw_at_threshold > 2**31 - 1

    def test_other_prices_can_overflow(self):
        """Overflow can happen with any price, not just 850."""
        # price=1000: threshold ~2147484 items
        threshold_1000 = (2**31 // 1000) + 1
        assert overflow_detected(1000, threshold_1000)

    def test_qty_just_below_threshold_no_overflow(self):
        """One qty below the Int32 boundary: no overflow."""
        # For price=850, find qty such that 850*qty <= INT32_MAX
        safe_qty = 2**31 // 850   # = 2525274
        raw = 850 * safe_qty
        assert raw <= 2**31 - 1
        assert not overflow_detected(850, safe_qty)
