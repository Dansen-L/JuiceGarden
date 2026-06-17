/**
 * Custom UUID v1 generator for Garden Fresh.
 *
 * Spec requirements:
 * - fixed clock_seq = 0x1234
 * - fixed node = container MAC address (fallback: 0x010203040506)
 * - nsecs pinned to 0
 * - Serialized minting: >=1ms monotonic advance between consecutive calls
 * - Accepts optional explicit timestamp (for seeder use)
 *
 * The serialization guarantee (atomic counter on timestamp only) prevents
 * PK collisions under concurrent load (BL-02 race, seeder ~28 rows).
 * The lock DOES NOT span the coupon check-to-decrement path (BL-02 race
 * window must remain open).
 */
'use strict';

const os = require('os');

// Fixed parameters per spec
const CLOCK_SEQ = 0x1234;

// Get container MAC address
function getNodeId() {
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    for (const addr of iface) {
      if (!addr.internal && addr.mac && addr.mac !== '00:00:00:00:00:00') {
        return addr.mac.split(':').map(h => parseInt(h, 16));
      }
    }
  }
  // Fallback fixed node ID
  return [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
}

const NODE_ID = getNodeId();

// Atomic timestamp state — only the timestamp field is locked
let lastTimestamp = 0;
let _lock = false;

function mintTimestamp(explicitTs) {
  if (explicitTs !== undefined) {
    // Seeder path: use provided timestamp directly (no monotonic enforcement)
    return explicitTs;
  }

  // Runtime path: enforce >=1ms monotonic advance
  // Simple spin-wait for atomicity (Node.js is single-threaded; this is a no-op
  // under normal conditions since multiple calls in a tight loop are rare.
  // For BL-02 concurrent orders, each arrives in its own event loop tick.)
  let ts = Date.now();
  if (ts <= lastTimestamp) {
    ts = lastTimestamp + 1;
  }
  lastTimestamp = ts;
  return ts;
}

/**
 * Generate a UUID v1.
 *
 * @param {number} [explicitTimestamp] - Optional explicit timestamp in ms since epoch.
 *   Used by the seeder to embed historical created_at values. If omitted, uses Date.now()
 *   with monotonic advance guarantee.
 * @returns {string} UUID v1 string (lowercase, hyphenated)
 */
function mintUuidV1(explicitTimestamp) {
  // UUID v1 timestamp is in 100-nanosecond intervals since Oct 15, 1582
  const UUID_EPOCH_OFFSET = 122192928000000000n;  // BigInt

  const tsMs = mintTimestamp(explicitTimestamp);
  // Convert ms to 100-ns intervals; nsecs pinned to 0
  const tsVal = BigInt(tsMs) * 10000n + UUID_EPOCH_OFFSET;

  // Split timestamp into time_low, time_mid, time_hi_and_version
  const time_low = Number(tsVal & 0xFFFFFFFFn);
  const time_mid = Number((tsVal >> 32n) & 0xFFFFn);
  const time_hi = Number((tsVal >> 48n) & 0x0FFFn) | 0x1000;  // version 1

  // clock_seq
  const clock_seq_hi = ((CLOCK_SEQ >> 8) & 0x3F) | 0x80;  // variant bits
  const clock_seq_low = CLOCK_SEQ & 0xFF;

  // Format as UUID string
  const hex = (n, len) => n.toString(16).padStart(len, '0');

  return [
    hex(time_low, 8),
    hex(time_mid, 4),
    hex(time_hi, 4),
    hex(clock_seq_hi, 2) + hex(clock_seq_low, 2),
    NODE_ID.map(b => hex(b, 2)).join('')
  ].join('-');
}

module.exports = { mintUuidV1 };
