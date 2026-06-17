/**
 * Order routes
 * BL-01: Negative quantity (server has no sign check)
 * BL-02: Coupon race condition
 * BL-03: Loyalty points integer overflow
 * BAC-01: IDOR receipt (no ownership check)
 * INJ-02: SQL injection via JSON body (order-search)
 * BAC-04: Path traversal via double URL encoding (file download)
 */
'use strict';

const express = require('express');
const { Order, Coupon, Product, User, AuditLog, sequelize, QueryTypes } = require('../models');
const { requireAuth } = require('../middleware/auth');
const { mintUuidV1 } = require('../utils/uuid_v1');
const { getFlag } = require('../utils/flags');
const path = require('path');
const fs = require('fs');

const router = express.Router();

// ──────────────────────────────────────────────
// GET /api/orders/recent (unauthenticated)
// BAC-01 timestamp anchor — only status=delivered orders
// Returns: order_id, created_at truncated to second
// ──────────────────────────────────────────────
router.get('/recent', async (req, res) => {
  try {
    const orders = await Order.findAll({
      where: { status: 'delivered' },
      order: [['created_at', 'DESC']],
      limit: 10,
      attributes: ['id', 'created_at']
    });

    res.json(orders.map(o => ({
      id: o.id,
      // BAC-01: truncate to second (reveals timestamp, hides sub-second precision)
      created_at: new Date(Math.floor(new Date(o.created_at).getTime() / 1000) * 1000).toISOString()
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch recent orders' });
  }
});

// ──────────────────────────────────────────────
// POST /api/orders
// BL-01: No server-side sign check on quantity
// BL-02: Coupon uses_remaining decremented AFTER order recorded (race window)
// BL-03: (unit_price * qty) | 0 bitwise Int32 coercion (overflow)
// ──────────────────────────────────────────────
router.post('/', requireAuth, async (req, res) => {
  try {
    const { items, coupon_code } = req.body;
    if (!items || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'items array required' });
    }

    // Calculate total — BL-01/BL-03 vulnerability: no sign check on quantity
    let totalCents = 0;
    let loyaltyDelta = 0;
    let overflowDetected = false;
    const bl03Flag = getFlag('bl03');

    const processedItems = [];
    for (const item of items) {
      const product = await Product.findByPk(item.product_id);
      if (!product) return res.status(404).json({ error: `Product ${item.product_id} not found` });

      const qty = item.quantity;  // BL-01: integer, no sign validation on server
      const lineTotal = product.price_cents * qty;  // BL-01: can be negative

      // BL-03: bitwise Int32 coercion — DELIBERATE VULNERABILITY
      // rawLineTotal is the JS float product; loyaltyPoints truncates to Int32.
      // Overflow is detected only when the truncated value differs from the float
      // result AND is negative — i.e. a genuine wraparound, not a negative quantity.
      const rawLineTotal = product.price_cents * qty;
      const loyaltyPoints = rawLineTotal | 0;  // Int32 coercion
      if (rawLineTotal !== loyaltyPoints && loyaltyPoints < 0 && bl03Flag) {
        overflowDetected = true;
      }

      totalCents += lineTotal;
      loyaltyDelta += loyaltyPoints;
      processedItems.push({ ...item, price_cents: product.price_cents });
    }

    // Handle coupon — BL-02: uses_remaining read BEFORE decrement (race window open)
    let couponDiscount = 0;
    let appliedCoupon = null;
    let bl02Flag = null;
    let isSecondApplication = false;

    if (coupon_code) {
      const coupon = await Coupon.findOne({ where: { code: coupon_code } });
      if (coupon && coupon.uses_remaining > 0) {
        // BL-02: multiple concurrent requests all see uses_remaining > 0 here
        // decrement happens AFTER order is recorded (race window)
        if (coupon.discount_type === 'percent') {
          couponDiscount = Math.floor(totalCents * coupon.discount_value / 100);
        } else {
          couponDiscount = coupon.discount_value;
        }
        appliedCoupon = coupon;
      }
    }

    const finalTotal = totalCents - couponDiscount;

    // BL-03: coerce the stored total to a signed 32-bit integer before
    // persisting. The raw JS float can exceed INT32_MAX and cause a
    // Postgres INTEGER overflow error. Applying | 0 wraps the value to the
    // INT32 range (negative when overflowed), which is what the spec intends:
    // the negative wrapped value fits in the INTEGER column and is the flag trigger.
    const storedTotal = finalTotal | 0;

    // Create order (UUID minter lock does NOT span coupon check path)
    const orderId = mintUuidV1();
    const order = await Order.create({
      id: orderId,
      user_id: req.user.id,
      status: 'confirmed',
      items_json: processedItems,
      total_price_cents: storedTotal,
      coupon_code: coupon_code || null,
      coupon_discount: couponDiscount,
      created_at: new Date(),
      updated_at: new Date()
    });

    // BL-01: negative total → debug_flag
    const bl01Flag = getFlag('bl01');
    const responseData = {
      id: order.id,
      status: order.status,
      total_price_cents: storedTotal,
      items: processedItems
    };

    // BL-01 checks finalTotal (pre-coercion): negative quantity gives a genuinely
    // negative total; overflow wraps positive-to-negative but finalTotal remains positive.
    if (finalTotal < 0 && bl01Flag) {
      responseData.debug_flag = bl01Flag;
    }

    // BL-03: overflow payout
    if (overflowDetected) {
      // BL-03: negative loyalty balance treated as large credit
      // payout logic checks loyaltyDelta != 0 (not > 0)
      if (loyaltyDelta !== 0) {
        await User.increment({ loyalty_points: loyaltyDelta }, { where: { id: req.user.id } });
        responseData.loyalty_payout = {
          delta: loyaltyDelta,
          message: 'Loyalty points applied',
          flag: bl03Flag
        };
      }
    } else if (loyaltyDelta > 0) {
      await User.increment({ loyalty_points: loyaltyDelta }, { where: { id: req.user.id } });
    }

    // BL-02: decrement uses_remaining AFTER order (race window)
    if (appliedCoupon) {
      // Check if this coupon was already used successfully before (BL-02 trigger)
      const currentCoupon = await Coupon.findOne({ where: { code: coupon_code } });
      if (currentCoupon && currentCoupon.uses_remaining < appliedCoupon.uses_remaining) {
        // Race condition: another request already decremented — this is the 2nd+ application
        bl02Flag = getFlag('bl02');
        isSecondApplication = true;
      }

      // Decrement (may go below 0 under race conditions)
      await Coupon.decrement('uses_remaining', { where: { id: appliedCoupon.id } });
    }

    if (isSecondApplication && bl02Flag) {
      res.set('X-Flag', bl02Flag);
    }

    // Audit log: record order placement
    AuditLog.create({
      actor_id: req.user.id,
      action: 'order.created',
      target_type: 'order',
      target_id: order.id,
      details_json: { total_price_cents: storedTotal, item_count: processedItems.length },
      ip_address: req.headers['x-real-ip'] || req.ip,
      timestamp: new Date()
    }).catch(() => {});  // fire-and-forget: audit failure must not break order flow

    res.status(201).json(responseData);
  } catch (err) {
    console.error('/orders POST error:', err);
    res.status(500).json({ error: 'Failed to create order' });
  }
});

// ──────────────────────────────────────────────
// GET /api/orders/:id/receipt
// BAC-01: IDOR — no ownership check
// ──────────────────────────────────────────────
router.get('/:id/receipt', requireAuth, async (req, res) => {
  try {
    const order = await Order.findByPk(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    // BAC-01 VULNERABILITY: no ownership check — any authenticated user can access
    const bac01Flag = getFlag('bac01');

    // Check if this is the target (admin's confirmed order)
    const user = await User.findByPk(order.user_id);
    const isTargetOrder = user && user.role === 'admin' && order.status === 'confirmed';

    const receipt = {
      id: order.id,
      status: order.status,
      items: order.items_json,
      total_price_cents: order.total_price_cents,
      created_at: order.created_at
    };

    if (isTargetOrder && bac01Flag) {
      receipt.flag = bac01Flag;
      receipt.receipt_note = 'Admin special order — receipt contains sensitive data';
    }

    res.json(receipt);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch receipt' });
  }
});

// ──────────────────────────────────────────────
// POST /api/orders/search
// INJ-02: ORM raw-query fallback; UNION SELECT via WAF bypass
// WAF blocks: UNION SELECT (direct)
// Bypass: UNION/**/SELECT, UNION%0aSELECT, UnIoN SeLeCt
// ──────────────────────────────────────────────
router.post('/search', requireAuth, async (req, res) => {
  try {
    const { query: searchQuery } = req.body;
    if (!searchQuery) return res.status(400).json({ error: 'query required' });

    // INJ-02 VULNERABILITY: raw Sequelize query with string interpolation.
    // status is cast to text in both the SELECT list and the WHERE clause so
    // LIKE operates on the string representation and UNION SELECT can inject
    // text values into column 2 (PostgreSQL rejects UNION where one side is
    // enum_orders_status and the other is text).
    const sql = `SELECT id, status::text, total_price_cents, created_at FROM orders WHERE user_id = '${req.user.id}' AND status::text LIKE '%${searchQuery}%'`;

    const orders = await sequelize.query(sql, {
      type: QueryTypes.SELECT
    });

    res.json(orders);
  } catch (err) {
    // Return error details (helps with injection)
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────
// GET /api/orders/:id
// ──────────────────────────────────────────────
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const order = await Order.findOne({
      where: { id: req.params.id, user_id: req.user.id }
    });
    if (!order) return res.status(404).json({ error: 'Order not found' });
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// ──────────────────────────────────────────────
// GET /api/orders/files/download?filename=...
// BAC-04: Path traversal via double URL encoding
// Validation step: framework-decoded value (no further decode)
// File-serving step: applies one explicit URL-decode (converts %2F → /)
// ──────────────────────────────────────────────
router.get('/files/download', requireAuth, async (req, res) => {
  try {
    const { filename } = req.query;
    if (!filename) return res.status(400).json({ error: 'filename required' });

    // BAC-04: VULNERABILITY — two-pass decode
    // req.query.filename is the framework-decoded value (one decode by Express)
    const frameworkDecoded = filename;  // Express has already decoded once

    // ── Validation step (on framework-decoded value, NO further decode) ──────
    // (a) Extension check
    const allowedExts = ['.txt', '.pdf', '.csv', '.json'];
    const ext = path.extname(frameworkDecoded).toLowerCase();
    if (!allowedExts.includes(ext)) {
      return res.status(400).json({ error: 'File type not allowed' });
    }

    // (b) Traversal-detection check (on the framework-decoded value)
    // Double-encoded input: %252F → framework decode → %2F (no '../' yet)
    // Single-encoded input: %2F → framework decode → / (contains '../' or starts with '/')
    if (frameworkDecoded.includes('../') || frameworkDecoded.startsWith('/')) {
      return res.status(400).json({ error: 'Invalid filename' });
    }
    // ─────────────────────────────────────────────────────────────────────────

    // ── File-serving step: applies one additional explicit URL-decode ─────────
    // BAC-04: this second decode converts %2F → / (traversal executes)
    const serverDecoded = decodeURIComponent(frameworkDecoded);
    // ─────────────────────────────────────────────────────────────────────────

    const baseDir = '/app/uploads/files/';
    fs.mkdirSync(baseDir, { recursive: true });
    const fullPath = path.resolve(baseDir, serverDecoded);

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.download(fullPath);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
