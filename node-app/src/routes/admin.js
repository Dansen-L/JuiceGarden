/**
 * Admin routes — requires JWT + staffSessionProof cookie
 * MISSION-ALPHA Step 3: GET /api/admin/config
 * AUTH-01: kid=/dev/null attack target
 */
'use strict';

const express = require('express');
const { User, AuditLog } = require('../models');
const { requireKidHmacJwt, requireRole, requireStaffProof } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');

const router = express.Router();

// All admin routes require:
// 1. Valid Admin-level JWT (kid-HMAC verifier)
// 2. Valid staffSessionProof cookie (HttpOnly, HMAC-signed)
router.use(requireKidHmacJwt);
router.use(requireRole('admin'));
router.use(requireStaffProof);  // MISSION-ALPHA gate

// ──────────────────────────────────────────────
// GET /api/admin/config
// MISSION-ALPHA: master flag in response
// AUTH-01: target endpoint
// Requires: Admin JWT with kid=/dev/null + staffSessionProof cookie
// ──────────────────────────────────────────────
router.get('/config', (req, res) => {
  const missionFlag = getFlag('mission_alpha');

  res.json({
    config: {
      version: '1.2.3',
      environment: process.env.NODE_ENV || 'production',
      features: {
        reviews_enabled: true,
        loyalty_program: true,
        webhooks_enabled: true
      }
    },
    flag: missionFlag,
    message: 'Admin configuration — MISSION-ALPHA COMPLETE'
  });
});

// ──────────────────────────────────────────────
// GET /api/admin/users
// ──────────────────────────────────────────────
router.get('/users', async (req, res) => {
  try {
    const users = await User.findAll({
      attributes: ['id', 'username', 'email', 'role', 'created_at']
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// ──────────────────────────────────────────────
// GET /api/admin/audit
// ──────────────────────────────────────────────
router.get('/audit', async (req, res) => {
  try {
    const logs = await AuditLog.findAll({
      order: [['timestamp', 'DESC']],
      limit: 100
    });
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

module.exports = router;
