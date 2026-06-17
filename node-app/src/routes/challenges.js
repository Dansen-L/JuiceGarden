/**
 * Challenge-specific routes
 * CS-03: flag oracle — returns flag iff admin_bot email has been changed
 * CS-02: /orders/track widget — no nonce CSP
 */
'use strict';

const express = require('express');
const { User } = require('../models');
const { requireAuth } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');

const router = express.Router();

// ──────────────────────────────────────────────
// GET /api/challenges/cs03/flag
// Returns flag iff admin_bot account email has been changed from its seed value
// ──────────────────────────────────────────────
router.get('/cs03/flag', requireAuth, async (req, res) => {
  try {
    const seedEmail = process.env.ADMIN_BOT_EMAIL || 'admin.bot@garden.lab';
    const adminBot = await User.findOne({ where: { username: 'admin_bot' } });

    if (!adminBot) {
      return res.status(500).json({ error: 'Admin bot account not found' });
    }

    if (adminBot.email !== seedEmail) {
      // Email was changed — CSRF succeeded
      const cs03Flag = getFlag('cs03');
      return res.json({
        success: true,
        flag: cs03Flag,
        message: 'CSRF attack succeeded — admin_bot email was changed'
      });
    }

    res.json({
      success: false,
      message: 'Admin bot email unchanged — CSRF attack has not yet fired',
      current_email: adminBot.email
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to check CS-03 flag' });
  }
});

module.exports = router;
