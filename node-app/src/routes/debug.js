/**
 * Debug routes (hidden bonus flag)
 * GET /api/debug/stats — not linked in UI; bonus flag embedded
 */
'use strict';

const express = require('express');
const { User, Order, Product, Review } = require('../models');
const { requireAuth } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');

const router = express.Router();

// ──────────────────────────────────────────────
// GET /api/debug/stats
// Hidden bonus flag — not linked anywhere in UI
// Accessible to any authenticated user (not role-gated)
// ──────────────────────────────────────────────
router.get('/stats', requireAuth, async (req, res) => {
  try {
    const [userCount, orderCount, productCount, reviewCount] = await Promise.all([
      User.count(),
      Order.count(),
      Product.count(),
      Review.count()
    ]);

    const bonusFlag = getFlag('bonus');

    res.json({
      stats: {
        users: userCount,
        orders: orderCount,
        products: productCount,
        reviews: reviewCount
      },
      version: '1.2.3-debug',
      bonus_flag: bonusFlag,  // Hidden bonus flag
      generated_at: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

module.exports = router;
