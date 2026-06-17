/**
 * Manager routes
 * AUTH-01: GET /api/manager/reports — kid-filesystem HMAC verifier ONLY
 * AUTH-02: GET /api/manager/promotions — RSA/JWKS alg-flexible verifier ONLY
 * DISTINCT middleware — must NOT share a verifier (would collapse the two exercises)
 */
'use strict';

const express = require('express');
const { Review, Product } = require('../models');
const { requireAuth, requireKidHmacJwt, requireAlgFlexibleJwt, requireRole } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');
const { getPublicKeyJwk } = require('../utils/jwt');

const router = express.Router();

// ──────────────────────────────────────────────
// GET /.well-known/jwks.json
// AUTH-02: public key exposed (unauthenticated)
// Attackers use this to extract the RSA public key for alg confusion
// ──────────────────────────────────────────────
router.get('/jwks', (req, res) => {
  res.json(getPublicKeyJwk());
});

// ──────────────────────────────────────────────
// GET /api/manager/reports
// AUTH-01 target: kid-filesystem HMAC verifier ONLY
// kid=/dev/null → empty HMAC key → forged JWT accepted
// RS256/alg-confusion JWTs REJECTED here
// ──────────────────────────────────────────────
router.get('/reports', requireKidHmacJwt, requireRole('manager', 'admin'), async (req, res) => {
  const auth01Flag = getFlag('auth01');

  res.json({
    reports: [
      {
        week: 'Current',
        total_orders: 42,
        total_revenue_cents: 58500,
        top_product: 'Green Garden Juice',
        notes_count: 15
      }
    ],
    flag: auth01Flag,
    note: 'Manager reports endpoint — AUTH-01 target'
  });
});

// ──────────────────────────────────────────────
// GET /api/manager/promotions
// AUTH-02 target: RSA/JWKS alg-flexible verifier ONLY
// RS256→HS256 alg confusion → forged JWT accepted
// kid-filesystem JWTs REJECTED here
// ──────────────────────────────────────────────
router.get('/promotions', requireAlgFlexibleJwt, requireRole('manager', 'admin'), async (req, res) => {
  const auth02Flag = getFlag('auth02');

  res.json({
    promotions: [
      {
        id: 1,
        title: 'Summer Detox Bundle',
        discount: '20% off',
        status: 'pending_approval',
        created_at: new Date().toISOString()
      }
    ],
    flag: auth02Flag,
    note: 'Manager promotions endpoint — AUTH-02 target'
  });
});

// ──────────────────────────────────────────────
// GET /api/manager/reviews (general auth, manager role)
// manager_bot: approve pending reviews
// Uses requireAuth (session or any valid JWT) — NOT the special AUTH-01/AUTH-02 verifiers
// so that manager_bot's RS256 login token is accepted here
// ──────────────────────────────────────────────
router.get('/reviews', requireAuth, requireRole('manager', 'admin'), async (req, res) => {
  try {
    const pending = await Review.findAll({ where: { approved: false } });
    res.json({ reviews: pending });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// ──────────────────────────────────────────────
// POST /api/manager/reviews/:id/approve
// manager_bot calls this to approve CS-01 XSS payloads
// Uses requireAuth (session or any valid JWT) for same reason as GET /reviews
// ──────────────────────────────────────────────
router.post('/reviews/:id/approve', requireAuth, requireRole('manager', 'admin'), async (req, res) => {
  try {
    const review = await Review.findByPk(req.params.id);
    if (!review) return res.status(404).json({ error: 'Review not found' });

    review.approved = true;
    await review.save();

    res.json({ message: 'Review approved', id: review.id });
  } catch (err) {
    res.status(500).json({ error: 'Failed to approve review' });
  }
});

// ──────────────────────────────────────────────
// POST /api/manager/reviews/:id/reject
// Manager rejects a pending review by removing it
// Uses requireAuth (session or any valid JWT) consistent with approve endpoint
// ──────────────────────────────────────────────
router.post('/reviews/:id/reject', requireAuth, requireRole('manager', 'admin'), async (req, res) => {
  try {
    const review = await Review.findByPk(req.params.id);
    if (!review) return res.status(404).json({ error: 'Review not found' });

    const rejectedId = review.id;
    await review.destroy();

    res.json({ message: 'Review rejected and removed', id: rejectedId });
  } catch (err) {
    res.status(500).json({ error: 'Failed to reject review' });
  }
});

// ──────────────────────────────────────────────
// POST /api/manager/promotions/:id/approve
// Manager approves a pending promotion (action endpoint, not the AUTH-02 target)
// Uses requireAuth so an authenticated manager's normal session/JWT is accepted.
// Distinct from GET /promotions which uses the AUTH-02 alg-flexible verifier.
// ──────────────────────────────────────────────
router.post('/promotions/:id/approve', requireAuth, requireRole('manager', 'admin'), async (req, res) => {
  try {
    const promoId = parseInt(req.params.id, 10);
    if (isNaN(promoId)) return res.status(400).json({ error: 'Invalid promotion id' });

    res.json({
      message: 'Promotion approved',
      id: promoId,
      approved_by: req.user && req.user.id,
      approved_at: new Date().toISOString()
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to approve promotion' });
  }
});

module.exports = router;
