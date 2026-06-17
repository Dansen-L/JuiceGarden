/**
 * Auth routes: register, login, logout, reset password
 * AUTH-03: LCG-based reset token (Date.now() seed)
 * AUTH-04: Rate-limit bypassable via X-Forwarded-For
 */
'use strict';

const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { User } = require('../models');
const { signToken } = require('../utils/jwt');
const { issueStaffProof } = require('../middleware/auth');

const router = express.Router();

// ──────────────────────────────────────────────
// AUTH-04: Rate limiting on login — bypassable via X-Forwarded-For
// The limiter reads X-Forwarded-For header without validation
// ──────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,  // 5 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX || '10', 10),
  keyGenerator: (req) => {
    // VULNERABILITY (AUTH-04): uses X-Forwarded-For without validation
    // Rotating this header bypasses the lockout
    return req.headers['x-forwarded-for'] || req.ip;
  },
  message: { error: 'Too many login attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// ──────────────────────────────────────────────
// AUTH-03: Custom LCG for password reset tokens
// Seeded with Date.now() (millisecond precision)
// Response Date header leaks server time to second granularity
// ──────────────────────────────────────────────
function lcg(seed) {
  // LCG parameters (documented in T2 hint): Numerical Recipes coefficients, mod 2^32.
  // BigInt arithmetic is used so that A*seed (up to ~2.8e18) is computed exactly.
  // A plain JS Number would lose low-order bits above 2^53, producing different tokens
  // than a standard big-integer LCG implementation (e.g. Python's).
  const A = 1664525n;
  const C = 1013904223n;
  const M = 2n ** 32n;
  return Number((A * BigInt(seed) + C) % M);
}

function generateResetToken() {
  const seed = Date.now();
  const token = lcg(seed);
  return { token: token.toString(16).padStart(8, '0'), seed };
}

// ──────────────────────────────────────────────
// POST /api/auth/register
// ──────────────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { username, email, password, display_name } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'username, email, and password required' });
    }

    const existing = await User.findOne({ where: { email } });
    if (existing) {
      return res.status(409).json({ error: 'Email already registered' });
    }

    const existingUsername = await User.findOne({ where: { username } });
    if (existingUsername) {
      return res.status(409).json({ error: 'Username already taken' });
    }

    const { mintUuidV1 } = require('../utils/uuid_v1');
    const hash = await bcrypt.hash(password, 6);

    const user = await User.create({
      id: mintUuidV1(),
      username,  // INJ-01: stored verbatim (no sanitization)
      display_name: display_name || username,
      email,
      password_hash: hash,
      role: 'customer',
      created_at: new Date()
    });

    req.session.userId = user.id;
    req.session.role = user.role;

    res.status(201).json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    });
  } catch (err) {
    console.error('/register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// ──────────────────────────────────────────────
// POST /api/auth/login
// ──────────────────────────────────────────────
router.post('/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Set session
    req.session.userId = user.id;
    req.session.role = user.role;
    req.session.username = user.username;

    // Issue JWT
    const token = signToken({ id: user.id, role: user.role, email: user.email });

    const responseData = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      token
    };

    // BAC-02: If user has staff role, issue staffSessionProof cookie
    if (user.role === 'staff' || user.role === 'manager' || user.role === 'admin') {
      issueStaffProof(res, user.id);
    }

    // CS-01: admin_bot cookie is NOT HttpOnly (deliberate flaw)
    // This is handled at the session level for admin_bot specifically
    if (user.role === 'admin') {
      // The flag is embedded in the session cookie
      const { getFlag } = require('../utils/flags');
      const cs01Flag = getFlag('cs01');
      if (cs01Flag) {
        // Set a separate non-HttpOnly cookie with the flag for CS-01
        res.cookie('cs01_session', `user=${user.id};flag=${cs01Flag}`, {
          httpOnly: false,  // Deliberate flaw — CS-01
          sameSite: 'Lax',
          maxAge: 24 * 60 * 60 * 1000
        });
      }
    }

    // BAC-02 flag: if role is staff (elevated via mass assignment), reveal flag
    if (user.role === 'staff') {
      const { getFlag } = require('../utils/flags');
      responseData.notice = 'Staff access granted';
    }

    res.json(responseData);
  } catch (err) {
    console.error('/login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// ──────────────────────────────────────────────
// POST /api/auth/logout
// ──────────────────────────────────────────────
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Session destroy error:', err);
    res.clearCookie('connect.sid');
    res.clearCookie('staffSessionProof');
    res.clearCookie('cs01_session');
    res.json({ message: 'Logged out' });
  });
});

// ──────────────────────────────────────────────
// POST /api/auth/reset-request
// AUTH-03: LCG token seeded with Date.now()
// Date header leaks server time (second granularity)
// ──────────────────────────────────────────────
router.post('/reset-request', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'email required' });

    const user = await User.findOne({ where: { email } });
    // Always respond 200 to prevent email enumeration
    if (!user) {
      return res.status(200).json({ message: 'If that email exists, a reset link was sent.' });
    }

    const { token } = generateResetToken();
    user.reset_token = token;
    user.reset_token_expires = new Date(Date.now() + 15 * 60 * 1000);  // 15min
    await user.save();

    console.log(`[auth] Reset token for ${email}: ${token}`);
    res.status(200).json({ message: 'If that email exists, a reset link was sent.' });
  } catch (err) {
    res.status(500).json({ error: 'Reset request failed' });
  }
});

// ──────────────────────────────────────────────
// POST /api/auth/reset-confirm
// AUTH-03: Validate LCG token
// ──────────────────────────────────────────────
router.post('/reset-confirm', async (req, res) => {
  try {
    const { email, token, new_password } = req.body;
    if (!email || !token || !new_password) {
      return res.status(400).json({ error: 'email, token, and new_password required' });
    }

    const user = await User.findOne({ where: { email } });
    if (!user || user.reset_token !== token) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    if (user.reset_token_expires < new Date()) {
      return res.status(400).json({ error: 'Reset token expired' });
    }

    const hash = await bcrypt.hash(new_password, 6);
    user.password_hash = hash;
    user.reset_token = null;
    user.reset_token_expires = null;
    await user.save();

    res.json({ message: 'Password reset successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Reset confirm failed' });
  }
});

module.exports = router;
