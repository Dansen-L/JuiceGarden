/**
 * User routes
 * BAC-02: Mass assignment — role field accepted in profile PUT
 * INJ-03: EJS SSTI via display_name in email-preview
 * AUTH-03: Flag in GET /api/user/profile after password reset
 */
'use strict';

const express = require('express');
const { User, AuditLog } = require('../models');
const { requireAuth } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');
const ejs = require('ejs');

const router = express.Router();

// ──────────────────────────────────────────────
// GET /api/user/profile
// ──────────────────────────────────────────────
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const profile = {
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      bio: user.bio,  // INJ-01: second-order exfil destination
      email: user.email,
      role: user.role,
      loyalty_points: user.loyalty_points,
      created_at: user.created_at
    };

    // AUTH-03: flag embedded in profile for the target account
    const auth03Flag = getFlag('auth03');
    if (auth03Flag && user.username === 'alice') {
      // The flag is in the profile — retrieved after successful password reset
      profile.auth03_flag = auth03Flag;
    }

    res.json(profile);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// ──────────────────────────────────────────────
// PUT /api/user/profile
// BAC-02 VULNERABILITY: accepts `role` field (mass assignment)
// The server silently updates the role if provided in the request body
// ──────────────────────────────────────────────
router.put('/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const { display_name, bio, email, profile_json, role } = req.body;

    const updates = {};
    if (display_name !== undefined) updates.display_name = display_name;
    if (bio !== undefined) updates.bio = bio;
    if (email !== undefined) updates.email = email;
    if (profile_json !== undefined) updates.profile_json = profile_json;

    // BAC-02 VULNERABILITY: role field accepted without authorization check
    if (role !== undefined) {
      updates.role = role;
    }

    await user.update(updates);

    // Update session role if changed
    if (role !== undefined) {
      req.session.role = updates.role;
    }

    // Audit log: record profile update
    AuditLog.create({
      actor_id: req.user.id,
      action: 'user.profile_updated',
      target_type: 'user',
      target_id: req.user.id,
      details_json: { updated_fields: Object.keys(updates) },
      ip_address: req.headers['x-real-ip'] || req.ip,
      timestamp: new Date()
    }).catch(() => {});  // fire-and-forget

    res.json({
      id: user.id,
      username: user.username,
      display_name: user.display_name,
      bio: user.bio,
      email: user.email,
      role: user.role
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

// ──────────────────────────────────────────────
// GET /api/user/email-preview
// INJ-03 VULNERABILITY: display_name passed directly to ejs.render()
// Confirmation probe: set display_name to `<%= 7*7 %>`, call this endpoint, "49" in body
// RCE gadget: <%= global.process.mainModule.require('child_process').execSync('...') %>
// ──────────────────────────────────────────────
router.get('/email-preview', requireAuth, async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    // INJ-03 VULNERABILITY: user-controlled display_name interpolated into the
    // template SOURCE string before ejs.render() compiles it.
    // When display_name = "<%= 7*7 %>", the template contains a live EJS tag
    // and ejs.render evaluates it, returning "49".
    // RCE gadget: display_name = "<%= global.process.mainModule.require('child_process').execSync('id').toString() %>"
    const rawName = user.display_name || 'Customer';
    const emailTemplate = `<!DOCTYPE html>
<html>
<head><title>Order Confirmation</title></head>
<body>
  <h1>Garden Fresh Order Confirmation</h1>
  <p>Dear ${rawName},</p>
  <p>Thank you for your order! Your fresh juices are being prepared.</p>
  <p>Track your order at: http://garden.lab/orders/track</p>
  <p>Best regards,<br>The Garden Fresh Team</p>
</body>
</html>`;

    // VULNERABILITY: template source already contains the user value;
    // ejs.render compiles it, executing any EJS tags the value introduced.
    const rendered = ejs.render(emailTemplate, {});

    res.set('Content-Type', 'text/html');
    res.send(rendered);
  } catch (err) {
    // INJ-03: execution errors show in the response body
    res.status(500).send(`Template error: ${err.message}`);
  }
});

// ──────────────────────────────────────────────
// GET /api/user/email-change — CS-03 CSRF target
// Developer shortcut: email change via GET request (should be POST)
// SameSite=Lax: top-level cross-site GET navigation sends the cookie
// SameSite=Strict: blocks cross-site navigation
// ──────────────────────────────────────────────
router.get('/email-change', requireAuth, async (req, res) => {
  try {
    const { new_email } = req.query;
    if (!new_email) return res.status(400).json({ error: 'new_email required' });

    const user = await User.findByPk(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });

    user.email = new_email;
    await user.save();

    res.json({ message: 'Email updated', email: new_email });
  } catch (err) {
    res.status(500).json({ error: 'Failed to change email' });
  }
});

module.exports = router;
