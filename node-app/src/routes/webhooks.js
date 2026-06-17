/**
 * Webhook routes
 * SS-01: Blind SSRF via webhook URL
 * Practitioner registers webhook pointing to redis-commander:8081
 * Server fetches it; response leaks Redis key list
 */
'use strict';

const express = require('express');
const axios = require('axios');
const { Webhook } = require('../models');
const { requireAuth } = require('../middleware/auth');
const { getFlag } = require('../utils/flags');

const router = express.Router();

router.use(requireAuth);

// ──────────────────────────────────────────────
// GET /api/webhooks
// ──────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const hooks = await Webhook.findAll({ where: { user_id: req.user.id } });
    res.json(hooks);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch webhooks' });
  }
});

// ──────────────────────────────────────────────
// POST /api/webhooks
// SS-01 VULNERABILITY: server fetches user-controlled URL
// Target: http://redis-commander:8081/apiv2/key/R:redis:6379:0/garden:ss01_flag
// The connectionId format is R:<host>:<port>:<db>; response body contains the flag value.
// ──────────────────────────────────────────────
router.post('/', async (req, res) => {
  try {
    const { url, event_type } = req.body;
    if (!url) return res.status(400).json({ error: 'url required' });

    // SS-01: store the webhook
    const hook = await Webhook.create({
      user_id: req.user.id,
      url,
      event_type: event_type || 'order.created',
      active: true,
      created_at: new Date()
    });

    // Test the webhook URL (SSRF vulnerability — server fetches user-controlled URL)
    let testResult = null;
    try {
      const response = await axios.get(url, {
        timeout: 5000,
        maxRedirects: 0,
        validateStatus: () => true  // Accept any status
      });
      // SS-01: body_preview uses JSON.stringify so object responses (JSON API replies)
      // are included verbatim — this is how the flag leaks when the redis-commander
      // key endpoint returns {"key":"garden:ss01_flag","val":"JG{...}",...}
      const raw = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data);
      testResult = {
        status: response.status,
        body_preview: raw.slice(0, 500)
      };
    } catch (fetchErr) {
      testResult = { error: fetchErr.message };
    }

    // SS-01: response includes the fetched content (SSRF exfiltration)
    res.status(201).json({
      id: hook.id,
      url: hook.url,
      event_type: hook.event_type,
      test_result: testResult,
      message: 'Webhook registered and tested'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create webhook' });
  }
});

// ──────────────────────────────────────────────
// DELETE /api/webhooks/:id
// ──────────────────────────────────────────────
router.delete('/:id', async (req, res) => {
  try {
    const hook = await Webhook.findOne({
      where: { id: req.params.id, user_id: req.user.id }
    });
    if (!hook) return res.status(404).json({ error: 'Webhook not found' });

    await hook.destroy();
    res.json({ message: 'Webhook deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete webhook' });
  }
});

module.exports = router;
