/**
 * CSRF protection middleware
 * Synchronizer-token pattern: per-session token stored in the session,
 * embedded in HTML forms as a hidden field, and verified on protected POSTs.
 *
 * Protected: POST /api/products/:id/reviews (review submission HTML form)
 * Deliberately unprotected: GET /api/user/email-change (CS-03 target)
 */
'use strict';

const crypto = require('crypto');

/**
 * Ensure the current session has a CSRF token, generating one if absent.
 * Safe to mount globally — reads/writes req.session only.
 */
function ensureCsrfToken(req, res, next) {
  if (req.session && !req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  next();
}

/**
 * Validate the CSRF token supplied in the request body (_csrf field) or
 * X-CSRF-Token header against the session token.
 * Returns 403 CSRF_INVALID when the token is absent or mismatched.
 */
function validateCsrf(req, res, next) {
  const submitted = req.body._csrf || req.headers['x-csrf-token'];
  const expected = req.session && req.session.csrfToken;

  if (!submitted || !expected || submitted !== expected) {
    return res.status(403).json({ error: 'Invalid CSRF token', code: 'CSRF_INVALID' });
  }
  next();
}

module.exports = { ensureCsrfToken, validateCsrf };
