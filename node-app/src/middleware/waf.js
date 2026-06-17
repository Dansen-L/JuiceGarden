/**
 * WAF-lite middleware for Garden Fresh routes.
 *
 * Scope: applies ONLY to Garden Fresh routes (not /platform/*, which nginx skips).
 * This middleware handles body-based checks that nginx cannot easily inspect.
 *
 * Rules:
 *   SQLi: blocks ' OR and UNION SELECT patterns in body
 *   Script-tag: blocks inline-body <script> and external src schemes;
 *               PERMITS same-origin src (/...)
 *   Event-handler: blocks on[a-z]+= patterns
 *   XXE: blocks ENTITY with http:// or https:// (NOT file://)
 */
'use strict';

// Patterns that are BLOCKED
const BLOCKED_PATTERNS = [
  // SQLi: ' OR
  { re: /'\s*OR\s/i, code: 'WAF_SQLI', msg: 'SQL injection pattern detected' },
  // SQLi: UNION SELECT — blocked when separated by literal space or tab only.
  // [ \t]+ (not \s+) so newlines are not blocked, enabling %0a bypass.
  // Intentional bypass gaps (lab design):
  //   UNION/**/SELECT  → not blocked (comment chars not [ \t])  [feature 56]
  //   UNION%0aSELECT   → not blocked (URL-decoded \n not [ \t]) [feature 57]
  //   UnIoN SeLeCt     → not blocked (case-sensitive)            [feature 58]
  { re: /UNION[ \t]+(?:ALL[ \t]+)?SELECT/, code: 'WAF_SQLI', msg: 'SQL injection pattern detected' },

  // Script-tag BLOCKED forms:
  //   - inline body: <script> with no src
  //   - src with https://, http://, //
  {
    re: /<script(?![^>]*\ssrc\s*=)[^>]*>/i,
    code: 'WAF_SCRIPT',
    msg: 'Inline script tag blocked'
  },
  {
    re: /<script[^>]+src\s*=\s*["']?\s*https?:\/\//i,
    code: 'WAF_SCRIPT',
    msg: 'External script source blocked'
  },
  {
    re: /<script[^>]+src\s*=\s*["']?\s*\/\//i,
    code: 'WAF_SCRIPT',
    msg: 'Protocol-relative script source blocked'
  },

  // Event handlers: on[a-z]+(optional whitespace)= in any context
  // HTML permits whitespace before = (e.g. onerror =payload), so \s* is required.
  { re: /\bon[a-zA-Z]+\s*=/i, code: 'WAF_EVTHANDLER', msg: 'Event handler attribute blocked' },

  // XML ENTITY with http/https (NOT file://)
  { re: /<!ENTITY[^>]*https?:\/\//i, code: 'WAF_XXE', msg: 'External entity declaration blocked' },
];

function checkValue(value) {
  if (typeof value !== 'string') return null;
  for (const { re, code, msg } of BLOCKED_PATTERNS) {
    if (re.test(value)) {
      return { code, msg };
    }
  }
  return null;
}

function checkObject(obj, depth = 0) {
  // Block — not pass — when nesting exceeds the depth limit so deeply-nested
  // JSON cannot bypass inspection by wrapping a payload in extra object levels.
  if (depth > 5) return { code: 'WAF_DEPTH', msg: 'Request structure too deeply nested' };
  if (typeof obj === 'string') return checkValue(obj);
  if (Array.isArray(obj)) {
    for (const v of obj) {
      const r = checkObject(v, depth + 1);
      if (r) return r;
    }
  } else if (obj && typeof obj === 'object') {
    for (const v of Object.values(obj)) {
      const r = checkObject(v, depth + 1);
      if (r) return r;
    }
  }
  return null;
}

function wafMiddleware(req, res, next) {
  // Skip WAF for platform routes (nginx handles /platform/* routing,
  // but in case this middleware sees a direct request)
  if (req.path.startsWith('/platform/')) {
    return next();
  }

  // Check body
  const bodyCheck = checkObject(req.body);
  if (bodyCheck) {
    return res.status(403).json({
      error: 'Request blocked by security filter',
      code: bodyCheck.code,
      message: bodyCheck.msg
    });
  }

  // Check query string
  const qsCheck = checkObject(req.query);
  if (qsCheck) {
    return res.status(403).json({
      error: 'Request blocked by security filter',
      code: qsCheck.code,
      message: qsCheck.msg
    });
  }

  next();
}

module.exports = { wafMiddleware };
