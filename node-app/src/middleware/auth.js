/**
 * Authentication middleware for Garden Fresh.
 */
'use strict';

const { verifyKidHmac, verifyAlgFlexible } = require('../utils/jwt');
const crypto = require('crypto');

/**
 * Require authentication via session or JWT Bearer token.
 */
function requireAuth(req, res, next) {
  // Session-based auth (web UI)
  if (req.session && req.session.userId) {
    req.user = { id: req.session.userId, role: req.session.role };
    return next();
  }

  // JWT Bearer token (API use)
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    try {
      // Try kid-based verifier first, then alg-flexible
      let payload;
      try {
        payload = verifyKidHmac(token);
      } catch (e) {
        payload = verifyAlgFlexible(token);
      }
      req.user = payload;
      return next();
    } catch (e) {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  return res.status(401).json({ error: 'Authentication required' });
}

/**
 * Require a specific role.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Authentication required' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient privileges' });
    }
    next();
  };
}

/**
 * AUTH-01 verifier middleware: kid-filesystem HMAC ONLY.
 * Used on /api/manager/reports.
 */
function requireKidHmacJwt(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Bearer token required' });
  }
  const token = authHeader.slice(7);
  try {
    const payload = verifyKidHmac(token);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token: ' + e.message });
  }
}

/**
 * AUTH-02 verifier middleware: RSA/JWKS alg-flexible ONLY.
 * Used on /api/manager/promotions.
 */
function requireAlgFlexibleJwt(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Bearer token required' });
  }
  const token = authHeader.slice(7);
  try {
    const payload = verifyAlgFlexible(token);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token: ' + e.message });
  }
}

/**
 * Verify staffSessionProof cookie (required for /api/admin/* endpoints).
 * HMAC-signed, HttpOnly. Issued only when a Staff-role account authenticates.
 */
function requireStaffProof(req, res, next) {
  const proof = req.cookies['staffSessionProof'];
  if (!proof) {
    return res.status(403).json({ error: 'staffSessionProof cookie required' });
  }

  const secret = process.env.STAFF_PROOF_SECRET || 'staff_proof_secret';
  const [data, sig] = proof.split('.');
  if (!data || !sig) {
    return res.status(403).json({ error: 'Invalid staffSessionProof format' });
  }

  const expectedSig = crypto
    .createHmac('sha256', secret)
    .update(data)
    .digest('hex');

  // Length check must precede timingSafeEqual — unequal-length buffers throw RangeError
  if (sig.length !== expectedSig.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expectedSig))) {
    return res.status(403).json({ error: 'Invalid staffSessionProof signature' });
  }

  const decoded = Buffer.from(data, 'base64').toString('utf8');
  let proofData;
  try {
    proofData = JSON.parse(decoded);
  } catch (e) {
    return res.status(403).json({ error: 'Invalid staffSessionProof data' });
  }

  // Check expiry
  if (proofData.exp && Date.now() > proofData.exp) {
    return res.status(403).json({ error: 'staffSessionProof expired' });
  }

  req.staffProof = proofData;
  next();
}

/**
 * Issue a staffSessionProof cookie for a staff-role user.
 */
function issueStaffProof(res, userId) {
  const secret = process.env.STAFF_PROOF_SECRET || 'staff_proof_secret';
  const proofData = {
    userId,
    issuedAt: Date.now(),
    exp: Date.now() + 24 * 60 * 60 * 1000  // 24h
  };
  const data = Buffer.from(JSON.stringify(proofData)).toString('base64');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('hex');
  const proof = `${data}.${sig}`;

  res.cookie('staffSessionProof', proof, {
    httpOnly: true,
    sameSite: 'Lax',
    maxAge: 24 * 60 * 60 * 1000
  });
}

module.exports = {
  requireAuth,
  requireRole,
  requireKidHmacJwt,
  requireAlgFlexibleJwt,
  requireStaffProof,
  issueStaffProof
};
