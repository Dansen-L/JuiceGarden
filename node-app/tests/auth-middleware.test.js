/**
 * auth-middleware.test.js — Tests for requireStaffProof middleware.
 *
 * Tests the ACTUAL requireStaffProof function from auth.js, including
 * the G5 fix that prevents RangeError when sig.length differs from expected.
 */
'use strict';

const crypto = require('crypto');

// Mock modules that requireStaffProof doesn't need
jest.mock('../src/utils/jwt', () => ({
  verifyKidHmac: jest.fn(),
  verifyAlgFlexible: jest.fn()
}));

const { requireStaffProof, issueStaffProof } = require('../src/middleware/auth');

// Helper: create a mock Express request with a cookie
function makeReq(cookieValue) {
  return { cookies: cookieValue !== undefined ? { staffSessionProof: cookieValue } : {} };
}

// Helper: create a mock Express response that records status/json calls
function makeRes() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

// Helper: create a valid staffSessionProof cookie using the same logic as issueStaffProof
function makeValidProof(secret = 'staff_proof_secret', overrideData = {}) {
  const proofData = {
    userId: 'test-user-123',
    issuedAt: Date.now(),
    exp: Date.now() + 24 * 60 * 60 * 1000,
    ...overrideData
  };
  const data = Buffer.from(JSON.stringify(proofData)).toString('base64');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('hex');
  return `${data}.${sig}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Normal cases
// ─────────────────────────────────────────────────────────────────────────────

describe('requireStaffProof — normal cases', () => {
  test('calls next() for a valid staffSessionProof cookie', () => {
    const proof = makeValidProof();
    const req = makeReq(proof);
    const res = makeRes();
    const next = jest.fn();

    requireStaffProof(req, res, next);
    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
  });

  test('populates req.staffProof with decoded data on success', () => {
    const proof = makeValidProof();
    const req = makeReq(proof);
    const res = makeRes();
    const next = jest.fn();

    requireStaffProof(req, res, next);
    expect(req.staffProof).toBeDefined();
    expect(req.staffProof.userId).toBe('test-user-123');
  });

  test('returns 403 when staffSessionProof cookie is missing', () => {
    const req = makeReq(undefined);
    const res = makeRes();
    const next = jest.fn();

    requireStaffProof(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// G5 fix: malformed cookie must NOT crash (previously threw RangeError)
// ─────────────────────────────────────────────────────────────────────────────

describe('requireStaffProof — G5 fix: no crash on malformed cookie', () => {
  const cases = [
    ['short sig (1 char)', makeValidProof().split('.')[0] + '.x'],
    ['empty sig', makeValidProof().split('.')[0] + '.'],
    ['no dot separator', Buffer.from('{"userId":"u"}').toString('base64')],
    ['totally invalid', 'not-a-valid-proof'],
    ['empty string', ''],
  ];

  test.each(cases)('%s → 403 (no RangeError)', (_label, cookieValue) => {
    const req = makeReq(cookieValue);
    const res = makeRes();
    const next = jest.fn();

    // Must NOT throw — pre-fix this would crash with RangeError from timingSafeEqual
    expect(() => requireStaffProof(req, res, next)).not.toThrow();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('tampered signature → 403 (not 500)', () => {
    const valid = makeValidProof();
    const [data] = valid.split('.');
    // Flip one character in the hex signature
    const tamperedSig = 'a'.repeat(64);
    const tampered = `${data}.${tamperedSig}`;

    const req = makeReq(tampered);
    const res = makeRes();
    const next = jest.fn();

    requireStaffProof(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('expired proof → 403', () => {
    const expiredProof = makeValidProof('staff_proof_secret', {
      exp: Date.now() - 1000  // expired 1 second ago
    });
    const req = makeReq(expiredProof);
    const res = makeRes();
    const next = jest.fn();

    requireStaffProof(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  test('wrong HMAC secret → 403', () => {
    const wrongSecretProof = makeValidProof('wrong_secret');
    const req = makeReq(wrongSecretProof);
    const res = makeRes();
    const next = jest.fn();

    requireStaffProof(req, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });
});
