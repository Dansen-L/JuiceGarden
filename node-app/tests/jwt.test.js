/**
 * jwt.test.js — Integration tests for JWT verifiers in jwt.js.
 *
 * Tests execute the ACTUAL verifyKidHmac and verifyAlgFlexible functions
 * from the real jwt.js module using the real jsonwebtoken and node-forge
 * libraries. These are pure-JS and work without Docker.
 *
 * AUTH-01 exploit: kid=/dev/null → empty HMAC key → forged token accepted
 * AUTH-02 exploit: alg confusion RS256→HS256 using RSA public key bytes
 */
'use strict';

// Stub out ensureHmacKey's fs.mkdirSync/writeFileSync (runs at module load)
// The key path used in production is /app/keys/hmac.key, which doesn't exist.
// jwt.js calls ensureHmacKey() at load time — this creates a temp key file.
// We let it run; it will create a file in /app/keys if writable, or silently
// fail. Tests that need a key file use /dev/null (the AUTH-01 exploit path).
jest.mock('fs', () => {
  const realFs = jest.requireActual('fs');
  return {
    ...realFs,
    mkdirSync: (p, opts) => {
      try { realFs.mkdirSync(p, opts); } catch (e) { /* ignore */ }
    },
    writeFileSync: (p, d, opts) => {
      try { realFs.writeFileSync(p, d, opts); } catch (e) { /* ignore */ }
    },
    existsSync: (p) => {
      // Pretend hmac.key exists so ensureHmacKey doesn't try to write it
      if (p && p.endsWith('hmac.key')) return true;
      return realFs.existsSync(p);
    },
    readFileSync: (p, enc) => {
      // /dev/null → returns empty buffer (AUTH-01 exploit path)
      if (p === '/dev/null') return Buffer.from('');
      return realFs.readFileSync(p, enc);
    }
  };
});

// Load the real jwt.js module (executes with the mocked fs above)
const {
  verifyKidHmac,
  verifyAlgFlexible,
  signToken,
  decodeToken,
  getPublicKeyPem,
  getPublicKeyJwk
} = require('../src/utils/jwt');

const jwt = require('jsonwebtoken');

// ─────────────────────────────────────────────────────────────────────────────
// AUTH-01: verifyKidHmac (kid-filesystem HMAC verifier)
// ─────────────────────────────────────────────────────────────────────────────

describe('AUTH-01: verifyKidHmac', () => {
  test('accepts HS256 token signed with /dev/null (empty key) — core exploit', () => {
    // The AUTH-01 exploit: forge a Manager JWT with kid=/dev/null
    // fs.readFileSync('/dev/null') → empty Buffer → empty string HMAC key
    const forgedToken = jwt.sign(
      { id: 'exploit-user', role: 'manager', email: 'mgr@test.lab' },
      Buffer.from(''),          // empty key = /dev/null content
      { algorithm: 'HS256', header: { kid: '/dev/null' } }
    );

    // verifyKidHmac reads the key from kid path (/dev/null → empty)
    // and should accept this token
    const payload = verifyKidHmac(forgedToken);
    expect(payload.role).toBe('manager');
  });

  test('rejects HS256 token with wrong key (even with kid=/dev/null)', () => {
    const wrongKeyToken = jwt.sign(
      { role: 'customer' },
      'wrong_secret',
      { algorithm: 'HS256', header: { kid: '/dev/null' } }
    );
    expect(() => verifyKidHmac(wrongKeyToken)).toThrow();
  });

  test('rejects RS256 token (wrong algorithm for this verifier)', () => {
    // signToken() uses RS256 by default
    const rsaToken = signToken({ role: 'customer' });
    // verifyKidHmac only accepts HS256/384/512
    expect(() => verifyKidHmac(rsaToken)).toThrow(/not supported by this verifier/i);
  });

  test('rejects token with no kid header', () => {
    const noKidToken = jwt.sign({ role: 'customer' }, 'secret', { algorithm: 'HS256' });
    expect(() => verifyKidHmac(noKidToken)).toThrow(/No kid/i);
  });

  test('rejects token with kid pointing to nonexistent file', () => {
    const badKidToken = jwt.sign(
      { role: 'manager' },
      'any',
      { algorithm: 'HS256', header: { kid: '/nonexistent/path/key.txt' } }
    );
    expect(() => verifyKidHmac(badKidToken)).toThrow(/Cannot load key/i);
  });

  test('rejects alg=none tokens', () => {
    // Manually craft alg=none token
    const [header, payload] = [
      Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
      Buffer.from(JSON.stringify({ role: 'manager' })).toString('base64url')
    ];
    const noneToken = `${header}.${payload}.`;
    expect(() => verifyKidHmac(noneToken)).toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// AUTH-02: verifyAlgFlexible (RSA/JWKS alg-flexible verifier)
// ─────────────────────────────────────────────────────────────────────────────

describe('AUTH-02: verifyAlgFlexible', () => {
  test('accepts normally-issued RS256 token (signed with private key)', () => {
    const token = signToken({ id: 'user1', role: 'manager' });
    const payload = verifyAlgFlexible(token);
    expect(payload.role).toBe('manager');
  });

  test('accepts HS256 token signed with RSA public key bytes — alg confusion exploit', () => {
    // AUTH-02 exploit: solver fetches /.well-known/jwks.json, reconstructs PEM,
    // signs HS256 with PEM bytes as HMAC secret
    const pubKeyPem = getPublicKeyPem();
    const forgedToken = jwt.sign(
      { id: 'exploit', role: 'manager' },
      Buffer.from(pubKeyPem),  // RSA public key bytes used as HMAC secret
      { algorithm: 'HS256' }
    );
    const payload = verifyAlgFlexible(forgedToken);
    expect(payload.role).toBe('manager');
  });

  test('rejects HS256 token signed with wrong bytes (wrong key for alg confusion)', () => {
    const wrongBytes = Buffer.from('not_the_public_key');
    const badToken = jwt.sign(
      { role: 'manager' },
      wrongBytes,
      { algorithm: 'HS256' }
    );
    expect(() => verifyAlgFlexible(badToken)).toThrow();
  });

  test('rejects kid=/dev/null trick (filesystem lookup not wired here)', () => {
    // kid=/dev/null works on AUTH-01 endpoint but NOT AUTH-02
    const auth01Token = jwt.sign(
      { role: 'manager' },
      Buffer.from(''),
      { algorithm: 'HS256', header: { kid: '/dev/null' } }
    );
    // AUTH-02 verifier uses RSA public key bytes as HMAC secret, not /dev/null
    expect(() => verifyAlgFlexible(auth01Token)).toThrow();
  });

  test('JWKS endpoint returns RSA public key with correct fields', () => {
    const jwks = getPublicKeyJwk();
    expect(jwks.keys).toHaveLength(1);
    const key = jwks.keys[0];
    expect(key.kty).toBe('RSA');
    expect(key.alg).toBe('RS256');
    expect(typeof key.n).toBe('string');
    expect(typeof key.e).toBe('string');
  });

  test('public key PEM is LF-normalized (G2 fix — byte match for alg confusion)', () => {
    const pem = getPublicKeyPem();
    // Must use LF only, never CRLF (forge emits CRLF by default pre-fix)
    expect(pem).not.toContain('\r\n');
    expect(pem).toContain('\n');
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----/);
    expect(pem).toMatch(/-----END PUBLIC KEY-----\n?$/);
  });

  test('rejects alg=none tokens', () => {
    const [h, p] = [
      Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url'),
      Buffer.from(JSON.stringify({ role: 'manager' })).toString('base64url')
    ];
    expect(() => verifyAlgFlexible(`${h}.${p}.`)).toThrow();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Verifier separation — AUTH-01 and AUTH-02 are mutually exclusive
// ─────────────────────────────────────────────────────────────────────────────

describe('JWT verifier separation (AUTH-01 vs AUTH-02)', () => {
  test('AUTH-01 exploit token rejected by AUTH-02 verifier', () => {
    const auth01Token = jwt.sign(
      { role: 'manager' },
      Buffer.from(''),
      { algorithm: 'HS256', header: { kid: '/dev/null' } }
    );
    // AUTH-02 uses RSA public key as HMAC — empty key token must fail
    expect(() => verifyAlgFlexible(auth01Token)).toThrow();
  });

  test('AUTH-02 exploit token rejected by AUTH-01 verifier', () => {
    const pubKeyPem = getPublicKeyPem();
    const auth02Token = jwt.sign(
      { role: 'manager' },
      Buffer.from(pubKeyPem),
      { algorithm: 'HS256' }
    );
    // AUTH-01 would need kid pointing to a file with the PEM content,
    // and the token has no kid → throws 'No kid'
    expect(() => verifyKidHmac(auth02Token)).toThrow();
  });
});
