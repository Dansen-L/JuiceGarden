/**
 * JWT utilities for Garden Fresh.
 *
 * Two distinct verifier architectures (by design — must NOT be merged):
 *
 *   verifyKidHmac(token) — AUTH-01 endpoint verifier
 *     Uses the `kid` header to locate the HMAC signing key on the filesystem.
 *     Exploit: kid=/dev/null → key is empty string → forged JWT with empty HMAC key.
 *     RSA/JWKS tokens REJECTED here (wrong verifier architecture).
 *
 *   verifyAlgFlexible(token) — AUTH-02 endpoint verifier
 *     Resolves signing key from /.well-known/jwks.json.
 *     When JWT's alg is HS256, uses RSA public key bytes as HMAC secret.
 *     Exploit: RS256→HS256 alg confusion.
 *     kid filesystem lookup NOT wired here; kid=/dev/null REJECTED.
 */
'use strict';

const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');

// RSA key pair — generated once at startup
let rsaPrivateKey = null;
let rsaPublicKey = null;
let rsaPublicKeyPem = null;

function generateRsaKeyPair() {
  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, e: 0x10001 });
  rsaPrivateKey = forge.pki.privateKeyToPem(keypair.privateKey);
  rsaPublicKey = forge.pki.publicKeyToPem(keypair.publicKey);
  // Normalize to LF-only line endings so that Buffer.from(rsaPublicKeyPem) bytes
  // match what any standard JWK-to-PEM reconstruction tool produces.
  // Forge emits CRLF; solvers converting the JWKS n/e back to PEM get LF.
  rsaPublicKeyPem = rsaPublicKey.replace(/\r\n/g, '\n');
  return { private: rsaPrivateKey, public: rsaPublicKeyPem };
}

// Generate key pair at module load
generateRsaKeyPair();

// Save public key for JWKS endpoint
function getPublicKeyPem() {
  return rsaPublicKeyPem;
}

function getPublicKeyJwk() {
  // Minimal JWK representation for RSA public key
  const pubKey = forge.pki.publicKeyFromPem(rsaPublicKeyPem);
  const n = Buffer.from(pubKey.n.toByteArray()).toString('base64url');
  const e = Buffer.from(pubKey.e.toByteArray()).toString('base64url');
  return {
    keys: [{
      kty: 'RSA',
      use: 'sig',
      alg: 'RS256',
      kid: 'garden-rsa-1',
      n: n,
      e: e
    }]
  };
}

/**
 * AUTH-01 verifier: kid-filesystem HMAC verifier ONLY.
 * Loads signing key from the path named in JWT kid header.
 * kid=/dev/null → empty string → forged token accepted.
 * RSA/JWKS tokens REJECTED.
 */
function verifyKidHmac(token) {
  // Decode header without verification to get kid
  let decoded;
  try {
    decoded = jwt.decode(token, { complete: true });
  } catch (e) {
    throw new Error('Invalid token format');
  }

  if (!decoded) throw new Error('Invalid token');

  const header = decoded.header;

  // Reject non-HMAC algorithms
  if (!['HS256', 'HS384', 'HS512'].includes(header.alg)) {
    throw new Error('Algorithm not supported by this verifier');
  }

  // alg=none: always reject
  if (header.alg === 'none') {
    throw new Error('Algorithm none not permitted');
  }

  const kidPath = header.kid;
  if (!kidPath) throw new Error('No kid in token header');

  // Load key from filesystem (VULNERABILITY: attacker controls path)
  let key;
  try {
    key = fs.readFileSync(kidPath);
  } catch (e) {
    throw new Error(`Cannot load key from kid path: ${kidPath}`);
  }

  // Verify HMAC
  const payload = jwt.verify(token, key, { algorithms: ['HS256', 'HS384', 'HS512'] });
  return payload;
}

/**
 * AUTH-02 verifier: RSA/JWKS alg-flexible verifier.
 * Resolves signing key from JWKS (not filesystem).
 * When alg=HS256, uses RSA public key bytes as HMAC secret.
 * kid filesystem lookup NOT wired here.
 */
function verifyAlgFlexible(token) {
  let decoded;
  try {
    decoded = jwt.decode(token, { complete: true });
  } catch (e) {
    throw new Error('Invalid token format');
  }

  if (!decoded) throw new Error('Invalid token');

  const header = decoded.header;

  // alg=none: always reject
  if (header.alg === 'none') {
    throw new Error('Algorithm none not permitted');
  }

  // Only accept RS256 or HS256
  if (!['RS256', 'HS256'].includes(header.alg)) {
    throw new Error('Algorithm not supported');
  }

  if (header.alg === 'RS256') {
    // Verify using RSA public key
    const payload = jwt.verify(token, rsaPublicKeyPem, { algorithms: ['RS256'] });
    return payload;
  } else if (header.alg === 'HS256') {
    // VULNERABILITY: alg confusion — uses RSA public key bytes as HMAC secret.
    // Implemented via raw crypto because jsonwebtoken v9 rejects PEM-shaped Buffers
    // for HS256 (symmetric-key guard). Raw HMAC-SHA256 reproduces the exploit path:
    //   attacker fetches /.well-known/jwks.json → reconstructs PEM → signs HS256 with PEM bytes.
    const crypto = require('crypto');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');
    const [headerB64, payloadB64, sigB64] = parts;
    const signingInput = `${headerB64}.${payloadB64}`;
    const expectedSig = crypto
      .createHmac('sha256', Buffer.from(rsaPublicKeyPem))
      .update(signingInput)
      .digest('base64url');
    if (expectedSig !== sigB64) {
      const err = new Error('Invalid signature');
      err.name = 'JsonWebTokenError';
      throw err;
    }
    // Validate expiry if present
    let payload;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch (e) {
      throw new Error('Invalid token payload');
    }
    if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) {
      const err = new Error('jwt expired');
      err.name = 'TokenExpiredError';
      throw err;
    }
    return payload;
  }
}

/**
 * Sign a JWT with the RSA private key (RS256) — used for normal auth tokens.
 */
function signToken(payload, options = {}) {
  const keyId = options.kid || path.join('/app/keys', 'hmac.key');
  return jwt.sign(payload, rsaPrivateKey, {
    algorithm: 'RS256',
    expiresIn: '24h',
    header: { kid: keyId }
  });
}

/**
 * Decode a JWT without verification (for reading payload).
 */
function decodeToken(token) {
  return jwt.decode(token, { complete: true });
}

// Ensure HMAC key file exists for AUTH-01 demonstration
function ensureHmacKey() {
  const keyDir = '/app/keys';
  const keyPath = path.join(keyDir, 'hmac.key');
  fs.mkdirSync(keyDir, { recursive: true });
  if (!fs.existsSync(keyPath)) {
    const key = require('crypto').randomBytes(32).toString('hex');
    fs.writeFileSync(keyPath, key, { mode: 0o600 });
  }
}

ensureHmacKey();

module.exports = {
  verifyKidHmac,
  verifyAlgFlexible,
  signToken,
  decodeToken,
  getPublicKeyPem,
  getPublicKeyJwk,
};
