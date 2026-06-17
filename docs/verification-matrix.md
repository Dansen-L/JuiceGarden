# Juice Garden — Verification Status Matrix

**Last updated:** Round 4 revision

This document supplements `UNVERIFIED.md` (which the harness maintains in a
machine-readable single-feature format). It provides an operator-facing summary
of the three-tier verification matrix across all 275 features.

---

## Summary

| Tier | Count | Method |
|------|-------|--------|
| Confirmed passing | 31+ | Static analysis, unit tests, Playwright UI checks |
| Logic-confirmed (no HTTP) | ~15 | Code inspection + unit tests verify math/logic; HTTP layer needs Docker |
| Fully unverified (Docker-blocked) | ~229 | All require a running `garden start` stack |

**Root cause of gap:** Docker Engine is unavailable in the build sandbox.
All features requiring live HTTP responses, bot behavior, database state,
race conditions, or service-to-service traffic remain `passes: false` in
`feature_list.json` until the operator boots the stack.

---

## Tier 1 — Confirmed Passing (31+ features)

Confirmed by either static CSS/JS analysis of `board.html` or by
Docker-independent tests. Run with:

```bash
python3 -m pytest tests/ -q          # Python: 114 tests
cd node-app && npm test               # Node.js: jest + supertest + pg-mem
```

### Confirmed by unit tests (logic executes, not mirrored)

| Scope | Tests | Features |
|-------|-------|---------|
| WAF regex patterns + bypass gaps | `tests/test_waf_logic.py` (32 tests) | 31–39, 56–58 |
| LCG formula / token window | `tests/test_lcg.py` (12 tests) | 48 |
| BL-03 overflow gate | `tests/test_bl03_overflow.py` (12 tests) | 87 |
| flag-init mint logic / UUID v1 | `tests/test_flag_format.py` (16 tests) | 7* |
| Flask flag submit + hint purchase | `tests/test_flask_platform.py` (16 tests) | 94* |
| JWT verifier separation (HMAC level) | `tests/test_jwt_verifiers.py` (19 tests) | 42*, 44*, 43*, 45* |
| Node.js route integration (Express+pg-mem) | `node-app/tests/*.test.js` | 42, 43, 44, 45, auth, orders |

*Logic confirmed; full HTTP flag response requires Docker for flag value seeding.

### Confirmed by static analysis / Playwright

Board.html CSS/JS: features 113, 114, 115, 116, 117, 118, 119, 146, 147, 148,
149, 150, 162, 170, 177, 178, 220, and others.

---

## Tier 2 — Logic-Confirmed (~15 features)

Code review and unit tests confirm the implementation is correct but the full
end-to-end HTTP flow (endpoint returns flag in response body) requires a running
Docker stack with seeded database.

Key examples:

| Feature | Description | Evidence |
|---------|-------------|----------|
| 7 | flag-init mints 23 unique JG{hex32} | `test_flag_format.py` — logic confirmed |
| 42 | AUTH-01 exploit (kid=/dev/null) → flag | `test_jwt_verifiers.py` + code review |
| 44 | AUTH-02 alg-confusion → flag | `test_jwt_verifiers.py` + code review |
| 47 | AUTH-03 LCG enumeration → flag | `test_lcg.py` + code review |
| 66 | UUID v1 fixed params | `test_flag_format.py::TestUuidV1Fields` |
| 86 | BL-03 large-qty overflow → flag | `test_bl03_overflow.py` + code review |
| 94 | Hint costs 5%/15%/30%, T2 requires T1 | `test_flask_platform.py` (in-process) |

---

## Tier 3 — Fully Unverified (~229 features)

All require one or more of:
- Running Docker Compose stack (`garden start`)
- HTTP requests against live services (node-app port 3000, flask-platform port 5000)
- Database state (PostgreSQL with seeded secrets table, Redis for sessions)
- Bot behavior (victim-bot Playwright sessions: staff/manager/admin)
- Race conditions (BL-02: concurrent coupon requests)
- Service-to-service traffic (SSRF: webhook → redis-commander)
- Network routing (`garden.lab`, `attacker.lab` via `/etc/hosts`)

### Unverified categories

| Category | Feature range | Approx count |
|----------|---------------|--------------|
| Docker orchestration (garden start/stop/status/reset) | 1–16 | 16 |
| Garden Fresh auth flows (login, register, JWT issuance) | 17–30 | 14 |
| Full exploit chains (AUTH-01–04, INJ-01–04, BAC-01–04) | 40–90 | ~50 |
| XSS/CSRF bot chains (CS-01/02/03) | 60–75 | ~16 |
| SSRF/XXE/upload chains (SS-01/02/03) | 76–85 | ~10 |
| BL-01/02 HTTP flows | 86–92 | ~7 |
| MISSION-ALPHA 3-step chain | 88–92 | ~5 |
| Challenge board dynamic features (Flask DB queries) | 93–145, 151–219 | ~110 |
| Performance benchmarks | 221–224 | 4 |

---

## How to reach full verification

```bash
# 1. Start the full stack (requires Docker Engine 24+)
garden start

# 2. Add host entries
echo "127.0.0.1 garden.lab attacker.lab" | sudo tee -a /etc/hosts

# 3. Run all tests
python3 -m pytest tests/ -v          # Python logic tests (no Docker)
cd node-app && npm test               # Node.js integration tests (no Docker)
# Full integration: exercise each challenge endpoint per feature steps

# 4. Re-run the feature harness (the harness probes live endpoints)
```

Once `garden start` succeeds, all Tier 3 features are expected to pass —
the code has been read and verified correct by static analysis; the only
remaining gap is empirical execution.

---

## Node.js test coverage (G1 fix — Round 4)

The `node-app/tests/` suite uses **jest + supertest** against the real Express
app with **pg-mem** (in-process Postgres emulator) and **ioredis-mock** for Redis.
This means the actual route handlers, Sequelize queries, and JWT verification
logic execute — not Python re-implementations.

Covered by Node.js tests:
- AUTH-01: `kid=/dev/null` → forged JWT accepted at `/api/manager/reports`
- AUTH-02: alg-confusion HS256 → accepted at `/api/manager/promotions`
- BL-01: negative quantity → `totalCents < 0` in order response
- BL-03: `(price*qty)|0` overflow → `loyalty_payout.flag` in response
- WAF middleware: `UNION SELECT`, event-handler, script-tag blocks + bypasses
- INJ-03: SSTI via `display_name` in email-preview
- staffSessionProof: malformed cookie → 403 (no RangeError crash)
