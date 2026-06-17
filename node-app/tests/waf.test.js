/**
 * waf.test.js — Integration tests for the WAF middleware.
 *
 * Tests execute the ACTUAL wafMiddleware from waf.js via a minimal Express app
 * (no database, no Redis) using supertest. This tests real JS, not a Python mirror.
 */
'use strict';

const express = require('express');
const request = require('supertest');
const { wafMiddleware } = require('../src/middleware/waf');

// Minimal Express app: just WAF + a catch-all that returns 200
function makeApp() {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.use(wafMiddleware);
  app.use((req, res) => res.status(200).json({ ok: true }));
  return app;
}

const app = makeApp();

// ─────────────────────────────────────────────────────────────────────────────
// SQLi: ' OR
// ─────────────────────────────────────────────────────────────────────────────

describe("WAF SQLi ' OR rule", () => {
  test("blocks basic ' OR in JSON body", async () => {
    const res = await request(app)
      .post('/api/orders/search')
      .send({ query: "x' OR 1=1" });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_SQLI');
  });

  test("blocks ' or (lowercase) in body", async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "' or 1=1" });
    expect(res.status).toBe(403);
  });

  test("does NOT block plain OR without apostrophe", async () => {
    const res = await request(app)
      .post('/test')
      .send({ text: "OR 1=1" });
    expect(res.status).toBe(200);
  });

  test("does NOT block boolean-blind AND 1=1 (WAF intentional scope)", async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "1 AND 1=1--" });
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// SQLi: UNION SELECT + bypass gaps
// ─────────────────────────────────────────────────────────────────────────────

describe('WAF UNION SELECT rule and documented bypass gaps', () => {
  test('blocks UNION SELECT with space (exact case)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "x UNION SELECT 1,2,3" });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_SQLI');
  });

  test('blocks UNION ALL SELECT', async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "x UNION ALL SELECT 1,2" });
    expect(res.status).toBe(403);
  });

  test('blocks UNION<tab>SELECT', async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "UNION\tSELECT 1,2" });
    expect(res.status).toBe(403);
  });

  // Feature 56: inline-comment bypass
  test('feature 56: UNION/**/SELECT NOT blocked (comment bypass)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "UNION/**/SELECT 1,2" });
    expect(res.status).toBe(200);
  });

  // Feature 57: newline bypass
  test('feature 57: UNION\\nSELECT NOT blocked (newline bypass)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "UNION\nSELECT 1,2" });
    expect(res.status).toBe(200);
  });

  // Feature 58: case-mangling bypass
  test('feature 58: UnIoN SeLeCt NOT blocked (case bypass)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ q: "UnIoN SeLeCt 1,2" });
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Script tag rule
// ─────────────────────────────────────────────────────────────────────────────

describe('WAF script tag rule', () => {
  test('blocks inline script tag', async () => {
    const res = await request(app)
      .post('/test')
      .send({ content: "<script>alert(1)</script>" });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_SCRIPT');
  });

  test('blocks external https:// script src', async () => {
    const res = await request(app)
      .post('/test')
      .send({ content: '<script src="https://evil.com/x.js">' });
    expect(res.status).toBe(403);
  });

  test('blocks protocol-relative // script src', async () => {
    const res = await request(app)
      .post('/test')
      .send({ content: '<script src="//evil.com/x.js">' });
    expect(res.status).toBe(403);
  });

  test('PERMITS same-origin path script src (CS-01 JSONP vector)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ content: '<script src="/api/products/search?callback=fn">' });
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Event handler rule
// ─────────────────────────────────────────────────────────────────────────────

describe('WAF event handler rule', () => {
  test('blocks onerror= in body', async () => {
    const res = await request(app)
      .post('/test')
      .send({ html: '<img src=x onerror=alert(1)>' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_EVTHANDLER');
  });

  test('blocks onerror = with space before equals (G4-R1 fix)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ html: '<img onerror =alert(1)>' });
    expect(res.status).toBe(403);
  });

  test('blocks onload= in body', async () => {
    const res = await request(app)
      .post('/test')
      .send({ html: '<body onload=init()>' });
    expect(res.status).toBe(403);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// XXE rule
// ─────────────────────────────────────────────────────────────────────────────

describe('WAF XXE rule', () => {
  test('blocks ENTITY with https:// URI', async () => {
    const res = await request(app)
      .post('/test')
      .send({ xml: '<!ENTITY xxe SYSTEM "https://evil.com">' });
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_XXE');
  });

  test('blocks ENTITY with http:// URI', async () => {
    const res = await request(app)
      .post('/test')
      .send({ xml: '<!ENTITY xxe SYSTEM "http://evil.com">' });
    expect(res.status).toBe(403);
  });

  test('PERMITS ENTITY with file:// URI (SS-02 exploit vector)', async () => {
    const res = await request(app)
      .post('/test')
      .send({ xml: '<!ENTITY xxe SYSTEM "file:///etc/passwd">' });
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Query string checks
// ─────────────────────────────────────────────────────────────────────────────

describe('WAF query string checks', () => {
  test("blocks ' OR in query string", async () => {
    const res = await request(app)
      .get("/test?q=x' OR 1=1");
    expect(res.status).toBe(403);
  });

  test('blocks UNION SELECT in query string', async () => {
    const res = await request(app)
      .get('/test?q=UNION SELECT 1');
    expect(res.status).toBe(403);
  });

  test('skips WAF for /platform/ routes', async () => {
    // /platform/ is excluded from WAF (nginx never forwards it through waf)
    const res = await request(app)
      .post('/platform/submit-flag')
      .send({ q: "UNION SELECT 1" });
    expect(res.status).toBe(200);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Depth-limit: deeply-nested JSON must NOT bypass inspection
// ─────────────────────────────────────────────────────────────────────────────

describe('WAF depth-limit blocking', () => {
  test('blocks payload wrapped in 6+ nesting levels (WAF_DEPTH)', async () => {
    // Wrap an injection string 7 levels deep to exceed the depth cap
    const nested = { a: { b: { c: { d: { e: { f: { g: "UNION SELECT 1,2,3" } } } } } } };
    const res = await request(app)
      .post('/test')
      .send(nested);
    // Must be 403 — not 200 (silent pass)
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_DEPTH');
  });

  test('passes payload nested at exactly 5 levels (at boundary)', async () => {
    // depth=0..4 → 5 levels deep — within the limit
    const nested = { a: { b: { c: { d: { e: 'safe content' } } } } };
    const res = await request(app)
      .post('/test')
      .send(nested);
    expect(res.status).toBe(200);
  });

  test('blocks 6-level injection even without outer WAF pattern at top level', async () => {
    // Ensures depth gate fires before the inner string is inspected
    const nested = { a: { b: { c: { d: { e: { f: "' OR 1=1" } } } } } };
    const res = await request(app)
      .post('/test')
      .send(nested);
    expect(res.status).toBe(403);
    expect(res.body.code).toBe('WAF_DEPTH');
  });
});
