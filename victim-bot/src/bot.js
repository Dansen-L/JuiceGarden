/**
 * Juice Garden Victim Bot
 *
 * Simulates three staff/bot accounts with scheduled behaviors:
 *
 * staff_bot  — every 60s: axios POST /api/staff/report
 *              (triggers INJ-01 second-order SQLi if malicious username registered)
 *
 * manager_bot — every 30s: axios GET /api/manager/reviews → approve all pending
 *               (CS-01: approves XSS payloads for admin_bot to encounter)
 *
 * admin_bot  — every 30s: login → product reviews page
 *              (CS-01 XSS fires if approved payload is present)
 *              admin_bot session cookie is NOT HttpOnly (CS-01 flaw)
 *
 * URL queue  — every 30s: dequeue up to 3 URLs and visit each in admin_bot session
 *              (CS-02 attack pages; CS-03 CSRF attack pages)
 *
 * Session caching: all four bot accounts share a 4-minute cookie/token cache.
 * This keeps total logins well under the rate-limit threshold.
 *
 * Chromium is launched with:
 *   --host-resolver-rules="MAP garden.lab nginx, MAP attacker.lab nginx"
 * This directs garden.lab and attacker.lab traffic to the nginx container
 * while preserving the original hostname in the Host header and document origin.
 */
'use strict';

const { chromium } = require('playwright');
const axios = require('axios');
const fs = require('fs');

const GARDEN_URL = process.env.GARDEN_URL || 'http://garden.lab:80';
const PLATFORM_URL = process.env.PLATFORM_URL || 'http://nginx/platform';
const NGINX_HOST = 'nginx';  // Docker Compose service name for nginx

const STAFF_BOT_EMAIL = process.env.STAFF_BOT_EMAIL || 'staff.bot@garden.lab';
const STAFF_BOT_PASSWORD = process.env.STAFF_BOT_PASSWORD || 'StaffBot2024!';
const MANAGER_BOT_EMAIL = process.env.MANAGER_BOT_EMAIL || 'manager.bot@garden.lab';
const MANAGER_BOT_PASSWORD = process.env.MANAGER_BOT_PASSWORD || 'ManagerBot2024!';
const ADMIN_BOT_EMAIL = process.env.ADMIN_BOT_EMAIL || 'admin.bot@garden.lab';
const ADMIN_BOT_PASSWORD = process.env.ADMIN_BOT_PASSWORD || 'AdminBot2024!';

// Chromium launch args — host resolver maps garden.lab and attacker.lab to nginx
const CHROMIUM_ARGS = [
  '--no-sandbox',
  '--disable-setuid-sandbox',
  '--disable-dev-shm-usage',
  '--host-resolver-rules=MAP garden.lab nginx, MAP attacker.lab nginx',
];

// ──────────────────────────────────────────────
// Unified session cache — shared across all bot cycles.
// Stores cookies (for Playwright storageState) and JWT (for API auth headers).
// TTL is shorter than the server session lifetime so we re-login before expiry.
// ──────────────────────────────────────────────
const _botSessions = {};  // email → { cookies, token, expiry }
const BOT_SESSION_TTL = 4 * 60 * 1000; // 4 minutes

async function getBotSession(email, password) {
  const now = Date.now();
  const cached = _botSessions[email];
  if (cached && now < cached.expiry) {
    return cached;
  }
  const loginResp = await axios.post(
    `http://${NGINX_HOST}/api/auth/login`,
    { email, password },
    { timeout: 10000 }
  );
  const rawSetCookie = loginResp.headers['set-cookie'] || [];
  const cookies = rawSetCookie
    .map(raw => {
      const [nameValue] = raw.split(';');
      const eqIdx = nameValue.indexOf('=');
      return {
        name:  nameValue.substring(0, eqIdx).trim(),
        value: nameValue.substring(eqIdx + 1).trim(),
        url:   'http://garden.lab'
      };
    })
    .filter(c => c.name && c.value);
  const token = loginResp.data && loginResp.data.token ? loginResp.data.token : null;
  const session = { cookies, token, expiry: now + BOT_SESSION_TTL };
  _botSessions[email] = session;
  return session;
}

// Concurrency guard: prevents overlapping queue-processor cycles from launching
// multiple Chromium instances simultaneously (resource exhaustion / OOM risk)
let _queueProcessorRunning = false;

// Path written after each successful Chromium launch.
// Healthcheck asserts this file exists and is recent.
const BROWSER_LIVENESS_FILE = '/tmp/playwright_ok';

async function createBrowser() {
  const browser = await chromium.launch({
    headless: true,
    args: CHROMIUM_ARGS
  });
  // Record a successful browser launch for the healthcheck
  try { fs.writeFileSync(BROWSER_LIVENESS_FILE, String(Date.now())); } catch (_) {}
  return browser;
}

// ──────────────────────────────────────────────
// staff_bot behavior (every 60s)
// Login → POST /api/staff/report (triggers INJ-01 second-order SQLi)
// Uses axios only — no browser required
// ──────────────────────────────────────────────
async function staffBotCycle() {
  try {
    const session = await getBotSession(STAFF_BOT_EMAIL, STAFF_BOT_PASSWORD);
    if (!session.token) {
      console.error('[staff_bot] Login returned no token');
      return;
    }
    await axios.post(
      `http://${NGINX_HOST}/api/staff/report`,
      {},
      {
        headers: { Authorization: 'Bearer ' + session.token },
        timeout: 15000
      }
    );
    console.log('[staff_bot] Report cycle complete');
  } catch (err) {
    console.error('[staff_bot] Error:', err.message);
  }
}

// ──────────────────────────────────────────────
// manager_bot behavior (every 30s)
// Login → review management → approve all pending reviews
// Uses axios only — no browser required
// ──────────────────────────────────────────────
async function managerBotCycle() {
  try {
    const session = await getBotSession(MANAGER_BOT_EMAIL, MANAGER_BOT_PASSWORD);
    if (!session.token) {
      console.error('[manager_bot] Login returned no token');
      return;
    }
    const token = session.token;

    const resp = await axios.get(`http://${NGINX_HOST}/api/manager/reviews`, {
      headers: { Authorization: 'Bearer ' + token },
      timeout: 5000
    });
    const reviews = resp.data.reviews || [];

    for (const review of reviews) {
      await axios.post(
        `http://${NGINX_HOST}/api/manager/reviews/${review.id}/approve`,
        {},
        {
          headers: { Authorization: 'Bearer ' + token },
          timeout: 3000
        }
      );
    }
    console.log(`[manager_bot] Approved ${reviews.length} review(s)`);
  } catch (err) {
    console.error('[manager_bot] Error:', err.message);
  }
}

// ──────────────────────────────────────────────
// admin_bot behavior (every 30s)
// Login → product reviews page (CS-01 XSS fires if approved payload present)
// admin_bot session cookie is NOT HttpOnly (deliberate flaw — CS-01)
// ──────────────────────────────────────────────
async function adminBotCycle() {
  let browser;
  try {
    const session = await getBotSession(ADMIN_BOT_EMAIL, ADMIN_BOT_PASSWORD);
    if (session.cookies.length === 0) {
      console.error('[admin_bot] Login returned no cookies');
      return;
    }

    browser = await createBrowser();
    const context = await browser.newContext({
      storageState: { cookies: session.cookies, origins: [] }
    });

    // Navigate to product reviews page (CS-01 fires here)
    try {
      const reviewsPage = await context.newPage();
      await reviewsPage.goto(`${GARDEN_URL}/reviews`, {
        waitUntil: 'networkidle',
        timeout: 20000
      });
      console.log('[admin_bot] Visited reviews page');
      await reviewsPage.close().catch(() => {});
    } catch (err) {
      console.error('[admin_bot] Reviews page error (non-fatal):', err.message);
    }
  } catch (err) {
    console.error('[admin_bot] Error:', err.message);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

// ──────────────────────────────────────────────
// URL queue processor cycle (every 30s)
// Obtains admin session via shared cache, visits each pending URL
// in a Playwright browser context pre-loaded with admin cookies.
// ──────────────────────────────────────────────
async function queueProcessorCycle() {
  // Concurrency guard: skip this cycle if a previous one is still running
  if (_queueProcessorRunning) {
    console.log('[queue-processor] Previous cycle still running — skipping');
    return;
  }
  _queueProcessorRunning = true;
  try {
    await _queueProcessorCycleInner();
  } finally {
    _queueProcessorRunning = false;
  }
}

async function _queueProcessorCycleInner() {
  // Step 1 — fetch pending entries without opening a browser at all
  let entries;
  try {
    const r = await axios.get(`${PLATFORM_URL}/exploit-server/queue/pending`, { timeout: 5000 });
    entries = (r.data || []).slice(0, 3);
  } catch (err) {
    console.error('[queue-processor] Queue fetch error:', err.message);
    return;
  }
  if (entries.length === 0) return;

  // Step 2 — obtain admin session cookie via shared cache (no login if still valid)
  let adminCookies;
  try {
    const session = await getBotSession(ADMIN_BOT_EMAIL, ADMIN_BOT_PASSWORD);
    adminCookies = session.cookies;
    if (adminCookies.length === 0) {
      console.error('[queue-processor] Login returned no cookies');
      return;
    }
  } catch (err) {
    console.error('[queue-processor] Admin login error:', err.message);
    return;
  }

  // Step 3 — visit each URL in a browser context pre-loaded with the admin cookie
  let browser;
  try {
    browser = await createBrowser();
    const context = await browser.newContext({
      storageState: { cookies: adminCookies, origins: [] }
    });
    for (const entry of entries) {
      const page = await context.newPage();
      try {
        console.log(`[bot-queue] Visiting: ${entry.url}`);
        await page.goto(entry.url, { waitUntil: 'networkidle', timeout: 20000 });
        await axios.post(
          `${PLATFORM_URL}/exploit-server/queue/${entry.id}/mark-visited`,
          {},
          { timeout: 3000 }
        );
        console.log(`[bot-queue] Visited entry ${entry.id}`);
      } catch (visitErr) {
        console.error(`[bot-queue] Error visiting ${entry.url}:`, visitErr.message);
        await axios.post(
          `${PLATFORM_URL}/exploit-server/queue/${entry.id}/mark-visited`,
          {},
          { timeout: 3000 }
        ).catch(() => {});
      } finally {
        await page.close().catch(() => {});
      }
    }
  } catch (err) {
    // Browser failed to launch — entries are NOT marked visited.
    // Leaving them pending ensures the queue reflects real visit status and
    // that a healthcheck-visible liveness failure surfaces the breakage.
    console.error('[queue-processor] Browser launch FAILED — entries remain pending:', err.message);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

// ──────────────────────────────────────────────
// Scheduled timers
// ──────────────────────────────────────────────
async function main() {
  console.log('[victim-bot] Starting up...');
  console.log(`[victim-bot] GARDEN_URL=${GARDEN_URL}`);

  // Wait for garden-fresh to be ready
  let ready = false;
  for (let i = 0; i < 30; i++) {
    try {
      await axios.get(`http://node-app:3000/health`, { timeout: 3000 });
      ready = true;
      break;
    } catch (e) {
      console.log(`[victim-bot] Waiting for node-app... (${i + 1}/30)`);
      await sleep(2000);
    }
  }

  if (!ready) {
    console.error('[victim-bot] node-app did not become ready');
    process.exit(1);
  }

  console.log('[victim-bot] node-app is ready. Starting bot cycles.');

  // Initial cycle delay to let sessions stabilize
  await sleep(5000);

  // Run initial cycles sequentially so staff/manager (axios-only) complete first,
  // then admin and queue each launch one Chromium instance with a gap between them
  await staffBotCycle();
  await managerBotCycle();
  await sleep(2000);
  await adminBotCycle();
  await sleep(3000);
  await queueProcessorCycle();

  // Schedule recurring cycles with offsets so browser-requiring cycles
  // (admin and queue) do not fire simultaneously
  setInterval(staffBotCycle, 60 * 1000);           // every 60s (offset: 0s)
  setInterval(managerBotCycle, 30 * 1000);         // every 30s (offset: 0s)
  setTimeout(() => setInterval(adminBotCycle, 30 * 1000), 10 * 1000);    // every 30s (offset: 10s)
  setTimeout(() => setInterval(queueProcessorCycle, 30 * 1000), 20 * 1000); // every 30s (offset: 20s)

  console.log('[victim-bot] All bot cycles scheduled.');

  // Keep-alive — process stays running
  // Health check: pgrep will find this node process
  setInterval(() => {
    // no-op heartbeat
  }, 60 * 1000);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

main().catch(err => {
  console.error('[victim-bot] Fatal error:', err);
  process.exit(1);
});
