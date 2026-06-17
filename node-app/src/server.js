/**
 * Garden Fresh — Main Server Entry Point
 * Juice Bar Delivery SaaS (Vulnerable Lab Application)
 */
'use strict';

const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const { sequelize, initDb } = require('./models');
const { redisClient, RedisStore } = require('./utils/redis');
const { loadFlags } = require('./utils/flags');

const app = express();
const PORT = process.env.PORT || 3000;

// ──────────────────────────────────────────────
// Health endpoint — registered FIRST, before session/Redis middleware,
// so Docker health checks never wait on Redis and always get a fast 200.
// ──────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'garden-fresh' });
});

// ──────────────────────────────────────────────
// Body parsing
// ──────────────────────────────────────────────
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(cookieParser());

// ──────────────────────────────────────────────
// WAF-lite middleware (Garden Fresh routes only)
// Handles body-based WAF checks that nginx can't easily do
// ──────────────────────────────────────────────
const { wafMiddleware } = require('./middleware/waf');
app.use(wafMiddleware);

// ──────────────────────────────────────────────
// Static files
// ──────────────────────────────────────────────
app.use('/static', express.static(path.join(__dirname, 'static')));
app.use('/uploads', express.static('/app/uploads'));

// ──────────────────────────────────────────────
// Session configuration
// ──────────────────────────────────────────────
const sameSite = process.env.SESSION_SAMESITE || 'Lax';

// CS-01 DELIBERATE FLAW: session cookie is NOT HttpOnly so JavaScript can read it.
// An XSS payload on /reviews (JSONP CSP-bypass) can exfiltrate the admin session.
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: false,   // deliberate flaw — session cookie readable by JS (CS-01)
    sameSite: sameSite,
    maxAge: 24 * 60 * 60 * 1000  // 24h
  }
}));

// ──────────────────────────────────────────────
// CSRF synchronizer-token middleware
// Generates a per-session token on every request (no-op if already set).
// Token is embedded in HTML forms as a hidden field and verified on
// protected POST endpoints (see middleware/csrf.js).
// ──────────────────────────────────────────────
const { ensureCsrfToken } = require('./middleware/csrf');
app.use(ensureCsrfToken);

// ──────────────────────────────────────────────
// View engine (EJS for email-preview template — INJ-03)
// ──────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ──────────────────────────────────────────────
// Routes
// ──────────────────────────────────────────────
const authRoutes = require('./routes/auth');
const productRoutes = require('./routes/products');
const orderRoutes = require('./routes/orders');
const userRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');
const staffRoutes = require('./routes/staff');
const managerRoutes = require('./routes/manager');
const webhookRoutes = require('./routes/webhooks');
const graphqlRouter = require('./routes/graphql');
const challengeRoutes = require('./routes/challenges');
const debugRoutes = require('./routes/debug');

app.use('/api/auth', authRoutes);
app.use('/api/products', productRoutes);
app.use('/api/orders', orderRoutes);
app.use('/api/user', userRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/staff', staffRoutes);
app.use('/api/manager', managerRoutes);
app.use('/api/webhooks', webhookRoutes);
// Mount at both /graphql (spec evaluator canonical path) and /api/graphql (API convention)
app.use('/graphql', graphqlRouter);
app.use('/api/graphql', graphqlRouter);
app.use('/api/challenges', challengeRoutes);
app.use('/api/debug', debugRoutes);

// ──────────────────────────────────────────────
// Frontend pages
// ──────────────────────────────────────────────
const pageRoutes = require('./routes/pages');
app.use('/', pageRoutes);

// ──────────────────────────────────────────────
// CSRF token endpoint — returns the session's current CSRF token.
// Used by programmatic clients (e2e scripts, API tools) that need
// to obtain a token before POSTing to a CSRF-protected endpoint.
// ──────────────────────────────────────────────
app.get('/api/csrf-token', (req, res) => {
  const token = req.session && req.session.csrfToken;
  if (!token) return res.status(503).json({ error: 'Session unavailable' });
  res.json({ csrf_token: token });
});

// ──────────────────────────────────────────────
// Error handler
// ──────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// ──────────────────────────────────────────────
// Startup
// ──────────────────────────────────────────────
async function start() {
  try {
    // Load flags from flag-data volume
    await loadFlags();

    // Connect to DB and run migrations/seed
    await initDb();

    // ──────────────────────────────────────────────
    // SS-01: Seed Redis key with ss01 flag value
    // The flag is stored in Redis so that redis-commander (internal, port 8081)
    // exposes it. SSRF via POST /api/webhooks/test reaches redis-commander and
    // the response body leaks the flag.
    // ──────────────────────────────────────────────
    const { getFlag } = require('./utils/flags');
    const { redisClient } = require('./utils/redis');
    try {
      const ss01Flag = getFlag('ss01');
      if (ss01Flag) {
        // Wait briefly for Redis to be connected
        await new Promise(resolve => setTimeout(resolve, 500));
        await redisClient.set('garden:ss01_flag', ss01Flag);
        await redisClient.set('garden:internal_config', JSON.stringify({
          ss01: ss01Flag,
          note: 'Internal config — not for external access'
        }));
        console.log('[garden-fresh] SS-01 flag seeded to Redis');
      }
    } catch (redisErr) {
      console.warn('[garden-fresh] Redis seed skipped:', redisErr.message);
    }

    // Start listening
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[garden-fresh] Listening on port ${PORT}`);
      console.log(`[garden-fresh] SESSION_SAMESITE=${sameSite}`);
    });
  } catch (err) {
    console.error('[garden-fresh] Startup failed:', err);
    process.exit(1);
  }
}

start();
