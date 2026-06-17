/**
 * Frontend page routes for Garden Fresh
 * CS-02: /orders/track — no nonce CSP (deliberate flaw)
 */
'use strict';

const express = require('express');
const path = require('path');
const { getFlag } = require('../utils/flags');
const { getPublicKeyJwk } = require('../utils/jwt');
const { Review } = require('../models');

const router = express.Router();

// ──────────────────────────────────────────────
// /.well-known/jwks.json — AUTH-02 key exposure
// ──────────────────────────────────────────────
router.get('/.well-known/jwks.json', (req, res) => {
  res.json(getPublicKeyJwk());
});

// ──────────────────────────────────────────────
// GET / — Garden Fresh homepage
// Normal juice bar SaaS with Recent Deliveries widget (BAC-01 anchor)
// CSP: nonce-based
// ──────────────────────────────────────────────
router.get('/', (req, res) => {
  const nonce = require('crypto').randomBytes(16).toString('base64');

  res.set('Content-Security-Policy',
    `default-src 'self'; ` +
    `script-src 'self' 'nonce-${nonce}'; ` +
    `style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ` +
    `font-src 'self' https://fonts.gstatic.com; ` +
    `connect-src 'self'; ` +
    `img-src 'self' data:; ` +
    `frame-src 'none';`
  );

  res.send(renderHomePage(nonce));
});

// ──────────────────────────────────────────────
// GET /orders/track — CS-02 DOM XSS target
// Deliberately served WITHOUT nonce-based CSP
// postMessage without origin check → innerHTML injection
// ──────────────────────────────────────────────
router.get('/orders/track', (req, res) => {
  // CS-02 FLAW: NO CSP header on this endpoint
  // Inline event handlers injected via innerHTML will execute

  const { getFlag } = require('../utils/flags');
  const cs02Flag = getFlag('cs02');

  // The admin-only flag div (only rendered if admin session)
  const isAdmin = req.session && req.session.role === 'admin';

  res.send(renderOrderTrackPage(cs02Flag, isAdmin));
});

// ──────────────────────────────────────────────
// GET /reviews — Product reviews page (CS-01 XSS fire location)
// Renders approved reviews including CS-01 XSS payloads
// CSP: nonce-based (but JSONP src-tag is in allowlist)
// ──────────────────────────────────────────────
router.get('/reviews', async (req, res) => {
  const nonce = require('crypto').randomBytes(16).toString('base64');

  // CS-01: JSONP endpoint (/api/products/search?callback=) is same-origin, permitted by 'self'
  // <script src="/api/products/search?callback=payload"> executes without a nonce
  res.set('Content-Security-Policy',
    `default-src 'self'; ` +
    `script-src 'self' 'nonce-${nonce}'; ` +
    `style-src 'self' 'unsafe-inline'; ` +
    `connect-src 'self'; ` +
    `img-src 'self' data:;`
  );

  // Fetch approved reviews server-side so <script src> payloads in review content
  // are embedded in the initial HTML parse tree and execute (innerHTML would not).
  let reviews = [];
  try {
    reviews = await Review.findAll({
      where: { approved: true },
      order: [['created_at', 'DESC']]
    });
  } catch (_) {
    // DB unavailable — render empty page
  }

  const csrfToken = req.session.csrfToken || '';
  res.send(renderReviewsPage(nonce, reviews, csrfToken));
});

// ──────────────────────────────────────────────
// Other pages
// ──────────────────────────────────────────────
router.get('/login', (req, res) => res.send(renderLoginPage(req.session.csrfToken || '')));
router.get('/register', (req, res) => res.send(renderRegisterPage(req.session.csrfToken || '')));
router.get('/menu', (req, res) => res.send(renderMenuPage()));
router.get('/orders', (req, res) => res.send(renderOrdersPage()));
router.get('/account', (req, res) => res.send(renderAccountPage()));
router.get('/staff', (req, res) => res.send(renderStaffPage()));
router.get('/manager', (req, res) => res.send(renderManagerPage()));
router.get('/admin', (req, res) => res.send(renderAdminPage()));

// ──────────────────────────────────────────────
// Page renderers (inline HTML — no template engine for static pages)
// ──────────────────────────────────────────────

function baseLayout(title, bodyContent, nonce = '', extraHead = '') {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — Garden Fresh</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Nunito', sans-serif; background: #f8f9fa; color: #333; }
    nav { position: sticky; top: 0; z-index: 100; background: #fff; border-bottom: 1px solid #e9ecef; padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
    nav .brand { font-size: 1.5rem; font-weight: 700; color: #3CAA6A; text-decoration: none; }
    nav .nav-links a { margin-left: 1.5rem; text-decoration: none; color: #555; font-weight: 600; }
    nav .nav-links a:hover { color: #3CAA6A; }
    .role-tabs { display: flex; border-bottom: 2px solid #e9ecef; margin-bottom: 2rem; }
    .role-tabs .tab { padding: 0.75rem 1.5rem; font-weight: 600; font-size: 0.95rem; cursor: pointer; color: #555; border-bottom: 3px solid transparent; margin-bottom: -2px; text-decoration: none; }
    .role-tabs .tab:hover { color: #3CAA6A; }
    .role-tabs .tab.active { color: #3CAA6A; border-bottom-color: #3CAA6A; }
    .role-panel { display: none; }
    .role-panel.active { display: block; }
    .role-badge { display: inline-block; padding: 0.2rem 0.65rem; border-radius: 99px; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
    .badge-staff { background: #e8f5ee; color: #2d8a52; }
    .badge-manager { background: #fff3e0; color: #e67e00; }
    .badge-admin { background: #fde8e8; color: #c0392b; }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    .btn { display: inline-flex; align-items: center; padding: 0.6rem 1.2rem; border-radius: 8px; font-size: 0.95rem; font-weight: 600; cursor: pointer; text-decoration: none; border: none; }
    .btn-primary { background: #3CAA6A; color: white; }
    .btn-primary:hover { background: #339959; }
    .btn-accent { background: #F5A623; color: white; }
    footer { background: #333; color: #bbb; text-align: center; padding: 2rem; margin-top: 4rem; font-size: 0.875rem; }
    ${extraHead}
  </style>
  ${nonce ? `<script nonce="${nonce}">const APP_NONCE = "${nonce}";</script>` : ''}
</head>
<body>
  <nav>
    <a href="/" class="brand">🥤 Garden Fresh</a>
    <div class="nav-links">
      <a href="/menu">Menu</a>
      <a href="/reviews">Reviews</a>
      <a href="/orders/track">Track Order</a>
      <a href="/account">Account</a>
    </div>
  </nav>
  ${bodyContent}
  <footer>
    <p>© 2024 Garden Fresh Juice Bar — Fresh. Local. Delivered.</p>
  </footer>
</body>
</html>`;
}

function renderHomePage(nonce) {
  return baseLayout('Home', `
  <section style="background: linear-gradient(135deg, #3CAA6A, #2d8a52); color: white; padding: 4rem 2rem; text-align: center;">
    <h1 style="font-size: 3rem; margin-bottom: 1rem;">Fresh Juices, Delivered Daily</h1>
    <p style="font-size: 1.25rem; opacity: 0.9; margin-bottom: 2rem;">Cold-pressed, organic, delivered to your door in under an hour.</p>
    <a href="/menu" class="btn btn-accent" style="font-size: 1.1rem; padding: 0.8rem 2rem;">Browse Our Menu →</a>
  </section>

  <div class="container">
    <h2 style="margin: 3rem 0 1.5rem; font-size: 1.75rem; color: #222;">Recent Deliveries</h2>
    <div id="recent-deliveries" style="background: white; border-radius: 12px; padding: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
      <p style="color: #888; font-size: 0.9rem;">Loading recent deliveries...</p>
    </div>

    <h2 style="margin: 3rem 0 1.5rem; font-size: 1.75rem; color: #222;">Our Top Products</h2>
    <div id="products" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1.5rem;">
      <p style="color: #888;">Loading products...</p>
    </div>
  </div>

  <script nonce="${nonce}">
    // Load recent deliveries (BAC-01 timestamp anchor visible here)
    fetch('/api/orders/recent')
      .then(r => r.json())
      .then(orders => {
        const el = document.getElementById('recent-deliveries');
        if (!orders.length) { el.innerHTML = '<p style="color:#888">No recent deliveries.</p>'; return; }
        el.innerHTML = '<table style="width:100%;border-collapse:collapse">' +
          '<thead><tr><th style="text-align:left;padding:0.5rem;color:#666;font-size:0.85rem">Order ID</th>' +
          '<th style="text-align:left;padding:0.5rem;color:#666;font-size:0.85rem">Delivered At</th></tr></thead>' +
          '<tbody>' + orders.map(o =>
            '<tr><td style="padding:0.5rem;font-family:monospace;font-size:0.85rem">' + o.id + '</td>' +
            '<td style="padding:0.5rem;font-size:0.85rem;color:#888">' + new Date(o.created_at).toLocaleString() + '</td></tr>'
          ).join('') + '</tbody></table>';
      })
      .catch(() => {
        document.getElementById('recent-deliveries').innerHTML = '<p style="color:#888">Could not load deliveries.</p>';
      });

    // Load products
    fetch('/api/products')
      .then(r => r.json())
      .then(products => {
        const el = document.getElementById('products');
        el.innerHTML = products.slice(0, 6).map(p =>
          '<div style="background:white;border-radius:12px;padding:1.5rem;box-shadow:0 2px 8px rgba(0,0,0,0.08)">' +
          '<h3 style="margin-bottom:0.5rem">' + p.name + '</h3>' +
          '<p style="color:#666;font-size:0.9rem;margin-bottom:1rem">' + (p.description || '') + '</p>' +
          '<p style="font-weight:700;color:#3CAA6A">$' + (p.price_cents / 100).toFixed(2) + '</p>' +
          '<a href="/menu" style="display:inline-block;margin-top:1rem;padding:0.5rem 1rem;background:#3CAA6A;color:white;border-radius:6px;text-decoration:none;font-size:0.85rem">Order Now</a>' +
          '</div>'
        ).join('');
      });
  </script>
  `, nonce);
}

function renderOrderTrackPage(cs02Flag, isAdmin) {
  // CS-02 FLAW: No CSP header set on this page
  // postMessage listener injects event.data directly into innerHTML
  const adminDiv = isAdmin
    ? `<div id="admin-flag" style="background:#fff3cd;border:1px solid #f5a623;border-radius:8px;padding:1rem;margin:1rem 0;">
         <strong>Admin Notice:</strong> <span id="flag-value">${cs02Flag || ''}</span>       </div>`
    // Non-admin: no flag value in DOM at all — must exploit CS-02 to get admin session
    : `<div id="admin-flag" style="display:none"><span id="flag-value"></span></div>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Track Your Order — Garden Fresh</title>
  <style>
    body { font-family: 'Nunito', sans-serif; background: #f8f9fa; margin: 0; padding: 2rem; }
    .widget { background: white; border-radius: 12px; padding: 2rem; max-width: 600px; margin: 0 auto; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
    h1 { color: #3CAA6A; margin-bottom: 1rem; }
    #status { min-height: 100px; }
  </style>
  <!-- CS-02: NO Content-Security-Policy header on this page — deliberate flaw -->
</head>
<body>
  <div class="widget">
    <h1>🚚 Order Tracking</h1>
    ${adminDiv}
    <div id="status">
      <p style="color:#888">Enter your order ID or receive tracking via postMessage.</p>
    </div>
    <input id="order-id" type="text" placeholder="Order ID" style="width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:8px;margin-top:1rem;font-size:1rem;">
    <button onclick="trackOrder()" style="margin-top:0.5rem;padding:0.6rem 1.2rem;background:#3CAA6A;color:white;border:none;border-radius:6px;cursor:pointer;font-size:0.95rem">Track</button>
  </div>

  <script>
    // CS-02 VULNERABILITY: postMessage listener with no origin check
    // Injects event.data directly into innerHTML (XSS vector)
    window.addEventListener('message', function(event) {
      // No origin check — accepts messages from any origin
      document.getElementById('status').innerHTML = event.data;
    });

    function trackOrder() {
      const orderId = document.getElementById('order-id').value;
      if (!orderId) return;
      fetch('/api/orders/' + orderId + '/receipt', {
        headers: { 'Content-Type': 'application/json' }
      })
        .then(r => r.json())
        .then(data => {
          document.getElementById('status').innerHTML =
            '<p><strong>Status:</strong> ' + (data.status || 'Unknown') + '</p>' +
            '<p><strong>Total:</strong> $' + ((data.total_price_cents || 0) / 100).toFixed(2) + '</p>';
        })
        .catch(() => {
          document.getElementById('status').innerHTML = '<p style="color:#dc3545">Order not found.</p>';
        });
    }
  </script>
</body>
</html>`;
}

function renderReviewsPage(nonce, reviews = [], csrfToken = '') {
  // CS-01: reviews are embedded server-side so any <script src> payload in review
  // content is present in the initial HTML parse tree and is executed by the browser.
  // innerHTML injection would silently discard <script> elements per the HTML spec.
  const reviewsHtml = reviews.length > 0
    ? reviews.map(r =>
        '<div style="background:white;border-radius:10px;padding:1.5rem;box-shadow:0 2px 6px rgba(0,0,0,0.07)">' +
        '<div style="color:#F5A623;margin-bottom:0.5rem">' + '★'.repeat(r.rating || 5) + '</div>' +
        '<div class="review-body">' + r.content + '</div>' +  // CS-01: stored content at parse time
        '<div style="color:#888;font-size:0.8rem;margin-top:0.5rem">' + new Date(r.created_at).toLocaleDateString() + '</div>' +
        '</div>'
      ).join('\n')
    : '<p style="color: #888;">No reviews yet. Be the first!</p>';

  return baseLayout('Product Reviews', `
  <div class="container">
    <h1 style="margin: 2rem 0 1rem; font-size: 2rem; color: #222;">Customer Reviews</h1>
    <div id="reviews" style="display: grid; gap: 1.5rem; max-width: 800px;">
      ${reviewsHtml}
    </div>
    <div style="margin-top: 3rem; background: white; border-radius: 12px; padding: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
      <h2 style="margin-bottom: 1rem; font-size: 1.25rem;">Leave a Review</h2>
      <form id="review-form" onsubmit="submitReview(event)">
        <input type="hidden" id="review-csrf-token" name="_csrf" value="${csrfToken}">
        <textarea id="review-content" placeholder="Share your experience..." style="width:100%;height:100px;padding:0.75rem;border:1px solid #ddd;border-radius:8px;resize:vertical;font-size:0.95rem;"></textarea>
        <select id="review-product" style="display:block;margin:0.5rem 0;padding:0.6rem;border:1px solid #ddd;border-radius:8px;">
          <option value="1">Green Garden Juice</option>
          <option value="2">Tropical Sunrise</option>
        </select>
        <button type="submit" class="btn btn-primary" style="margin-top:0.5rem">Submit Review</button>
      </form>
    </div>
  </div>

  <script nonce="${nonce}">
    function submitReview(event) {
      if (event) event.preventDefault();
      const content = document.getElementById('review-content').value;
      const productId = document.getElementById('review-product').value;
      const csrf = document.getElementById('review-csrf-token').value;
      if (!content) return alert('Please enter a review');

      fetch('/api/products/' + productId + '/reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content, rating: 5, _csrf: csrf })
      })
        .then(r => r.json())
        .then(d => {
          if (d.id) {
            alert('Review submitted for moderation!');
          }
        });
    }
  </script>
  `, nonce);
}

function renderLoginPage(csrfToken) {
  return baseLayout('Login', `
  <div class="container" style="max-width: 400px; margin-top: 3rem;">
    <h1 style="margin-bottom: 2rem; font-size: 1.75rem; color: #222;">Sign In</h1>
    <div style="background: white; border-radius: 12px; padding: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
      <form id="login-form" onsubmit="login(event)">
        <input type="hidden" id="csrf-token" name="_csrf" value="${csrfToken}">
        <div style="margin-bottom: 1rem;">
          <label style="display:block;margin-bottom:0.4rem;font-weight:600;color:#555;">Email</label>
          <input id="email" type="email" placeholder="you@example.com" style="width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;">
        </div>
        <div style="margin-bottom: 1.5rem;">
          <label style="display:block;margin-bottom:0.4rem;font-weight:600;color:#555;">Password</label>
          <input id="password" type="password" style="width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;font-size:1rem;">Sign In</button>
      </form>
      <p style="text-align:center;margin-top:1rem;color:#888;font-size:0.9rem">
        Don't have an account? <a href="/register" style="color:#3CAA6A">Register</a>
      </p>
      <p style="text-align:center;margin-top:0.5rem;font-size:0.85rem">
        <a href="#" onclick="forgotPassword()" style="color:#888">Forgot password?</a>
      </p>
    </div>
  </div>
  <script>
    function login(event) {
      if (event) event.preventDefault();
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const csrf = document.getElementById('csrf-token').value;
      fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, _csrf: csrf })
      })
        .then(r => r.json())
        .then(d => {
          if (d.token) {
            localStorage.setItem('garden_token', d.token);
            window.location.href = '/';
          } else {
            alert(d.error || 'Login failed');
          }
        });
    }
    function forgotPassword() {
      const email = prompt('Enter your email address:');
      if (email) {
        fetch('/api/auth/reset-request', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ email })
        }).then(() => alert('If that email exists, a reset link was sent.'));
      }
    }
  </script>
  `);
}

function renderRegisterPage(csrfToken) {
  return baseLayout('Register', `
  <div class="container" style="max-width: 400px; margin-top: 3rem;">
    <h1 style="margin-bottom: 2rem; font-size: 1.75rem; color: #222;">Create Account</h1>
    <div style="background: white; border-radius: 12px; padding: 2rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
      <form id="register-form" onsubmit="register(event)">
        <input type="hidden" id="csrf-token" name="_csrf" value="${csrfToken}">
        <div style="margin-bottom: 1rem;">
          <label style="display:block;margin-bottom:0.4rem;font-weight:600;color:#555;">Username</label>
          <input id="username" type="text" placeholder="juicefan42" style="width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;">
        </div>
        <div style="margin-bottom: 1rem;">
          <label style="display:block;margin-bottom:0.4rem;font-weight:600;color:#555;">Email</label>
          <input id="email" type="email" placeholder="you@example.com" style="width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;">
        </div>
        <div style="margin-bottom: 1.5rem;">
          <label style="display:block;margin-bottom:0.4rem;font-weight:600;color:#555;">Password</label>
          <input id="password" type="password" style="width:100%;padding:0.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;">
        </div>
        <button type="submit" class="btn btn-primary" style="width:100%;justify-content:center;font-size:1rem;">Create Account</button>
      </form>
      <p style="text-align:center;margin-top:1rem;color:#888;font-size:0.9rem">
        Already have an account? <a href="/login" style="color:#3CAA6A">Sign in</a>
      </p>
    </div>
  </div>
  <script>
    function register(event) {
      if (event) event.preventDefault();
      const username = document.getElementById('username').value;
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const csrf = document.getElementById('csrf-token').value;
      fetch('/api/auth/register', {
        method: 'POST', headers: {'Content-Type':'application/json'},
        body: JSON.stringify({ username, email, password, _csrf: csrf })
      }).then(r => r.json()).then(d => {
        if (d.id) window.location.href = '/';
        else alert(d.error || 'Registration failed');
      });
    }
  </script>
  `);
}

function renderMenuPage() {
  const nonce = require('crypto').randomBytes(16).toString('base64');
  return baseLayout('Menu', `
  <div class="container">
    <h1 style="margin: 2rem 0 1rem; font-size: 2rem; color: #222;">Our Menu</h1>
    <div id="menu-grid" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 1.5rem;">
      <p style="color: #888;">Loading menu...</p>
    </div>
  </div>
  <script nonce="${nonce}">
    fetch('/api/products').then(r => r.json()).then(products => {
      const el = document.getElementById('menu-grid');
      el.innerHTML = products.map(p =>
        '<div style="background:white;border-radius:12px;padding:1.5rem;box-shadow:0 2px 8px rgba(0,0,0,0.08)">' +
        '<span style="background:#e8f5e9;color:#3CAA6A;border-radius:4px;padding:2px 8px;font-size:0.8rem">' + (p.category || 'juice') + '</span>' +
        '<h3 style="margin:0.75rem 0 0.5rem">' + p.name + '</h3>' +
        '<p style="color:#666;font-size:0.9rem;margin-bottom:1rem">' + (p.description || '') + '</p>' +
        '<div style="display:flex;justify-content:space-between;align-items:center;gap:0.5rem">' +
        '<span style="font-weight:700;color:#3CAA6A;font-size:1.1rem">$' + (p.price_cents / 100).toFixed(2) + '</span>' +
        '<div style="display:flex;align-items:center;gap:0.5rem">' +
        '<input id="qty-' + p.id + '" type="number" min="1" value="1" ' +
          'style="width:60px;padding:0.4rem;border:1px solid #ddd;border-radius:6px;font-size:0.95rem" ' +
          'aria-label="Quantity">' +
        '<button onclick="addToCart(' + p.id + ',' + p.price_cents + ')" ' +
          'style="padding:0.5rem 1rem;background:#F5A623;color:white;border:none;border-radius:6px;cursor:pointer;font-weight:600">Add to Cart</button>' +
        '</div></div></div>'
      ).join('');
    });

    let cart = [];
    function addToCart(id, price) {
      // BL-01: client-side min=1 guard — bypassed by sending qty<0 directly to the API
      const input = document.getElementById('qty-' + id);
      const qty = parseInt(input ? input.value : '1', 10);
      if (isNaN(qty) || qty < 1) { alert('Quantity must be at least 1'); return; }
      cart.push({ product_id: id, quantity: qty });
      alert('Added to cart! Cart has ' + cart.length + ' item(s).');
    }
  </script>
  `);
}

function renderOrdersPage() { return baseLayout('My Orders', '<div class="container"><h1>My Orders</h1><p>Please log in to view your orders.</p></div>'); }
function renderAccountPage() { return baseLayout('Account', '<div class="container"><h1>My Account</h1><p>Please log in to manage your account.</p></div>'); }
function renderStaffPage() {
  return baseLayout('Staff Dashboard', `
  <div class="container">
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.5rem;">
      <h1 style="font-size:1.75rem;font-weight:700;">Staff Dashboard</h1>
      <span class="role-badge badge-staff">Staff</span>
    </div>
    <nav class="role-tabs" role="tablist">
      <a class="tab active" href="#order-queue" role="tab" aria-selected="true">Order Queue</a>
      <a class="tab" href="#order-notes" role="tab" aria-selected="false">Add Notes</a>
      <a class="tab" href="#fulfil-order" role="tab" aria-selected="false">Fulfil Order</a>
    </nav>
    <div id="order-queue" class="role-panel active">
      <h2 style="margin-bottom:1rem;">Pending Orders</h2>
      <p style="color:#666;">Orders with status <strong>pending</strong> or <strong>confirmed</strong> appear here. Use the API: <code>GET /api/staff/queue</code>.</p>
    </div>
    <div id="order-notes" class="role-panel">
      <h2 style="margin-bottom:1rem;">Internal Notes</h2>
      <p style="color:#666;">Add internal notes to an order: <code>POST /api/staff/orders/:id/notes</code>.</p>
    </div>
    <div id="fulfil-order" class="role-panel">
      <h2 style="margin-bottom:1rem;">Fulfil / Update Order Status</h2>
      <p style="color:#666;">Update an order to <em>confirmed</em>, <em>delivered</em>, or <em>cancelled</em>: <code>PATCH /api/staff/orders/:id/status</code>.</p>
    </div>
  </div>
  <script>
    document.querySelectorAll('.role-tabs .tab').forEach(tab => {
      tab.addEventListener('click', e => {
        e.preventDefault();
        document.querySelectorAll('.role-tabs .tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected','false'); });
        document.querySelectorAll('.role-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        tab.setAttribute('aria-selected','true');
        const target = document.querySelector(tab.getAttribute('href'));
        if (target) target.classList.add('active');
      });
    });
  </script>`);
}

function renderManagerPage() {
  return baseLayout('Manager Dashboard', `
  <div class="container">
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.5rem;">
      <h1 style="font-size:1.75rem;font-weight:700;">Manager Dashboard</h1>
      <span class="role-badge badge-manager">Manager</span>
    </div>
    <nav class="role-tabs" role="tablist">
      <a class="tab active" href="#reviews" role="tab" aria-selected="true">Reviews</a>
      <a class="tab" href="#promotions" role="tab" aria-selected="false">Promotions</a>
      <a class="tab" href="#reports" role="tab" aria-selected="false">Reports</a>
    </nav>
    <div id="reviews" class="role-panel active">
      <h2 style="margin-bottom:1rem;">Review Moderation</h2>
      <p style="color:#666;">Approve: <code>POST /api/manager/reviews/:id/approve</code><br>
      Reject: <code>POST /api/manager/reviews/:id/reject</code></p>
    </div>
    <div id="promotions" class="role-panel">
      <h2 style="margin-bottom:1rem;">Promotion Approvals</h2>
      <p style="color:#666;">View pending: <code>GET /api/manager/promotions</code> (AUTH-02 gate)<br>
      Approve: <code>POST /api/manager/promotions/:id/approve</code></p>
    </div>
    <div id="reports" class="role-panel">
      <h2 style="margin-bottom:1rem;">Manager Reports</h2>
      <p style="color:#666;">View reports: <code>GET /api/manager/reports</code> (AUTH-01 gate)</p>
    </div>
  </div>
  <script>
    document.querySelectorAll('.role-tabs .tab').forEach(tab => {
      tab.addEventListener('click', e => {
        e.preventDefault();
        document.querySelectorAll('.role-tabs .tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected','false'); });
        document.querySelectorAll('.role-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        tab.setAttribute('aria-selected','true');
        const target = document.querySelector(tab.getAttribute('href'));
        if (target) target.classList.add('active');
      });
    });
  </script>`);
}

function renderAdminPage() {
  return baseLayout('Admin Dashboard', `
  <div class="container">
    <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.5rem;">
      <h1 style="font-size:1.75rem;font-weight:700;">Admin Dashboard</h1>
      <span class="role-badge badge-admin">Admin</span>
    </div>
    <nav class="role-tabs" role="tablist">
      <a class="tab active" href="#users" role="tab" aria-selected="true">User Management</a>
      <a class="tab" href="#bulk-import" role="tab" aria-selected="false">Bulk Import</a>
      <a class="tab" href="#graphql" role="tab" aria-selected="false">GraphQL</a>
    </nav>
    <div id="users" class="role-panel active">
      <h2 style="margin-bottom:1rem;">User Management</h2>
      <p style="color:#666;">Admin user list: <code>GET /api/admin/users</code><br>
      Role updates: <code>PUT /api/admin/users/:id/role</code></p>
    </div>
    <div id="bulk-import" class="role-panel">
      <h2 style="margin-bottom:1rem;">Bulk Product Import (XML)</h2>
      <p style="color:#666;">Import products via XML: <code>POST /api/products/bulk-import</code><br>
      Supports <code>&lt;!ENTITY&gt; SYSTEM</code> file:// declarations.</p>
    </div>
    <div id="graphql" class="role-panel">
      <h2 style="margin-bottom:1rem;">GraphQL Explorer</h2>
      <p style="color:#666;">Interactive GraphQL: <code>GET /graphql</code></p>
    </div>
  </div>
  <script>
    document.querySelectorAll('.role-tabs .tab').forEach(tab => {
      tab.addEventListener('click', e => {
        e.preventDefault();
        document.querySelectorAll('.role-tabs .tab').forEach(t => { t.classList.remove('active'); t.setAttribute('aria-selected','false'); });
        document.querySelectorAll('.role-panel').forEach(p => p.classList.remove('active'));
        tab.classList.add('active');
        tab.setAttribute('aria-selected','true');
        const target = document.querySelector(tab.getAttribute('href'));
        if (target) target.classList.add('active');
      });
    });
  </script>`);
}

module.exports = router;
