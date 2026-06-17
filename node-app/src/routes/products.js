/**
 * Product routes
 * INJ-02: SQL injection via JSON body (order-search raw query fallback)
 * CS-01: stored XSS in product reviews
 * JSONP endpoint for CS-01 CSP bypass
 */
'use strict';

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const ejs = require('ejs');
const { Product, Review, AuditLog, sequelize, QueryTypes } = require('../models');
const { requireAuth, requireRole } = require('../middleware/auth');
const { validateCsrf } = require('../middleware/csrf');

const router = express.Router();

// ──────────────────────────────────────────────
// File upload for SS-03 (double-extension bypass)
// ──────────────────────────────────────────────
const upload = multer({
  dest: '/app/uploads/temp/',
  fileFilter: (req, file, cb) => {
    // SS-03 VULNERABILITY: validates only the LAST extension segment
    // double-extension (payload.ejs.jpg) passes because last ext is .jpg
    const lastExt = path.extname(file.originalname).toLowerCase();
    const allowedExts = ['.jpg', '.jpeg', '.png', '.gif', '.webp'];
    const allowedMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

    if (allowedExts.includes(lastExt) && allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type'), false);
    }
  },
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ──────────────────────────────────────────────
// GET /api/products
// ──────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const products = await Product.findAll({ where: { is_active: true } });
    res.json(products);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch products' });
  }
});

// ──────────────────────────────────────────────
// GET /api/products/search?q=...&callback=...
// CS-01: JSONP endpoint (in script-src allowlist)
// The callback parameter becomes executed code: callback(...)
// WAF PERMITS: <script src="/api/products/search?callback=...">
// ──────────────────────────────────────────────
router.get('/search', async (req, res) => {
  try {
    const { q, callback } = req.query;

    let products = [];
    if (q) {
      products = await Product.findAll({
        where: { is_active: true },
        // Simple search (not injection-vulnerable — uses ORM)
        // INJ-02 is on the order-search raw query, not here
      });
      products = products.filter(p =>
        p.name.toLowerCase().includes(q.toLowerCase()) ||
        (p.description && p.description.toLowerCase().includes(q.toLowerCase()))
      );
    } else {
      products = await Product.findAll({ where: { is_active: true } });
    }

    const data = JSON.stringify(products.map(p => ({
      id: p.id, name: p.name, price_cents: p.price_cents, category: p.category
    })));

    // JSONP response
    if (callback) {
      res.set('Content-Type', 'application/javascript');
      // CS-01: callback value is injected directly into the response
      // This is the exploitable JSONP endpoint
      res.send(`${callback}(${data})`);
    } else {
      res.json(JSON.parse(data));
    }
  } catch (err) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ──────────────────────────────────────────────
// GET /api/products/image-preview?file=...
// SS-03: derives "effective type" by stripping last extension
// If effective type is .ejs → passes through ejs.render()
// Registered BEFORE /:id so the literal segment is not shadowed.
// ──────────────────────────────────────────────
router.get('/image-preview', async (req, res) => {
  try {
    const { file } = req.query;
    if (!file) return res.status(400).json({ error: 'file parameter required' });

    // Prevent directory traversal in preview (basic check)
    if (file.includes('/') || file.includes('..')) {
      return res.status(400).json({ error: 'Invalid filename' });
    }

    const filePath = path.join('/app/uploads/products/', file);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // SS-03 VULNERABILITY: derive effective type by stripping LAST extension
    // path.parse('payload.ejs.jpg').name → 'payload.ejs'
    // path.extname('payload.ejs') → '.ejs'
    const nameWithoutLast = path.parse(file).name;
    const effectiveExt = path.extname(nameWithoutLast).toLowerCase();

    if (effectiveExt === '.ejs') {
      // SS-03: EJS template execution path
      const content = fs.readFileSync(filePath, 'utf8');
      const rendered = ejs.render(content, {});
      res.set('Content-Type', 'text/html');
      return res.send(rendered);
    }

    // Normal image serving
    res.sendFile(filePath);
  } catch (err) {
    // SS-03: error response body may contain executed command output
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────
// GET /api/products/:id
// ──────────────────────────────────────────────
router.get('/:id', async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });
    res.json(product);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch product' });
  }
});

// ──────────────────────────────────────────────
// GET /api/products/:id/reviews
// Includes approved reviews (CS-01: stored XSS payload rendered here)
// ──────────────────────────────────────────────
router.get('/:id/reviews', async (req, res) => {
  try {
    const reviews = await Review.findAll({
      where: { product_id: req.params.id, approved: true }
    });
    // CS-01: review content is returned as-is (rendered in admin_bot's browser)
    res.json(reviews.map(r => ({
      id: r.id,
      content: r.content,  // XSS payload stored verbatim
      rating: r.rating,
      created_at: r.created_at
    })));
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

// ──────────────────────────────────────────────
// POST /api/products/:id/reviews
// CS-01: stores review content verbatim
// CSRF-protected: requests must include _csrf token from the review form
// ──────────────────────────────────────────────
router.post('/:id/reviews', requireAuth, validateCsrf, async (req, res) => {
  try {
    const { content, rating } = req.body;
    if (!content) return res.status(400).json({ error: 'content required' });

    const product = await Product.findByPk(req.params.id);
    if (!product) return res.status(404).json({ error: 'Product not found' });

    const review = await Review.create({
      user_id: req.user.id,
      product_id: parseInt(req.params.id),
      content,  // CS-01: no sanitization — stored XSS
      rating: rating || 5,
      approved: false,
      created_at: new Date()
    });

    // Audit log: record review submission
    AuditLog.create({
      actor_id: req.user.id,
      action: 'review.submitted',
      target_type: 'product',
      target_id: String(req.params.id),
      details_json: { review_id: review.id, rating: rating || 5 },
      ip_address: req.headers['x-real-ip'] || req.ip,
      timestamp: new Date()
    }).catch(() => {});  // fire-and-forget

    res.status(201).json({
      id: review.id,
      message: 'Review submitted for moderation'
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to submit review' });
  }
});

// ──────────────────────────────────────────────
// POST /api/products/image-upload
// SS-03: double-extension bypass → EJS execution
// INJ-04: command injection in thumbnail generator (pipes not filtered)
// ──────────────────────────────────────────────
router.post('/image-upload', requireAuth, upload.single('image'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const originalName = req.file.originalname;
    const uploadDir = '/app/uploads/products/';
    const thumbDir = '/app/uploads/thumbnails/';
    fs.mkdirSync(uploadDir, { recursive: true });
    fs.mkdirSync(thumbDir, { recursive: true });

    // INJ-04: Filter semicolons and forward-slashes from filename (deliberate partial sanitization).
    // Pipes (|) and backticks (`) are intentionally NOT filtered — they are the exploit vectors.
    const sanitizedName = originalName.replace(/[;\/]/g, '');
    const storedName = Date.now() + '_' + sanitizedName;
    const destPath = path.join(uploadDir, storedName);
    fs.renameSync(req.file.path, destPath);

    // ──────────────────────────────────────────────
    // INJ-04 VULNERABILITY: thumbnail generator passes unsanitized filename to shell.
    // Semicolons (;) and forward-slashes (/) are filtered; BACKTICKS (`) are NOT.
    //
    // Working attack — slash-free backtick substitution:
    //   Upload filename: `cd flags&&cat inj04.txt`.jpg
    //   After sanitization (no ; or / → unchanged): `cd flags&&cat inj04.txt`.jpg
    //   destPath = "/app/uploads/products/1234_`cd flags&&cat inj04.txt`.jpg"
    //   Command (UNQUOTED): convert /app/uploads/products/1234_`cd flags&&cat inj04.txt`.jpg ...
    //   Shell subshell: cd flags (from CWD /app → /app/flags/), then cat inj04.txt
    //   Shell expands backtick → flag value substituted → error includes flag:
    //     "convert: unable to open image '...JG{abc...}.jpg'"
    //
    // Why absolute paths fail: `/` is stripped, turning `/app/flags/inj04.txt`
    //   into `appflagsinj04.txt` (no such file — injection fails silently).
    // Why pipe form fails: `x|cat path|y.jpg` sends flag into next stage's stdin
    //   (discarded), not into any error channel the response returns.
    // ──────────────────────────────────────────────
    const { execSync } = require('child_process');
    const thumbPath = path.join(thumbDir, Date.now() + '_thumb.jpg');
    let thumbnailInfo = null;

    try {
      // INJ-04: destPath is NOT quoted in shell command (vulnerable to injection)
      const thumbOutput = execSync(
        `convert ${destPath} -thumbnail 150x150 ${thumbPath} 2>&1`,
        { timeout: 5000, encoding: 'utf8', shell: '/bin/sh' }
      );
      thumbnailInfo = { generated: true, output: thumbOutput.slice(0, 200) };
    } catch (execErr) {
      // INJ-04: error output contains expanded backtick/pipe output (flag leaks here)
      const errorOutput = [execErr.stdout, execErr.stderr, execErr.message]
        .filter(Boolean).join('\n');
      thumbnailInfo = { generated: false, error: errorOutput.slice(0, 500) };
    }

    res.json({
      path: `/uploads/products/${storedName}`,
      preview_url: `/api/products/image-preview?file=${storedName}`,
      thumbnail: thumbnailInfo
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ──────────────────────────────────────────────
// POST /api/products/bulk-import (XML upload)
// SS-02: XXE via file:// URI entity (http/https blocked by WAF, file:// not)
// ──────────────────────────────────────────────
// Access gate: Manager/Admin only (SS-02 route — customer access would be unintended)
router.post('/bulk-import', requireAuth, requireRole('manager', 'admin'), async (req, res) => {
  const xml2js = require('xml2js');

  try {
    const xmlData = req.body.xml || (typeof req.body === 'string' ? req.body : null);
    if (!xmlData) return res.status(400).json({ error: 'XML data required' });

    // SS-02 VULNERABILITY: simulated XXE via regex-based entity resolution.
    //
    // Resolves <!ENTITY> SYSTEM declarations pointing to file:// URIs by calling
    // fs.readFileSync on the resolved path and string-replacing all &name; references.
    // Replicates the observable behaviour of LIBXML_NOENT for the payloads below.
    // http:// and https:// URIs are blocked by the WAF before reaching this route.
    //
    // Supported payload shapes (all of the following resolve identically):
    //   Double-quoted SYSTEM: <!ENTITY xxe SYSTEM "file:///app/flags/ss02.txt">
    //   Single-quoted SYSTEM: <!ENTITY xxe SYSTEM 'file:///app/flags/ss02.txt'>
    //   Multiple references:  <!ENTITY e SYSTEM "file:///..."> ... &e; ... &e;
    //   Parameter entities are NOT resolved (% syntax not implemented).
    const fs = require('fs');
    // Match SYSTEM entities with either single or double-quoted file:// URIs
    const ENTITY_RE = /<!ENTITY\s+(\w+)\s+SYSTEM\s+["'](file:\/\/[^"']+)["']/g;
    const entities = {};
    let m;
    while ((m = ENTITY_RE.exec(xmlData)) !== null) {
      const [, name, uri] = m;
      const filePath = uri.replace('file://', '');
      try {
        entities[name] = fs.readFileSync(filePath, 'utf8');
      } catch (e) {
        entities[name] = `Error reading: ${filePath}`;
      }
    }

    const { parseStringPromise } = xml2js;
    let result;
    let importedCount = 0;
    try {
      // Replace all &name; references for every resolved entity
      let processedXml = xmlData;
      for (const [name, value] of Object.entries(entities)) {
        const refRe = new RegExp(`&${name};`, 'g');
        processedXml = processedXml.replace(refRe, value);
      }
      // Strip DOCTYPE declarations — they contain ENTITY defs that xml2js cannot
      // handle; entity resolution has already been done above.
      // [^[>]* stops at '[' so the optional (?:\[...\]) group captures the internal
      // subset (including any '>' inside ENTITY declarations) before the closing '>'.
      processedXml = processedXml.replace(/<!DOCTYPE[^[>]*(?:\[[\s\S]*?\])?\s*>/i, '');
      result = await parseStringPromise(processedXml, { explicitArray: false });

    } catch (parseErr) {
      result = { error: parseErr.message };
    }

    // Persist imported products if the XML describes a <products> structure.
    // This step is deliberately isolated from the parse/entity-resolution block
    // so that a persistence failure cannot clobber the already-resolved entity
    // values in `result` (the XXE exfil payload must always surface in the response).
    if (result && result.products && result.products.product) {
      try {
        const productList = result.products.product;
        const items = Array.isArray(productList) ? productList : [productList];
        for (const item of items) {
          if (item.name) {
            await Product.create({
              name: item.name,
              description: item.description || '',
              price_cents: parseInt(item.price_cents || item.price || 0, 10),
              category: item.category || 'imported',
              is_active: true,
              created_at: new Date()
            });
            importedCount++;
          }
        }
      } catch (persistErr) {
        // Persistence failure is non-fatal: the response still returns the parsed result
      }
    }

    res.json({
      message: 'Import processed',
      imported_products: importedCount,
      result: result || {}
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
