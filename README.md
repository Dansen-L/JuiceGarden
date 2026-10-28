# Juice Garden — Moderate-Difficulty Vulnerable Web Lab Platform

A Docker-based vulnerable web lab platform for intermediate security practitioners. Garden Fresh (the target app) is a fictional juice bar delivery SaaS with **21 deliberately introduced vulnerabilities** across six tracks, requiring bypass techniques and multi-step exploitation chains.

## Quick Start

```bash
# 1. Add required /etc/hosts entries
echo "127.0.0.1 garden.lab attacker.lab" | sudo tee -a /etc/hosts

# 2. Install the garden CLI (Python 3.11+ required)
pip install -e .

# 3. Start the platform
./init.sh
# or:
garden start
```

## Prerequisites

| Requirement | Minimum Version |
|-------------|----------------|
| Docker Engine | 24+ |
| Docker Compose | v2 |
| Python | 3.11+ |
| RAM | 4 GB available for Docker |
| Ports | 80 and 8081 free on host |

Add to `/etc/hosts`:
```
127.0.0.1 garden.lab attacker.lab
```

## Platform URLs

| Service | URL |
|---------|-----|
| Garden Fresh (Target App) | http://garden.lab:80/ |
| Challenge Board | http://garden.lab:80/platform/ |
| Exploit Server | http://garden.lab:80/platform/exploit-server/ |
| CS-02 Attack Pages (cross-origin, same-site) | http://garden.lab:8081/payloads/<id\> |
| CS-03 Attack Pages (cross-site) | http://attacker.lab/payloads/<id\> |

## Challenge Tracks

### Authentication Track (AUTH)
| Challenge | Technique |
|-----------|-----------|
| AUTH-01 | JWT kid parameter path traversal (kid=/dev/null) |
| AUTH-02 | RS256→HS256 algorithm confusion |
| AUTH-03 | LCG reset token enumeration (~3000 candidates) |
| AUTH-04 | Rate-limit bypass via X-Forwarded-For header |

### Injection Track (INJ)
| Challenge | Technique |
|-----------|-----------|
| INJ-01 | Second-order SQLi via stored username payload |
| INJ-02 | SQLi UNION bypass (inline-comment / alternate-whitespace / case-mangling) |
| INJ-03 | EJS Server-Side Template Injection (SSTI → RCE) |
| INJ-04 | Command injection via unsanitized filename (pipe/backtick) |

### Broken Access Control Track (BAC)
| Challenge | Technique |
|-----------|-----------|
| BAC-01 | IDOR via UUID v1 timestamp enumeration |
| BAC-02 | Mass assignment (undocumented role field in PUT) |
| BAC-03 | GraphQL BOLA (missing ownership check on resolver) |
| BAC-04 | Path traversal via URL double-encoding |

### Client-Side Track (CS)
| Challenge | Technique |
|-----------|-----------|
| CS-01 | Stored XSS + CSP bypass via JSONP same-origin src |
| CS-02 | DOM-based XSS via postMessage (no origin check, no CSP on /orders/track) |
| CS-03 | CSRF via GET-based email-change (SameSite=Lax bypass) |

### Server-Side Track (SS)
| Challenge | Technique |
|-----------|-----------|
| SS-01 | Blind SSRF via webhook URL (redis-commander internal target) |
| SS-02 | XXE with file:// entity (http/https blocked by WAF, file:// allowed) |
| SS-03 | File upload bypass via double-extension (payload.ejs.jpg → EJS execution) |

### Business Logic Track (BL)
| Challenge | Technique |
|-----------|-----------|
| BL-01 | Negative quantity order (no server-side sign check) |
| BL-02 | Coupon race condition (10 parallel requests exhaust single-use limit) |
| BL-03 | Loyalty points Int32 overflow via \`(price * qty) \| 0\` coercion |

### Mission Track
| Challenge | Description |
|-----------|-------------|
| MISSION-ALPHA | Admin takeover chain: BL-03 → BAC-02 → AUTH-01 (Admin gate) |
| Hidden Bonus | Undocumented endpoint discovery (GET /api/debug/stats) |

## Operator CLI Reference

```bash
garden start [--build]         # Start all services; stream logs until healthy
garden stop [--timeout N]      # Stop and remove containers (volumes preserved)
garden reset                   # Soft reset: regenerate all 23 flags; reseed data
garden reset --hard            # Hard reset: destroy volumes, rebuild, regenerate flags
garden status                  # Health check 7 persistent services (flag-init is one-shot); exits non-zero if unhealthy
garden flags list              # Print all 23 current flag values (operator only)
garden flags verify FLAG       # Verify a flag; return challenge code if valid
garden hosts check             # Verify /etc/hosts entries for garden.lab and attacker.lab
garden restart [--service S]   # Soft restart one service (default: node-app)
```

## Architecture

```
Host Browser
     │
     ├─ :80 (Host:garden.lab) ──► nginx ──► node-app (Garden Fresh)
     │                                   │
     │                                   └─► flask-platform (/platform/*)
     │
     ├─ :80 (Host:attacker.lab) ─► nginx ──► CS-03 exploit pages (cross-site)
     │
     └─ :8081 ────────────────────► nginx ──► CS-02 exploit pages (cross-origin/same-site)

Internal networks (egress-blocked):
  app-internal:      node-app, postgres, redis, redis-commander, victim-bot
  platform-internal: flask-platform

Victim bot: Playwright headless Chromium with --host-resolver-rules
  staff_bot:   every 60s — login, generate weekly notes report (INJ-01 trigger)
  manager_bot: every 30s — login, approve pending reviews (CS-01 trigger)
  admin_bot:   every 30s — login, visit reviews page (CS-01 XSS target)
               every 30s — dequeue up to 3 URLs from bot queue (CS-02, CS-03)
```

## Flag System

- **23 total flags**: 21 standalone + 1 MISSION-ALPHA master + 1 hidden bonus
- **Format**: `JG{` + 32 lowercase hex chars + `}`
- Generated by `flag-init` container at every `garden start`/`garden reset`
- Shared between node-app and flask-platform via `flag-data` Docker volume

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Vulnerable App (Garden Fresh) | Node.js / Express |
| Challenge Platform | Python / Flask + SQLAlchemy + SQLite |
| Victim Bot | Node.js / Playwright (headless Chromium) |
| App Database | PostgreSQL 15 |
| Session Store | Redis 7 |
| Redis Management | redis-commander (internal only — SS-01 SSRF target) |
| Reverse Proxy / WAF-lite | Nginx |
| Orchestration | Docker Compose v2 |
| Operator CLI | Python / Click |

## WAF-Lite Rules (Garden Fresh routes only)

The WAF applies **only** to Garden Fresh (`/` routes). `/platform/*` is NOT WAF-inspected.

| Payload | Result |
|---------|--------|
| `<script>alert(1)</script>` | BLOCKED |
| `<script src="https://evil.com/x.js">` | BLOCKED |
| `<script src="//evil.com/x.js">` | BLOCKED |
| `<script src="/api/products/search?callback=payload">` | **PERMITTED** |
| `<script src="/static/app.js">` | **PERMITTED** |
| `UNION SELECT` | BLOCKED |
| `UNION/**/SELECT` | **PERMITTED** (INJ-02 bypass) |
| `AND 1=1` | **PERMITTED** |
| `on[a-z]+=...` (event handlers) | BLOCKED |
| `<!ENTITY xxe SYSTEM "http://...">` | BLOCKED |
| `<!ENTITY xxe SYSTEM "file://...">` | **PERMITTED** (SS-02 bypass) |

## Resetting Between Sessions

For cohort/concurrent deployments, reset between practitioner sessions:
```bash
garden reset        # Regenerates all 23 flags; clears exploit-server collections
garden reset --hard # Full reset including platform user progress (with prompt)
```
