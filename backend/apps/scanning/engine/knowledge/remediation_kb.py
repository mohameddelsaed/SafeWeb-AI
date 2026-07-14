"""
Remediation Knowledge Base — Phase 41.

Provides two main datasets:

1. ``REMEDIATION_DB`` — code-level fix examples (Python, Java, PHP, Node.js,
   C#, Go), server configuration snippets (Nginx, Apache, IIS), security header
   recommendations, and framework-specific guidance — keyed by CWE string.

2. ``COMPLIANCE_MAP`` — mapping of each CWE to the relevant controls in nine
   major compliance frameworks: OWASP Top 10 2021, OWASP API Top 10 2023,
   OWASP LLM Top 10, PCI DSS v4.0, SOC 2, ISO 27001, NIST 800-53, HIPAA, GDPR.
"""
from __future__ import annotations

from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Remediation Database
# ──────────────────────────────────────────────────────────────────────────────

REMEDIATION_DB: dict[str, dict] = {

    # ── SQL Injection (CWE-89) ────────────────────────────────────────────────
    'CWE-89': {
        'code_fixes': {
            'python': (
                '# Use parameterised queries with psycopg2 / SQLAlchemy\n'
                '# UNSAFE:\n'
                '# cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
                '\n'
                '# SAFE — positional parameter placeholder:\n'
                'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
                '\n'
                '# SAFE — SQLAlchemy ORM (never interpolates input):\n'
                'user = session.query(User).filter(User.id == user_id).first()\n'
            ),
            'java': (
                '// Use PreparedStatement, never Statement.execute()\n'
                '// UNSAFE: stmt.execute("SELECT * FROM users WHERE id = " + id);\n'
                '\n'
                '// SAFE:\n'
                'PreparedStatement ps = conn.prepareStatement(\n'
                '    "SELECT * FROM users WHERE id = ?");\n'
                'ps.setInt(1, userId);\n'
                'ResultSet rs = ps.executeQuery();\n'
            ),
            'php': (
                '// Use PDO prepared statements\n'
                '// UNSAFE: $db->query("SELECT * FROM users WHERE id = $_GET[\'id\']");\n'
                '\n'
                '// SAFE:\n'
                '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n'
                '$stmt->execute([":id" => $userId]);\n'
                '$row = $stmt->fetch();\n'
            ),
            'nodejs': (
                '// Use parameterised queries with pg / mysql2\n'
                '// UNSAFE: db.query(`SELECT * FROM users WHERE id = ${userId}`);\n'
                '\n'
                '// SAFE (pg):\n'
                'const { rows } = await db.query(\n'
                '    "SELECT * FROM users WHERE id = $1", [userId]);\n'
                '\n'
                '// SAFE (mysql2):\n'
                'const [rows] = await db.execute(\n'
                '    "SELECT * FROM users WHERE id = ?", [userId]);\n'
            ),
            'csharp': (
                '// Use SqlParameter with SqlCommand\n'
                '// UNSAFE: cmd.CommandText = "SELECT * FROM Users WHERE Id = " + id;\n'
                '\n'
                '// SAFE:\n'
                'using var cmd = new SqlCommand(\n'
                '    "SELECT * FROM Users WHERE Id = @Id", connection);\n'
                'cmd.Parameters.AddWithValue("@Id", userId);\n'
                'using var reader = cmd.ExecuteReader();\n'
            ),
            'go': (
                '// Use db.Query with positional placeholders (database/sql)\n'
                '// UNSAFE: db.Query("SELECT * FROM users WHERE id = " + id)\n'
                '\n'
                '// SAFE:\n'
                'rows, err := db.QueryContext(ctx,\n'
                '    "SELECT * FROM users WHERE id = $1", userID)\n'
            ),
        },
        'server_configs': {
            'nginx': (
                '# Enable ModSecurity WAF with OWASP Core Rule Set for SQLi protection\n'
                'load_module modules/ngx_http_modsecurity_module.so;\n'
                '\n'
                'server {\n'
                '    modsecurity on;\n'
                '    modsecurity_rules_file /etc/nginx/modsec/main.conf;\n'
                '}\n'
            ),
            'apache': (
                '# Enable ModSecurity + OWASP CRS\n'
                '<IfModule mod_security2.c>\n'
                '    SecRuleEngine On\n'
                '    Include modsecurity.d/activated_rules/*.conf\n'
                '</IfModule>\n'
            ),
            'iis': (
                '<!-- Enable Dynamic IP Restrictions & URL Scan to block SQLi patterns -->\n'
                '<system.webServer>\n'
                '  <security>\n'
                '    <dynamicIpSecurity />\n'
                '    <requestFiltering>\n'
                '      <denyStrings>\n'
                '        <add string="union select" />\n'
                '        <add string="1=1" />\n'
                '      </denyStrings>\n'
                '    </requestFiltering>\n'
                '  </security>\n'
                '</system.webServer>\n'
            ),
        },
        'header_fixes': [],
        'framework_guidance': {
            'django': (
                'Django ORM escapes all values by default.  Never use raw() or '
                'extra() with unvalidated user input.  Use F() objects and '
                'Q() objects for dynamic SQL composition.'
            ),
            'spring': (
                'Use Spring Data JPA/Repositories with @Query and named parameters.  '
                'Avoid EntityManager.createNativeQuery() with string concatenation.'
            ),
            'rails': (
                'ActiveRecord escapes values by default in where() with hash '
                'conditions.  Never use string interpolation in where() clauses: '
                'use where("column = ?", value) instead.'
            ),
        },
    },

    # ── Cross-Site Scripting (CWE-79) ─────────────────────────────────────────
    'CWE-79': {
        'code_fixes': {
            'python': (
                '# Use markupsafe or framework-provided escaping\n'
                'from markupsafe import escape\n'
                '\n'
                '# UNSAFE: return f"<p>Hello {user_name}</p>"\n'
                '# SAFE:\n'
                'safe_name = escape(user_name)\n'
                'return f"<p>Hello {safe_name}</p>"\n'
                '\n'
                '# In Django templates, use |escape or {{ var }} (auto-escaped).\n'
                '# Mark safe only with mark_safe() on trusted, server-generated HTML.\n'
            ),
            'nodejs': (
                '// Use a DOM sanitisation library such as DOMPurify (browser) or\n'
                '// sanitize-html (server-side)\n'
                'const sanitizeHtml = require("sanitize-html");\n'
                '\n'
                '// UNSAFE: res.send(`<p>${req.query.name}</p>`);\n'
                '// SAFE:\n'
                'const clean = sanitizeHtml(req.query.name, {\n'
                '    allowedTags: [],\n'
                '    allowedAttributes: {},\n'
                '});\n'
                'res.send(`<p>${clean}</p>`);\n'
            ),
            'php': (
                '// Use htmlspecialchars() with ENT_QUOTES and UTF-8\n'
                '// UNSAFE: echo "<p>Hello " . $_GET["name"] . "</p>";\n'
                '// SAFE:\n'
                'echo "<p>Hello " . htmlspecialchars($_GET["name"],\n'
                '    ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8") . "</p>";\n'
            ),
            'java': (
                '// Use OWASP Java Encoder\n'
                'import org.owasp.encoder.Encode;\n'
                '\n'
                '// SAFE:\n'
                'String safe = Encode.forHtml(userInput);\n'
            ),
            'csharp': (
                '// Use HtmlEncoder from System.Text.Encodings.Web\n'
                'using System.Text.Encodings.Web;\n'
                '\n'
                'string safe = HtmlEncoder.Default.Encode(userInput);\n'
            ),
            'go': (
                '// Use html/template (not text/template) — it auto-escapes by context\n'
                'import "html/template"\n'
                '\n'
                't := template.Must(template.New("page").Parse(\n'
                '    "<p>Hello {{.Name}}</p>"))\n'
                't.Execute(w, data)  // .Name is automatically HTML-encoded\n'
            ),
        },
        'server_configs': {
            'nginx': (
                'server {\n'
                '    # Prevent browsers from MIME-sniffing the response\n'
                '    add_header X-Content-Type-Options "nosniff" always;\n'
                '    # Restrict framing (clickjacking + XSS chaining)\n'
                '    add_header X-Frame-Options "DENY" always;\n'
                '    # Enable XSS filter (legacy browsers)\n'
                '    add_header X-XSS-Protection "1; mode=block" always;\n'
                '}\n'
            ),
            'apache': (
                '<IfModule mod_headers.c>\n'
                '    Header always set X-Content-Type-Options "nosniff"\n'
                '    Header always set X-Frame-Options "DENY"\n'
                '    Header always set X-XSS-Protection "1; mode=block"\n'
                '</IfModule>\n'
            ),
            'iis': (
                '<system.webServer>\n'
                '  <httpProtocol>\n'
                '    <customHeaders>\n'
                '      <add name="X-Content-Type-Options" value="nosniff" />\n'
                '      <add name="X-Frame-Options" value="DENY" />\n'
                '      <add name="X-XSS-Protection" value="1; mode=block" />\n'
                '    </customHeaders>\n'
                '  </httpProtocol>\n'
                '</system.webServer>\n'
            ),
        },
        'header_fixes': [
            {
                'header': 'Content-Security-Policy',
                'value': "default-src 'self'; script-src 'self'; object-src 'none'",
                'reason': (
                    'CSP is the primary XSS mitigation.  A restrictive policy prevents '
                    'execution of injected inline scripts and restricts script sources '
                    'to the same origin.'
                ),
            },
            {
                'header': 'X-Content-Type-Options',
                'value': 'nosniff',
                'reason': (
                    'Prevents MIME-type sniffing, which can cause browsers to '
                    'execute non-script responses as scripts.'
                ),
            },
        ],
        'framework_guidance': {
            'react': (
                'Never use dangerouslySetInnerHTML with unsanitised user content.  '
                'JSX auto-escapes all values by default.  Use DOMPurify before any '
                'innerHTML assignment.'
            ),
            'angular': (
                'Angular sanitises all interpolated values by default.  '
                'Never use [innerHTML] with untrusted data; if necessary, use '
                'DomSanitizer.bypassSecurityTrustHtml() only with content that '
                'has been sanitised by a trusted library.'
            ),
            'vue': (
                'Use {{ }} interpolation (HTML-escaped) instead of v-html.  '
                'If v-html is required, sanitise the HTML with DOMPurify first.'
            ),
        },
    },

    # ── SSRF (CWE-918) ───────────────────────────────────────────────────────
    'CWE-918': {
        'code_fixes': {
            'python': (
                '# Validate the scheme and host against an allow-list before fetching\n'
                'from urllib.parse import urlparse\n'
                '\n'
                'ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}\n'
                '\n'
                'def safe_fetch(url: str):\n'
                '    parsed = urlparse(url)\n'
                '    if parsed.scheme not in ("http", "https"):\n'
                '        raise ValueError("Invalid scheme")\n'
                '    if parsed.hostname not in ALLOWED_HOSTS:\n'
                '        raise ValueError("Host not allowed")\n'
                '    return requests.get(url, timeout=5, allow_redirects=False)\n'
            ),
            'nodejs': (
                '// Validate URL against an allow-list before making the request\n'
                'const ALLOWED_HOSTS = new Set(["api.example.com"]);\n'
                '\n'
                'function safeRequest(urlStr) {\n'
                '    const url = new URL(urlStr);\n'
                '    if (!["http:", "https:"].includes(url.protocol))\n'
                '        throw new Error("Invalid scheme");\n'
                '    if (!ALLOWED_HOSTS.has(url.hostname))\n'
                '        throw new Error("Host not allowed");\n'
                '    return fetch(urlStr, { redirect: "manual" });\n'
                '}\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {
            'nginx': (
                '# Block requests to private/metadata IP ranges at the network layer\n'
                '# (also enforce via egress firewall rules)\n'
                'geo $is_internal {\n'
                '    default 0;\n'
                '    10.0.0.0/8 1;\n'
                '    172.16.0.0/12 1;\n'
                '    192.168.0.0/16 1;\n'
                '    169.254.0.0/16 1;  # AWS IMDS\n'
                '}\n'
            ),
            'apache': '',
            'iis': '',
        },
        'header_fixes': [],
        'framework_guidance': {
            'django': (
                'Use "ALLOWED_HOSTS" to control the server-side hostname.  '
                'For outbound requests, enforce a strict URL allow-list via a '
                'dedicated HTTP client wrapper that validates scheme, hostname, '
                'and blocks RFC-1918 / link-local addresses.'
            ),
        },
    },

    # ── Path Traversal (CWE-22) ──────────────────────────────────────────────
    'CWE-22': {
        'code_fixes': {
            'python': (
                'import os, pathlib\n'
                '\n'
                'BASE_DIR = pathlib.Path("/var/www/uploads").resolve()\n'
                '\n'
                'def safe_open(filename: str):\n'
                '    target = (BASE_DIR / filename).resolve()\n'
                '    # Reject paths that escape BASE_DIR\n'
                '    if not str(target).startswith(str(BASE_DIR) + os.sep):\n'
                '        raise ValueError("Path traversal detected")\n'
                '    return open(target, "rb")\n'
            ),
            'nodejs': (
                'const path = require("path");\n'
                'const BASE_DIR = path.resolve("/var/www/uploads");\n'
                '\n'
                'function safeOpen(filename) {\n'
                '    const target = path.resolve(BASE_DIR, filename);\n'
                '    if (!target.startsWith(BASE_DIR + path.sep))\n'
                '        throw new Error("Path traversal detected");\n'
                '    return fs.createReadStream(target);\n'
                '}\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {
            'nginx': (
                'location /uploads/ {\n'
                '    # Disable path normalisation bypass\n'
                '    merge_slashes on;\n'
                '    # Serve only known file types\n'
                '    location ~* \\.(php|sh|pl|py|rb)$ { deny all; }\n'
                '}\n'
            ),
            'apache': (
                '<Directory "/var/www/uploads">\n'
                '    Options -Indexes -FollowSymLinks\n'
                '    AllowOverride None\n'
                '    Require all granted\n'
                '</Directory>\n'
            ),
            'iis': '',
        },
        'header_fixes': [],
        'framework_guidance': {},
    },

    # ── CSRF (CWE-352) ───────────────────────────────────────────────────────
    'CWE-352': {
        'code_fixes': {
            'python': (
                '# Django: CSRF middleware is enabled by default.\n'
                '# Ensure CsrfViewMiddleware is in MIDDLEWARE.\n'
                '# Ensure {% csrf_token %} is in every POST form.\n'
                '\n'
                '# For DRF APIs, use SessionAuthentication which enforces CSRF,\n'
                '# or use stateless JWT with HttpOnly cookies + custom header.\n'
            ),
            'nodejs': (
                '// Use the csurf middleware (or csrf-csrf for ESM)\n'
                'const csrf = require("csurf");\n'
                'app.use(csrf({ cookie: { httpOnly: true, sameSite: "strict" } }));\n'
                '\n'
                'app.get("/form", (req, res) => {\n'
                '    res.render("form", { csrfToken: req.csrfToken() });\n'
                '});\n'
                'app.post("/submit", (req, res) => { /* csurf validates automatically */ });\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {'nginx': '', 'apache': '', 'iis': ''},
        'header_fixes': [
            {
                'header': 'Set-Cookie',
                'value': 'SameSite=Strict; Secure; HttpOnly',
                'reason': (
                    'SameSite=Strict prevents the browser from sending the session '
                    'cookie on cross-site requests, eliminating the CSRF attack vector '
                    'for modern browsers.'
                ),
            },
        ],
        'framework_guidance': {
            'django': (
                'Keep CsrfViewMiddleware enabled.  Use {% csrf_token %} in all forms.  '
                'For AJAX, include the csrfmiddlewaretoken in the X-CSRFToken header.'
            ),
            'rails': (
                'Use protect_from_forgery :with => :exception in ApplicationController.  '
                'Enable the Lax/Strict SameSite cookie attribute via cookies_same_site_protection.'
            ),
        },
    },

    # ── Broken Authentication (CWE-287) ──────────────────────────────────────
    'CWE-287': {
        'code_fixes': {
            'python': (
                '# Use bcrypt / argon2 for password hashing (never SHA-1/MD5)\n'
                'import bcrypt\n'
                '\n'
                'def hash_password(plain: str) -> bytes:\n'
                '    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12))\n'
                '\n'
                'def verify_password(plain: str, hashed: bytes) -> bool:\n'
                '    return bcrypt.checkpw(plain.encode(), hashed)\n'
            ),
            'nodejs': (
                '// Use bcrypt (or argon2) — never store plaintext or MD5 passwords\n'
                'const bcrypt = require("bcryptjs");\n'
                '\n'
                'async function hashPassword(plain) {\n'
                '    return bcrypt.hash(plain, 12);\n'
                '}\n'
                'async function verifyPassword(plain, hash) {\n'
                '    return bcrypt.compare(plain, hash);\n'
                '}\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {'nginx': '', 'apache': '', 'iis': ''},
        'header_fixes': [],
        'framework_guidance': {
            'django': (
                'Use Django\'s built-in password hashers (Argon2PasswordHasher is '
                'recommended).  Enable account lockout with django-axes or similar.  '
                'Enforce multi-factor authentication with django-otp.'
            ),
        },
    },

    # ── Sensitive Data Exposure (CWE-312) ───────────────────────────────────
    'CWE-312': {
        'code_fixes': {
            'python': (
                '# Encrypt sensitive fields at rest using cryptography (Fernet = AES-128-CBC + HMAC)\n'
                'from cryptography.fernet import Fernet\n'
                '\n'
                'key = Fernet.generate_key()        # store securely in vault\n'
                'cipher = Fernet(key)\n'
                '\n'
                'def encrypt(value: str) -> bytes:\n'
                '    return cipher.encrypt(value.encode())\n'
                '\n'
                'def decrypt(token: bytes) -> str:\n'
                '    return cipher.decrypt(token).decode()\n'
            ),
            'nodejs': (
                '// Use AES-256-GCM for symmetric encryption at rest\n'
                'const { createCipheriv, createDecipheriv, randomBytes } = require("crypto");\n'
                '\n'
                'const KEY = Buffer.from(process.env.ENCRYPTION_KEY, "hex");  // 32 bytes\n'
                '\n'
                'function encrypt(plaintext) {\n'
                '    const iv = randomBytes(12);\n'
                '    const cipher = createCipheriv("aes-256-gcm", KEY, iv);\n'
                '    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);\n'
                '    const tag = cipher.getAuthTag();\n'
                '    return { iv: iv.toString("hex"), ciphertext: ciphertext.toString("hex"), tag: tag.toString("hex") };\n'
                '}\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {
            'nginx': (
                'server {\n'
                '    # Enforce TLS 1.2+ and disable weak ciphers\n'
                '    ssl_protocols TLSv1.2 TLSv1.3;\n'
                '    ssl_prefer_server_ciphers on;\n'
                '    ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK";\n'
                '    ssl_session_cache shared:SSL:10m;\n'
                '    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;\n'
                '}\n'
            ),
            'apache': (
                'SSLEngine on\n'
                'SSLProtocol -all +TLSv1.2 +TLSv1.3\n'
                'SSLCipherSuite HIGH:!aNULL:!MD5:!3DES\n'
                'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"\n'
            ),
            'iis': '',
        },
        'header_fixes': [
            {
                'header': 'Strict-Transport-Security',
                'value': 'max-age=63072000; includeSubDomains; preload',
                'reason': (
                    'HSTS forces browsers to connect via HTTPS, preventing protocol '
                    'downgrade attacks and cleartext transmission of sensitive data.'
                ),
            },
            {
                'header': 'Cache-Control',
                'value': 'no-store, no-cache, max-age=0, must-revalidate',
                'reason': (
                    'Prevents browsers and intermediary proxies from caching pages '
                    'that contain sensitive data.'
                ),
            },
        ],
        'framework_guidance': {
            'django': (
                'Set SECURE_HSTS_SECONDS, SECURE_SSL_REDIRECT, and SESSION_COOKIE_SECURE.  '
                'Use Django\'s encrypted field libraries (e.g., django-encrypted-model-fields) '
                'for PII fields.'
            ),
        },
    },

    # ── XXE (CWE-611) ────────────────────────────────────────────────────────
    'CWE-611': {
        'code_fixes': {
            'python': (
                '# Use defusedxml to prevent XXE, entity expansion, and other XML attacks\n'
                'import defusedxml.ElementTree as ET\n'
                '\n'
                '# UNSAFE: xml.etree.ElementTree.parse(user_file)\n'
                '# SAFE:\n'
                'tree = ET.parse(user_file)   # defusedxml rejects XXE payloads\n'
                'root = tree.getroot()\n'
            ),
            'java': (
                '// Disable external entity processing in DocumentBuilderFactory\n'
                'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n'
                'factory.setFeature(\n'
                '    "http://apache.org/xml/features/disallow-doctype-decl", true);\n'
                'factory.setFeature(\n'
                '    "http://xml.org/sax/features/external-general-entities", false);\n'
                'factory.setFeature(\n'
                '    "http://xml.org/sax/features/external-parameter-entities", false);\n'
                'factory.setExpandEntityReferences(false);\n'
                'DocumentBuilder builder = factory.newDocumentBuilder();\n'
            ),
            'php': '',
            'nodejs': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {'nginx': '', 'apache': '', 'iis': ''},
        'header_fixes': [],
        'framework_guidance': {
            'spring': (
                'Configure Jackson\'s XmlMapper with StaxBuilder and disable external '
                'entities.  Use Spring Security\'s default XSS defaults as a baseline '
                'and add custom XML parsing beans with disabled entity expansion.'
            ),
        },
    },

    # ── IDOR (CWE-639) ───────────────────────────────────────────────────────
    'CWE-639': {
        'code_fixes': {
            'python': (
                '# Always scope queries by the authenticated user\n'
                '# UNSAFE:\n'
                '# document = Document.objects.get(id=request.GET["doc_id"])\n'
                '\n'
                '# SAFE — ownership enforced at query level:\n'
                'document = Document.objects.get(\n'
                '    id=request.GET["doc_id"],\n'
                '    owner=request.user,          # ownership check\n'
                ')\n'
            ),
            'nodejs': (
                '// Scope DB queries by the authenticated user ID\n'
                'const doc = await Document.findOne({\n'
                '    _id: req.params.id,\n'
                '    ownerId: req.user.id,   // ownership check\n'
                '});\n'
                'if (!doc) return res.status(403).send("Not authorised");\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {'nginx': '', 'apache': '', 'iis': ''},
        'header_fixes': [],
        'framework_guidance': {
            'django': (
                'Use object-level permissions (django-guardian or DRF\'s '
                'has_object_permission).  Never retrieve objects by PK alone; '
                'always filter by the authenticated user.'
            ),
        },
    },

    # ── Open Redirect (CWE-601) ──────────────────────────────────────────────
    'CWE-601': {
        'code_fixes': {
            'python': (
                '# Only redirect to paths on the same host (relative URLs)\n'
                'from urllib.parse import urlparse\n'
                '\n'
                'def safe_redirect(url: str) -> str:\n'
                '    parsed = urlparse(url)\n'
                '    # Reject absolute URLs (external domains)\n'
                '    if parsed.netloc:\n'
                '        return "/"\n'
                '    return url\n'
            ),
            'nodejs': (
                '// Only allow relative redirects (no network location)\n'
                'function safeRedirect(url) {\n'
                '    try {\n'
                '        const parsed = new URL(url, "http://dummy.host");\n'
                '        if (parsed.hostname !== "dummy.host") return "/";\n'
                '        return parsed.pathname + parsed.search;\n'
                '    } catch { return "/"; }\n'
                '}\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {'nginx': '', 'apache': '', 'iis': ''},
        'header_fixes': [],
        'framework_guidance': {
            'django': (
                'Use is_safe_url() (Django ≤ 3.x) / url_has_allowed_host_and_scheme() '
                '(Django ≥ 4.x) before redirecting.  Always pass allowed_hosts=request.get_host().'
            ),
        },
    },

    # ── SSTI (CWE-1336) ──────────────────────────────────────────────────────
    'CWE-1336': {
        'code_fixes': {
            'python': (
                '# Never render user-supplied strings as Jinja2/Mako templates.\n'
                '# Use jinja2.Environment with a Loader pointing to a trusted template dir.\n'
                '\n'
                '# UNSAFE:\n'
                '# jinja2.Environment().from_string(user_input).render()\n'
                '\n'
                '# SAFE — user input passed as data, not template code:\n'
                'from jinja2 import Environment, FileSystemLoader\n'
                'env = Environment(loader=FileSystemLoader("/templates"), autoescape=True)\n'
                'template = env.get_template("welcome.html")          # from disk\n'
                'html = template.render(name=user_input)              # user input = data\n'
            ),
            'nodejs': (
                '// Never pass user input as Handlebars/Nunjucks/Pug template source.\n'
                '// Treat user input as data context only.\n'
                '// UNSAFE: nunjucks.renderString(userTemplate, context)\n'
                '// SAFE:   nunjucks.render("trusted_file.html", { name: userInput })\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {'nginx': '', 'apache': '', 'iis': ''},
        'header_fixes': [],
        'framework_guidance': {
            'flask': (
                'Never pass request data to render_template_string().  '
                'Use render_template() with trusted files from the templates/ directory.  '
                'Enable Jinja2\'s autoescape globally in the Flask app factory.'
            ),
        },
    },

    # ── RCE / Code Injection (CWE-94) ────────────────────────────────────────
    'CWE-94': {
        'code_fixes': {
            'python': (
                '# Never pass user input to eval(), exec(), or compile()\n'
                '# UNSAFE: eval(user_formula)\n'
                '\n'
                '# For mathematical expressions, use ast.literal_eval (literals only):\n'
                'import ast\n'
                'value = ast.literal_eval(user_expression)  # raises ValueError on code\n'
                '\n'
                '# For dynamic imports, use an explicit allow-list:\n'
                'ALLOWED_MODULES = {"math", "statistics"}\n'
                'if module_name not in ALLOWED_MODULES:\n'
                '    raise ValueError("Module not permitted")\n'
                'module = importlib.import_module(module_name)\n'
            ),
            'nodejs': (
                '// Never pass user input to eval(), new Function(), or vm.runInThisContext()\n'
                '// Use a sandboxed VM with a timeout:\n'
                'const vm = require("vm");\n'
                'const sandbox = {};\n'
                'const script = new vm.Script(userCode);\n'
                'const ctx = vm.createContext(sandbox);\n'
                'script.runInContext(ctx, { timeout: 100 });  // 100 ms timeout\n'
                '// Note: vm is NOT a security boundary—use a subprocess + seccomp instead\n'
            ),
            'java': '',
            'php': '',
            'csharp': '',
            'go': '',
        },
        'server_configs': {
            'nginx': (
                '# Harden the server process with mandatory access controls\n'
                '# (systemd unit example — not nginx.conf)\n'
                '# ProtectSystem=strict\n'
                '# NoNewPrivileges=yes\n'
                '# CapabilityBoundingSet=\n'
            ),
            'apache': '',
            'iis': '',
        },
        'header_fixes': [],
        'framework_guidance': {
            'django': (
                'Never use Django\'s Shell Plus with user-supplied code in production.  '
                'Sandbox user-provided eval scenarios in a subprocess with a restricted '
                'Python interpreter (RestrictedPython) or a dedicated container.'
            ),
        },
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Compliance Mapping
# ──────────────────────────────────────────────────────────────────────────────

COMPLIANCE_MAP: dict[str, dict] = {

    'CWE-89': {
        'owasp_top10_2021': 'A03:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['6.2.4', '6.3.1', '11.3.1'],
        'soc2': ['CC6.1', 'CC6.6'],
        'iso_27001': ['A.14.2.5', 'A.14.3.1'],
        'nist_800_53': ['SI-10', 'SA-15', 'SC-28'],
        'hipaa': ['§164.312(a)(2)(i)', '§164.312(e)(2)(ii)'],
        'gdpr': ['Art. 25', 'Art. 32'],
    },

    'CWE-79': {
        'owasp_top10_2021': 'A03:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': 'LLM02',
        'pci_dss_v4': ['6.2.4', '6.4.1'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SI-10', 'SC-18'],
        'hipaa': ['§164.312(a)(2)(i)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-918': {
        'owasp_top10_2021': 'A10:2021',
        'owasp_api_top10_2023': 'API7:2023',
        'owasp_llm_top10': 'LLM07',
        'pci_dss_v4': ['6.2.4', '1.3.2'],
        'soc2': ['CC6.6', 'CC6.7'],
        'iso_27001': ['A.13.1.3', 'A.14.2.5'],
        'nist_800_53': ['SC-7', 'SI-10'],
        'hipaa': ['§164.312(c)(1)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-639': {
        'owasp_top10_2021': 'A01:2021',
        'owasp_api_top10_2023': 'API1:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['7.2.1', '7.2.2'],
        'soc2': ['CC6.3'],
        'iso_27001': ['A.9.4.1'],
        'nist_800_53': ['AC-3', 'AC-6'],
        'hipaa': ['§164.312(a)(1)'],
        'gdpr': ['Art. 5(1)(f)', 'Art. 32'],
    },

    'CWE-22': {
        'owasp_top10_2021': 'A01:2021',
        'owasp_api_top10_2023': 'API1:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['6.2.4', '6.3.1'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SI-10', 'AC-3'],
        'hipaa': ['§164.312(c)(1)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-611': {
        'owasp_top10_2021': 'A05:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['6.2.4'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SI-10'],
        'hipaa': ['§164.312(a)(2)(i)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-352': {
        'owasp_top10_2021': 'A01:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['6.2.4', '6.4.1'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SC-23', 'SI-10'],
        'hipaa': ['§164.312(d)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-601': {
        'owasp_top10_2021': 'A01:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['6.2.4'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SI-10'],
        'hipaa': [],
        'gdpr': ['Art. 32'],
    },

    'CWE-287': {
        'owasp_top10_2021': 'A07:2021',
        'owasp_api_top10_2023': 'API2:2023',
        'owasp_llm_top10': None,
        'pci_dss_v4': ['8.2.1', '8.3.6', '8.6.1'],
        'soc2': ['CC6.1', 'CC6.2'],
        'iso_27001': ['A.9.4.3', 'A.9.2.4'],
        'nist_800_53': ['IA-5', 'AC-7', 'IA-2'],
        'hipaa': ['§164.312(d)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-312': {
        'owasp_top10_2021': 'A02:2021',
        'owasp_api_top10_2023': 'API3:2023',
        'owasp_llm_top10': 'LLM06',
        'pci_dss_v4': ['3.5.1', '4.2.1'],
        'soc2': ['CC6.1', 'CC6.7'],
        'iso_27001': ['A.10.1.1', 'A.8.2.3'],
        'nist_800_53': ['SC-28', 'SC-8', 'IA-5'],
        'hipaa': ['§164.312(a)(2)(iv)', '§164.312(e)(1)'],
        'gdpr': ['Art. 5(1)(f)', 'Art. 32'],
    },

    'CWE-1336': {
        'owasp_top10_2021': 'A03:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': 'LLM02',
        'pci_dss_v4': ['6.2.4'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SI-10'],
        'hipaa': ['§164.312(a)(2)(i)'],
        'gdpr': ['Art. 32'],
    },

    'CWE-94': {
        'owasp_top10_2021': 'A03:2021',
        'owasp_api_top10_2023': 'API8:2023',
        'owasp_llm_top10': 'LLM02',
        'pci_dss_v4': ['6.2.4', '6.3.1'],
        'soc2': ['CC6.1'],
        'iso_27001': ['A.14.2.5'],
        'nist_800_53': ['SI-10', 'SA-15'],
        'hipaa': ['§164.312(a)(2)(i)'],
        'gdpr': ['Art. 32'],
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

_ALL_FRAMEWORKS = (
    'owasp_top10_2021', 'owasp_api_top10_2023', 'owasp_llm_top10',
    'pci_dss_v4', 'soc2', 'iso_27001', 'nist_800_53', 'hipaa', 'gdpr',
)


class RemediationKB:
    """Read-only interface to the remediation and compliance knowledge base."""

    def get_remediation(self, cwe: str) -> Optional[dict]:
        """Return the full remediation record for a CWE, or None."""
        return REMEDIATION_DB.get(cwe)

    def get_code_fix(self, cwe: str, language: str) -> Optional[str]:
        """
        Return the code fix snippet for *cwe* in *language*.

        *language* is one of: python, java, php, nodejs, csharp, go.
        Returns None if the CWE or language is not in the database, or if the
        snippet is an empty string (not yet written).
        """
        entry = REMEDIATION_DB.get(cwe)
        if not entry:
            return None
        snippet = entry.get('code_fixes', {}).get(language)
        return snippet or None

    def get_server_config(self, cwe: str, server: str) -> Optional[str]:
        """Return a server configuration snippet for *cwe* and *server* (nginx/apache/iis)."""
        entry = REMEDIATION_DB.get(cwe)
        if not entry:
            return None
        snippet = entry.get('server_configs', {}).get(server)
        return snippet or None

    def get_header_fixes(self, cwe: str) -> list[dict]:
        """Return the list of recommended security header dicts for *cwe*."""
        entry = REMEDIATION_DB.get(cwe)
        return entry.get('header_fixes', []) if entry else []

    def get_framework_guidance(self, cwe: str) -> dict:
        """Return the framework-specific guidance dict for *cwe*."""
        entry = REMEDIATION_DB.get(cwe)
        return entry.get('framework_guidance', {}) if entry else {}

    def get_compliance(self, cwe: str) -> Optional[dict]:
        """Return the full compliance mapping dict for *cwe*, or None."""
        return COMPLIANCE_MAP.get(cwe)

    def get_compliance_for_framework(
        self,
        cwe: str,
        framework: str,
    ) -> list[str]:
        """
        Return the compliance control list for *cwe* and *framework*.

        *framework* is one of the keys in *_ALL_FRAMEWORKS*.
        Returns an empty list if the CWE is not mapped or the framework has
        no associated controls.
        """
        mapping = COMPLIANCE_MAP.get(cwe)
        if not mapping:
            return []
        value = mapping.get(framework)
        if not value:
            return []
        if isinstance(value, str):
            return [value]
        return list(value)

    def all_frameworks(self) -> tuple[str, ...]:
        """Return a tuple of all supported compliance framework keys."""
        return _ALL_FRAMEWORKS

    def has_remediation(self, cwe: str) -> bool:
        """Return True if the CWE has any remediation entry."""
        return cwe in REMEDIATION_DB
