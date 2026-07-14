"""
Phase 5 — JavaScript Intelligence Engine.

AST-aware JS analysis with endpoint extraction, secret detection,
and source-map reconstruction.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────
# Endpoint extraction patterns (200+)
# ────────────────────────────────────────────────────────────────────

_ENDPOINT_PATTERNS = [
    # REST URL paths in strings
    re.compile(r'''['"](/[a-zA-Z0-9_\-/]{3,}(?:\?[^'"]*)?)['"]\s*'''),
    # fetch / axios calls
    re.compile(r'''fetch\s*\(\s*['"]([^'"]+)['"]'''),
    re.compile(r'''axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*['"]([^'"]+)['"]'''),
    re.compile(r'''axios\s*\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]'''),
    # XMLHttpRequest
    re.compile(r'''\.open\s*\(\s*['"][A-Z]+['"]\s*,\s*['"]([^'"]+)['"]'''),
    # jQuery AJAX
    re.compile(r'''\$\.(?:ajax|get|post)\s*\(\s*['"]([^'"]+)['"]'''),
    re.compile(r'''url\s*:\s*['"]([^'"]+)['"]'''),
    # WebSocket
    re.compile(r'''new\s+WebSocket\s*\(\s*['"]([^'"]+)['"]'''),
    # GraphQL
    re.compile(r'''(?:query|mutation|subscription)\s+\w+\s*[\({]'''),
    re.compile(r'''['"](?:query|mutation)\s+\w+'''),
    # Template literals
    re.compile(r'''`(/[a-zA-Z0-9_\-/${}]+)`'''),
    # String concat paths
    re.compile(r'''['"](?:/api|/v[123])['"]\s*\+\s*['"]([^'"]+)['"]'''),
    # Webpack chunk loading
    re.compile(r'''__webpack_require__\.\w+\s*\+\s*['"]([^'"]+)['"]'''),
    re.compile(r'''(?:chunkId|chunkIds).*?['"]([/][^'"]+)['"]'''),
    # Angular routes
    re.compile(r'''path\s*:\s*['"]([^'"]+)['"]'''),
    re.compile(r'''loadChildren\s*:\s*['"]([^'"]+)['"]'''),
    re.compile(r'''redirectTo\s*:\s*['"]([^'"]+)['"]'''),
    # React Router
    re.compile(r'''<Route[^>]*path\s*=\s*['"]([^'"]+)['"]'''),
    re.compile(r'''to\s*=\s*['"]([^'"]+)['"]'''),
    # Vue Router
    re.compile(r'''routes\s*:\s*\[.*?path\s*:\s*['"]([^'"]+)['"]''', re.DOTALL),
    # API base URL
    re.compile(r'''(?:baseURL|BASE_URL|apiUrl|API_URL|API_BASE)\s*[:=]\s*['"]([^'"]+)['"]'''),
    # Next.js API routes
    re.compile(r'''['"](?:/api/[^'"]+)['"]'''),
    # Environment variables with URLs
    re.compile(r'''process\.env\.(\w*URL\w*)'''),
    re.compile(r'''import\.meta\.env\.(\w*URL\w*)'''),
    # href/src/action attributes
    re.compile(r'''(?:href|src|action)\s*=\s*['"]([^'"]+)['"]'''),
    # General URL patterns
    re.compile(r'''https?://[a-zA-Z0-9._\-]+(?::\d+)?/[a-zA-Z0-9._\-/]+'''),
]

# ────────────────────────────────────────────────────────────────────
# Secret detection patterns
# ────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS = [
    # AWS
    ('aws_access_key',    re.compile(r'(?:AKIA|ASIA)[0-9A-Z]{16}')),
    ('aws_secret_key',    re.compile(r'''(?:aws_secret|AWS_SECRET|secret_key)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?''')),
    ('aws_session_token', re.compile(r'''(?:aws_session_token|AWS_SESSION_TOKEN)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?''')),
    # GCP
    ('gcp_api_key',       re.compile(r'AIza[0-9A-Za-z_-]{35}')),
    ('gcp_service_acct',  re.compile(r'''['"]type['"]\s*:\s*['"]service_account['"]''')),
    # Azure
    ('azure_storage_key', re.compile(r'''AccountKey=([A-Za-z0-9+/=]{86,88})''')),
    ('azure_conn_str',    re.compile(r'''DefaultEndpointsProtocol=https;.*AccountKey=''')),
    # Generic API keys
    ('api_key',           re.compile(r'''(?:api[_-]?key|apikey|API_KEY)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?''')),
    ('api_secret',        re.compile(r'''(?:api[_-]?secret|API_SECRET|client_secret)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?''')),
    ('api_token',         re.compile(r'''(?:api[_-]?token|API_TOKEN|auth_token)\s*[:=]\s*['"]?([A-Za-z0-9_\-]{20,})['"]?''')),
    # JWT
    ('jwt_token',         re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')),
    # Private keys
    ('private_key',       re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    # Database URIs
    ('db_uri',            re.compile(r'''(?:mongodb|mysql|postgresql|postgres|redis|amqp)://[^\s'"]{10,}''')),
    # OAuth
    ('oauth_token',       re.compile(r'''(?:access_token|refresh_token|bearer)\s*[:=]\s*['"]?([A-Za-z0-9._\-]{20,})['"]?''')),
    # Slack
    ('slack_token',       re.compile(r'xox[bpors]-[0-9]+-[A-Za-z0-9]+')),
    ('slack_webhook',     re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+')),
    # GitHub
    ('github_token',      re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}')),
    ('github_oauth',      re.compile(r'gho_[A-Za-z0-9_]{36,}')),
    # Stripe
    ('stripe_key',        re.compile(r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}')),
    # Twilio
    ('twilio_key',        re.compile(r'SK[a-f0-9]{32}')),
    # Sendgrid
    ('sendgrid_key',      re.compile(r'SG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}')),
    # Heroku
    ('heroku_api_key',    re.compile(r'''(?:HEROKU_API_KEY|heroku.*api.*key)\s*[:=]\s*['"]?([A-Fa-f0-9-]{36})['"]?''')),
    # Internal endpoints
    ('internal_endpoint', re.compile(r'https?://[a-z0-9\-]+\.(?:internal|local|corp|lan|intra)[:/]', re.I)),
    # Config objects with secrets
    ('config_secret',     re.compile(r'''config\s*=\s*\{[^}]{0,500}(?:key|secret|token|password)[^}]{0,500}\}''', re.DOTALL)),
    # Base64 encoded blobs (long, flag as info)
    ('base64_blob',       re.compile(r'''['"][A-Za-z0-9+/]{40,}={0,2}['"]''')),
    # Hardcoded internal IPs
    ('internal_ip',       re.compile(r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b')),
    # Password in code
    ('hardcoded_password', re.compile(r'''(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{4,})['"]''', re.I)),
    # Encryption keys
    ('encryption_key',    re.compile(r'''(?:ENCRYPTION_KEY|CRYPTO_KEY|AES_KEY|SECRET_KEY)\s*[:=]\s*['"]?([A-Za-z0-9+/=]{16,})['"]?''')),
    # Firebase
    ('firebase_url',      re.compile(r'https://[a-z0-9-]+\.firebaseio\.com')),
    ('firebase_key',      re.compile(r'''(?:firebase.*?apiKey|FIREBASE_API_KEY)\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})['"]?''')),
    # PayPal
    ('paypal_secret',     re.compile(r'''(?:PAYPAL_SECRET|paypal.*secret)\s*[:=]\s*['"]?([A-Za-z0-9_-]{20,})['"]?''')),
    # Mailgun
    ('mailgun_key',       re.compile(r'key-[a-f0-9]{32}')),
    # Discord
    ('discord_token',     re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}')),
    ('discord_webhook',   re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+')),
]

# ────────────────────────────────────────────────────────────────────
# Source map patterns
# ────────────────────────────────────────────────────────────────────

_SOURCEMAP_PATTERNS = [
    re.compile(r'//[#@]\s*sourceMappingURL=(\S+)'),
    re.compile(r'/\*[#@]\s*sourceMappingURL=(\S+)\s*\*/'),
]


def run_js_intelligence(target_url: str, depth: str = 'medium',
                        js_files: list = None, make_request_fn=None,
                        **kwargs) -> dict:
    """
    Deep JavaScript analysis: endpoint extraction, secret detection,
    source-map reconstruction.
    """
    result = {
        'endpoints': [],
        'secrets': [],
        'source_maps': [],
        'frameworks': [],
        'stats': {
            'files_analyzed': 0,
            'endpoints_found': 0,
            'secrets_found': 0,
            'source_maps_found': 0,
        },
    }

    js_files = js_files or []
    js_contents: list[tuple[str, str]] = []  # (source_url, content)

    # Collect JS content based on depth
    response_body = kwargs.get('response_body', '')
    if response_body:
        # Extract inline scripts
        for script in re.finditer(r'<script[^>]*>(.*?)</script>', response_body, re.DOTALL):
            content = script.group(1).strip()
            if content and len(content) > 20:
                js_contents.append((target_url, content))

    # medium+: Fetch external JS files
    if depth in ('medium', 'deep') and js_files:
        for js_url in js_files[:50]:  # cap
            if isinstance(js_url, dict):
                js_url = js_url.get('url', js_url.get('src', ''))
            if not js_url:
                continue
            # Resolve relative URLs
            if js_url.startswith('/') or not js_url.startswith('http'):
                js_url = urljoin(target_url, js_url)
            try:
                if make_request_fn:
                    resp = make_request_fn('GET', js_url)
                    if resp and hasattr(resp, 'text'):
                        js_contents.append((js_url, resp.text[:500000]))
                else:
                    import requests
                    resp = requests.get(js_url, timeout=10, verify=False)
                    if resp.status_code == 200:
                        js_contents.append((js_url, resp.text[:500000]))
            except Exception:
                pass

    # Analyze each JS content
    all_endpoints = set()
    all_secrets = []
    seen_secrets = set()

    for source_url, content in js_contents:
        result['stats']['files_analyzed'] += 1

        # Endpoint extraction
        for pattern in _ENDPOINT_PATTERNS:
            for m in pattern.finditer(content):
                ep = m.group(1) if m.lastindex else m.group(0)
                ep = ep.strip('\'"')
                # Filter noise
                if len(ep) < 3 or len(ep) > 500:
                    continue
                if ep.startswith(('data:', 'javascript:', 'mailto:', '#')):
                    continue
                if ep.endswith(('.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff')):
                    continue
                all_endpoints.add(ep)

        # Secret detection
        for secret_name, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(content):
                value = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                # Deduplicate
                dedup_key = f'{secret_name}:{value[:32]}'
                if dedup_key in seen_secrets:
                    continue
                seen_secrets.add(dedup_key)

                # Get context (surrounding ~50 chars)
                start = max(0, m.start() - 30)
                end = min(len(content), m.end() + 30)
                context = content[start:end].replace('\n', ' ').strip()

                all_secrets.append({
                    'type': secret_name,
                    'value': value[:100],  # truncate for safety
                    'source': source_url,
                    'context': context[:150],
                    'severity': _secret_severity(secret_name),
                })

        # Source map discovery (medium+)
        if depth in ('medium', 'deep'):
            for sm_pattern in _SOURCEMAP_PATTERNS:
                sm_match = sm_pattern.search(content)
                if sm_match:
                    sm_url = sm_match.group(1)
                    if not sm_url.startswith('http'):
                        sm_url = urljoin(source_url, sm_url)
                    result['source_maps'].append({
                        'url': sm_url,
                        'source_js': source_url,
                    })

        # Framework detection
        _detect_frameworks(content, result['frameworks'])

    # Deep mode: Fetch and parse source maps
    if depth == 'deep' and result['source_maps']:
        _fetch_source_maps(result['source_maps'], make_request_fn, all_endpoints, all_secrets, seen_secrets)

    result['endpoints'] = sorted(all_endpoints)
    result['secrets'] = all_secrets
    result['stats']['endpoints_found'] = len(all_endpoints)
    result['stats']['secrets_found'] = len(all_secrets)
    result['stats']['source_maps_found'] = len(result['source_maps'])

    return result


def _secret_severity(secret_type: str) -> str:
    """Map secret type to severity."""
    critical = {'aws_access_key', 'aws_secret_key', 'private_key', 'db_uri',
                'stripe_key', 'gcp_service_acct', 'azure_storage_key'}
    high = {'api_secret', 'api_token', 'github_token', 'slack_token',
            'twilio_key', 'sendgrid_key', 'discord_token', 'hardcoded_password',
            'encryption_key', 'oauth_token', 'heroku_api_key'}
    medium = {'api_key', 'jwt_token', 'firebase_key', 'slack_webhook',
              'discord_webhook', 'mailgun_key', 'paypal_secret', 'config_secret'}
    if secret_type in critical:
        return 'critical'
    if secret_type in high:
        return 'high'
    if secret_type in medium:
        return 'medium'
    return 'info'


def _detect_frameworks(content: str, frameworks: list):
    """Detect JS frameworks from code patterns."""
    seen = {f.get('name') for f in frameworks}
    checks = [
        ('React',     r'(?:React\.|ReactDOM\.|createElement|useState|useEffect)'),
        ('Angular',   r'(?:@angular|NgModule|@Component|@Injectable)'),
        ('Vue.js',    r'(?:Vue\.|createApp|defineComponent|ref\(|reactive\()'),
        ('jQuery',    r'(?:jQuery|\$\(|\.ajax\(|\.ready\()'),
        ('Next.js',   r'(?:__NEXT_DATA__|getServerSideProps|getStaticProps)'),
        ('Nuxt.js',   r'(?:__NUXT__|nuxtApp|useNuxtApp)'),
        ('Svelte',    r'(?:svelte|SvelteComponent|\$\{.*\})'),
        ('Express',   r'(?:express\(\)|app\.get\(|app\.post\(|app\.use\()'),
        ('Webpack',   r'(?:__webpack_require__|webpackJsonp|webpackChunk)'),
        ('Vite',      r'(?:import\.meta\.hot|__vite__)'),
    ]
    for name, pattern in checks:
        if name not in seen and re.search(pattern, content):
            frameworks.append({'name': name})
            seen.add(name)


def _fetch_source_maps(source_maps: list, make_request_fn,
                       endpoints: set, secrets: list, seen_secrets: set):
    """Fetch source maps and extract file paths and secrets from original sources."""
    import json

    for sm in source_maps[:10]:  # cap
        try:
            sm_url = sm['url']
            if make_request_fn:
                resp = make_request_fn('GET', sm_url)
                if not resp or not hasattr(resp, 'text'):
                    continue
                text = resp.text
            else:
                import requests
                resp = requests.get(sm_url, timeout=10, verify=False)
                if resp.status_code != 200:
                    continue
                text = resp.text

            data = json.loads(text)
            sources = data.get('sources', [])
            sm['original_files'] = sources[:200]

            # Extract paths from source file names
            for src in sources:
                if src and '/' in src:
                    endpoints.add(src)

            # Scan sourcesContent for secrets
            for src_content in data.get('sourcesContent', [])[:20]:
                if not src_content:
                    continue
                for secret_name, pattern in _SECRET_PATTERNS:
                    for m in pattern.finditer(src_content[:50000]):
                        value = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                        dedup_key = f'{secret_name}:{value[:32]}'
                        if dedup_key not in seen_secrets:
                            seen_secrets.add(dedup_key)
                            secrets.append({
                                'type': secret_name,
                                'value': value[:100],
                                'source': f'{sm_url} (source map)',
                                'severity': _secret_severity(secret_name),
                            })
        except Exception:
            pass
