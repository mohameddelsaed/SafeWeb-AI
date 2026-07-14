"""
JavaScript Analyzer Module — Extract security-relevant data from JS.

Discovers: API keys, endpoints, secrets, internal paths, domains,
and framework indicators from JavaScript content.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time
from urllib.parse import urlparse

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Secret / API Key Patterns ─────────────────────────────────────────────
# Each entry: (name, compiled regex, severity)
_SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # ── AWS ──
    ('AWS Access Key', re.compile(r'AKIA[0-9A-Z]{16}'), 'high'),
    ('AWS Secret Key', re.compile(r'(?:aws_secret_access_key|AWS_SECRET)\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']'), 'critical'),
    ('AWS MWS Key', re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), 'high'),
    ('AWS Session Token', re.compile(r'(?:aws_session_token|AWS_SESSION_TOKEN)\s*[:=]\s*["\']([A-Za-z0-9/+=]{100,})["\']'), 'critical'),

    # ── Google / GCP ──
    ('Google API Key', re.compile(r'AIza[0-9A-Za-z\-_]{35}'), 'high'),
    ('Google OAuth', re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), 'medium'),
    ('Google Cloud Key', re.compile(r'(?:GOOG|goog)[A-Za-z0-9_\-]{20,}'), 'medium'),
    ('Firebase Database URL', re.compile(r'https://[\w-]+\.firebaseio\.com'), 'medium'),
    ('Firebase Auth Domain', re.compile(r'[\w-]+\.firebaseapp\.com'), 'low'),

    # ── Stripe ──
    ('Stripe Publishable Key', re.compile(r'pk_(live|test)_[0-9a-zA-Z]{24,}'), 'medium'),
    ('Stripe Secret Key', re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24,}'), 'critical'),
    ('Stripe Restricted Key', re.compile(r'rk_(live|test)_[0-9a-zA-Z]{24,}'), 'high'),

    # ── GitHub / GitLab ──
    ('GitHub Token', re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), 'critical'),
    ('GitHub OAuth', re.compile(r'github_pat_[A-Za-z0-9_]{22,}'), 'critical'),
    ('GitLab Token', re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'), 'critical'),
    ('GitLab Runner Token', re.compile(r'GR1348941[A-Za-z0-9\-_]{20,}'), 'critical'),

    # ── Communication ──
    ('Slack Token', re.compile(r'xox[bpras]-[0-9]{10,}-[0-9A-Za-z\-]+'), 'high'),
    ('Slack Webhook', re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+'), 'high'),
    ('Discord Bot Token', re.compile(r'(?:Bot |Bearer )?[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}'), 'high'),
    ('Discord Webhook', re.compile(r'https://discord(?:app)?\.com/api/webhooks/\d+/[\w-]+'), 'high'),
    ('Telegram Bot Token', re.compile(r'\d{8,10}:[A-Za-z0-9_-]{35}'), 'high'),
    ('Twilio API Key', re.compile(r'SK[0-9a-fA-F]{32}'), 'high'),
    ('Twilio Account SID', re.compile(r'AC[a-f0-9]{32}'), 'medium'),

    # ── Email Services ──
    ('SendGrid API Key', re.compile(r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'), 'critical'),
    ('Mailgun API Key', re.compile(r'key-[0-9a-zA-Z]{32}'), 'high'),
    ('Mailchimp API Key', re.compile(r'[0-9a-f]{32}-us\d{1,2}'), 'high'),
    ('Postmark Token', re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'), 'medium'),

    # ── Payment / Fintech ──
    ('Square Access Token', re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}'), 'critical'),
    ('Square OAuth Secret', re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'), 'critical'),
    ('PayPal Braintree Token', re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'), 'critical'),
    ('Plaid Secret', re.compile(r'(?:plaid[_-]?secret)\s*[:=]\s*["\']([a-z0-9]{30,})["\']', re.IGNORECASE), 'critical'),

    # ── Cloud / DevOps ──
    ('Heroku API Key', re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), 'medium'),
    ('Azure Client Secret', re.compile(r'(?:client_secret|AZURE_SECRET)\s*[:=]\s*["\']([A-Za-z0-9~._\-]{34,})["\']', re.IGNORECASE), 'critical'),
    ('Azure SAS Token', re.compile(r'(?:sig|sv|se|sp|spr|srt)=[^&\s]{10,}'), 'high'),
    ('DigitalOcean Token', re.compile(r'dop_v1_[a-f0-9]{64}'), 'critical'),
    ('Doppler Token', re.compile(r'dp\.pt\.[a-zA-Z0-9]{43}'), 'high'),
    ('Vault Token', re.compile(r'hvs\.[a-zA-Z0-9_-]{24,}'), 'critical'),
    ('NPM Token', re.compile(r'npm_[A-Za-z0-9]{36}'), 'high'),
    ('PyPI Token', re.compile(r'pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}'), 'critical'),
    ('Docker Hub Token', re.compile(r'dckr_pat_[A-Za-z0-9\-_]{36,}'), 'high'),

    # ── Auth Tokens ──
    ('JWT Token', re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), 'high'),
    ('Private Key', re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'critical'),
    ('Bearer Token', re.compile(r'["\']Bearer\s+[A-Za-z0-9\-_.~+/]{20,}["\']'), 'high'),
    ('Basic Auth Encoded', re.compile(r'Basic\s+[A-Za-z0-9+/]{20,}={0,2}'), 'high'),
    ('OAuth Token', re.compile(r'(?:oauth[_-]?token|access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9\-_.]{20,})["\']', re.IGNORECASE), 'high'),

    # ── Database ──
    ('MongoDB URI', re.compile(r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}'), 'critical'),
    ('PostgreSQL URI', re.compile(r'postgres(?:ql)?://[^\s"\'<>]{10,}'), 'critical'),
    ('MySQL URI', re.compile(r'mysql://[^\s"\'<>]{10,}'), 'critical'),
    ('Redis URI', re.compile(r'redis://[^\s"\'<>]{10,}'), 'high'),

    # ── AI / ML ──
    ('OpenAI API Key', re.compile(r'sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}'), 'critical'),
    ('OpenAI Project Key', re.compile(r'sk-proj-[A-Za-z0-9\-_]{40,}'), 'critical'),
    ('Anthropic API Key', re.compile(r'sk-ant-[A-Za-z0-9\-_]{40,}'), 'critical'),
    ('HuggingFace Token', re.compile(r'hf_[A-Za-z0-9]{34}'), 'high'),
    ('Replicate API Token', re.compile(r'r8_[A-Za-z0-9]{40}'), 'high'),
    ('Cohere API Key', re.compile(r'[A-Za-z0-9]{40}'), 'low'),  # Only as fallback

    # ── Generic ──
    ('Generic Secret Assignment', re.compile(
        r'(?:api[_-]?key|api[_-]?secret|auth[_-]?token|access[_-]?token|'
        r'secret[_-]?key|private[_-]?key|password|passwd|credentials|'
        r'encryption[_-]?key|signing[_-]?key|jwt[_-]?secret|session[_-]?secret|'
        r'db[_-]?password|database[_-]?password|admin[_-]?password|master[_-]?key)'
        r'\s*[:=]\s*["\']([^"\']{8,})["\']',
        re.IGNORECASE,
    ), 'high'),
    ('Hardcoded Password', re.compile(
        r'(?:pass(?:word|wd)?|secret|token)\s*[:=]\s*["\'](?!(?:test|example|placeholder|your|xxx|change|TODO)["\'])[^"\']{6,}["\']',
        re.IGNORECASE,
    ), 'high'),
]

# ── Endpoint Patterns ──────────────────────────────────────────────────────
_ENDPOINT_RE = re.compile(
    r'["\'](\s*/(?:api|v[0-9]|graphql|rest|rpc|ws|webhook|auth|oauth|'
    r'login|register|upload|download|admin|user|account|'
    r'search|health|status|config|settings)[^\s"\']*\s*)["\']',
    re.IGNORECASE,
)

# LinkFinder-style comprehensive endpoint regex
# Extracts relative paths, protocol-relative URLs and path-like strings
_LINKFINDER_RE = re.compile(
    r"""(?:"|')"""
    r"""("""
    r"""(?:[a-zA-Z]{1,10}://|//)"""     # scheme or protocol-relative
    r"""[^"'/]{1,}"""
    r"""\."""
    r"""[a-zA-Z]{2,}[^"']{0,}"""
    r"""|"""
    r"""(?:/|\.\./|\./)[^"'><,;| *()(%%$^/\\\[\]]"""     # relative path start
    r"""[^"'><,;|()]{1,}"""
    r"""|"""
    r"""[a-zA-Z0-9_\-/]{1,}/"""
    r"""[a-zA-Z0-9_\-/]{1,}"""
    r"""\.(?:[a-zA-Z]{1,4}|action)"""
    r"""(?:[\?|#][^"|']{0,}|)"""
    r"""|"""
    r"""[a-zA-Z0-9_\-/]{1,}/"""
    r"""[a-zA-Z0-9_\-/]{3,}"""
    r""")"""
    r"""(?:"|')""",
    re.VERBOSE,
)

# fetch / axios / XMLHttpRequest URL extraction
_FETCH_RE = re.compile(
    r'(?:fetch|axios\.(?:get|post|put|delete|patch)|\.open)\s*\(\s*'
    r'[`"\']([^`"\']+)[`"\']',
    re.IGNORECASE,
)

# ── Domain / URL Patterns ─────────────────────────────────────────────────
_HARDCODED_URL_RE = re.compile(
    r'["\'](\s*https?://[^\s"\']{5,}\s*)["\']',
)

# Source map reference  (//# sourceMappingURL=app.js.map)
_SOURCE_MAP_RE = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*([^\s"\']+)',
    re.IGNORECASE,
)

# Webpack / Vite asset manifest path references
_WEBPACK_CHUNK_RE = re.compile(
    r'(?:chunkFilename|filename|publicPath)\s*:\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)

# Email addresses
_EMAIL_RE = re.compile(
    r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b',
)

# Internal / RFC-1918 IP addresses
_INTERNAL_IP_RE = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|'
    r'172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'
    r'192\.168\.\d{1,3}\.\d{1,3}|'
    r'127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
)

# ── Framework Indicators ──────────────────────────────────────────────────
_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ('React', re.compile(r'(?:React\.createElement|__REACT_DEVTOOLS|reactDom|react-dom)', re.IGNORECASE)),
    ('Angular', re.compile(r'(?:ng\.(?:core|common)|angular\.(?:module|bootstrap)|__ng_)', re.IGNORECASE)),
    ('Vue.js', re.compile(r'(?:Vue\.(?:component|directive|use)|__VUE__|createApp)', re.IGNORECASE)),
    ('jQuery', re.compile(r'(?:jQuery|\.fn\.jquery|\$\.(?:ajax|get|post))', re.IGNORECASE)),
    ('Next.js', re.compile(r'(?:__NEXT_DATA__|_next/static|nextjs)', re.IGNORECASE)),
    ('Nuxt.js', re.compile(r'(?:__NUXT__|_nuxt/|nuxtjs)', re.IGNORECASE)),
    ('Svelte', re.compile(r'(?:__svelte|svelte-[\w]+|SvelteComponent)', re.IGNORECASE)),
    ('Webpack', re.compile(r'(?:webpackChunk|__webpack_require__|webpackJsonp)')),
    ('Vite', re.compile(r'(?:__vite__|/@vite/|import\.meta\.hot)')),
    ('Socket.IO', re.compile(r'(?:socket\.io|io\.connect|io\.sockets)')),
    ('GraphQL', re.compile(r'(?:__schema|IntrospectionQuery|graphql-tag|gql`)', re.IGNORECASE)),
    ('Axios', re.compile(r'(?:axios\.(?:create|defaults|interceptors))')),
    ('Lodash', re.compile(r'(?:_\.(?:map|filter|reduce|each|find)|lodash)')),
    ('Moment.js', re.compile(r'(?:moment\.(?:utc|locale|duration)|momentjs)')),
    ('D3.js', re.compile(r'(?:d3\.(?:select|scale|axis|svg))')),
    ('TensorFlow.js', re.compile(r'(?:tf\.(?:tensor|layers|train|model)|tensorflow)', re.IGNORECASE)),
    ('Three.js', re.compile(r'(?:THREE\.(?:Scene|Camera|Renderer|Mesh))')),
]

# Max content size to analyse per JS file (bytes)
_MAX_JS_SIZE = 500 * 1024  # 500 KB

# Max external JS files to fetch
_MAX_JS_FILES = 5


# ── Helpers ────────────────────────────────────────────────────────────────

def _mask_secret(value: str, visible: int = 6) -> str:
    """Truncate / mask a secret value for safe reporting."""
    value = value.strip()
    if len(value) <= visible:
        return value[:2] + '***'
    return value[:visible] + '...' + value[-3:]


def _context_snippet(content: str, start: int, length: int = 60) -> str:
    """Return a short surrounding snippet for context."""
    lo = max(0, start - 20)
    hi = min(len(content), start + length + 20)
    snippet = content[lo:hi].replace('\n', ' ').strip()
    if lo > 0:
        snippet = '...' + snippet
    if hi < len(content):
        snippet = snippet + '...'
    return snippet


def _analyze_content(content: str, target_hostname: str, root_domain: str) -> dict:
    """Analyse a single JS content blob and return categorised findings.

    Returns dict with keys: secrets, endpoints, domains, frameworks,
    source_maps, emails, internal_ips.
    """
    secrets: list[dict] = []
    endpoints: set[str] = set()
    domains: set[str] = set()
    frameworks: set[str] = set()
    source_maps: list[str] = []
    emails: set[str] = set()
    internal_ips: set[str] = set()

    # Truncate oversized content
    if len(content) > _MAX_JS_SIZE:
        content = content[:_MAX_JS_SIZE]

    # ── Secrets ──
    seen_secrets: set[str] = set()
    for name, pattern, severity in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            raw = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            raw = raw.strip()
            # Deduplicate
            dedup_key = f'{name}:{raw[:20]}'
            if dedup_key in seen_secrets:
                continue
            seen_secrets.add(dedup_key)
            secrets.append({
                'type': name,
                'value_preview': _mask_secret(raw),
                'severity': severity,
                'context': _context_snippet(content, match.start()),
            })

    # ── Endpoints (specific API patterns) ──
    for match in _ENDPOINT_RE.finditer(content):
        ep = match.group(1).strip()
        endpoints.add(ep)

    # ── Endpoints (LinkFinder-style deep extraction) ──
    for match in _LINKFINDER_RE.finditer(content):
        raw = match.group(1).strip()
        if not raw or len(raw) < 2:
            continue
        if raw.startswith(('http://', 'https://', '//')):
            try:
                parsed = urlparse(raw if raw.startswith('http') else 'https:' + raw)
                host = parsed.hostname or ''
                if host and host != target_hostname and not host.endswith(f'.{root_domain}'):
                    domains.add(raw)
                elif parsed.path and parsed.path != '/':
                    endpoints.add(parsed.path)
            except Exception:
                pass
        elif raw.startswith('/') or raw.startswith('./') or raw.startswith('../'):
            endpoints.add(raw)
        elif '/' in raw and not raw.startswith(('data:', 'javascript:', 'mailto:')):
            # path/like/this
            if re.match(r'^[A-Za-z0-9_\-/]{3,}$', raw):
                endpoints.add('/' + raw.lstrip('/'))

    for match in _FETCH_RE.finditer(content):
        url = match.group(1).strip()
        if url.startswith('/'):
            endpoints.add(url)
        elif url.startswith('http'):
            domains.add(url)

    # ── Hardcoded URLs / domains ──
    for match in _HARDCODED_URL_RE.finditer(content):
        url = match.group(1).strip()
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            if host and host != target_hostname and not host.endswith(f'.{root_domain}'):
                domains.add(url)
            elif host:
                # Internal full URL — extract path as endpoint
                if parsed.path and parsed.path != '/':
                    endpoints.add(parsed.path)
        except Exception:
            pass

    # ── Source map detection ──
    for match in _SOURCE_MAP_RE.finditer(content):
        map_ref = match.group(1).strip()
        source_maps.append(map_ref)

    # ── Webpack/Vite chunk references ──
    for match in _WEBPACK_CHUNK_RE.finditer(content):
        chunk_path = match.group(1).strip()
        if chunk_path and '/' in chunk_path:
            endpoints.add(chunk_path if chunk_path.startswith('/') else '/' + chunk_path)

    # ── Email addresses ──
    for match in _EMAIL_RE.finditer(content):
        email = match.group(0)
        # Filter out example/placeholder emails
        if not any(x in email.lower() for x in ('example', 'test', 'user@', 'foo@', 'bar@')):
            emails.add(email)

    # ── Internal IP addresses ──
    for match in _INTERNAL_IP_RE.finditer(content):
        internal_ips.add(match.group(0))

    # ── Frameworks ──
    for fw_name, fw_pattern in _FRAMEWORK_PATTERNS:
        if fw_pattern.search(content):
            frameworks.add(fw_name)

    return {
        'secrets': secrets,
        'endpoints': sorted(endpoints),
        'domains': sorted(domains),
        'frameworks': sorted(frameworks),
        'source_maps': source_maps,
        'emails': sorted(emails),
        'internal_ips': sorted(internal_ips),
    }


def _fetch_js_files(
    js_urls: list[str],
    make_request_fn,
    max_files: int = _MAX_JS_FILES,
) -> dict[str, str]:
    """Fetch up to *max_files* JS URLs and return ``{url: content}``."""
    fetched: dict[str, str] = {}
    for url in js_urls[:max_files]:
        try:
            resp = make_request_fn('GET', url)
            if resp is None:
                continue
            # Support both requests.Response and raw string
            if hasattr(resp, 'text'):
                text = resp.text
            elif isinstance(resp, str):
                text = resp
            else:
                continue
            if len(text) > _MAX_JS_SIZE:
                text = text[:_MAX_JS_SIZE]
            fetched[url] = text
        except Exception as exc:
            logger.debug('Failed to fetch JS file %s: %s', url, exc)
    return fetched


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_js_analyzer(
    target_url: str,
    js_urls: list | None = None,
    js_content: str = '',
    make_request_fn=None,
) -> dict:
    """Analyse JavaScript content for security-relevant intelligence.

    Args:
        target_url:      The target page URL (for domain classification).
        js_urls:         Optional list of JS file URLs to fetch and analyse.
        js_content:      Optional pre-fetched JS content string.
        make_request_fn: Optional callable ``fn(url) -> response`` used to
                         fetch *js_urls*. If ``None``, external JS files
                         are not fetched.

    Returns:
        Standardised result dict with legacy keys:
        ``secrets``, ``endpoints``, ``domains``, ``frameworks``,
        ``source_maps``, ``emails``, ``internal_ips``, ``issues``.
    """
    start = time.time()
    result = create_result('js_analyzer', target_url)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # ── Legacy top-level keys ──
    result['secrets'] = []
    result['endpoints'] = []
    result['domains'] = []
    result['frameworks'] = []
    result['source_maps'] = []
    result['emails'] = []
    result['internal_ips'] = []
    # result['issues'] already exists via create_result

    if not js_content and not js_urls:
        result['errors'].append('No JS content or JS URLs provided for analysis')
        return finalize_result(result, start)

    all_secrets: list[dict] = []
    all_endpoints: set[str] = set()
    all_domains: set[str] = set()
    all_frameworks: set[str] = set()
    all_source_maps: list[str] = []
    all_emails: set[str] = set()
    all_internal_ips: set[str] = set()
    files_analysed = 0

    # ── Analyse inline / provided content ──
    if js_content:
        result['stats']['total_checks'] += 1
        try:
            res = _analyze_content(js_content, hostname, root_domain)
            all_secrets.extend(res['secrets'])
            all_endpoints.update(res['endpoints'])
            all_domains.update(res['domains'])
            all_frameworks.update(res['frameworks'])
            all_source_maps.extend(res['source_maps'])
            all_emails.update(res['emails'])
            all_internal_ips.update(res['internal_ips'])
            files_analysed += 1
            result['stats']['successful_checks'] += 1
        except Exception as exc:
            result['errors'].append(f'Error analysing inline JS: {exc}')
            result['stats']['failed_checks'] += 1
            logger.error('JS analysis error (inline): %s', exc)

    # ── Fetch and analyse external JS files ──
    if js_urls and make_request_fn:
        fetched = _fetch_js_files(js_urls, make_request_fn)
        for url, content in fetched.items():
            result['stats']['total_checks'] += 1
            try:
                res = _analyze_content(content, hostname, root_domain)
                all_secrets.extend(res['secrets'])
                all_endpoints.update(res['endpoints'])
                all_domains.update(res['domains'])
                all_frameworks.update(res['frameworks'])
                all_source_maps.extend(res['source_maps'])
                all_emails.update(res['emails'])
                all_internal_ips.update(res['internal_ips'])
                files_analysed += 1
                result['stats']['successful_checks'] += 1
            except Exception as exc:
                result['errors'].append(f'Error analysing {url}: {exc}')
                result['stats']['failed_checks'] += 1
                logger.error('JS analysis error (%s): %s', url, exc)
    elif js_urls and not make_request_fn:
        logger.info('JS URLs provided but no make_request_fn — skipping external fetch')

    # ── Populate legacy keys ──
    result['secrets'] = all_secrets
    result['endpoints'] = sorted(all_endpoints)
    result['domains'] = sorted(all_domains)
    result['frameworks'] = sorted(all_frameworks)
    result['source_maps'] = list(dict.fromkeys(all_source_maps))  # deduplicated
    result['emails'] = sorted(all_emails)
    result['internal_ips'] = sorted(all_internal_ips)

    # ── Add findings ──
    for secret in all_secrets:
        add_finding(result, {
            'type': 'exposed_secret',
            'secret_type': secret['type'],
            'value_preview': secret['value_preview'],
            'severity': secret['severity'],
            'context': secret['context'],
        })
        result['issues'].append(
            f"Exposed {secret['type']} found in JavaScript "
            f"(severity: {secret['severity']})"
        )

    for ep in sorted(all_endpoints):
        add_finding(result, {
            'type': 'js_endpoint',
            'endpoint': ep,
            'source': 'javascript',
        })

    for domain in sorted(all_domains):
        add_finding(result, {
            'type': 'js_domain',
            'url': domain,
            'source': 'javascript',
        })

    for fw in sorted(all_frameworks):
        add_finding(result, {
            'type': 'framework_detected',
            'name': fw,
            'source': 'javascript',
        })

    for sm in result['source_maps']:
        add_finding(result, {
            'type': 'source_map_exposed',
            'path': sm,
            'severity': 'medium',
        })
        result['issues'].append(f'JS source map exposed: {sm}')

    for ip in sorted(all_internal_ips):
        add_finding(result, {
            'type': 'internal_ip_disclosed',
            'ip': ip,
            'severity': 'medium',
        })
        result['issues'].append(f'Internal IP disclosed in JavaScript: {ip}')

    if all_emails:
        add_finding(result, {
            'type': 'email_addresses',
            'emails': sorted(all_emails),
            'count': len(all_emails),
        })

    # ── Summary metadata ──
    result['metadata']['files_analysed'] = files_analysed
    result['metadata']['total_secrets'] = len(all_secrets)
    result['metadata']['total_endpoints'] = len(all_endpoints)
    result['metadata']['source_maps_found'] = len(result['source_maps'])
    result['metadata']['emails_found'] = len(all_emails)
    result['metadata']['internal_ips_found'] = len(all_internal_ips)

    logger.info(
        'JS analysis complete for %s: %d secrets, %d endpoints, '
        '%d domains, %d frameworks, %d source maps, %d IPs across %d files',
        target_url, len(all_secrets), len(all_endpoints),
        len(all_domains), len(all_frameworks), len(result['source_maps']),
        len(all_internal_ips), files_analysed,
    )

    # ── External JS endpoint discovery (getJS / LinkFinder) ──
    try:
        from apps.scanning.engine.tools.wrappers.getjs_wrapper import GetJSTool
        from apps.scanning.engine.tools.wrappers.linkfinder_wrapper import LinkFinderTool
        _getjs = GetJSTool()
        _lf = LinkFinderTool()
        if _getjs.is_available():
            for _tr in _getjs.run(target_url):
                _js_url = _tr.host or _tr.metadata.get('js_url', '')
                if _js_url and _lf.is_available():
                    for _ep in _lf.run(_js_url):
                        _endpoint = _ep.metadata.get('endpoint', '')
                        if _endpoint and _endpoint not in all_endpoints:
                            all_endpoints.add(_endpoint)
                            result['endpoints'] = sorted(all_endpoints)
    except Exception:
        pass

    return finalize_result(result, start)
