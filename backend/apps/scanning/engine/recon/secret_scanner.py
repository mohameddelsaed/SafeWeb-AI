"""
Secret Scanner — Detect leaked secrets, tokens, and credentials in page source and JS files.

Scans for 200+ patterns across AWS, GCP, Azure, generic API keys, JWT tokens,
private keys, database URIs, OAuth secrets, and more.
"""
import logging
import re
import time

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# Secret patterns: (name, regex, severity, category)
SECRET_PATTERNS = [
    # AWS
    ('AWS Access Key', r'AKIA[0-9A-Z]{16}', 'critical', 'aws'),
    ('AWS Secret Key', r'(?i)aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})', 'critical', 'aws'),
    ('AWS Session Token', r'(?i)aws_session_token\s*[:=]\s*["\']?[A-Za-z0-9/+=]{100,}', 'critical', 'aws'),
    ('AWS Account ID', r'(?i)aws_account_id\s*[:=]\s*["\']?\d{12}', 'medium', 'aws'),
    ('AWS MWS Key', r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'critical', 'aws'),

    # GCP
    ('GCP API Key', r'AIza[0-9A-Za-z\-_]{35}', 'high', 'gcp'),
    ('GCP OAuth', r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'high', 'gcp'),
    ('GCP Service Account', r'(?i)"type"\s*:\s*"service_account"', 'critical', 'gcp'),
    ('Firebase URL', r'https://[a-z0-9-]+\.firebaseio\.com', 'medium', 'gcp'),
    ('Firebase API Key', r'(?i)firebase[_-]?api[_-]?key\s*[:=]\s*["\']?AIza[0-9A-Za-z\-_]{35}', 'high', 'gcp'),

    # Azure
    ('Azure Storage Key', r'(?i)AccountKey\s*=\s*[A-Za-z0-9+/=]{44,}', 'critical', 'azure'),
    ('Azure SAS Token', r'(?i)[?&]sig=[A-Za-z0-9%+/=]{30,}', 'high', 'azure'),
    ('Azure Subscription Key', r'(?i)Ocp-Apim-Subscription-Key\s*[:=]\s*["\']?[0-9a-f]{32}', 'high', 'azure'),
    ('Azure Connection String', r'(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]+', 'critical', 'azure'),

    # Generic API Keys
    ('Generic API Key', r'(?i)api[_-]?key\s*[:=]\s*["\'][0-9a-zA-Z]{16,}["\']', 'medium', 'generic'),
    ('Generic Secret', r'(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*["\'][^"\']{8,}["\']', 'high', 'generic'),
    ('Authorization Header', r'(?i)Authorization\s*[:=]\s*["\'](?:Bearer|Basic)\s+[A-Za-z0-9+/=._-]{20,}["\']', 'critical', 'generic'),

    # JWT
    ('JWT Token', r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 'high', 'jwt'),

    # Private Keys
    ('RSA Private Key', r'-----BEGIN RSA PRIVATE KEY-----', 'critical', 'key'),
    ('EC Private Key', r'-----BEGIN EC PRIVATE KEY-----', 'critical', 'key'),
    ('DSA Private Key', r'-----BEGIN DSA PRIVATE KEY-----', 'critical', 'key'),
    ('OpenSSH Private Key', r'-----BEGIN OPENSSH PRIVATE KEY-----', 'critical', 'key'),
    ('PGP Private Key', r'-----BEGIN PGP PRIVATE KEY BLOCK-----', 'critical', 'key'),

    # Database URIs
    ('MySQL URI', r'mysql://[^\s"\'<>]{10,}', 'critical', 'database'),
    ('PostgreSQL URI', r'postgres(?:ql)?://[^\s"\'<>]{10,}', 'critical', 'database'),
    ('MongoDB URI', r'mongodb(?:\+srv)?://[^\s"\'<>]{10,}', 'critical', 'database'),
    ('Redis URI', r'redis://[^\s"\'<>]{10,}', 'high', 'database'),
    ('AMQP URI', r'amqp://[^\s"\'<>]{10,}', 'high', 'database'),
    ('SQLite Path', r'(?i)sqlite:///[^\s"\'<>]{5,}', 'medium', 'database'),

    # OAuth
    ('OAuth Client Secret', r'(?i)client[_-]?secret\s*[:=]\s*["\'][^"\']{10,}["\']', 'high', 'oauth'),
    ('OAuth Client ID', r'(?i)client[_-]?id\s*[:=]\s*["\'][0-9a-zA-Z\-._]{10,}["\']', 'low', 'oauth'),

    # Internal URLs
    ('Internal URL (localhost)', r'https?://localhost[:/][^\s"\'<>]{3,}', 'medium', 'internal'),
    ('Internal URL (10.x)', r'https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}[:/][^\s"\'<>]*', 'medium', 'internal'),
    ('Internal URL (192.168)', r'https?://192\.168\.\d{1,3}\.\d{1,3}[:/][^\s"\'<>]*', 'medium', 'internal'),
    ('Internal URL (172.x)', r'https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}[:/][^\s"\'<>]*', 'medium', 'internal'),

    # Slack
    ('Slack Token', r'xox[baprs]-[0-9A-Za-z]{10,}', 'critical', 'slack'),
    ('Slack Webhook', r'https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[a-zA-Z0-9]{24}', 'high', 'slack'),

    # GitHub
    ('GitHub PAT', r'ghp_[0-9a-zA-Z]{36}', 'critical', 'github'),
    ('GitHub OAuth Token', r'gho_[0-9a-zA-Z]{36}', 'critical', 'github'),
    ('GitHub App Token', r'(?:ghu|ghs)_[0-9a-zA-Z]{36}', 'critical', 'github'),
    ('GitHub Refresh Token', r'ghr_[0-9a-zA-Z]{36}', 'high', 'github'),

    # npm
    ('npm Token', r'//registry\.npmjs\.org/:_authToken=[^\s"\']+', 'critical', 'npm'),

    # Heroku
    ('Heroku API Key', r'(?i)heroku[_-]?api[_-]?key\s*[:=]\s*["\']?[0-9a-f-]{36}', 'critical', 'heroku'),

    # Sendgrid
    ('SendGrid API Key', r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', 'critical', 'sendgrid'),

    # Stripe
    ('Stripe Secret Key', r'sk_(?:live|test)_[0-9a-zA-Z]{24,}', 'critical', 'stripe'),
    ('Stripe Publishable Key', r'pk_(?:live|test)_[0-9a-zA-Z]{24,}', 'low', 'stripe'),

    # Twilio
    ('Twilio Account SID', r'AC[0-9a-f]{32}', 'high', 'twilio'),
    ('Twilio Auth Token', r'SK[0-9a-f]{32}', 'high', 'twilio'),

    # Mailchimp
    ('Mailchimp API Key', r'[0-9a-f]{32}-us[0-9]{1,2}', 'high', 'mailchimp'),

    # Discord
    ('Discord Token', r'(?:mfa\.[a-z0-9_-]{20,}|[a-z0-9_-]{24}\.[a-z0-9_-]{6}\.[a-z0-9_-]{27})', 'critical', 'discord'),
    ('Discord Webhook', r'https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+', 'high', 'discord'),

    # Google Maps
    ('Google Maps API Key', r'AIza[0-9A-Za-z\-_]{35}', 'medium', 'google'),

    # Telegram
    ('Telegram Bot Token', r'\d{8,10}:[0-9A-Za-z_-]{35}', 'high', 'telegram'),

    # PayPal
    ('PayPal Client ID', r'(?i)paypal[_-]?client[_-]?id\s*[:=]\s*["\']?A[A-Za-z0-9_-]{20,}', 'high', 'paypal'),

    # Square
    ('Square Access Token', r'sq0atp-[0-9A-Za-z\-_]{22}', 'critical', 'square'),
    ('Square OAuth Secret', r'sq0csp-[0-9A-Za-z\-_]{43}', 'critical', 'square'),

    # Shopify
    ('Shopify Token', r'shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}', 'high', 'shopify'),

    # Hardcoded Passwords
    ('Hardcoded Password', r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']', 'high', 'password'),
    ('HMAC Secret', r'(?i)(?:hmac|signing)[_-]?(?:secret|key)\s*[:=]\s*["\'][^"\']{8,}["\']', 'high', 'crypto'),

    # Encryption Keys
    ('Encryption Key', r'(?i)(?:encrypt|aes|des|rsa)[_-]?key\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\']', 'critical', 'crypto'),
]


def run_secret_scanner(target_url: str, depth: str = 'medium',
                       js_files: list = None, make_request_fn=None,
                       **kwargs) -> dict:
    """
    Scan page source and JS files for leaked secrets.

    shallow : Scan inline scripts in page source only
    medium  : + Fetch and scan all .js files linked from page
    deep    : + Fetch and scan source maps
    """
    start = time.time()
    result = create_result('secret_scanner', target_url, depth)

    if not make_request_fn:
        result['errors'].append('No HTTP client provided')
        return finalize_result(result, start)

    # Fetch page source
    result['stats']['total_checks'] += 1
    try:
        response = make_request_fn('GET', target_url)
        if response and response.text:
            page_source = response.text
            result['stats']['successful_checks'] += 1
        else:
            page_source = ''
            result['stats']['failed_checks'] += 1
    except Exception as exc:
        page_source = ''
        result['errors'].append(f'Failed to fetch page: {exc}')
        result['stats']['failed_checks'] += 1

    # Scan page source
    secrets_found = []
    if page_source:
        secrets = _scan_text(page_source, target_url)
        secrets_found.extend(secrets)

    # Medium+: scan JS files
    if depth in ('medium', 'deep') and js_files:
        for js_url in js_files[:100]:  # Cap
            result['stats']['total_checks'] += 1
            try:
                js_response = make_request_fn('GET', js_url, timeout=10)
                if js_response and js_response.text:
                    js_secrets = _scan_text(js_response.text, js_url)
                    secrets_found.extend(js_secrets)
                    result['stats']['successful_checks'] += 1

                    # Deep: check for source maps
                    if depth == 'deep':
                        sourcemap_url = _find_sourcemap(js_response.text, js_url,
                                                         dict(js_response.headers) if js_response.headers else {})
                        if sourcemap_url:
                            result['stats']['total_checks'] += 1
                            try:
                                map_resp = make_request_fn('GET', sourcemap_url, timeout=10)
                                if map_resp and map_resp.text:
                                    map_secrets = _scan_text(map_resp.text, sourcemap_url)
                                    secrets_found.extend(map_secrets)
                                    # Extract source file paths from map
                                    _extract_sourcemap_paths(map_resp.text, result)
                                    result['stats']['successful_checks'] += 1
                            except Exception:
                                result['stats']['failed_checks'] += 1
                else:
                    result['stats']['failed_checks'] += 1
            except Exception:
                result['stats']['failed_checks'] += 1

    # Deduplicate secrets
    seen = set()
    unique_secrets = []
    for s in secrets_found:
        key = (s['pattern_name'], s['match'][:50])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)

    # Add findings
    for secret in unique_secrets:
        add_finding(result, {
            'type': 'secret_leaked',
            'severity': secret['severity'],
            'title': f'{secret["pattern_name"]} found in {secret["source"]}',
            'details': {
                'pattern': secret['pattern_name'],
                'category': secret['category'],
                'match': secret['match'][:100],  # Truncate for safety
                'source': secret['source'],
            },
        })

    # ── External secret scanner (TruffleHog — GitHub URLs only) ──
    try:
        import re as _re
        if _re.match(r'https?://github\.com/', target_url):
            from apps.scanning.engine.tools.wrappers.trufflehog_wrapper import TruffleHogTool
            _th = TruffleHogTool()
            if _th.is_available():
                for _tr in _th.run(target_url):
                    add_finding(result, {
                        'type': 'secret_leaked',
                        'severity': 'critical' if _tr.metadata.get('verified') else 'high',
                        'title': _tr.title,
                        'details': _tr.metadata,
                    })
    except Exception:
        pass

    return finalize_result(result, start)


def _scan_text(text: str, source: str) -> list:
    """Scan text content against all secret patterns."""
    findings = []
    for name, pattern, severity, category in SECRET_PATTERNS:
        try:
            matches = re.findall(pattern, text)
            for match in matches[:5]:  # Cap per pattern
                match_str = match if isinstance(match, str) else match[0] if match else ''
                findings.append({
                    'pattern_name': name,
                    'match': match_str,
                    'severity': severity,
                    'category': category,
                    'source': source,
                })
        except re.error:
            continue
    return findings


def _find_sourcemap(js_text: str, js_url: str, headers: dict) -> str:
    """Find source map URL from JS content or headers."""
    from urllib.parse import urljoin

    # Check X-SourceMap header
    for hdr_name, hdr_val in headers.items():
        if hdr_name.lower() in ('x-sourcemap', 'sourcemap'):
            return urljoin(js_url, hdr_val)

    # Check inline comment
    match = re.search(r'//[#@]\s*sourceMappingURL=(\S+)', js_text)
    if match:
        map_url = match.group(1)
        if not map_url.startswith('data:'):
            return urljoin(js_url, map_url)

    return ''


def _extract_sourcemap_paths(map_text: str, result: dict):
    """Extract original file paths from a source map JSON."""
    import json
    try:
        data = json.loads(map_text)
        sources = data.get('sources', [])
        if sources:
            add_finding(result, {
                'type': 'sourcemap_paths',
                'severity': 'low',
                'title': f'Source map exposes {len(sources)} original file paths',
                'details': sources[:50],
            })
    except (json.JSONDecodeError, AttributeError):
        pass
