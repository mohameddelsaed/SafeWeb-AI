"""
CMS Fingerprinting Module — Deep CMS identification and version detection.

Goes beyond basic tech fingerprinting to determine exact CMS version,
installed plugins/themes, and CMS-specific security indicators.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
)

logger = logging.getLogger(__name__)

# ── WordPress patterns ─────────────────────────────────────────────────────

_WP_META_VERSION_RE = re.compile(
    r'<meta\s+name="generator"\s+content="WordPress\s*([\d.]+)"',
    re.IGNORECASE,
)
_WP_FEED_VERSION_RE = re.compile(
    r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
    re.IGNORECASE,
)
_WP_PLUGIN_RE = re.compile(
    r'wp-content/plugins/([\w\-]+)',
    re.IGNORECASE,
)
_WP_THEME_RE = re.compile(
    r'wp-content/themes/([\w\-]+)',
    re.IGNORECASE,
)

# ── Drupal patterns ────────────────────────────────────────────────────────

_DRUPAL_META_RE = re.compile(
    r'<meta\s+name="generator"\s+content="Drupal\s*([\d.]+)"',
    re.IGNORECASE,
)
_DRUPAL_VERSION_RE = re.compile(
    r'Drupal\s+([\d.]+)',
    re.IGNORECASE,
)
_DRUPAL_JS_RE = re.compile(
    r'(?:sites/all/|/core/misc/|/modules/)',
    re.IGNORECASE,
)

# ── Joomla patterns ───────────────────────────────────────────────────────

_JOOMLA_META_RE = re.compile(
    r'<meta\s+name="generator"\s+content="Joomla!\s*([\d.]*)"',
    re.IGNORECASE,
)
_JOOMLA_SCRIPT_RE = re.compile(
    r'/media/jui/|/media/system/',
    re.IGNORECASE,
)

# ── Generic CMS detectors ─────────────────────────────────────────────────

_CMS_INDICATORS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'wp-content/', re.I), 'WordPress'),
    (re.compile(r'wp-includes/', re.I), 'WordPress'),
    (re.compile(r'/sites/default/files/', re.I), 'Drupal'),
    (re.compile(r'X-Drupal-Cache', re.I), 'Drupal'),
    (re.compile(r'/media/system/', re.I), 'Joomla'),
    (re.compile(r'content="Shopify"', re.I), 'Shopify'),
    (re.compile(r'cdn\.shopify\.com', re.I), 'Shopify'),
    (re.compile(r'/skin/frontend/', re.I), 'Magento'),
    (re.compile(r'Mage\.Cookies', re.I), 'Magento'),
    (re.compile(r'ghost\.io|"ghost-', re.I), 'Ghost'),
    (re.compile(r'squarespace\.com', re.I), 'Squarespace'),
    (re.compile(r'wix\.com|wixstatic\.com', re.I), 'Wix'),
    (re.compile(r'weebly\.com', re.I), 'Weebly'),
    (re.compile(r'typo3conf/', re.I), 'TYPO3'),
    (re.compile(r'content="Hugo', re.I), 'Hugo'),
    (re.compile(r'Powered by.*Gatsby', re.I), 'Gatsby'),
]

# CMS-specific probe paths (used when make_request_fn is supplied)
_CMS_PROBES: dict[str, list[dict]] = {
    'WordPress': [
        {'path': '/wp-login.php', 'expect_status': [200, 302], 'label': 'Login page'},
        {'path': '/wp-json/', 'expect_status': [200], 'label': 'REST API'},
        {'path': '/readme.html', 'expect_status': [200], 'label': 'Readme (version leak)'},
        {'path': '/xmlrpc.php', 'expect_status': [200, 405], 'label': 'XML-RPC'},
        {'path': '/wp-json/wp/v2/users', 'expect_status': [200], 'label': 'User enumeration'},
    ],
    'Drupal': [
        {'path': '/CHANGELOG.txt', 'expect_status': [200], 'label': 'Changelog (version leak)'},
        {'path': '/core/CHANGELOG.txt', 'expect_status': [200], 'label': 'Core changelog'},
        {'path': '/user/login', 'expect_status': [200], 'label': 'Login page'},
        {'path': '/core/install.php', 'expect_status': [200], 'label': 'Install script'},
    ],
    'Joomla': [
        {'path': '/administrator/', 'expect_status': [200], 'label': 'Admin panel'},
        {'path': '/language/en-GB/en-GB.xml', 'expect_status': [200], 'label': 'Language XML (version)'},
        {'path': '/configuration.php~', 'expect_status': [200], 'label': 'Config backup'},
    ],
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _detect_cms_from_html(body: str, headers: dict) -> tuple[str | None, str | None, str]:
    """Identify CMS and version from HTML body and response headers.

    Returns:
        ``(cms_name, version, confidence)``
    """
    if not body and not headers:
        return None, None, 'none'

    combined = body + ' '.join(f'{k}: {v}' for k, v in (headers or {}).items())

    # WordPress
    m = _WP_META_VERSION_RE.search(body) if body else None
    if m:
        return 'WordPress', m.group(1), 'high'
    m = _WP_FEED_VERSION_RE.search(body) if body else None
    if m:
        return 'WordPress', m.group(1), 'high'

    # Drupal
    m = _DRUPAL_META_RE.search(body) if body else None
    if m:
        return 'Drupal', m.group(1) or None, 'high'

    # Joomla
    m = _JOOMLA_META_RE.search(body) if body else None
    if m:
        return 'Joomla', m.group(1) or None, 'high'

    # Generic indicator scan
    for regex, name in _CMS_INDICATORS:
        if regex.search(combined):
            return name, None, 'medium'

    return None, None, 'none'


def _extract_wp_plugins(body: str) -> list[str]:
    """Return sorted list of WP plugin slugs found in HTML."""
    return sorted(set(_WP_PLUGIN_RE.findall(body)))


def _extract_wp_themes(body: str) -> list[str]:
    """Return sorted list of WP theme slugs found in HTML."""
    return sorted(set(_WP_THEME_RE.findall(body)))


def _probe_cms_paths(
    cms: str,
    target_url: str,
    make_request_fn,
) -> list[dict]:
    """Probe CMS-specific paths and return findings for accessible ones."""
    findings: list[dict] = []
    probes = _CMS_PROBES.get(cms, [])
    base = target_url.rstrip('/')

    for probe in probes:
        url = f'{base}{probe["path"]}'
        try:
            resp = make_request_fn('GET', url)
            status = getattr(resp, 'status_code', None) or getattr(resp, 'status', 0)
            if status in probe['expect_status']:
                findings.append({
                    'type': 'cms_probe',
                    'path': probe['path'],
                    'label': probe['label'],
                    'status': status,
                    'accessible': True,
                })
            else:
                findings.append({
                    'type': 'cms_probe',
                    'path': probe['path'],
                    'label': probe['label'],
                    'status': status,
                    'accessible': False,
                })
        except Exception as exc:  # noqa: BLE001
            logger.debug('CMS probe error for %s: %s', url, exc)
            findings.append({
                'type': 'cms_probe',
                'path': probe['path'],
                'label': probe['label'],
                'status': None,
                'accessible': False,
                'error': str(exc),
            })
    return findings


def _check_security_issues(
    cms: str | None,
    version: str | None,
    body: str,
    probe_results: list[dict],
) -> list[str]:
    """Generate CMS-specific security observations."""
    issues: list[str] = []
    if not cms:
        return issues

    if version:
        issues.append(f'{cms} version {version} detected — check for known CVEs')

    # WordPress specifics
    if cms == 'WordPress':
        xmlrpc = [p for p in probe_results if p.get('path') == '/xmlrpc.php' and p.get('accessible')]
        if xmlrpc:
            issues.append('XML-RPC is enabled — susceptible to brute-force amplification attacks')
        user_enum = [p for p in probe_results if '/users' in (p.get('path') or '') and p.get('accessible')]
        if user_enum:
            issues.append('WordPress user enumeration is possible via REST API')
        if 'wp-config.php' in body.lower():
            issues.append('wp-config.php reference found in HTML — potential exposure')
        readme = [p for p in probe_results if p.get('path') == '/readme.html' and p.get('accessible')]
        if readme:
            issues.append('WordPress readme.html is publicly accessible (version disclosure)')

    # Drupal specifics
    if cms == 'Drupal':
        changelog = [p for p in probe_results
                     if 'CHANGELOG' in (p.get('path') or '') and p.get('accessible')]
        if changelog:
            issues.append('Drupal CHANGELOG.txt is publicly accessible (version disclosure)')
        install = [p for p in probe_results if 'install.php' in (p.get('path') or '') and p.get('accessible')]
        if install:
            issues.append('Drupal install.php is accessible — potential re-installation risk')

    # Joomla specifics
    if cms == 'Joomla':
        config_bak = [p for p in probe_results
                      if 'configuration.php~' in (p.get('path') or '') and p.get('accessible')]
        if config_bak:
            issues.append('Joomla configuration backup file is accessible')

    # Debug / development mode indicators
    if re.search(r'WP_DEBUG.*true|DRUPAL_DEBUG|error_reporting\s*=\s*E_ALL', body, re.I):
        issues.append(f'{cms} appears to be running in debug/development mode')

    return issues


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_cms_fingerprint(
    target_url: str,
    response_body: str = '',
    response_headers: dict | None = None,
    make_request_fn=None,
) -> dict:
    """Deep CMS fingerprinting with plugin/theme enumeration.

    Args:
        target_url:       Target URL.
        response_body:    HTML body (optional).
        response_headers: HTTP response headers (optional).
        make_request_fn:  Callable ``fn(url) -> response`` for probing paths (optional).

    Returns:
        Standardised result dict with legacy keys:
        ``cms``, ``version``, ``plugins``, ``themes``, ``security_issues``,
        ``confidence``, ``issues``.
    """
    start = time.time()
    result = create_result('cms_fingerprint', target_url)

    hostname = extract_hostname(target_url)
    headers = response_headers or {}
    body = response_body or ''

    # Legacy top-level keys
    result['cms'] = None
    result['version'] = None
    result['plugins'] = []
    result['themes'] = []
    result['security_issues'] = []
    result['confidence'] = 'none'

    if not hostname:
        result['errors'].append('Could not extract hostname from target URL')
        return finalize_result(result, start)

    logger.info('Starting CMS fingerprint for %s', hostname)
    checks = 0

    # 1. Detect CMS from HTML + headers
    checks += 1
    try:
        cms, version, confidence = _detect_cms_from_html(body, headers)
        result['cms'] = cms
        result['version'] = version
        result['confidence'] = confidence
        result['stats']['successful_checks'] += 1

        if cms:
            add_finding(result, {
                'type': 'cms_detected',
                'cms': cms,
                'version': version,
                'confidence': confidence,
            })
            logger.info('Detected CMS: %s %s (confidence=%s)', cms, version or '', confidence)
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'CMS detection error: {exc}')
        result['stats']['failed_checks'] += 1

    # 2. Extract plugins (WordPress)
    checks += 1
    try:
        if result['cms'] == 'WordPress' and body:
            plugins = _extract_wp_plugins(body)
            result['plugins'] = plugins
            for plugin in plugins:
                add_finding(result, {
                    'type': 'cms_plugin',
                    'cms': 'WordPress',
                    'name': plugin,
                })
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Plugin extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 3. Extract themes (WordPress)
    checks += 1
    try:
        if result['cms'] == 'WordPress' and body:
            themes = _extract_wp_themes(body)
            result['themes'] = themes
            for theme in themes:
                add_finding(result, {
                    'type': 'cms_theme',
                    'cms': 'WordPress',
                    'name': theme,
                })
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Theme extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 4. Active probing (only when make_request_fn is provided)
    probe_results: list[dict] = []
    if make_request_fn and result['cms']:
        checks += 1
        try:
            probe_results = _probe_cms_paths(result['cms'], target_url, make_request_fn)
            for pr in probe_results:
                add_finding(result, pr)
            result['stats']['successful_checks'] += 1
        except Exception as exc:  # noqa: BLE001
            result['errors'].append(f'CMS probe error: {exc}')
            result['stats']['failed_checks'] += 1

    # 5. Security issue analysis
    checks += 1
    try:
        sec_issues = _check_security_issues(result['cms'], result['version'], body, probe_results)
        result['security_issues'] = sec_issues
        result['issues'].extend(sec_issues)
        for issue in sec_issues:
            add_finding(result, {
                'type': 'cms_security_issue',
                'cms': result['cms'],
                'detail': issue,
            })
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Security check error: {exc}')
        result['stats']['failed_checks'] += 1

    result['stats']['total_checks'] = checks

    logger.info(
        'CMS fingerprint complete for %s: cms=%s version=%s plugins=%d themes=%d issues=%d',
        hostname,
        result['cms'] or 'none',
        result['version'] or 'unknown',
        len(result['plugins']),
        len(result['themes']),
        len(result['security_issues']),
    )
    return finalize_result(result, start)
