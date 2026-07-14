"""
Drupal Scanner — Deep inspection of Drupal installations.

Detects:
  - Drupal version via CHANGELOG.txt, meta generator, update.php
  - Drupalgeddon 1 (SA-CORE-2014-005)
  - Drupalgeddon 2 (SA-CORE-2018-002)
  - Drupalgeddon 3 (SA-CORE-2018-004)
  - Module enumeration
  - User enumeration
  - Sensitive path exposure
"""
import logging
import re

logger = logging.getLogger(__name__)

# ── Detection patterns ───────────────────────────────────────────────────────
DRUPAL_INDICATORS = [
    re.compile(r'Drupal\.settings', re.IGNORECASE),
    re.compile(r'sites/default/files', re.IGNORECASE),
    re.compile(r'/misc/drupal\.js', re.IGNORECASE),
    re.compile(r'name=["\']generator["\']\s+content=["\']Drupal', re.IGNORECASE),
    re.compile(r'X-Drupal-Cache', re.IGNORECASE),
    re.compile(r'/core/misc/drupal\.js', re.IGNORECASE),
]

DRUPAL_VERSION_META = re.compile(
    r'content=["\']Drupal\s+([\d.]+)', re.IGNORECASE,
)

DRUPAL_VERSION_CHANGELOG = re.compile(
    r'Drupal\s+([\d.]+)', re.IGNORECASE,
)

# ── Common modules to probe ──────────────────────────────────────────────────
TOP_MODULES = [
    'admin_toolbar', 'pathauto', 'token', 'ctools', 'views',
    'webform', 'metatag', 'redirect', 'paragraphs', 'devel',
    'entity_reference_revisions', 'google_analytics', 'captcha',
    'field_group', 'twig_tweak', 'search_api', 'backup_migrate',
    'module_filter', 'xmlsitemap', 'recaptcha',
]

# Sensitive Drupal paths
SENSITIVE_PATHS = [
    'CHANGELOG.txt',
    'INSTALL.txt',
    'MAINTAINERS.txt',
    'LICENSE.txt',
    'core/CHANGELOG.txt',
    'core/INSTALL.txt',
    'update.php',
    'install.php',
    'user/login',
    'admin/config',
    'sites/default/settings.php',
    'sites/default/default.settings.php',
]


class DrupalScanner:
    """
    Deep scanner for Drupal installations.

    Usage:
        scanner = DrupalScanner(make_request_fn)
        findings = scanner.scan(base_url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        self._request = make_request_fn

    @staticmethod
    def is_drupal(body: str, headers: dict = None) -> bool:
        """Detect whether the page is a Drupal site."""
        if body and any(p.search(body) for p in DRUPAL_INDICATORS):
            return True
        if headers:
            h_str = str(headers)
            if 'X-Drupal-Cache' in h_str or 'X-Generator' in h_str and 'Drupal' in h_str:
                return True
        return False

    def scan(self, base_url: str, body: str, depth: str = 'medium') -> list:
        findings = []
        base = base_url.rstrip('/')

        # 1. Version detection
        finding = self._detect_version(base, body)
        if finding:
            findings.append(finding)

        if depth == 'shallow':
            return findings

        # 2. Drupalgeddon checks
        findings.extend(self._check_drupalgeddon(base))

        # 3. User enumeration
        finding = self._check_user_enum(base)
        if finding:
            findings.append(finding)

        if depth == 'deep':
            # 4. Module enumeration
            findings.extend(self._enumerate_modules(base))

            # 5. Sensitive path exposure
            findings.extend(self._check_sensitive_paths(base))

        return findings

    # ── Version detection ────────────────────────────────────────────────────

    def _detect_version(self, base: str, body: str):
        match = DRUPAL_VERSION_META.search(body)
        if match:
            return {
                'check': 'drupal_version',
                'detail': f'Drupal version {match.group(1)} detected via meta generator',
                'severity': 'info',
                'evidence': f'Drupal {match.group(1)}',
            }

        # Try CHANGELOG.txt
        for path in ['CHANGELOG.txt', 'core/CHANGELOG.txt']:
            try:
                resp = self._request('GET', f'{base}/{path}')
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    m = DRUPAL_VERSION_CHANGELOG.search(text)
                    if m:
                        return {
                            'check': 'drupal_version',
                            'detail': f'Drupal version {m.group(1)} detected via {path}',
                            'severity': 'low',
                            'evidence': f'{path}: Drupal {m.group(1)}',
                        }
            except Exception:
                continue
        return None

    # ── Drupalgeddon checks ──────────────────────────────────────────────────

    def _check_drupalgeddon(self, base: str) -> list:
        findings = []

        # Drupalgeddon 2 (SA-CORE-2018-002) — check for vulnerable endpoint
        try:
            url = f'{base}/user/register'
            resp = self._request('GET', url, params={
                'element_parents': 'account/mail/#value',
                'ajax_form': '1',
                '_wrapper_format': 'drupal_ajax',
            })
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'ajax' in text.lower() or 'command' in text.lower():
                    findings.append({
                        'check': 'drupalgeddon2',
                        'detail': 'Potential Drupalgeddon 2 (SA-CORE-2018-002) vulnerability',
                        'severity': 'critical',
                        'evidence': '/user/register AJAX endpoint responsive to crafted params',
                    })
        except Exception:
            pass

        # Drupalgeddon 3 (SA-CORE-2018-004) — check if admin paths accessible
        try:
            resp = self._request('GET', f'{base}/admin/config')
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'configuration' in text.lower() or 'admin' in text.lower():
                    findings.append({
                        'check': 'drupalgeddon3',
                        'detail': 'Admin config exposed — potential SA-CORE-2018-004',
                        'severity': 'high',
                        'evidence': '/admin/config accessible without auth',
                    })
        except Exception:
            pass

        return findings

    # ── User enumeration ─────────────────────────────────────────────────────

    def _check_user_enum(self, base: str):
        try:
            resp = self._request('GET', f'{base}/user/1')
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'member for' in text.lower() or 'profile' in text.lower():
                    return {
                        'check': 'drupal_user_enum',
                        'detail': 'User profiles accessible at /user/N',
                        'severity': 'medium',
                        'evidence': '/user/1 returns user profile',
                    }
        except Exception:
            pass
        return None

    # ── Module enumeration ───────────────────────────────────────────────────

    def _enumerate_modules(self, base: str) -> list:
        findings = []
        for module in TOP_MODULES:
            try:
                # Drupal 8+ modules
                url = f'{base}/modules/contrib/{module}/{module}.info.yml'
                resp = self._request('GET', url)
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    if 'name:' in text.lower() or 'type:' in text.lower():
                        findings.append({
                            'check': 'drupal_module',
                            'detail': f'Module detected: {module}',
                            'severity': 'info',
                            'evidence': f'{url} — 200 OK',
                        })
                        continue

                # Drupal 7 modules
                url = f'{base}/sites/all/modules/{module}/{module}.info'
                resp = self._request('GET', url)
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    if 'name' in text.lower():
                        findings.append({
                            'check': 'drupal_module',
                            'detail': f'Module detected: {module}',
                            'severity': 'info',
                            'evidence': f'{url} — 200 OK',
                        })
            except Exception:
                continue
        return findings

    # ── Sensitive paths ──────────────────────────────────────────────────────

    def _check_sensitive_paths(self, base: str) -> list:
        findings = []
        for path in SENSITIVE_PATHS:
            try:
                resp = self._request('GET', f'{base}/{path}')
                if resp and resp.status_code == 200:
                    findings.append({
                        'check': 'drupal_sensitive_path',
                        'detail': f'Sensitive path exposed: /{path}',
                        'severity': 'low',
                        'evidence': f'/{path} — HTTP 200',
                    })
            except Exception:
                continue
        return findings
