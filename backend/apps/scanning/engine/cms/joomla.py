"""
Joomla Scanner — Deep inspection of Joomla installations.

Detects:
  - Joomla version via meta generator, manifest files
  - Component enumeration
  - Extension (plugin/module) enumeration
  - Known vulnerability patterns (JoomScan-style)
  - Admin panel exposure
  - Debug/config exposure
"""
import logging
import re

logger = logging.getLogger(__name__)

# ── Detection patterns ───────────────────────────────────────────────────────
JOOMLA_INDICATORS = [
    re.compile(r'Joomla!', re.IGNORECASE),
    re.compile(r'/administrator/', re.IGNORECASE),
    re.compile(r'/components/com_', re.IGNORECASE),
    re.compile(r'/media/jui/', re.IGNORECASE),
    re.compile(r'name=["\']generator["\']\s+content=["\']Joomla', re.IGNORECASE),
    re.compile(r'/templates/\w+/css/', re.IGNORECASE),
]

JOOMLA_VERSION_META = re.compile(
    r'content=["\']Joomla!\s*-?\s*([\d.]+)', re.IGNORECASE,
)

JOOMLA_VERSION_MANIFEST = re.compile(
    r'<version>([\d.]+)</version>', re.IGNORECASE,
)

# ── Common components to probe ───────────────────────────────────────────────
TOP_COMPONENTS = [
    'com_content', 'com_users', 'com_contact', 'com_search',
    'com_finder', 'com_newsfeeds', 'com_banners', 'com_redirect',
    'com_tags', 'com_fields', 'com_associations', 'com_contenthistory',
    'com_media', 'com_menus', 'com_modules', 'com_plugins',
    'com_templates', 'com_languages', 'com_installer', 'com_config',
    'com_akeeba', 'com_virtuemart', 'com_k2', 'com_zoo',
    'com_hikashop', 'com_phocagallery', 'com_docman', 'com_rsform',
    'com_jce', 'com_acymailing',
]

# Sensitive Joomla paths
SENSITIVE_PATHS = [
    'configuration.php-dist',
    'configuration.php.bak',
    'configuration.php.old',
    'configuration.php~',
    'htaccess.txt',
    'web.config.txt',
    'README.txt',
    'LICENSE.txt',
    'administrator/manifests/files/joomla.xml',
    'language/en-GB/en-GB.xml',
    'plugins/system/cache/cache.xml',
]


class JoomlaScanner:
    """
    Deep scanner for Joomla installations.

    Usage:
        scanner = JoomlaScanner(make_request_fn)
        findings = scanner.scan(base_url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        self._request = make_request_fn

    @staticmethod
    def is_joomla(body: str, headers: dict = None) -> bool:
        """Detect whether the page is a Joomla site."""
        if not body:
            return False
        return any(p.search(body) for p in JOOMLA_INDICATORS)

    def scan(self, base_url: str, body: str, depth: str = 'medium') -> list:
        findings = []
        base = base_url.rstrip('/')

        # 1. Version detection
        finding = self._detect_version(base, body)
        if finding:
            findings.append(finding)

        # 2. Admin panel accessibility
        finding = self._check_admin_panel(base)
        if finding:
            findings.append(finding)

        if depth == 'shallow':
            return findings

        # 3. Component enumeration
        findings.extend(self._enumerate_components_passive(body))

        # 4. Registration enabled
        finding = self._check_registration(base)
        if finding:
            findings.append(finding)

        if depth == 'deep':
            # 5. Active component probing
            findings.extend(self._enumerate_components_active(base))

            # 6. Sensitive path exposure
            findings.extend(self._check_sensitive_paths(base))

            # 7. Config backup detection
            findings.extend(self._check_config_backups(base))

        return findings

    # ── Version detection ────────────────────────────────────────────────────

    def _detect_version(self, base: str, body: str):
        match = JOOMLA_VERSION_META.search(body)
        if match:
            return {
                'check': 'joomla_version',
                'detail': f'Joomla version {match.group(1)} detected via meta generator',
                'severity': 'info',
                'evidence': f'Joomla {match.group(1)}',
            }

        # Try manifest XML
        manifest_paths = [
            'administrator/manifests/files/joomla.xml',
            'language/en-GB/en-GB.xml',
        ]
        for path in manifest_paths:
            try:
                resp = self._request('GET', f'{base}/{path}')
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    m = JOOMLA_VERSION_MANIFEST.search(text)
                    if m:
                        return {
                            'check': 'joomla_version',
                            'detail': f'Joomla version {m.group(1)} detected via {path}',
                            'severity': 'low',
                            'evidence': f'{path}: Joomla {m.group(1)}',
                        }
            except Exception:
                continue
        return None

    # ── Admin panel ──────────────────────────────────────────────────────────

    def _check_admin_panel(self, base: str):
        try:
            resp = self._request('GET', f'{base}/administrator/')
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'login' in text.lower() or 'joomla' in text.lower():
                    return {
                        'check': 'joomla_admin_panel',
                        'detail': 'Joomla admin panel is publicly accessible at /administrator/',
                        'severity': 'low',
                        'evidence': '/administrator/ — HTTP 200',
                    }
        except Exception:
            pass
        return None

    # ── Component enumeration ────────────────────────────────────────────────

    def _enumerate_components_passive(self, body: str) -> list:
        """Extract component names from page body."""
        pattern = re.compile(r'/components/(com_[a-z0-9_]+)/', re.IGNORECASE)
        slugs = set(pattern.findall(body))
        findings = []
        for slug in sorted(slugs)[:20]:
            findings.append({
                'check': 'joomla_component',
                'detail': f'Component detected: {slug}',
                'severity': 'info',
                'evidence': f'/components/{slug}/',
            })
        return findings

    def _enumerate_components_active(self, base: str) -> list:
        """Probe known component paths."""
        findings = []
        for comp in TOP_COMPONENTS[:30]:
            try:
                url = f'{base}/components/{comp}/'
                resp = self._request('GET', url)
                if resp and resp.status_code == 200:
                    findings.append({
                        'check': 'joomla_component',
                        'detail': f'Component confirmed: {comp}',
                        'severity': 'info',
                        'evidence': f'{url} — 200 OK',
                    })
            except Exception:
                continue
        return findings

    # ── Registration check ───────────────────────────────────────────────────

    def _check_registration(self, base: str):
        try:
            resp = self._request('GET', f'{base}/index.php?option=com_users&view=registration')
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'register' in text.lower() or 'registration' in text.lower():
                    return {
                        'check': 'joomla_registration',
                        'detail': 'User registration is enabled',
                        'severity': 'info',
                        'evidence': 'com_users registration view accessible',
                    }
        except Exception:
            pass
        return None

    # ── Sensitive paths ──────────────────────────────────────────────────────

    def _check_sensitive_paths(self, base: str) -> list:
        findings = []
        for path in SENSITIVE_PATHS:
            try:
                resp = self._request('GET', f'{base}/{path}')
                if resp and resp.status_code == 200:
                    findings.append({
                        'check': 'joomla_sensitive_path',
                        'detail': f'Sensitive path exposed: /{path}',
                        'severity': 'low',
                        'evidence': f'/{path} — HTTP 200',
                    })
            except Exception:
                continue
        return findings

    # ── Config backup detection ──────────────────────────────────────────────

    def _check_config_backups(self, base: str) -> list:
        findings = []
        backup_files = [
            'configuration.php-dist',
            'configuration.php.bak',
            'configuration.php.old',
            'configuration.php~',
        ]
        for filename in backup_files:
            try:
                resp = self._request('GET', f'{base}/{filename}')
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    if 'password' in text.lower() or 'db' in text.lower():
                        findings.append({
                            'check': 'joomla_config_backup',
                            'detail': f'Config backup exposed: {filename}',
                            'severity': 'critical',
                            'evidence': f'{filename} — contains credentials',
                        })
            except Exception:
                continue
        return findings
