"""
WordPress Scanner — Deep inspection of WordPress installations.

Detects:
  - WordPress version (meta generator, readme.html, RSS, login page)
  - Plugin enumeration (passive from HTML, aggressive path probing)
  - Theme enumeration (passive + active)
  - User enumeration (wp-json REST API, ?author=N)
  - xmlrpc.php exposure and abuse vectors
  - wp-cron.php exposure
  - Config backup files (wp-config.php.bak, .wp-config.php.swp, etc.)
  - Debug/maintenance mode exposure
"""
import logging
import re

logger = logging.getLogger(__name__)

# ── Detection patterns ───────────────────────────────────────────────────────
WP_INDICATORS = [
    re.compile(r'/wp-content/', re.IGNORECASE),
    re.compile(r'/wp-includes/', re.IGNORECASE),
    re.compile(r'/wp-login\.php', re.IGNORECASE),
    re.compile(r'/wp-admin/', re.IGNORECASE),
    re.compile(r'wordpress', re.IGNORECASE),
]

# Generator meta tag for version
WP_VERSION_META = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s+([\d.]+)["\']',
    re.IGNORECASE,
)

# Version from readme.html
WP_VERSION_README = re.compile(
    r'Version\s+([\d.]+)', re.IGNORECASE,
)

# Version from RSS feed
WP_VERSION_RSS = re.compile(
    r'<generator>https?://wordpress\.org/\?v=([\d.]+)</generator>',
    re.IGNORECASE,
)

# Plugin/theme slug extraction from wp-content paths
WP_PLUGIN_RE = re.compile(
    r'/wp-content/plugins/([a-z0-9_-]+)/', re.IGNORECASE,
)
WP_THEME_RE = re.compile(
    r'/wp-content/themes/([a-z0-9_-]+)/', re.IGNORECASE,
)

# User JSON endpoint
WP_USER_JSON_RE = re.compile(
    r'"slug"\s*:\s*"([^"]+)"', re.IGNORECASE,
)

# ── Common plugins to probe (top 30 by popularity) ──────────────────────────
TOP_PLUGINS = [
    'akismet', 'contact-form-7', 'yoast-seo', 'wordfence', 'jetpack',
    'elementor', 'woocommerce', 'classic-editor', 'wpforms-lite',
    'really-simple-ssl', 'all-in-one-seo-pack', 'updraftplus',
    'google-analytics-for-wordpress', 'wp-mail-smtp', 'redirection',
    'litespeed-cache', 'wp-super-cache', 'w3-total-cache', 'duplicate-post',
    'limit-login-attempts-reloaded', 'tinymce-advanced', 'tablepress',
    'wp-fastest-cache', 'instagram-feed', 'mailchimp-for-wp',
    'regenerate-thumbnails', 'advanced-custom-fields', 'wp-smushit',
    'sucuri-scanner', 'all-in-one-wp-migration',
]

# ── Common themes to probe ───────────────────────────────────────────────────
TOP_THEMES = [
    'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
    'twentytwentyone', 'twentytwenty', 'astra', 'flavor',
]

# ── Config backup filenames ──────────────────────────────────────────────────
CONFIG_BACKUP_FILES = [
    'wp-config.php.bak',
    'wp-config.php.old',
    'wp-config.php.orig',
    'wp-config.php.save',
    'wp-config.php.txt',
    'wp-config.php~',
    'wp-config.bak',
    'wp-config.old',
    '.wp-config.php.swp',
    'wp-config.php.dist',
]


class WordPressScanner:
    """
    Deep scanner for WordPress installations.

    Usage:
        scanner = WordPressScanner(make_request_fn)
        findings = scanner.scan(base_url, body, depth='medium')
    """

    def __init__(self, make_request_fn):
        """
        Args:
            make_request_fn: Callable (method, url, **kwargs) -> Response.
        """
        self._request = make_request_fn

    @staticmethod
    def is_wordpress(body: str, headers: dict = None) -> bool:
        """Detect whether the page is a WordPress site."""
        if not body:
            return False
        return any(p.search(body) for p in WP_INDICATORS)

    def scan(self, base_url: str, body: str, depth: str = 'medium') -> list:
        """
        Run WordPress-specific checks.

        Returns list of finding dicts with keys:
            check, detail, severity, evidence.
        """
        findings = []
        base = base_url.rstrip('/')

        # 1. Version detection
        finding = self._detect_version(base, body)
        if finding:
            findings.append(finding)

        # 2. Passive plugin enumeration
        findings.extend(self._enumerate_plugins_passive(body))

        # 3. Passive theme enumeration
        findings.extend(self._enumerate_themes_passive(body))

        if depth == 'shallow':
            return findings

        # 4. User enumeration
        findings.extend(self._enumerate_users(base))

        # 5. xmlrpc.php check
        finding = self._check_xmlrpc(base)
        if finding:
            findings.append(finding)

        # 6. wp-cron.php check
        finding = self._check_wp_cron(base)
        if finding:
            findings.append(finding)

        if depth == 'deep':
            # 7. Aggressive plugin enumeration
            findings.extend(self._enumerate_plugins_aggressive(base))

            # 8. Config backup detection
            findings.extend(self._check_config_backups(base))

            # 9. Debug mode detection
            finding = self._check_debug_log(base)
            if finding:
                findings.append(finding)

        return findings

    # ── Version detection ────────────────────────────────────────────────────

    def _detect_version(self, base: str, body: str):
        """Detect WordPress version from meta generator tag."""
        match = WP_VERSION_META.search(body)
        if match:
            version = match.group(1)
            return {
                'check': 'wordpress_version',
                'detail': f'WordPress version {version} detected via meta generator',
                'severity': 'info',
                'evidence': f'WordPress {version}',
            }

        # Try readme.html
        try:
            resp = self._request('GET', f'{base}/readme.html')
            if resp and resp.status_code == 200:
                rm = WP_VERSION_README.search(getattr(resp, 'text', ''))
                if rm:
                    return {
                        'check': 'wordpress_version',
                        'detail': f'WordPress version {rm.group(1)} detected via readme.html',
                        'severity': 'low',
                        'evidence': f'readme.html: WordPress {rm.group(1)}',
                    }
        except Exception:
            pass

        # Try RSS feed
        try:
            resp = self._request('GET', f'{base}/feed/')
            if resp and resp.status_code == 200:
                rm = WP_VERSION_RSS.search(getattr(resp, 'text', ''))
                if rm:
                    return {
                        'check': 'wordpress_version',
                        'detail': f'WordPress version {rm.group(1)} detected via RSS feed',
                        'severity': 'info',
                        'evidence': f'RSS feed: WordPress {rm.group(1)}',
                    }
        except Exception:
            pass
        return None

    # ── Plugin enumeration ───────────────────────────────────────────────────

    def _enumerate_plugins_passive(self, body: str) -> list:
        """Extract plugin slugs from page body (wp-content/plugins/…)."""
        slugs = set(WP_PLUGIN_RE.findall(body))
        findings = []
        for slug in sorted(slugs)[:20]:
            findings.append({
                'check': 'wordpress_plugin',
                'detail': f'Plugin detected: {slug}',
                'severity': 'info',
                'evidence': f'wp-content/plugins/{slug}/',
            })
        return findings

    def _enumerate_plugins_aggressive(self, base: str) -> list:
        """Probe known plugin paths to discover installed plugins."""
        findings = []
        for slug in TOP_PLUGINS[:30]:
            try:
                url = f'{base}/wp-content/plugins/{slug}/readme.txt'
                resp = self._request('GET', url)
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    if 'stable tag' in text.lower() or 'plugin name' in text.lower():
                        findings.append({
                            'check': 'wordpress_plugin',
                            'detail': f'Plugin confirmed: {slug} (readme.txt accessible)',
                            'severity': 'info',
                            'evidence': f'{url} — 200 OK',
                        })
            except Exception:
                continue
        return findings

    # ── Theme enumeration ────────────────────────────────────────────────────

    def _enumerate_themes_passive(self, body: str) -> list:
        """Extract theme slugs from page body (wp-content/themes/…)."""
        slugs = set(WP_THEME_RE.findall(body))
        findings = []
        for slug in sorted(slugs)[:10]:
            findings.append({
                'check': 'wordpress_theme',
                'detail': f'Theme detected: {slug}',
                'severity': 'info',
                'evidence': f'wp-content/themes/{slug}/',
            })
        return findings

    # ── User enumeration ─────────────────────────────────────────────────────

    def _enumerate_users(self, base: str) -> list:
        """Enumerate WordPress users via REST API and author archives."""
        findings = []

        # REST API
        try:
            resp = self._request('GET', f'{base}/wp-json/wp/v2/users')
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                usernames = WP_USER_JSON_RE.findall(text)
                if usernames:
                    findings.append({
                        'check': 'wordpress_user_enum',
                        'detail': f'Users exposed via REST API: {", ".join(usernames[:5])}',
                        'severity': 'medium',
                        'evidence': f'/wp-json/wp/v2/users — {len(usernames)} users',
                    })
        except Exception:
            pass

        # Author archives (?author=1..5)
        found_users = []
        for author_id in range(1, 6):
            try:
                resp = self._request('GET', f'{base}/?author={author_id}')
                if resp and resp.status_code in (200, 301, 302):
                    loc = getattr(resp, 'headers', {}).get('Location', '')
                    match = re.search(r'/author/([^/]+)', loc)
                    if match:
                        found_users.append(match.group(1))
            except Exception:
                continue

        if found_users:
            findings.append({
                'check': 'wordpress_user_enum',
                'detail': f'Users enumerated via ?author=N: {", ".join(found_users[:5])}',
                'severity': 'low',
                'evidence': f'?author=N redirect — {len(found_users)} users',
            })

        return findings

    # ── xmlrpc.php ───────────────────────────────────────────────────────────

    def _check_xmlrpc(self, base: str):
        """Check if xmlrpc.php is accessible."""
        try:
            resp = self._request('POST', f'{base}/xmlrpc.php', data=(
                '<?xml version="1.0"?>'
                '<methodCall><methodName>system.listMethods</methodName></methodCall>'
            ), headers={'Content-Type': 'text/xml'})
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'methodResponse' in text:
                    return {
                        'check': 'wordpress_xmlrpc',
                        'detail': 'xmlrpc.php is enabled and responds to system.listMethods',
                        'severity': 'medium',
                        'evidence': 'xmlrpc.php — methodResponse returned',
                    }
        except Exception:
            pass
        return None

    # ── wp-cron.php ──────────────────────────────────────────────────────────

    def _check_wp_cron(self, base: str):
        """Check if wp-cron.php is publicly accessible."""
        try:
            resp = self._request('GET', f'{base}/wp-cron.php')
            if resp and resp.status_code == 200:
                return {
                    'check': 'wordpress_wp_cron',
                    'detail': 'wp-cron.php is publicly accessible (DoS vector)',
                    'severity': 'low',
                    'evidence': 'wp-cron.php — HTTP 200',
                }
        except Exception:
            pass
        return None

    # ── Config backup detection ──────────────────────────────────────────────

    def _check_config_backups(self, base: str) -> list:
        """Check for exposed WordPress config backup files."""
        findings = []
        for filename in CONFIG_BACKUP_FILES:
            try:
                resp = self._request('GET', f'{base}/{filename}')
                if resp and resp.status_code == 200:
                    text = getattr(resp, 'text', '')
                    if 'DB_PASSWORD' in text or 'DB_NAME' in text:
                        findings.append({
                            'check': 'wordpress_config_backup',
                            'detail': f'Config backup exposed: {filename}',
                            'severity': 'critical',
                            'evidence': f'{filename} — contains database credentials',
                        })
            except Exception:
                continue
        return findings

    # ── Debug log ────────────────────────────────────────────────────────────

    def _check_debug_log(self, base: str):
        """Check for exposed debug.log file."""
        try:
            resp = self._request('GET', f'{base}/wp-content/debug.log')
            if resp and resp.status_code == 200:
                text = getattr(resp, 'text', '')
                if 'PHP' in text or 'Warning' in text or 'Fatal' in text:
                    return {
                        'check': 'wordpress_debug_log',
                        'detail': 'debug.log is publicly accessible',
                        'severity': 'high',
                        'evidence': 'wp-content/debug.log — contains PHP errors',
                    }
        except Exception:
            pass
        return None
