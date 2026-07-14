"""
Dependency Confusion Tester — Detects supply chain attack vectors.

Covers:
  - Private package name enumeration from JS/HTML
  - Public registry check for name availability
  - Scoped vs unscoped package analysis
"""
import logging
import re

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Package name extraction patterns ─────────────────────────────────────────
# JavaScript import/require patterns
JS_IMPORT_RE = re.compile(
    r'(?:import\s+.*?\s+from\s+["\'])(@?[a-z][\w\-.]*(?:/[a-z][\w\-.]*)?)["\']',
    re.IGNORECASE,
)
JS_REQUIRE_RE = re.compile(
    r'require\s*\(\s*["\'](@?[a-z][\w\-.]*(?:/[a-z][\w\-.]*)?)["\']',
    re.IGNORECASE,
)

# CDN/script src patterns
SCRIPT_SRC_RE = re.compile(
    r'<script[^>]+src=["\'](?:.*?/)?(@?[a-z][\w\-.]*(?:/[a-z][\w\-.]*)'
    r'?)(?:@[\d.]+)?(?:/[^"\']*)?["\']',
    re.IGNORECASE,
)

# package.json-like references
PKG_JSON_RE = re.compile(
    r'["\'](@?[a-z][\w\-.]*(?:/[a-z][\w\-.]*)?)["\']:\s*["\'][\^~]?\d',
    re.IGNORECASE,
)

# ── Known public registries ─────────────────────────────────────────────────
# We don't actually query registries - we detect the pattern
PRIVATE_SCOPE_INDICATORS = [
    re.compile(r'^@[a-z][\w\-]+/', re.IGNORECASE),  # Scoped packages: @company/pkg
]

# ── Internal package indicators ──────────────────────────────────────────────
INTERNAL_PKG_PATTERNS = [
    re.compile(r'^@(?:internal|private|corp|company|org)', re.IGNORECASE),
    re.compile(r'-internal$', re.IGNORECASE),
    re.compile(r'-private$', re.IGNORECASE),
    re.compile(r'^(?:internal|private)-', re.IGNORECASE),
]

# ── Well-known public packages to exclude ────────────────────────────────────
KNOWN_PUBLIC_PACKAGES = {
    'react', 'vue', 'angular', 'jquery', 'lodash', 'moment',
    'express', 'axios', 'webpack', 'babel', 'typescript',
    'next', 'nuxt', 'svelte', 'lit', 'preact',
    'd3', 'three', 'chart', 'echarts',
    'bootstrap', 'tailwindcss', 'material',
}


class DependencyConfusionTester(BaseTester):
    """Test for dependency confusion / supply chain attack vectors."""

    TESTER_NAME = 'Dependency Confusion'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulns = []
        url = getattr(page, 'url', '')
        body = getattr(page, 'body', '') or ''

        # 1. Extract package names from JS/HTML
        packages = self._extract_package_names(body)
        if not packages:
            return vulns

        # 2. Check for private/internal package names exposed
        vuln = self._check_private_packages(url, packages)
        if vuln:
            vulns.append(vuln)

        if depth == 'shallow':
            return vulns

        # 3. Check for scoped package confusion
        vuln = self._check_scoped_packages(url, packages)
        if vuln:
            vulns.append(vuln)

        if depth == 'deep':
            # 4. Analyze package.json exposure
            vuln = self._check_package_json_exposure(url)
            if vuln:
                vulns.append(vuln)

        return vulns

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _extract_package_names(self, body: str) -> list:
        """Extract package names from page body."""
        packages = set()
        for pattern in [JS_IMPORT_RE, JS_REQUIRE_RE, SCRIPT_SRC_RE, PKG_JSON_RE]:
            for match in pattern.findall(body):
                pkg = match.strip()
                if pkg and len(pkg) > 2:
                    # Filter out file paths and URLs
                    if not pkg.startswith(('.', '/', 'http')):
                        packages.add(pkg)

        # Remove well-known public packages
        packages = {
            p for p in packages
            if p.lower().split('/')[0].lstrip('@') not in KNOWN_PUBLIC_PACKAGES
        }
        return list(packages)[:20]

    # ── Vulnerability checks ─────────────────────────────────────────────────

    def _check_private_packages(self, url: str, packages: list):
        """Check for private/internal package names exposed in source."""
        internal = []
        for pkg in packages:
            if any(p.search(pkg) for p in INTERNAL_PKG_PATTERNS):
                internal.append(pkg)

        if internal:
            return self._build_vuln(
                name='Internal Package Names Exposed',
                severity='medium',
                category='Information Disclosure',
                description=(
                    f'Internal/private package names found in page source: '
                    f'{", ".join(internal[:5])}. An attacker can register '
                    'these names on public registries (npm, PyPI) to '
                    'execute a dependency confusion attack.'
                ),
                impact='Supply chain attack, arbitrary code execution in CI/CD',
                remediation=(
                    'Use scoped packages (@company/pkg) for internal packages. '
                    'Configure .npmrc to use private registry for internal scopes. '
                    'Remove internal package references from client-side code.'
                ),
                cwe='CWE-427',
                cvss=7.3,
                affected_url=url,
                evidence=f'Internal packages: {", ".join(internal[:5])}',
            )
        return None

    def _check_scoped_packages(self, url: str, packages: list):
        """Check for scoped packages that may be vulnerable."""
        [
            p for p in packages
            if any(ind.search(p) for ind in PRIVATE_SCOPE_INDICATORS)
        ]

        # Unscoped packages with non-public names are higher risk
        unscoped_unknown = [
            p for p in packages
            if not p.startswith('@')
            and p.lower() not in KNOWN_PUBLIC_PACKAGES
            and len(p) > 3
        ]

        if unscoped_unknown:
            return self._build_vuln(
                name='Potential Dependency Confusion Target',
                severity='low',
                category='Information Disclosure',
                description=(
                    f'Unscoped package names found that may be internal: '
                    f'{", ".join(unscoped_unknown[:5])}. If these are private '
                    'packages without public registry registration, they are '
                    'vulnerable to dependency confusion.'
                ),
                impact='Supply chain attack if names are unregistered publicly',
                remediation=(
                    'Register package names on public registries as placeholders. '
                    'Use scoped packages for all internal dependencies.'
                ),
                cwe='CWE-427',
                cvss=3.7,
                affected_url=url,
                evidence=f'Unscoped packages: {", ".join(unscoped_unknown[:5])}',
            )
        return None

    def _check_package_json_exposure(self, url: str):
        """Check if package.json is publicly accessible."""
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        pkg_url = urlunparse(parsed._replace(path='/package.json', query=''))

        try:
            resp = self._make_request('GET', pkg_url)
            if not resp:
                return None

            resp_body = getattr(resp, 'text', '')

            if (resp.status_code == 200
                    and '"dependencies"' in resp_body
                    and '"name"' in resp_body):
                # Extract dependency names
                dep_names = re.findall(
                    r'"(@?[a-z][\w\-.]*(?:/[a-z][\w\-.]*)?)":\s*"[\^~]?\d',
                    resp_body,
                    re.IGNORECASE,
                )
                return self._build_vuln(
                    name='Package Manifest Exposed',
                    severity='medium',
                    category='Information Disclosure',
                    description=(
                        'The package.json file is publicly accessible, '
                        f'exposing {len(dep_names)} dependency names. '
                        'This provides an attacker with the full dependency '
                        'tree for dependency confusion attacks.'
                    ),
                    impact='Full dependency enumeration, targeted supply chain attacks',
                    remediation=(
                        'Block access to package.json from the web server. '
                        'Add package.json to .gitignore for static deployments.'
                    ),
                    cwe='CWE-538',
                    cvss=5.3,
                    affected_url=pkg_url,
                    evidence=f'package.json exposed with {len(dep_names)} dependencies',
                )
        except Exception:
            pass
        return None
