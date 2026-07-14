"""
ComponentTester — Tests for vulnerable and outdated components.
OWASP A06:2021 — Vulnerable and Outdated Components.

Checks: server headers, client-side libraries (30+ known CVEs), CMS fingerprints,
JavaScript dependency scanning, deprecated features, and security header analysis.
"""
import re
import logging
from .base_tester import BaseTester

logger = logging.getLogger(__name__)

# ── Known vulnerable version database (30+ components) ────────────────────────
KNOWN_VULNERABLE = {
    # ── Web Servers ──
    'Apache': {
        'pattern': r'Apache/(\d+\.\d+\.\d+)',
        'vulnerable_below': '2.4.58',
        'cve': 'CVE-2023-43622',
        'category': 'server',
    },
    'nginx': {
        'pattern': r'nginx/(\d+\.\d+\.\d+)',
        'vulnerable_below': '1.25.3',
        'cve': 'CVE-2023-44487',
        'category': 'server',
    },
    'OpenSSL': {
        'pattern': r'OpenSSL/(\d+\.\d+\.\d+)',
        'vulnerable_below': '3.1.4',
        'cve': 'CVE-2023-5678',
        'category': 'server',
    },
    'IIS': {
        'pattern': r'Microsoft-IIS/(\d+\.\d+)',
        'vulnerable_below': '10.0',
        'cve': 'Multiple CVEs',
        'category': 'server',
    },
    # ── Server-side Frameworks ──
    'PHP': {
        'pattern': r'PHP/(\d+\.\d+\.\d+)',
        'vulnerable_below': '8.2.0',
        'cve': 'CVE-2023-0568',
        'category': 'framework',
    },
    'ASP.NET': {
        'pattern': r'X-AspNet-Version:\s*(\d+\.\d+\.\d+)',
        'vulnerable_below': '4.8.0',
        'cve': 'Multiple CVEs',
        'category': 'framework',
    },
    'Express': {
        'pattern': r'[Ee]xpress[/-](\d+\.\d+\.\d+)',
        'vulnerable_below': '4.18.2',
        'cve': 'CVE-2022-24999',
        'category': 'framework',
    },
    'Django': {
        'pattern': r'Django[/-](\d+\.\d+)',
        'vulnerable_below': '4.2',
        'cve': 'CVE-2023-31047',
        'category': 'framework',
    },
    'Rails': {
        'pattern': r'Rails[/-](\d+\.\d+\.\d+)',
        'vulnerable_below': '7.0.4',
        'cve': 'CVE-2023-22795',
        'category': 'framework',
    },
    'Spring': {
        'pattern': r'Spring[/-](\d+\.\d+\.\d+)',
        'vulnerable_below': '6.0.0',
        'cve': 'CVE-2022-22965 (Spring4Shell)',
        'category': 'framework',
    },
    # ── JavaScript Libraries (client-side) ──
    'jQuery': {
        'pattern': r'jquery[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '3.5.0',
        'cve': 'CVE-2020-11023',
        'category': 'js',
    },
    'jQuery UI': {
        'pattern': r'jquery-ui[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '1.13.0',
        'cve': 'CVE-2021-41184',
        'category': 'js',
    },
    'Bootstrap': {
        'pattern': r'bootstrap[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '5.2.0',
        'cve': 'CVE-2019-8331',
        'category': 'js',
    },
    'Angular': {
        'pattern': r'angular[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '1.8.0',
        'cve': 'CVE-2022-25869',
        'category': 'js',
    },
    'AngularJS': {
        'pattern': r'angular(?:\.min)?\.js.*?(\d+\.\d+\.\d+)',
        'vulnerable_below': '1.8.0',
        'cve': 'CVE-2022-25869 (Prototype pollution + XSS)',
        'category': 'js',
    },
    'React': {
        'pattern': r'react[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '18.0.0',
        'cve': 'Multiple CVEs',
        'category': 'js',
    },
    'Vue.js': {
        'pattern': r'vue[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '3.2.0',
        'cve': 'Multiple CVEs',
        'category': 'js',
    },
    'Lodash': {
        'pattern': r'lodash[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '4.17.21',
        'cve': 'CVE-2021-23337 (Command Injection)',
        'category': 'js',
    },
    'Moment.js': {
        'pattern': r'moment[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '2.29.4',
        'cve': 'CVE-2022-31129 (ReDoS)',
        'category': 'js',
    },
    'Handlebars': {
        'pattern': r'handlebars[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '4.7.7',
        'cve': 'CVE-2021-23369 (RCE via template)',
        'category': 'js',
    },
    'Underscore': {
        'pattern': r'underscore[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '1.13.6',
        'cve': 'CVE-2021-23358 (Code Injection)',
        'category': 'js',
    },
    'DOMPurify': {
        'pattern': r'dompurify[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '3.0.0',
        'cve': 'CVE-2023-23631 (mXSS bypass)',
        'category': 'js',
    },
    'Axios': {
        'pattern': r'axios[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '1.3.4',
        'cve': 'CVE-2023-26159 (SSRF)',
        'category': 'js',
    },
    'Socket.IO': {
        'pattern': r'socket\.io[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '4.6.0',
        'cve': 'CVE-2023-32695',
        'category': 'js',
    },
    'TinyMCE': {
        'pattern': r'tinymce[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '6.4.0',
        'cve': 'CVE-2023-27602 (XSS)',
        'category': 'js',
    },
    'CKEditor': {
        'pattern': r'ckeditor[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '4.22.0',
        'cve': 'CVE-2023-28439 (XSS)',
        'category': 'js',
    },
    'Prototype.js': {
        'pattern': r'prototype[.-](\d+\.\d+\.\d+)',
        'vulnerable_below': '1.7.3',
        'cve': 'CVE-2020-27511',
        'category': 'js',
    },
    'D3.js': {
        'pattern': r'd3[.-]v?(\d+\.\d+\.\d+)',
        'vulnerable_below': '7.0.0',
        'cve': 'Multiple CVEs',
        'category': 'js',
    },
    # ── CMS ──
    'WordPress': {
        'pattern': r'WordPress\s+(\d+\.\d+)',
        'vulnerable_below': '6.3',
        'cve': 'Multiple CVEs',
        'category': 'cms',
    },
    'Drupal': {
        'pattern': r'Drupal\s+(\d+\.\d+)',
        'vulnerable_below': '10.0',
        'cve': 'CVE-2022-25277',
        'category': 'cms',
    },
    'Joomla': {
        'pattern': r'Joomla!\s+(\d+\.\d+)',
        'vulnerable_below': '4.3',
        'cve': 'CVE-2023-23752',
        'category': 'cms',
    },
}

# Additional script patterns to detect JS libraries in page source
_JS_CDN_PATTERNS = [
    (r'cdnjs\.cloudflare\.com/ajax/libs/(\w[\w.-]+)/(\d+\.\d+\.\d+)', 'cdnjs'),
    (r'cdn\.jsdelivr\.net/npm/(\w[\w@.-]+)@(\d+\.\d+\.\d+)', 'jsDelivr'),
    (r'unpkg\.com/(\w[\w@.-]+)@(\d+\.\d+\.\d+)', 'unpkg'),
    (r'ajax\.googleapis\.com/ajax/libs/(\w+)/(\d+\.\d+\.\d+)', 'Google CDN'),
]

FRAMEWORK_HEADERS = {
    'X-Powered-By': 'Technology stack disclosure',
    'Server': 'Web server disclosure',
    'X-AspNet-Version': 'ASP.NET version disclosure',
    'X-AspNetMvc-Version': 'ASP.NET MVC version disclosure',
    'X-Drupal-Cache': 'Drupal CMS detected',
    'X-Generator': 'CMS/framework disclosure',
    'X-Powered-CMS': 'CMS version disclosure',
    'X-Runtime': 'Server runtime disclosure',
    'X-Turbo-Charged-By': 'LiteSpeed web server detected',
}

# Security headers that should be present
_SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'description': 'HSTS missing — no enforcement of HTTPS connections',
        'remediation': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
    },
    'X-Content-Type-Options': {
        'description': 'Missing X-Content-Type-Options — browser MIME sniffing enabled',
        'remediation': 'Add X-Content-Type-Options: nosniff',
    },
    'X-Frame-Options': {
        'description': 'Missing X-Frame-Options — clickjacking possible',
        'remediation': 'Add X-Frame-Options: DENY (or SAMEORIGIN)',
    },
    'Referrer-Policy': {
        'description': 'Missing Referrer-Policy — sensitive URL data may leak via Referer header',
        'remediation': 'Add Referrer-Policy: strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'description': 'Missing Permissions-Policy — browser features unrestricted',
        'remediation': 'Add Permissions-Policy to restrict camera, microphone, geolocation, etc.',
    },
}


class ComponentTester(BaseTester):
    """Test for vulnerable and outdated components."""

    TESTER_NAME = 'Components'

    def test(self, page, depth: str = 'medium', recon_data: dict = None) -> list:
        vulnerabilities = []

        # Check response headers for server/framework versions
        response = self._make_request('GET', page.url)
        if response:
            vulns = self._check_server_headers(response, page.url)
            vulnerabilities.extend(vulns)

            # Security header analysis (medium/deep)
            if depth in ('medium', 'deep'):
                sec_vulns = self._check_security_headers(response, page.url)
                vulnerabilities.extend(sec_vulns)

        # Check page source for library versions
        if depth in ('medium', 'deep'):
            vulns = self._check_client_libraries(page)
            vulnerabilities.extend(vulns)

            # CDN-based JavaScript dependency scanning
            cdn_vulns = self._scan_cdn_dependencies(page)
            vulnerabilities.extend(cdn_vulns)

        # Check for common CMS fingerprints
        vulns = self._check_cms_fingerprints(page)
        vulnerabilities.extend(vulns)

        # Check for outdated TLS
        vuln = self._check_deprecated_features(page)
        if vuln:
            vulnerabilities.append(vuln)

        # Deep: scan inline script tags for library references
        if depth == 'deep':
            vulns = self._scan_inline_scripts(page)
            vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_server_headers(self, response, url):
        """Check for version information in response headers."""
        vulnerabilities = []

        for header, description in FRAMEWORK_HEADERS.items():
            value = response.headers.get(header, '')
            if not value:
                continue

            # Check if it reveals a version number
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', value)

            # Check against known vulnerable versions
            for component, info in KNOWN_VULNERABLE.items():
                match = re.search(info['pattern'], value, re.IGNORECASE)
                if match:
                    detected_version = match.group(1)
                    if self._is_version_below(detected_version, info['vulnerable_below']):
                        vulnerabilities.append(self._build_vuln(
                            name=f'Vulnerable {component} Version: {detected_version}',
                            severity='high',
                            category='Vulnerable Components',
                            description=f'{component} version {detected_version} is outdated and has known vulnerabilities.',
                            impact=f'Known vulnerabilities ({info["cve"]}) may allow remote code execution, '
                                  f'denial of service, or data disclosure.',
                            remediation=f'Update {component} to the latest stable version.',
                            cwe='CWE-1104',
                            cvss=7.5,
                            affected_url=url,
                            evidence=f'{header}: {value}',
                        ))
                        break

            # General version disclosure
            if version_match and not any(v['name'] == f'Vulnerable {c} Version' for c in KNOWN_VULNERABLE for v in vulnerabilities if 'name' in v):
                vulnerabilities.append(self._build_vuln(
                    name=f'Technology Version Disclosed: {header}',
                    severity='low',
                    category='Vulnerable Components',
                    description=f'{description}. Value: {value}',
                    impact='Version information helps attackers find known vulnerabilities '
                          'specific to the detected version.',
                    remediation=f'Remove or suppress the {header} header in production. '
                               'Configure the web server to not reveal version information.',
                    cwe='CWE-200',
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'{header}: {value}',
                ))

        return vulnerabilities

    def _check_client_libraries(self, page):
        """Check for vulnerable client-side libraries in page source."""
        vulnerabilities = []
        body = page.body

        for component, info in KNOWN_VULNERABLE.items():
            match = re.search(info['pattern'], body, re.IGNORECASE)
            if match:
                detected_version = match.group(1)
                if self._is_version_below(detected_version, info['vulnerable_below']):
                    vulnerabilities.append(self._build_vuln(
                        name=f'Vulnerable Client Library: {component} {detected_version}',
                        severity='medium',
                        category='Vulnerable Components',
                        description=f'{component} version {detected_version} is outdated and vulnerable.',
                        impact=f'Known vulnerabilities ({info["cve"]}) in this library may be exploited.',
                        remediation=f'Update {component} to the latest version. '
                                   'Use a dependency management tool to track updates.',
                        cwe='CWE-1104',
                        cvss=6.1,
                        affected_url=page.url,
                        evidence=f'Detected {component} version {detected_version} in page source.',
                    ))

        return vulnerabilities

    def _check_cms_fingerprints(self, page):
        """Check for CMS fingerprints that reveal technology."""
        vulnerabilities = []
        body = page.body

        cms_patterns = {
            'WordPress': [
                r'wp-content/', r'wp-includes/', r'wp-json/',
                r'<meta name="generator" content="WordPress\s+([\d.]+)"',
            ],
            'Drupal': [
                r'sites/default/files/', r'Drupal\.settings',
                r'<meta name="generator" content="Drupal\s+([\d.]+)"',
            ],
            'Joomla': [
                r'/media/jui/', r'/components/com_',
                r'<meta name="generator" content="Joomla',
            ],
        }

        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else 'unknown'
                    vulnerabilities.append(self._build_vuln(
                        name=f'CMS Detected: {cms}',
                        severity='info',
                        category='Vulnerable Components',
                        description=f'{cms} CMS detected (version: {version}). '
                                   f'This information helps attackers target known CMS vulnerabilities.',
                        impact='Knowing the CMS and version allows attackers to use specific exploits.',
                        remediation=f'Keep {cms} updated to the latest version. '
                                   'Remove version information from meta tags.',
                        cwe='CWE-200',
                        cvss=3.1,
                        affected_url=page.url,
                        evidence=f'{cms} fingerprint detected via pattern: {pattern}',
                    ))
                    break  # One finding per CMS

        return vulnerabilities

    def _check_deprecated_features(self, page):
        """Check for deprecated/insecure features in page source."""
        body = page.body

        deprecated_patterns = {
            'document.domain': 'Deprecated DOM property that weakens same-origin policy',
            'X-UA-Compatible': 'Targets old IE versions, indicating legacy support',
        }

        for pattern, description in deprecated_patterns.items():
            if pattern in body:
                return self._build_vuln(
                    name=f'Deprecated Feature: {pattern}',
                    severity='info',
                    category='Vulnerable Components',
                    description=f'{description}.',
                    impact='Use of deprecated features may introduce security weaknesses.',
                    remediation='Remove deprecated features and update to modern alternatives.',
                    cwe='CWE-477',
                    cvss=2.0,
                    affected_url=page.url,
                    evidence=f'Deprecated feature "{pattern}" found in page source.',
                )
        return None

    def _is_version_below(self, version, threshold):
        """Compare version strings (semver-like)."""
        try:
            v_parts = [int(x) for x in version.split('.')]
            t_parts = [int(x) for x in threshold.split('.')]
            # Pad shorter list
            while len(v_parts) < len(t_parts):
                v_parts.append(0)
            while len(t_parts) < len(v_parts):
                t_parts.append(0)
            return v_parts < t_parts
        except (ValueError, AttributeError):
            return False

    # ── New Phase 3 methods ───────────────────────────────────────────────────

    def _check_security_headers(self, response, url):
        """Check for missing security headers."""
        vulnerabilities = []

        for header, info in _SECURITY_HEADERS.items():
            if not response.headers.get(header):
                vulnerabilities.append(self._build_vuln(
                    name=f'Missing Security Header: {header}',
                    severity='low',
                    category='Vulnerable Components',
                    description=info['description'] + '.',
                    impact='Missing security headers leave the application vulnerable to '
                          'various attacks that modern browsers can prevent.',
                    remediation=info['remediation'],
                    cwe='CWE-693',
                    cvss=3.7,
                    affected_url=url,
                    evidence=f'Header "{header}" not found in response.',
                ))

        # Check for deprecated/weak header values
        hsts = response.headers.get('Strict-Transport-Security', '')
        if hsts and 'max-age' in hsts:
            max_age_match = re.search(r'max-age=(\d+)', hsts)
            if max_age_match and int(max_age_match.group(1)) < 31536000:
                vulnerabilities.append(self._build_vuln(
                    name='Weak HSTS max-age Value',
                    severity='low',
                    category='Vulnerable Components',
                    description=f'HSTS max-age is {max_age_match.group(1)} seconds '
                               f'(less than 1 year recommended minimum).',
                    impact='Short HSTS duration gives attackers a larger window '
                          'for SSL stripping attacks.',
                    remediation='Set max-age to at least 31536000 (1 year).',
                    cwe='CWE-693',
                    cvss=3.1,
                    affected_url=url,
                    evidence=f'Strict-Transport-Security: {hsts}',
                ))

        return vulnerabilities

    def _scan_cdn_dependencies(self, page):
        """Scan page source for JavaScript libraries loaded from CDNs.

        Detects libraries loaded from cdnjs, jsDelivr, unpkg, Google CDN
        and checks their versions against the vulnerability database.
        """
        vulnerabilities = []
        body = page.body
        if not body:
            return vulnerabilities

        detected = set()
        for pattern, cdn_name in _JS_CDN_PATTERNS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            for lib_name, version in matches:
                # Normalize library name
                clean_name = lib_name.lstrip('@').split('/')[-1]
                key = f'{clean_name}-{version}'
                if key in detected:
                    continue
                detected.add(key)

                # Check against known vulnerable versions
                for component, info in KNOWN_VULNERABLE.items():
                    if info.get('category') != 'js':
                        continue
                    if component.lower().replace('.', '').replace(' ', '') in \
                       clean_name.lower().replace('.', '').replace(' ', ''):
                        if self._is_version_below(version, info['vulnerable_below']):
                            vulnerabilities.append(self._build_vuln(
                                name=f'Vulnerable CDN Library: {clean_name} {version}',
                                severity='medium',
                                category='Vulnerable Components',
                                description=f'{clean_name} version {version} loaded from {cdn_name} '
                                           f'is below the safe version {info["vulnerable_below"]}.',
                                impact=f'Known vulnerability {info["cve"]} may allow XSS, '
                                      f'prototype pollution, or other client-side attacks.',
                                remediation=f'Update {clean_name} to at least version '
                                           f'{info["vulnerable_below"]}. Use SRI hashes for CDN resources.',
                                cwe='CWE-1104',
                                cvss=6.1,
                                affected_url=page.url,
                                evidence=f'CDN: {cdn_name}\nLibrary: {clean_name} {version}\n'
                                        f'Safe version: {info["vulnerable_below"]}\n'
                                        f'CVE: {info["cve"]}',
                            ))

        # Check for missing Subresource Integrity (SRI) on CDN scripts
        cdn_scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']*(?:cdnjs|jsdelivr|unpkg|googleapis)[^"\']*)["\']([^>]*)>',
            body, re.IGNORECASE,
        )
        scripts_without_sri = [
            url for url, attrs in cdn_scripts if 'integrity' not in attrs.lower()
        ]
        if scripts_without_sri:
            vulnerabilities.append(self._build_vuln(
                name=f'Missing SRI on {len(scripts_without_sri)} CDN Script(s)',
                severity='low',
                category='Vulnerable Components',
                description=f'{len(scripts_without_sri)} script(s) loaded from CDNs lack '
                           f'Subresource Integrity (SRI) attributes.',
                impact='If the CDN is compromised, malicious code can be injected into '
                      'the application without detection.',
                remediation='Add integrity="sha384-..." and crossorigin="anonymous" to all '
                           'CDN-loaded script tags.',
                cwe='CWE-830',
                cvss=3.7,
                affected_url=page.url,
                evidence='Scripts without SRI:\n' +
                        '\n'.join(f'  - {s[:100]}' for s in scripts_without_sri[:5]),
            ))

        return vulnerabilities

    def _scan_inline_scripts(self, page):
        """Deep scan: extract version comments from inline script blocks."""
        vulnerabilities = []
        body = page.body
        if not body:
            return vulnerabilities

        # Find version comments in scripts: e.g., "/*! jQuery v3.2.1 */"
        version_comments = re.findall(
            r'/\*[!*]\s*(\w[\w.]+)\s+v?(\d+\.\d+\.\d+)\s',
            body, re.IGNORECASE,
        )

        detected = set()
        for lib_name, version in version_comments:
            key = f'{lib_name}-{version}'
            if key in detected:
                continue
            detected.add(key)

            for component, info in KNOWN_VULNERABLE.items():
                if component.lower() in lib_name.lower():
                    if self._is_version_below(version, info['vulnerable_below']):
                        vulnerabilities.append(self._build_vuln(
                            name=f'Vulnerable Inline Library: {lib_name} {version}',
                            severity='medium',
                            category='Vulnerable Components',
                            description=f'{lib_name} {version} detected in inline script comment. '
                                       f'This version has known vulnerabilities ({info["cve"]}).',
                            impact='Known vulnerability may allow exploitation.',
                            remediation=f'Update {lib_name} to the latest version.',
                            cwe='CWE-1104',
                            cvss=6.1,
                            affected_url=page.url,
                            evidence=f'Inline detection: {lib_name} v{version}\n'
                                    f'CVE: {info["cve"]}',
                        ))
                    break

        return vulnerabilities
