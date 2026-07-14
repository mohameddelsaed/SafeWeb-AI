"""
Vulnerability Correlator Module — Cross-reference recon data for vuln patterns.
Analyzes combinations of tech stack, misconfigurations, and exposed services
to identify potential vulnerability patterns and known CVE applicability.
"""
import logging
import re
import time
from typing import Optional

from ._base import (
    create_result,
    add_finding,
    finalize_result,
)

logger = logging.getLogger(__name__)

# ── Known vulnerable technology versions ───────────────────────────────────

TECH_VULN_DB = [
    {
        'tech': 'WordPress',
        'version_below': '6.0',
        'severity': 'high',
        'cves': ['CVE-2022-21661', 'CVE-2022-21664', 'CVE-2022-21663'],
        'description': 'WordPress < 6.0 has SQL injection, stored XSS, and authentication bypass vulnerabilities',
    },
    {
        'tech': 'jQuery',
        'version_below': '3.5.0',
        'severity': 'medium',
        'cves': ['CVE-2020-11022', 'CVE-2020-11023'],
        'description': 'jQuery < 3.5.0 is vulnerable to prototype pollution and XSS via htmlPrefilter',
    },
    {
        'tech': 'Angular',
        'version_below': '1.6',
        'severity': 'high',
        'cves': ['CVE-2019-14863', 'CVE-2020-7676'],
        'description': 'AngularJS < 1.6 allows XSS via template injection in sandbox escape',
    },
    {
        'tech': 'Apache',
        'version_below': '2.4.50',
        'severity': 'critical',
        'cves': ['CVE-2021-41773', 'CVE-2021-42013'],
        'description': 'Apache < 2.4.50 path traversal and RCE via mod_cgi',
    },
    {
        'tech': 'nginx',
        'version_below': '1.21',
        'severity': 'medium',
        'cves': ['CVE-2021-23017', 'CVE-2021-3618'],
        'description': 'nginx < 1.21 DNS resolver vulnerability and ALPACA attack vector',
    },
    {
        'tech': 'PHP',
        'version_below': '8.0',
        'severity': 'high',
        'cves': ['CVE-2021-21702', 'CVE-2021-21705', 'CVE-2022-31625'],
        'description': 'PHP < 8.0 has type confusion, SSRF, and use-after-free vulnerabilities',
    },
    {
        'tech': 'OpenSSL',
        'version_below': '3.0',
        'severity': 'high',
        'cves': ['CVE-2022-0778', 'CVE-2021-3711', 'CVE-2021-3712'],
        'description': 'OpenSSL < 3.0 has infinite-loop DoS, SM2 buffer overflow, and read overrun',
    },
    {
        'tech': 'React',
        'version_below': '16.0',
        'severity': 'medium',
        'cves': ['CVE-2018-6341'],
        'description': 'React < 16.0 vulnerable to XSS via attribute injection in SSR',
    },
    {
        'tech': 'Django',
        'version_below': '3.2',
        'severity': 'high',
        'cves': ['CVE-2021-44420', 'CVE-2021-45115', 'CVE-2021-45116'],
        'description': 'Django < 3.2 has potential directory traversal and DoS vulnerabilities',
    },
    {
        'tech': 'Express.js',
        'version_below': '4.17',
        'severity': 'medium',
        'cves': ['CVE-2022-24999'],
        'description': 'Express.js < 4.17 vulnerable to prototype pollution via qs dependency',
    },
    {
        'tech': 'Laravel',
        'version_below': '9.0',
        'severity': 'medium',
        'cves': ['CVE-2021-43617'],
        'description': 'Laravel < 9.0 has improper validation bypass vulnerabilities',
    },
    {
        'tech': 'Bootstrap',
        'version_below': '5.0',
        'severity': 'low',
        'cves': ['CVE-2019-8331'],
        'description': 'Bootstrap < 5.0 XSS in data-template and data-content attributes',
    },
]

# ── Dangerous configuration combinations ───────────────────────────────────

DANGEROUS_COMBOS = [
    {
        'name': 'Exposed Admin Without WAF',
        'conditions': ['admin_panel_exposed', 'no_waf'],
        'severity': 'critical',
        'description': 'Admin panel is publicly accessible without WAF protection — high risk of brute-force and exploitation',
        'confidence': 0.9,
    },
    {
        'name': 'Debug Mode Public Access',
        'conditions': ['debug_mode', 'public_access'],
        'severity': 'critical',
        'description': 'Application running in debug/development mode on a publicly accessible server — exposes stack traces, environment variables, and internal paths',
        'confidence': 0.95,
    },
    {
        'name': 'Deprecated TLS with Sensitive Cookies',
        'conditions': ['deprecated_tls', 'sensitive_cookies'],
        'severity': 'high',
        'description': 'TLS 1.0/1.1 in use with cookies lacking Secure flag — session hijacking risk via protocol downgrade',
        'confidence': 0.85,
    },
    {
        'name': 'Missing CSP with Detected Framework',
        'conditions': ['missing_csp', 'framework_detected'],
        'severity': 'medium',
        'description': 'No Content-Security-Policy header with a known framework — elevated XSS risk in framework-generated content',
        'confidence': 0.7,
    },
    {
        'name': 'Self-Signed Certificate on Public Site',
        'conditions': ['self_signed_cert', 'public_site'],
        'severity': 'high',
        'description': 'Self-signed TLS certificate on a public-facing site — MITM risk and user trust issues',
        'confidence': 0.9,
    },
    {
        'name': 'Version Disclosure with Known Vulns',
        'conditions': ['version_disclosed', 'known_vulns'],
        'severity': 'high',
        'description': 'Server versions publicly disclosed and match known vulnerable versions — targeted exploitation likely',
        'confidence': 0.85,
    },
    {
        'name': 'Missing HSTS with Login Forms',
        'conditions': ['missing_hsts', 'has_login'],
        'severity': 'high',
        'description': 'No HSTS header on a site with login functionality — SSL stripping attack possible',
        'confidence': 0.8,
    },
    {
        'name': 'Open CORS with Authentication',
        'conditions': ['open_cors', 'has_auth'],
        'severity': 'high',
        'description': 'Overly permissive CORS policy on authenticated endpoints — credential theft via cross-origin requests',
        'confidence': 0.85,
    },
    {
        'name': 'Directory Listing with Sensitive Files',
        'conditions': ['directory_listing', 'sensitive_files'],
        'severity': 'high',
        'description': 'Directory listing enabled with potentially sensitive files exposed — information disclosure',
        'confidence': 0.9,
    },
    {
        'name': 'Outdated CMS with Public Plugins',
        'conditions': ['outdated_cms', 'plugins_detected'],
        'severity': 'high',
        'description': 'Outdated CMS with third-party plugins — compound vulnerability risk from unmaintained components',
        'confidence': 0.8,
    },
]


# ── Helpers ────────────────────────────────────────────────────────────────

def _parse_version(version_str: str) -> tuple:
    """Parse a version string into a comparable tuple of integers."""
    try:
        parts = re.findall(r'\d+', str(version_str))
        return tuple(int(p) for p in parts[:4]) if parts else ()
    except (ValueError, TypeError):
        return ()


def _version_below(detected: str, threshold: str) -> bool:
    """Return True if *detected* version is below *threshold*."""
    d = _parse_version(detected)
    t = _parse_version(threshold)
    if not d or not t:
        return False
    return d < t


def _extract_condition_flags(recon_data: dict) -> set:
    """Derive boolean condition flags from the aggregated recon data."""
    flags: set = set()

    # WAF
    waf = recon_data.get('waf', {}) or {}
    if not waf.get('detected') and not waf.get('findings'):
        flags.add('no_waf')

    # Certificate
    cert = recon_data.get('certificate', {}) or {}
    if cert.get('self_signed'):
        flags.add('self_signed_cert')
    if cert.get('protocol') in ('SSLv3', 'TLSv1', 'TLSv1.1'):
        flags.add('deprecated_tls')
    if cert.get('valid') is not False:
        flags.add('public_site')

    # Headers
    headers = recon_data.get('headers', {}) or {}
    header_findings = headers.get('findings', [])
    header_names = {f.get('header', '').lower() for f in header_findings}
    if not any('content-security-policy' in h for h in header_names):
        flags.add('missing_csp')
    if not any('strict-transport-security' in h for h in header_names):
        flags.add('missing_hsts')

    # Technologies
    techs = recon_data.get('technologies', {}) or {}
    detected_techs = techs.get('technologies', techs.get('findings', []))
    if detected_techs:
        flags.add('framework_detected')
    # Check for version disclosure
    for tech in detected_techs if isinstance(detected_techs, list) else []:
        v = tech.get('version', '') if isinstance(tech, dict) else ''
        if v:
            flags.add('version_disclosed')
            break

    # Content discovery / admin panels
    content = recon_data.get('content_discovery', {}) or {}
    discovered = content.get('findings', content.get('discovered_paths', []))
    admin_patterns = re.compile(r'admin|login|dashboard|wp-admin|phpmyadmin', re.I)
    for item in discovered if isinstance(discovered, list) else []:
        path = item.get('path', item.get('url', '')) if isinstance(item, dict) else str(item)
        if admin_patterns.search(path):
            flags.add('admin_panel_exposed')
            flags.add('has_login')
            break

    # CORS
    cors = recon_data.get('cors', {}) or {}
    cors_issues = cors.get('findings', cors.get('issues', []))
    if cors_issues:
        flags.add('open_cors')

    # Cookies
    cookies = recon_data.get('cookies', {}) or {}
    cookie_issues = cookies.get('findings', cookies.get('issues', []))
    if cookie_issues:
        flags.add('sensitive_cookies')

    # Debug mode detection (via headers or content findings)
    for tech in detected_techs if isinstance(detected_techs, list) else []:
        name = tech.get('name', '') if isinstance(tech, dict) else str(tech)
        if re.search(r'debug|development|dev.mode', name, re.I):
            flags.add('debug_mode')
            break

    # Public access — assume public unless explicitly internal
    flags.add('public_access')

    # CMS / plugins
    cms = recon_data.get('cms', {}) or {}
    if cms.get('cms') or cms.get('findings'):
        if cms.get('outdated'):
            flags.add('outdated_cms')
        if cms.get('plugins'):
            flags.add('plugins_detected')

    # Sensitive files
    for item in discovered if isinstance(discovered, list) else []:
        path = item.get('path', item.get('url', '')) if isinstance(item, dict) else str(item)
        if re.search(r'\.(env|bak|sql|log|conf|key|pem)', path, re.I):
            flags.add('sensitive_files')
            flags.add('directory_listing')
            break

    # Auth detection from cookies/forms
    if cookies.get('findings') or cookies.get('cookies'):
        flags.add('has_auth')

    # Known vulns flag — set during tech version checks
    return flags


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_vuln_correlator(target_url: str, recon_data: Optional[dict] = None) -> dict:
    """
    Cross-reference recon findings to identify potential vulnerability patterns.

    Args:
        target_url: The target URL being scanned.
        recon_data: Aggregated dict of all prior recon module results
                    (dns, whois, technologies, waf, certificate, headers, etc.).

    Returns:
        Standardised result dict with legacy keys:
        ``correlations``, ``risk_factors``, ``total_correlations``, ``issues``.
    """
    start = time.time()
    result = create_result('vuln_correlator', target_url)

    # Legacy keys
    result['correlations'] = []
    result['risk_factors'] = []
    result['total_correlations'] = 0
    result['issues'] = []

    if recon_data is None:
        recon_data = {}

    logger.info('Starting vulnerability correlation for %s', target_url)

    try:
        # ── Phase 1: Technology version correlation ────────────────────
        result['stats']['total_checks'] += len(TECH_VULN_DB)
        condition_flags = _extract_condition_flags(recon_data)

        techs = recon_data.get('technologies', {}) or {}
        detected_techs = techs.get('technologies', techs.get('findings', []))

        for vuln_entry in TECH_VULN_DB:
            try:
                for tech in detected_techs if isinstance(detected_techs, list) else []:
                    tech_name = tech.get('name', '') if isinstance(tech, dict) else str(tech)
                    tech_version = tech.get('version', '') if isinstance(tech, dict) else ''

                    if not re.search(re.escape(vuln_entry['tech']), tech_name, re.I):
                        continue

                    if tech_version and _version_below(tech_version, vuln_entry['version_below']):
                        correlation = {
                            'type': 'tech_version_vuln',
                            'severity': vuln_entry['severity'],
                            'technologies': [f"{tech_name} {tech_version}"],
                            'description': vuln_entry['description'],
                            'cves': vuln_entry['cves'],
                            'confidence': 0.85,
                        }
                        result['correlations'].append(correlation)
                        add_finding(result, {
                            'type': 'vulnerable_technology',
                            'tech': tech_name,
                            'version': tech_version,
                            'severity': vuln_entry['severity'],
                            'cves': vuln_entry['cves'],
                            'description': vuln_entry['description'],
                        })
                        condition_flags.add('known_vulns')
                        result['stats']['successful_checks'] += 1

                        result['issues'].append(
                            f"{vuln_entry['severity'].upper()}: {tech_name} {tech_version} — {vuln_entry['description']}"
                        )
                        logger.info('Correlated vuln: %s %s', tech_name, tech_version)
            except Exception as exc:
                logger.debug('Error checking tech vuln %s: %s', vuln_entry['tech'], exc)
                result['stats']['failed_checks'] += 1

        # ── Phase 2: Dangerous combination correlation ─────────────────
        result['stats']['total_checks'] += len(DANGEROUS_COMBOS)

        for combo in DANGEROUS_COMBOS:
            try:
                if all(cond in condition_flags for cond in combo['conditions']):
                    correlation = {
                        'type': 'dangerous_combination',
                        'severity': combo['severity'],
                        'technologies': combo['conditions'],
                        'description': combo['description'],
                        'cves': [],
                        'confidence': combo['confidence'],
                    }
                    result['correlations'].append(correlation)
                    add_finding(result, {
                        'type': 'dangerous_combination',
                        'name': combo['name'],
                        'severity': combo['severity'],
                        'conditions': combo['conditions'],
                        'description': combo['description'],
                        'confidence': combo['confidence'],
                    })
                    result['stats']['successful_checks'] += 1

                    result['issues'].append(
                        f"{combo['severity'].upper()}: {combo['name']} — {combo['description']}"
                    )
                    result['risk_factors'].append(combo['name'])
                    logger.info('Dangerous combo detected: %s', combo['name'])
            except Exception as exc:
                logger.debug('Error checking combo %s: %s', combo['name'], exc)
                result['stats']['failed_checks'] += 1

        # ── Phase 3: Derive risk factors from condition flags ──────────
        flag_risk_map = {
            'no_waf': 'No WAF protection detected',
            'deprecated_tls': 'Deprecated TLS version in use',
            'self_signed_cert': 'Self-signed certificate',
            'missing_csp': 'Missing Content-Security-Policy header',
            'missing_hsts': 'Missing Strict-Transport-Security header',
            'admin_panel_exposed': 'Admin panel publicly accessible',
            'open_cors': 'Overly permissive CORS configuration',
            'debug_mode': 'Debug/development mode enabled',
            'version_disclosed': 'Server/software version publicly disclosed',
            'sensitive_files': 'Sensitive files exposed',
            'directory_listing': 'Directory listing enabled',
        }

        for flag, desc in flag_risk_map.items():
            if flag in condition_flags and desc not in result['risk_factors']:
                result['risk_factors'].append(desc)

        result['total_correlations'] = len(result['correlations'])

    except Exception as exc:
        msg = f'Vulnerability correlation error: {exc}'
        logger.error(msg, exc_info=True)
        result['errors'].append(msg)

    logger.info(
        'Vulnerability correlation complete for %s — %d correlations, %d risk factors',
        target_url, result['total_correlations'], len(result['risk_factors']),
    )

    return finalize_result(result, start)
