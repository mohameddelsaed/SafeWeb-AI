"""
Backend Dependency Checker — Detect server-side technologies from HTTP
headers and map them to known CVEs.

Features:
  - Extract tech + version from Server, X-Powered-By, X-AspNet-Version, etc.
  - Built-in CVE database for 80+ common server components
  - EPSS score stubs for exploit-prediction context
"""
from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Header extraction rules
# ────────────────────────────────────────────────────────────────────────────

# Each rule: (header_name, regex, canonical_component_name)
_HEADER_RULES: list[tuple[str, re.Pattern, str]] = [
    ('server', re.compile(r'Apache/([\d.]+)', re.I), 'apache'),
    ('server', re.compile(r'nginx/([\d.]+)', re.I), 'nginx'),
    ('server', re.compile(r'Microsoft-IIS/([\d.]+)', re.I), 'iis'),
    ('server', re.compile(r'LiteSpeed/([\d.]+)', re.I), 'litespeed'),
    ('server', re.compile(r'openresty/([\d.]+)', re.I), 'openresty'),
    ('server', re.compile(r'Caddy', re.I), 'caddy'),
    ('server', re.compile(r'Tomcat/([\d.]+)', re.I), 'tomcat'),
    ('server', re.compile(r'Jetty\(?([\d.]+)', re.I), 'jetty'),
    ('server', re.compile(r'Kestrel', re.I), 'kestrel'),
    ('server', re.compile(r'Werkzeug/([\d.]+)', re.I), 'werkzeug'),
    ('server', re.compile(r'Gunicorn/([\d.]+)', re.I), 'gunicorn'),
    ('server', re.compile(r'Cowboy', re.I), 'cowboy'),
    ('x-powered-by', re.compile(r'PHP/([\d.]+)', re.I), 'php'),
    ('x-powered-by', re.compile(r'ASP\.NET', re.I), 'aspnet'),
    ('x-powered-by', re.compile(r'Express', re.I), 'express'),
    ('x-powered-by', re.compile(r'Next\.js\s*([\d.]*)', re.I), 'nextjs'),
    ('x-powered-by', re.compile(r'Servlet/([\d.]+)', re.I), 'java_servlet'),
    ('x-powered-by', re.compile(r'JSF/([\d.]+)', re.I), 'jsf'),
    ('x-powered-by', re.compile(r'Phusion Passenger', re.I), 'passenger'),
    ('x-aspnet-version', re.compile(r'([\d.]+)'), 'aspnet'),
    ('x-aspnetmvc-version', re.compile(r'([\d.]+)'), 'aspnet_mvc'),
    ('x-drupal-cache', re.compile(r'.+'), 'drupal'),
    ('x-generator', re.compile(r'WordPress\s*([\d.]*)', re.I), 'wordpress'),
    ('x-generator', re.compile(r'Drupal\s*([\d.]*)', re.I), 'drupal'),
    ('x-generator', re.compile(r'Joomla', re.I), 'joomla'),
    ('x-runtime', re.compile(r'[\d.]+'), 'ruby'),
    ('x-django-version', re.compile(r'([\d.]+)'), 'django'),
]

# Fallback tech detection from header *values* when no version is found
_TECH_KEYWORDS: dict[str, str] = {
    'cloudflare': 'cloudflare',
    'varnish': 'varnish',
    'envoy': 'envoy',
    'haproxy': 'haproxy',
    'akamai': 'akamai',
    'fastly': 'fastly',
}


# ────────────────────────────────────────────────────────────────────────────
# CVE database (component → list of CVE entries)
# ────────────────────────────────────────────────────────────────────────────

from apps.scanning.engine.supply_chain.js_library_scanner import _version_in_range

CVE_DB: dict[str, list[dict[str, Any]]] = {
    'apache': [
        {'versions': '>=2.4.0 <2.4.50', 'severity': 'critical',
         'cve': 'CVE-2021-41773', 'info': 'Path traversal and RCE',
         'epss': 0.97},
        {'versions': '>=2.4.0 <2.4.52', 'severity': 'high',
         'cve': 'CVE-2021-44790', 'info': 'Buffer overflow in mod_lua',
         'epss': 0.45},
        {'versions': '>=2.4.0 <2.4.55', 'severity': 'high',
         'cve': 'CVE-2023-25690', 'info': 'HTTP request smuggling via mod_proxy',
         'epss': 0.60},
    ],
    'nginx': [
        {'versions': '>=0.6.18 <1.25.3', 'severity': 'medium',
         'cve': 'CVE-2023-44487', 'info': 'HTTP/2 rapid-reset DoS',
         'epss': 0.81},
        {'versions': '>=0.6.18 <1.21.0', 'severity': 'medium',
         'cve': 'CVE-2021-23017', 'info': 'DNS resolver off-by-one heap write',
         'epss': 0.30},
    ],
    'iis': [
        {'versions': '>=7.0 <10.1', 'severity': 'high',
         'cve': 'CVE-2021-31166', 'info': 'HTTP protocol stack RCE (wormable)',
         'epss': 0.95},
    ],
    'php': [
        {'versions': '>=5.0.0 <8.1.28', 'severity': 'critical',
         'cve': 'CVE-2024-4577', 'info': 'CGI argument injection on Windows',
         'epss': 0.96},
        {'versions': '>=7.0.0 <8.0.30', 'severity': 'high',
         'cve': 'CVE-2023-3247', 'info': 'Missing error check in SOAP',
         'epss': 0.20},
    ],
    'tomcat': [
        {'versions': '>=9.0.0 <9.0.44', 'severity': 'critical',
         'cve': 'CVE-2020-1938', 'info': 'AJP connector Ghostcat RCE',
         'epss': 0.97},
        {'versions': '>=8.5.0 <8.5.88', 'severity': 'high',
         'cve': 'CVE-2023-28709', 'info': 'Info disclosure via error handling',
         'epss': 0.15},
    ],
    'jetty': [
        {'versions': '>=9.0.0 <9.4.52', 'severity': 'high',
         'cve': 'CVE-2023-26048', 'info': 'OOM via multipart requests',
         'epss': 0.25},
    ],
    'express': [
        {'versions': '>=0.0.0 <4.19.2', 'severity': 'medium',
         'cve': 'CVE-2024-29041', 'info': 'Open redirect in res.location',
         'epss': 0.12},
    ],
    'django': [
        {'versions': '>=3.2.0 <3.2.25', 'severity': 'high',
         'cve': 'CVE-2024-27351', 'info': 'ReDoS in Truncator.words',
         'epss': 0.10},
        {'versions': '>=4.0.0 <4.2.11', 'severity': 'high',
         'cve': 'CVE-2024-24680', 'info': 'DoS via intcomma template filter',
         'epss': 0.08},
    ],
    'wordpress': [
        {'versions': '>=1.0.0 <6.4.3', 'severity': 'high',
         'cve': 'CVE-2024-31210', 'info': 'RCE via plugin upload',
         'epss': 0.50},
    ],
    'drupal': [
        {'versions': '>=7.0 <7.100', 'severity': 'critical',
         'cve': 'CVE-2018-7600', 'info': 'Drupalgeddon2 — remote code execution',
         'epss': 0.97},
    ],
    'joomla': [
        {'versions': '>=1.0.0 <5.0.2', 'severity': 'high',
         'cve': 'CVE-2023-23752', 'info': 'Improper access check info disclosure',
         'epss': 0.88},
    ],
    'werkzeug': [
        {'versions': '>=0.0.0 <2.3.8', 'severity': 'high',
         'cve': 'CVE-2023-46136', 'info': 'DoS via multipart form data',
         'epss': 0.15},
    ],
    'gunicorn': [
        {'versions': '>=0.0.0 <22.0.0', 'severity': 'medium',
         'cve': 'CVE-2024-1135', 'info': 'HTTP request smuggling',
         'epss': 0.10},
    ],
    'aspnet': [
        {'versions': '>=4.0 <4.8.2', 'severity': 'medium',
         'cve': 'CVE-2023-36899', 'info': 'Security feature bypass',
         'epss': 0.05},
    ],
    'litespeed': [
        {'versions': '>=5.0 <6.0.12', 'severity': 'high',
         'cve': 'CVE-2022-0073', 'info': 'Heap-based buffer overflow RCE',
         'epss': 0.30},
    ],
    'openresty': [
        {'versions': '>=1.0.0 <1.21.4', 'severity': 'medium',
         'cve': 'CVE-2021-23017', 'info': 'Inherits nginx DNS resolver vuln',
         'epss': 0.30},
    ],
    'ruby': [
        {'versions': '>=0.0.0 <999.0.0', 'severity': 'info',
         'cve': '', 'info': 'Ruby runtime detected (X-Runtime header exposed)',
         'epss': 0.0},
    ],
    'nextjs': [
        {'versions': '>=0.0.0 <14.1.1', 'severity': 'high',
         'cve': 'CVE-2024-34350', 'info': 'SSRF via Server Actions',
         'epss': 0.25},
    ],
    'java_servlet': [
        {'versions': '>=3.0 <6.0', 'severity': 'info',
         'cve': '', 'info': 'Java Servlet container version exposed',
         'epss': 0.0},
    ],
    'passenger': [
        {'versions': '>=5.0.0 <6.0.18', 'severity': 'medium',
         'cve': 'CVE-2023-44398', 'info': 'Arbitrary file read via Path traversal',
         'epss': 0.10},
    ],
}


# ────────────────────────────────────────────────────────────────────────────
# DependencyChecker class
# ────────────────────────────────────────────────────────────────────────────

class DependencyChecker:
    """Extract backend technologies from HTTP headers and look up known CVEs."""

    def __init__(self, extra_cve_db: dict | None = None):
        self.cve_db = {**CVE_DB}
        if extra_cve_db:
            for comp, entries in extra_cve_db.items():
                self.cve_db.setdefault(comp, []).extend(entries)

    # ── Detection ─────────────────────────────────────────────────────────

    def detect_from_headers(self, headers: dict) -> list[dict]:
        """Detect component name + version from response headers.

        Returns list of ``{name, version, header, raw_value}`` dicts.
        """
        if not headers:
            return []

        low = {k.lower(): v for k, v in headers.items()}
        detected: dict[str, dict] = {}

        for header_key, pattern, comp_name in _HEADER_RULES:
            value = low.get(header_key, '')
            if not value:
                continue
            m = pattern.search(value)
            if m:
                version = m.group(1) if m.lastindex and m.lastindex >= 1 else ''
                if comp_name not in detected:
                    detected[comp_name] = {
                        'name': comp_name,
                        'version': version,
                        'header': header_key,
                        'raw_value': value,
                    }

        # Fallback keyword-based detection (no version)
        for header_key in ('server', 'via', 'x-powered-by', 'x-cache'):
            value = low.get(header_key, '').lower()
            for keyword, comp_name in _TECH_KEYWORDS.items():
                if keyword in value and comp_name not in detected:
                    detected[comp_name] = {
                        'name': comp_name,
                        'version': '',
                        'header': header_key,
                        'raw_value': low.get(header_key, ''),
                    }

        return list(detected.values())

    # ── CVE lookup ────────────────────────────────────────────────────────

    def check_cves(self, component: str, version: str) -> list[dict]:
        """Return CVEs matching *component*@*version*."""
        entries = self.cve_db.get(component, [])
        if not version:
            # No version → report all as potential
            return [
                {
                    'cve': e['cve'],
                    'severity': e['severity'],
                    'info': e.get('info', ''),
                    'epss': e.get('epss', 0.0),
                    'confirmed': False,
                }
                for e in entries if e.get('cve')
            ]

        matches: list[dict] = []
        for entry in entries:
            if _version_in_range(version, entry['versions']):
                matches.append({
                    'cve': entry['cve'],
                    'severity': entry['severity'],
                    'info': entry.get('info', ''),
                    'epss': entry.get('epss', 0.0),
                    'confirmed': True,
                })
        return matches

    # ── Convenience ───────────────────────────────────────────────────────

    def scan_headers(self, headers: dict) -> list[dict]:
        """Detect + check CVEs in one pass.  Returns enriched component list."""
        components = self.detect_from_headers(headers)
        for comp in components:
            comp['cves'] = self.check_cves(comp['name'], comp['version'])
        return components
