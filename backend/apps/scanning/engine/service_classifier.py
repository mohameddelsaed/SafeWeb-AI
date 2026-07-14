"""
Phase 3 — Service Classifier.

Maps port + banner + headers → service type, product, version, and
recommended testers for targeting.
"""
from __future__ import annotations

import re

# ────────────────────────────────────────────────────────────────────
# Port → default service mapping
# ────────────────────────────────────────────────────────────────────

_PORT_SERVICE_MAP: dict[int, dict] = {
    21:    {'service_type': 'ftp',           'product': 'ftp',       'risk_level': 'medium'},
    22:    {'service_type': 'ssh',           'product': 'ssh',       'risk_level': 'low'},
    23:    {'service_type': 'telnet',        'product': 'telnet',    'risk_level': 'critical'},
    25:    {'service_type': 'smtp',          'product': 'smtp',      'risk_level': 'medium'},
    53:    {'service_type': 'dns',           'product': 'dns',       'risk_level': 'low'},
    80:    {'service_type': 'web_app',       'product': 'http',      'risk_level': 'medium'},
    110:   {'service_type': 'pop3',          'product': 'pop3',      'risk_level': 'medium'},
    143:   {'service_type': 'imap',          'product': 'imap',      'risk_level': 'medium'},
    443:   {'service_type': 'web_app',       'product': 'https',     'risk_level': 'medium'},
    445:   {'service_type': 'smb',           'product': 'smb',       'risk_level': 'critical'},
    993:   {'service_type': 'imap',          'product': 'imaps',     'risk_level': 'low'},
    995:   {'service_type': 'pop3',          'product': 'pop3s',     'risk_level': 'low'},
    1433:  {'service_type': 'database',      'product': 'mssql',     'risk_level': 'critical'},
    1521:  {'service_type': 'database',      'product': 'oracle',    'risk_level': 'critical'},
    2375:  {'service_type': 'container',     'product': 'docker',    'risk_level': 'critical'},
    2376:  {'service_type': 'container',     'product': 'docker',    'risk_level': 'high'},
    3000:  {'service_type': 'web_app',       'product': 'node',      'risk_level': 'medium'},
    3306:  {'service_type': 'database',      'product': 'mysql',     'risk_level': 'critical'},
    3389:  {'service_type': 'rdp',           'product': 'rdp',       'risk_level': 'high'},
    4443:  {'service_type': 'web_app',       'product': 'https-alt', 'risk_level': 'medium'},
    5000:  {'service_type': 'web_app',       'product': 'flask',     'risk_level': 'medium'},
    5432:  {'service_type': 'database',      'product': 'postgresql','risk_level': 'critical'},
    5672:  {'service_type': 'message_queue', 'product': 'rabbitmq',  'risk_level': 'high'},
    5900:  {'service_type': 'vnc',           'product': 'vnc',       'risk_level': 'high'},
    6379:  {'service_type': 'cache',         'product': 'redis',     'risk_level': 'critical'},
    6443:  {'service_type': 'container',     'product': 'kubernetes','risk_level': 'high'},
    8080:  {'service_type': 'web_app',       'product': 'http-alt',  'risk_level': 'medium'},
    8443:  {'service_type': 'web_app',       'product': 'https-alt', 'risk_level': 'medium'},
    8888:  {'service_type': 'web_app',       'product': 'jupyter',   'risk_level': 'high'},
    9090:  {'service_type': 'monitoring',    'product': 'prometheus','risk_level': 'high'},
    9200:  {'service_type': 'database',      'product': 'elasticsearch','risk_level': 'high'},
    9300:  {'service_type': 'database',      'product': 'elasticsearch','risk_level': 'high'},
    11211: {'service_type': 'cache',         'product': 'memcached', 'risk_level': 'critical'},
    27017: {'service_type': 'database',      'product': 'mongodb',   'risk_level': 'critical'},
    50000: {'service_type': 'ci_cd',         'product': 'jenkins',   'risk_level': 'high'},
}

# ────────────────────────────────────────────────────────────────────
# Banner / header → product detection
# ────────────────────────────────────────────────────────────────────

_BANNER_PATTERNS: list[tuple[str, str, str]] = [
    # (regex_pattern, product_name, service_type)
    (r'nginx/?(\S*)',          'nginx',         'web_app'),
    (r'apache/?(\S*)',         'apache',        'web_app'),
    (r'microsoft-iis/?(\S*)', 'iis',           'web_app'),
    (r'tomcat/?(\S*)',         'tomcat',        'web_app'),
    (r'jetty/?(\S*)',          'jetty',         'web_app'),
    (r'lighttpd/?(\S*)',       'lighttpd',      'web_app'),
    (r'caddy/?(\S*)',          'caddy',         'web_app'),
    (r'gunicorn/?(\S*)',       'gunicorn',      'web_app'),
    (r'uvicorn/?(\S*)',        'uvicorn',       'web_app'),
    (r'openresty/?(\S*)',      'openresty',     'web_app'),
    (r'litespeed/?(\S*)',      'litespeed',     'web_app'),
    (r'envoy/?(\S*)',          'envoy',         'web_app'),
    (r'haproxy/?(\S*)',        'haproxy',       'web_app'),
    (r'traefik/?(\S*)',        'traefik',       'web_app'),
    (r'jenkins/?(\S*)',        'jenkins',       'ci_cd'),
    (r'gitlab/?(\S*)',         'gitlab',        'ci_cd'),
    (r'grafana/?(\S*)',        'grafana',       'monitoring'),
    (r'kibana/?(\S*)',         'kibana',        'monitoring'),
    (r'prometheus/?(\S*)',     'prometheus',    'monitoring'),
    (r'redis/?(\S*)',          'redis',         'cache'),
    (r'memcached/?(\S*)',      'memcached',     'cache'),
    (r'rabbitmq/?(\S*)',       'rabbitmq',      'message_queue'),
    (r'mysql/?(\S*)',          'mysql',         'database'),
    (r'postgresql/?(\S*)',     'postgresql',    'database'),
    (r'mongodb/?(\S*)',        'mongodb',       'database'),
    (r'elastic/?(\S*)',        'elasticsearch', 'database'),
    (r'kubernetes/?(\S*)',     'kubernetes',    'container'),
    (r'docker/?(\S*)',         'docker',        'container'),
]

# ────────────────────────────────────────────────────────────────────
# Service type → relevant testers
# ────────────────────────────────────────────────────────────────────

_SERVICE_TESTER_MAP: dict[str, list[str]] = {
    'web_app':       ['XSS', 'SQLi', 'CSRF', 'SSRF', 'CMDi', 'SSTI', 'XXE',
                      'Auth', 'AccessControl', 'Misconfig', 'DataExposure',
                      'HostHeader', 'CRLF', 'OpenRedirect'],
    'api':           ['SQLi', 'SSRF', 'Auth', 'AccessControl', 'IDOR',
                      'MassAssignment', 'JWT', 'GraphQL', 'API'],
    'admin_panel':   ['Auth', 'AccessControl', 'CSRF', 'XSS', 'SQLi',
                      'DataExposure', 'Misconfig'],
    'database':      ['SQLi', 'Auth', 'DataExposure', 'Misconfig'],
    'cache':         ['Misconfig', 'DataExposure', 'Auth'],
    'message_queue': ['Misconfig', 'Auth', 'DataExposure'],
    'ci_cd':         ['Auth', 'AccessControl', 'CMDi', 'Misconfig', 'SSRF'],
    'monitoring':    ['Auth', 'DataExposure', 'SSRF', 'Misconfig'],
    'container':     ['Auth', 'Misconfig', 'CMDi', 'SSRF', 'DataExposure'],
    'unknown':       ['Misconfig', 'Auth', 'DataExposure'],
}


# ────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────

def classify_service(port: int, banner: str = '', headers: dict = None) -> dict:
    """
    Map port + response → service type, product, version and relevant testers.

    Returns dict with keys:
      service_type, product, version, relevant_testers, risk_level
    """
    headers = headers or {}
    result = {
        'service_type': 'unknown',
        'product': 'unknown',
        'version': '',
        'relevant_testers': [],
        'risk_level': 'low',
        'port': port,
    }

    # 1. Try port-based default
    if port in _PORT_SERVICE_MAP:
        defaults = _PORT_SERVICE_MAP[port]
        result['service_type'] = defaults['service_type']
        result['product'] = defaults['product']
        result['risk_level'] = defaults['risk_level']

    # 2. Refine from banner
    combined = banner.lower()
    server_header = headers.get('Server', headers.get('server', ''))
    if server_header:
        combined = f'{combined} {server_header}'.lower()

    x_powered = headers.get('X-Powered-By', headers.get('x-powered-by', ''))
    if x_powered:
        combined = f'{combined} {x_powered}'.lower()

    for pattern, product, svc_type in _BANNER_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            result['product'] = product
            result['service_type'] = svc_type
            if m.group(1):
                result['version'] = m.group(1).strip('/')
            break

    # 3. Map to relevant testers
    result['relevant_testers'] = list(
        _SERVICE_TESTER_MAP.get(result['service_type'],
                                _SERVICE_TESTER_MAP['unknown'])
    )

    # 4. Adjust risk for exposed databases/admin on common ports
    if result['service_type'] == 'database' and port not in (993, 995):
        result['risk_level'] = 'critical'
    if result['service_type'] == 'container':
        result['risk_level'] = 'critical'

    return result
