"""
CORS Analyzer Module — Cross-Origin Resource Sharing security analysis.

Tests for common CORS misconfigurations that could allow data theft:
null origin, reflected origin, wildcard with credentials, subdomain trust.
"""
import logging
import time
from urllib.parse import urlparse

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── CORS Test Origins ──────────────────────────────────────────────────────

_SEVERITY_MAP = {
    'wildcard_credentials': 'critical',
    'null_origin': 'high',
    'origin_reflection': 'high',
    'arbitrary_origin': 'high',
    'subdomain_trust': 'medium',
    'prefix_match': 'medium',
    'suffix_match': 'medium',
    'http_trust': 'medium',
    'overly_permissive_methods': 'low',
    'overly_permissive_headers': 'low',
}


def _build_test_origins(target_url: str) -> list[dict]:
    """Build a list of origin test cases based on the target URL."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ''
    scheme = parsed.scheme or 'https'
    root_domain = extract_root_domain(hostname)

    origins = [
        {
            'origin': 'null',
            'test_type': 'null_origin',
            'description': 'Null origin — can be triggered by sandboxed iframes, redirects',
        },
        {
            'origin': f'{scheme}://{hostname}',
            'test_type': 'same_origin',
            'description': 'Same origin (baseline — should be allowed)',
        },
        {
            'origin': 'https://evil.com',
            'test_type': 'arbitrary_origin',
            'description': 'Arbitrary external origin',
        },
        {
            'origin': f'https://evil.{root_domain}',
            'test_type': 'subdomain_trust',
            'description': 'Subdomain of target domain — tests wildcard subdomain trust',
        },
        {
            'origin': f'https://{root_domain}.evil.com',
            'test_type': 'suffix_match',
            'description': 'Target domain as prefix of attacker domain',
        },
        {
            'origin': f'https://evil-{root_domain}',
            'test_type': 'prefix_match',
            'description': 'Attacker domain containing target domain',
        },
        {
            'origin': f'http://{hostname}',
            'test_type': 'http_trust',
            'description': 'HTTP version of the target — tests HTTPS downgrade',
        },
    ]

    return origins


def _send_cors_request(make_request_fn, target_url: str, origin: str) -> dict | None:
    """Send a request with a specific Origin header and return CORS headers."""
    try:
        extra_headers = {'Origin': origin}
        response = make_request_fn('GET', target_url, headers=extra_headers)
        if response is None:
            return None

        headers = {}
        if hasattr(response, 'headers') and response.headers:
            headers = {k.lower(): v for k, v in response.headers.items()}

        return {
            'acao': headers.get('access-control-allow-origin', ''),
            'acac': headers.get('access-control-allow-credentials', ''),
            'acam': headers.get('access-control-allow-methods', ''),
            'acah': headers.get('access-control-allow-headers', ''),
            'acma': headers.get('access-control-max-age', ''),
            'status': getattr(response, 'status_code', 0),
        }
    except Exception as exc:
        logger.debug('CORS request failed for origin %s: %s', origin, exc)
        return None


def _analyze_cors_response(
    cors_headers: dict,
    test_origin: str,
    test_type: str,
    target_url: str,
) -> list[dict]:
    """Analyse CORS response headers and return any misconfigurations found."""
    misconfigs = []
    acao = cors_headers.get('acao', '')
    acac = cors_headers.get('acac', '').lower()
    acam = cors_headers.get('acam', '')
    credentials = acac == 'true'

    # Skip same_origin — it's the baseline
    if test_type == 'same_origin':
        return misconfigs

    # ── Wildcard + Credentials ──
    if acao == '*' and credentials:
        misconfigs.append({
            'type': 'wildcard_credentials',
            'severity': _SEVERITY_MAP['wildcard_credentials'],
            'detail': 'Access-Control-Allow-Origin: * combined with '
                      'Access-Control-Allow-Credentials: true. '
                      'This is technically invalid per spec but some browsers may mishandle it.',
            'evidence': f'ACAO: {acao}, ACAC: {acac}',
        })

    # ── Null origin accepted ──
    if test_type == 'null_origin' and acao == 'null':
        severity = 'critical' if credentials else 'high'
        misconfigs.append({
            'type': 'null_origin',
            'severity': severity,
            'detail': 'Server accepts null origin'
                      + (' with credentials — allows cross-origin data theft via sandboxed iframes'
                         if credentials else ''),
            'evidence': f'Origin: null → ACAO: {acao}, ACAC: {acac}',
        })

    # ── Origin reflection (echoes back any origin) ──
    if test_type == 'arbitrary_origin' and acao == test_origin:
        severity = 'critical' if credentials else 'high'
        misconfigs.append({
            'type': 'origin_reflection',
            'severity': severity,
            'detail': 'Server reflects arbitrary Origin header back in '
                      'Access-Control-Allow-Origin'
                      + (' with credentials — full cross-origin data theft possible'
                         if credentials else ''),
            'evidence': f'Origin: {test_origin} → ACAO: {acao}, ACAC: {acac}',
        })

    # ── Subdomain trust ──
    if test_type == 'subdomain_trust' and acao == test_origin:
        misconfigs.append({
            'type': 'subdomain_trust',
            'severity': _SEVERITY_MAP['subdomain_trust'],
            'detail': 'Server trusts subdomains of the root domain. '
                      'XSS on any subdomain can steal data cross-origin.',
            'evidence': f'Origin: {test_origin} → ACAO: {acao}',
        })

    # ── Prefix/suffix match bypass ──
    if test_type in ('prefix_match', 'suffix_match') and acao == test_origin:
        misconfigs.append({
            'type': test_type,
            'severity': _SEVERITY_MAP[test_type],
            'detail': f'Server trusts origins based on {test_type.replace("_", " ")} '
                      f'— weak origin validation.',
            'evidence': f'Origin: {test_origin} → ACAO: {acao}',
        })

    # ── HTTP trust (HTTPS downgrade) ──
    if test_type == 'http_trust' and acao == test_origin:
        misconfigs.append({
            'type': 'http_trust',
            'severity': _SEVERITY_MAP['http_trust'],
            'detail': 'Server trusts the HTTP (non-TLS) version of itself. '
                      'A MitM attacker could inject an Origin from the HTTP variant.',
            'evidence': f'Origin: {test_origin} → ACAO: {acao}',
        })

    # ── Overly permissive methods ──
    if acam:
        dangerous_methods = {'PUT', 'DELETE', 'PATCH'}
        allowed = {m.strip().upper() for m in acam.split(',')}
        exposed = allowed & dangerous_methods
        if exposed:
            misconfigs.append({
                'type': 'overly_permissive_methods',
                'severity': _SEVERITY_MAP['overly_permissive_methods'],
                'detail': f'CORS allows dangerous HTTP methods: {", ".join(sorted(exposed))}',
                'evidence': f'Access-Control-Allow-Methods: {acam}',
            })

    return misconfigs


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_cors_analyzer(target_url: str, make_request_fn=None) -> dict:
    """Analyse CORS configuration for security misconfigurations.

    Args:
        target_url:       The target URL to test.
        make_request_fn:  Callable ``fn(method, url, **kwargs) -> response``.
                          If ``None`` the module returns immediately with empty
                          results (no HTTP requests are made).

    Returns:
        Standardised result dict with legacy keys:
        ``vulnerable``, ``misconfigurations``, ``tested_origins``, ``issues``.
    """
    start = time.time()
    result = create_result('cors_analyzer', target_url)

    # ── Legacy keys ──
    result['vulnerable'] = False
    result['misconfigurations'] = []
    result['tested_origins'] = []

    if not make_request_fn:
        logger.info('CORS analyzer: no make_request_fn provided — skipping')
        return finalize_result(result, start)

    test_cases = _build_test_origins(target_url)

    for tc in test_cases:
        origin = tc['origin']
        test_type = tc['test_type']

        result['stats']['total_checks'] += 1
        result['tested_origins'].append(origin)

        cors_headers = _send_cors_request(make_request_fn, target_url, origin)
        if cors_headers is None:
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'Request with Origin {origin} failed')
            continue

        result['stats']['successful_checks'] += 1

        misconfigs = _analyze_cors_response(cors_headers, origin, test_type, target_url)
        for mc in misconfigs:
            result['misconfigurations'].append(mc)
            add_finding(result, {
                'type': 'cors_misconfiguration',
                'subtype': mc['type'],
                'severity': mc['severity'],
                'detail': mc['detail'],
                'evidence': mc['evidence'],
                'test_origin': origin,
            })
            result['issues'].append({
                'severity': mc['severity'],
                'title': f'CORS misconfiguration: {mc["type"]}',
                'detail': mc['detail'],
            })

    # ── Set top-level vulnerable flag ──
    if result['misconfigurations']:
        result['vulnerable'] = True

    logger.info(
        'CORS analysis complete for %s — %d origins tested, %d misconfigurations found',
        target_url, len(result['tested_origins']), len(result['misconfigurations']),
    )

    return finalize_result(result, start)
