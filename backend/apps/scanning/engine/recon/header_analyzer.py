"""
HTTP Security Header Analyzer — Deep analysis of response headers.

Evaluates: Content-Security-Policy (CSP), Cross-Origin headers (COOP/COEP/CORP),
Permissions-Policy, legacy headers, security header completeness scoring,
and misconfiguration detection.
"""
import re
import logging
import time

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────
# Required security headers and their expected values
# ──────────────────────────────────────────────────────
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'required': True,
        'description': 'HSTS — Force HTTPS connections',
        'best_practice': 'max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'required': True,
        'description': 'CSP — Mitigate XSS, injection attacks',
        'best_practice': "default-src 'self'; script-src 'self'; style-src 'self'",
    },
    'X-Content-Type-Options': {
        'required': True,
        'description': 'Prevent MIME-type sniffing',
        'best_practice': 'nosniff',
    },
    'X-Frame-Options': {
        'required': True,
        'description': 'Prevent clickjacking (legacy, use CSP frame-ancestors)',
        'best_practice': 'DENY',
    },
    'Referrer-Policy': {
        'required': True,
        'description': 'Control referrer information',
        'best_practice': 'strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'required': True,
        'description': 'Restrict browser features',
        'best_practice': 'geolocation=(), camera=(), microphone=()',
    },
    'Cross-Origin-Opener-Policy': {
        'required': False,
        'description': 'COOP — Isolate browsing context',
        'best_practice': 'same-origin',
    },
    'Cross-Origin-Embedder-Policy': {
        'required': False,
        'description': 'COEP — Require CORS/CORP for subresources',
        'best_practice': 'require-corp',
    },
    'Cross-Origin-Resource-Policy': {
        'required': False,
        'description': 'CORP — Restrict cross-origin resource loading',
        'best_practice': 'same-origin',
    },
    'X-Permitted-Cross-Domain-Policies': {
        'required': False,
        'description': 'Restrict Adobe Flash/PDF cross-domain',
        'best_practice': 'none',
    },
    'Cache-Control': {
        'required': False,
        'description': 'Prevent sensitive data caching',
        'best_practice': 'no-store, no-cache, must-revalidate',
    },
}

# Dangerous headers that should NOT be present
DANGEROUS_HEADERS = {
    'X-Powered-By': 'Leaks technology information',
    'Server': 'Leaks server software',
    'X-AspNet-Version': 'Leaks ASP.NET version',
    'X-AspNetMvc-Version': 'Leaks ASP.NET MVC version',
    'X-Runtime': 'Leaks runtime timing (timing attacks)',
    'X-Debug-Token': 'Debug token in production',
    'X-Debug-Token-Link': 'Debug link in production',
}

# CSP dangerous directives
CSP_DANGEROUS_DIRECTIVES = {
    "unsafe-inline": "Allows inline scripts — XSS risk",
    "unsafe-eval": "Allows eval() — Code injection risk",
    "unsafe-hashes": "Allows specific inline event handlers",
    "data:": "Allows data: URIs — XSS bypass vector",
    "blob:": "Allows blob: URIs — Script injection vector",
    "*": "Wildcard source — No restriction",
}


def run_header_analysis(target_url: str, response_headers: dict = None) -> dict:
    """
    Perform comprehensive HTTP security header analysis.

    Args:
        target_url: The target URL being analyzed
        response_headers: HTTP response headers as a dict

    Returns standardised dict (findings/metadata/errors/stats) **plus**
    legacy keys for backward compatibility:

        present, missing, issues, csp_analysis, cross_origin,
        dangerous_headers, permissions_policy, score, grade
    """
    start = time.time()
    result = create_result('header_analysis', target_url)

    # ── Legacy keys ──
    result['present'] = []
    result['missing'] = []
    result['issues'] = []
    result['csp_analysis'] = None
    result['cross_origin'] = {}
    result['dangerous_headers'] = []
    result['permissions_policy'] = None
    result['score'] = 0
    result['grade'] = 'F'

    if not response_headers:
        result['issues'].append({
            'severity': 'critical',
            'message': 'No response headers available for analysis',
        })
        return finalize_result(result, start)

    headers = {k.lower(): v for k, v in response_headers.items()}

    # ── 1. Check required security headers ──
    _check_security_headers(headers, result)

    # ── 2. Deep CSP analysis ──
    csp_value = headers.get('content-security-policy', '')
    if csp_value:
        result['csp_analysis'] = _analyze_csp(csp_value)
    else:
        # Check for report-only (not enforcing)
        csp_ro = headers.get('content-security-policy-report-only', '')
        if csp_ro:
            result['csp_analysis'] = _analyze_csp(csp_ro)
            result['csp_analysis']['report_only'] = True
            result['issues'].append({
                'severity': 'medium',
                'message': 'CSP is in report-only mode — not enforcing policies',
            })

    # ── 3. Cross-origin header analysis ──
    result['cross_origin'] = _analyze_cross_origin(headers)

    # ── 4. Permissions-Policy analysis ──
    pp = headers.get('permissions-policy', '') or headers.get('feature-policy', '')
    if pp:
        result['permissions_policy'] = _analyze_permissions_policy(pp, headers)

    # ── 5. Detect dangerous/information-leaking headers ──
    _check_dangerous_headers(headers, response_headers, result)

    # ── 6. HSTS specifics ──
    hsts = headers.get('strict-transport-security', '')
    if hsts:
        _analyze_hsts(hsts, result)

    # ── 7. Compute score and grade ──
    _compute_score(result)

    # ── Add findings ──
    for m in result['missing']:
        add_finding(result, {'type': 'missing_header', 'header': m['header'],
                             'severity': m.get('severity', 'high')})
    for iss in result['issues']:
        add_finding(result, {'type': 'header_issue',
                             'severity': iss.get('severity', 'medium'),
                             'detail': iss.get('message', '')})
    for dh in result['dangerous_headers']:
        add_finding(result, {'type': 'dangerous_header', 'header': dh['header'],
                             'risk': dh['risk']})
    add_finding(result, {'type': 'header_score', 'score': result['score'],
                         'grade': result['grade']})

    return finalize_result(result, start)


# ──────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────

def _check_security_headers(headers: dict, results: dict):
    """Check presence and quality of security headers."""
    for header_name, info in SECURITY_HEADERS.items():
        key = header_name.lower()
        value = headers.get(key, '')

        if value:
            entry = {
                'header': header_name,
                'value': value[:200],  # Truncate long values
                'description': info['description'],
                'best_practice': info['best_practice'],
            }
            results['present'].append(entry)
        elif info['required']:
            results['missing'].append({
                'header': header_name,
                'description': info['description'],
                'severity': 'high',
                'recommendation': f"Add: {header_name}: {info['best_practice']}",
            })


def _analyze_csp(csp_value: str) -> dict:
    """Parse and analyze Content-Security-Policy."""
    analysis = {
        'raw': csp_value[:500],
        'directives': {},
        'issues': [],
        'has_default_src': False,
        'allows_inline': False,
        'allows_eval': False,
        'report_only': False,
        'nonce_based': False,
        'hash_based': False,
    }

    # Parse directives
    parts = [p.strip() for p in csp_value.split(';') if p.strip()]
    for part in parts:
        tokens = part.split()
        if not tokens:
            continue
        directive = tokens[0].lower()
        values = tokens[1:] if len(tokens) > 1 else []
        analysis['directives'][directive] = values

    # Check default-src
    if 'default-src' in analysis['directives']:
        analysis['has_default_src'] = True
    else:
        analysis['issues'].append({
            'severity': 'medium',
            'message': "Missing 'default-src' directive — no fallback policy",
        })

    # Check for dangerous values
    for directive, values in analysis['directives'].items():
        for val in values:
            val_lower = val.strip("'").lower()
            if val_lower in CSP_DANGEROUS_DIRECTIVES:
                severity = 'high' if val_lower in ('unsafe-eval', 'unsafe-inline', '*') else 'medium'
                analysis['issues'].append({
                    'severity': severity,
                    'directive': directive,
                    'value': val,
                    'message': f"{directive} contains '{val}': {CSP_DANGEROUS_DIRECTIVES[val_lower]}",
                })
                if val_lower == 'unsafe-inline':
                    analysis['allows_inline'] = True
                if val_lower == 'unsafe-eval':
                    analysis['allows_eval'] = True

    # Check for nonce/hash usage (modern best practice)
    full_lower = csp_value.lower()
    if "'nonce-" in full_lower:
        analysis['nonce_based'] = True
    if "'sha256-" in full_lower or "'sha384-" in full_lower or "'sha512-" in full_lower:
        analysis['hash_based'] = True

    # Check script-src specifically
    script_src = analysis['directives'].get('script-src', [])
    if not script_src and not analysis['has_default_src']:
        analysis['issues'].append({
            'severity': 'high',
            'message': "No script-src or default-src — scripts unrestricted",
        })

    # Check for overly permissive sources
    for directive, values in analysis['directives'].items():
        for val in values:
            if val == 'https:' and directive in ('script-src', 'default-src'):
                analysis['issues'].append({
                    'severity': 'medium',
                    'directive': directive,
                    'message': f"{directive} allows any HTTPS source — too permissive",
                })
            if val == 'http:':
                analysis['issues'].append({
                    'severity': 'high',
                    'directive': directive,
                    'message': f"{directive} allows HTTP sources — insecure",
                })

    return analysis


def _analyze_cross_origin(headers: dict) -> dict:
    """Analyze COOP, COEP, CORP headers."""
    analysis = {}

    # COOP
    coop = headers.get('cross-origin-opener-policy', '')
    if coop:
        analysis['coop'] = {
            'value': coop,
            'secure': coop.lower() in ('same-origin', 'same-origin-allow-popups'),
        }
    else:
        analysis['coop'] = {'value': None, 'secure': False}

    # COEP
    coep = headers.get('cross-origin-embedder-policy', '')
    if coep:
        analysis['coep'] = {
            'value': coep,
            'secure': coep.lower() in ('require-corp', 'credentialless'),
        }
    else:
        analysis['coep'] = {'value': None, 'secure': False}

    # CORP
    corp = headers.get('cross-origin-resource-policy', '')
    if corp:
        analysis['corp'] = {
            'value': corp,
            'secure': corp.lower() in ('same-origin', 'same-site'),
        }
    else:
        analysis['corp'] = {'value': None, 'secure': False}

    # Cross-origin isolation check (needs both COOP + COEP)
    analysis['cross_origin_isolated'] = (
        analysis['coop'].get('secure', False) and
        analysis['coep'].get('secure', False)
    )

    return analysis


def _analyze_permissions_policy(value: str, headers: dict) -> dict:
    """Parse Permissions-Policy (or legacy Feature-Policy)."""
    analysis = {
        'raw': value[:300],
        'features': {},
        'is_legacy': 'feature-policy' in headers,
        'issues': [],
    }

    SENSITIVE_FEATURES = [
        'camera', 'microphone', 'geolocation', 'payment',
        'usb', 'bluetooth', 'midi', 'magnetometer',
        'accelerometer', 'gyroscope', 'autoplay', 'fullscreen',
    ]

    # Parse: feature=(origins) or feature=()
    for part in value.split(','):
        part = part.strip()
        match = re.match(r'(\w[\w-]*)=\(([^)]*)\)', part)
        if match:
            feature = match.group(1)
            origins = match.group(2).strip()
            analysis['features'][feature] = origins if origins else 'none'
        elif '=' in part:
            feature, _, origins = part.partition('=')
            analysis['features'][feature.strip()] = origins.strip()

    # Check if sensitive features are restricted
    for feat in SENSITIVE_FEATURES:
        if feat not in analysis['features']:
            analysis['issues'].append({
                'severity': 'low',
                'message': f"Sensitive feature '{feat}' not restricted in Permissions-Policy",
            })
        elif analysis['features'][feat] not in ('none', '', 'self'):
            if '*' in analysis['features'][feat]:
                analysis['issues'].append({
                    'severity': 'medium',
                    'message': f"Feature '{feat}' allows wildcard origins",
                })

    if analysis['is_legacy']:
        analysis['issues'].append({
            'severity': 'low',
            'message': 'Using deprecated Feature-Policy — migrate to Permissions-Policy',
        })

    return analysis


def _check_dangerous_headers(headers: dict, original_headers: dict, results: dict):
    """Detect information-leaking headers."""
    for header, risk in DANGEROUS_HEADERS.items():
        key = header.lower()
        if key in headers and headers[key]:
            results['dangerous_headers'].append({
                'header': header,
                'value': headers[key][:100],
                'risk': risk,
                'recommendation': f'Remove or suppress the {header} header',
            })

    # Check for verbose Server header
    server = headers.get('server', '')
    if server and re.search(r'\d+\.\d+', server):
        results['issues'].append({
            'severity': 'medium',
            'message': f"Server header leaks version: '{server}' — suppress version info",
        })

    # Check for CORS misconfiguration
    acao = headers.get('access-control-allow-origin', '')
    acac = headers.get('access-control-allow-credentials', '')
    if acao == '*' and acac.lower() == 'true':
        results['issues'].append({
            'severity': 'critical',
            'message': 'CORS: wildcard origin with credentials — allows any site to steal data',
        })
    elif acao == '*':
        results['issues'].append({
            'severity': 'low',
            'message': 'CORS: wildcard origin configured (ensure intended)',
        })

    # Check for X-XSS-Protection misconfiguration
    xxss = headers.get('x-xss-protection', '')
    if xxss:
        if '1; mode=block' not in xxss and xxss != '0':
            results['issues'].append({
                'severity': 'low',
                'message': 'X-XSS-Protection present but not set to "0" or "1; mode=block"',
            })
        results['issues'].append({
            'severity': 'info',
            'message': 'X-XSS-Protection is deprecated — rely on CSP instead',
        })


def _analyze_hsts(hsts_value: str, results: dict):
    """Analyze HSTS header quality."""
    max_age_match = re.search(r'max-age=(\d+)', hsts_value, re.IGNORECASE)
    if max_age_match:
        max_age = int(max_age_match.group(1))
        if max_age < 31536000:  # Less than 1 year
            results['issues'].append({
                'severity': 'medium',
                'message': f"HSTS max-age is {max_age}s ({max_age // 86400} days) — "
                           f"recommend at least 31536000 (1 year)",
            })
        if max_age < 86400:
            results['issues'].append({
                'severity': 'high',
                'message': f"HSTS max-age is very short ({max_age}s) — effectively no protection",
            })
    else:
        results['issues'].append({
            'severity': 'high',
            'message': 'HSTS header present but missing max-age directive',
        })

    if 'includesubdomains' not in hsts_value.lower():
        results['issues'].append({
            'severity': 'low',
            'message': 'HSTS missing includeSubDomains — subdomains not protected',
        })

    if 'preload' not in hsts_value.lower():
        results['issues'].append({
            'severity': 'info',
            'message': 'HSTS missing preload directive — not eligible for HSTS preload list',
        })


def _compute_score(results: dict):
    """Compute a security header score (0-100) and letter grade."""
    score = 100
    deductions = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3,
        'info': 0,
    }

    # Deduct for missing required headers
    for missing in results['missing']:
        severity = missing.get('severity', 'medium')
        score -= deductions.get(severity, 5)

    # Deduct for issues
    for issue in results['issues']:
        severity = issue.get('severity', 'medium')
        score -= deductions.get(severity, 5)

    # Deduct for CSP issues
    if results['csp_analysis']:
        for issue in results['csp_analysis'].get('issues', []):
            severity = issue.get('severity', 'medium')
            score -= deductions.get(severity, 5)

    # Deduct for dangerous headers
    score -= len(results['dangerous_headers']) * 3

    # Bonus for cross-origin isolation
    if results['cross_origin'].get('cross_origin_isolated'):
        score = min(100, score + 5)

    # Clamp
    score = max(0, min(100, score))
    results['score'] = score

    # Grade
    if score >= 90:
        results['grade'] = 'A'
    elif score >= 75:
        results['grade'] = 'B'
    elif score >= 60:
        results['grade'] = 'C'
    elif score >= 40:
        results['grade'] = 'D'
    else:
        results['grade'] = 'F'
