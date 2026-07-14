"""
Cookie Security Analyzer — Deep analysis of HTTP cookies.

Evaluates: Secure/HttpOnly/SameSite attributes, __Host-/__Secure- prefix
validation, session fixation indicators, cookie scope issues,
sensitive data exposure, and best-practice compliance.
"""
import re
import logging
import time
from urllib.parse import urlparse
from typing import Optional

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────
# Sensitive patterns that should never appear in cookies
# ──────────────────────────────────────────────────────
SENSITIVE_PATTERNS = [
    (r'password|passwd|pwd', 'Password in cookie'),
    (r'token|jwt|bearer', 'Auth token in cookie'),
    (r'api[_-]?key', 'API key in cookie'),
    (r'secret', 'Secret value in cookie'),
    (r'ssn|social.security', 'SSN in cookie'),
    (r'credit.card|cc.num', 'Credit card data in cookie'),
    (r'private[_-]?key', 'Private key in cookie'),
]

# Known session cookie names by framework
SESSION_COOKIE_NAMES = {
    'PHPSESSID': 'PHP',
    'JSESSIONID': 'Java',
    'ASP.NET_SessionId': 'ASP.NET',
    'connect.sid': 'Express.js',
    'session': 'Generic',
    'sessionid': 'Django',
    'csrftoken': 'Django CSRF',
    '_session_id': 'Ruby on Rails',
    'laravel_session': 'Laravel',
    'ci_session': 'CodeIgniter',
    'CFID': 'ColdFusion',
    'CFTOKEN': 'ColdFusion',
    '_gorilla_session': 'Go Gorilla',
}


def run_cookie_analysis(target_url: str, cookies: dict = None,
                        set_cookie_headers: list = None) -> dict:
    """
    Perform comprehensive cookie security analysis.

    Args:
        target_url: The URL being analyzed
        cookies: Dict of cookie name→value pairs
        set_cookie_headers: Raw Set-Cookie header values (list of strings)

    Returns standardised dict (findings/metadata/errors/stats) **plus**
    legacy keys for backward compatibility:

        cookies, issues, session_cookies, total_cookies, score, summary
    """
    start = time.time()
    parsed = urlparse(target_url)
    is_https = parsed.scheme == 'https'
    domain = parsed.hostname or ''

    result = create_result('cookie_analysis', target_url)

    # ── Legacy keys ──
    result['cookies'] = []
    result['issues'] = []
    result['session_cookies'] = []
    result['total_cookies'] = 0
    result['score'] = 100
    result['summary'] = ''

    if not cookies and not set_cookie_headers:
        result['summary'] = 'No cookies detected'
        return finalize_result(result, start)

    # Parse Set-Cookie headers for full attribute info
    parsed_cookies = {}
    if set_cookie_headers:
        for header in set_cookie_headers:
            cookie = _parse_set_cookie(header)
            if cookie:
                parsed_cookies[cookie['name']] = cookie

    # Merge with simple cookie dict
    if cookies:
        for name, value in cookies.items():
            if name not in parsed_cookies:
                parsed_cookies[name] = {
                    'name': name,
                    'value': str(value),
                    'secure': False,
                    'httponly': False,
                    'samesite': None,
                    'path': '/',
                    'domain': None,
                    'max_age': None,
                    'expires': None,
                }

    result['total_cookies'] = len(parsed_cookies)

    # Analyze each cookie
    for name, cookie in parsed_cookies.items():
        analysis = _analyze_cookie(cookie, is_https, domain)
        result['cookies'].append(analysis)

        # Collect issues
        for issue in analysis.get('issues', []):
            result['issues'].append(issue)

        # Identify session cookies
        if analysis.get('is_session'):
            result['session_cookies'].append(name)

    # Global cookie analysis
    _check_global_issues(result, is_https)

    # Compute score
    _compute_cookie_score(result)

    # Summary
    issue_count = len(result['issues'])
    if issue_count == 0:
        result['summary'] = 'All cookies follow security best practices'
    elif issue_count <= 3:
        result['summary'] = f'{issue_count} minor cookie security issues found'
    else:
        result['summary'] = f'{issue_count} cookie security issues detected — review recommended'

    # ── Add findings ──
    for iss in result['issues']:
        add_finding(result, {
            'type': 'cookie_issue',
            'cookie': iss.get('cookie', ''),
            'severity': iss.get('severity', 'medium'),
            'detail': iss.get('message', ''),
        })
    add_finding(result, {'type': 'cookie_score', 'score': result['score'],
                         'total': result['total_cookies']})

    return finalize_result(result, start)


def _parse_set_cookie(header: str) -> Optional[dict]:
    """Parse a Set-Cookie header string into structured attributes."""
    if not header:
        return None

    parts = [p.strip() for p in header.split(';')]
    if not parts:
        return None

    # First part is name=value
    first = parts[0]
    if '=' not in first:
        return None

    name, _, value = first.partition('=')
    cookie = {
        'name': name.strip(),
        'value': value.strip(),
        'secure': False,
        'httponly': False,
        'samesite': None,
        'path': None,
        'domain': None,
        'max_age': None,
        'expires': None,
    }

    # Parse attributes
    for part in parts[1:]:
        part_lower = part.strip().lower()

        if part_lower == 'secure':
            cookie['secure'] = True
        elif part_lower == 'httponly':
            cookie['httponly'] = True
        elif part_lower.startswith('samesite='):
            cookie['samesite'] = part.split('=', 1)[1].strip()
        elif part_lower.startswith('path='):
            cookie['path'] = part.split('=', 1)[1].strip()
        elif part_lower.startswith('domain='):
            cookie['domain'] = part.split('=', 1)[1].strip()
        elif part_lower.startswith('max-age='):
            try:
                cookie['max_age'] = int(part.split('=', 1)[1].strip())
            except ValueError:
                pass
        elif part_lower.startswith('expires='):
            cookie['expires'] = part.split('=', 1)[1].strip()

    return cookie


def _analyze_cookie(cookie: dict, is_https: bool, domain: str) -> dict:
    """Analyze a single cookie for security issues."""
    name = cookie['name']
    value = cookie.get('value', '')
    issues = []

    analysis = {
        'name': name,
        'value_length': len(value),
        'secure': cookie.get('secure', False),
        'httponly': cookie.get('httponly', False),
        'samesite': cookie.get('samesite'),
        'path': cookie.get('path'),
        'domain': cookie.get('domain'),
        'is_session': False,
        'has_prefix': False,
        'prefix_valid': True,
        'issues': [],
    }

    # ── 1. Identify session cookies ──
    name_lower = name.lower()
    is_session = False
    for session_name in SESSION_COOKIE_NAMES:
        if session_name.lower() == name_lower or name_lower.startswith(session_name.lower()):
            is_session = True
            analysis['framework'] = SESSION_COOKIE_NAMES[session_name]
            break

    # Heuristic: long random values are likely session tokens
    if not is_session and len(value) >= 32 and re.match(r'^[a-zA-Z0-9+/=_-]+$', value):
        is_session = True

    analysis['is_session'] = is_session

    # ── 2. __Host- and __Secure- prefix validation ──
    if name.startswith('__Host-'):
        analysis['has_prefix'] = True
        # __Host- requires: Secure, Path=/, no Domain
        if not cookie.get('secure'):
            analysis['prefix_valid'] = False
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'__Host- prefix cookie "{name}" missing Secure flag',
            })
        if cookie.get('domain'):
            analysis['prefix_valid'] = False
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'__Host- prefix cookie "{name}" must not set Domain attribute',
            })
        if cookie.get('path') != '/':
            analysis['prefix_valid'] = False
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'__Host- prefix cookie "{name}" must have Path=/',
            })

    elif name.startswith('__Secure-'):
        analysis['has_prefix'] = True
        if not cookie.get('secure'):
            analysis['prefix_valid'] = False
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'__Secure- prefix cookie "{name}" missing Secure flag',
            })

    # ── 3. Secure flag ──
    if is_https and not cookie.get('secure'):
        severity = 'high' if is_session else 'medium'
        issues.append({
            'cookie': name,
            'severity': severity,
            'message': f'Cookie "{name}" missing Secure flag on HTTPS site',
        })

    # ── 4. HttpOnly flag ──
    if is_session and not cookie.get('httponly'):
        issues.append({
            'cookie': name,
            'severity': 'high',
            'message': f'Session cookie "{name}" missing HttpOnly flag — XSS can steal it',
        })
    elif not cookie.get('httponly'):
        issues.append({
            'cookie': name,
            'severity': 'low',
            'message': f'Cookie "{name}" missing HttpOnly flag',
        })

    # ── 5. SameSite attribute ──
    samesite = (cookie.get('samesite') or '').lower()
    if not samesite or samesite not in ('strict', 'lax', 'none'):
        severity = 'medium' if is_session else 'low'
        issues.append({
            'cookie': name,
            'severity': severity,
            'message': f'Cookie "{name}" missing SameSite attribute — defaults to Lax in modern browsers',
        })
    elif samesite == 'none':
        if not cookie.get('secure'):
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'Cookie "{name}" has SameSite=None without Secure — rejected by browsers',
            })
        else:
            issues.append({
                'cookie': name,
                'severity': 'medium',
                'message': f'Cookie "{name}" uses SameSite=None — sent in all cross-site requests (CSRF risk)',
            })

    # ── 6. Domain scope issues ──
    cookie_domain = cookie.get('domain', '')
    if cookie_domain:
        # Over-broad domain
        if cookie_domain.startswith('.') and cookie_domain.count('.') <= 1:
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'Cookie "{name}" has overly broad domain: {cookie_domain}',
            })
        # Supercookie on public suffix (simplified check)
        if cookie_domain.lstrip('.') in ('com', 'org', 'net', 'io', 'co', 'dev'):
            issues.append({
                'cookie': name,
                'severity': 'critical',
                'message': f'Cookie "{name}" set on public suffix domain: {cookie_domain}',
            })

    # ── 7. Path scope ──
    path = cookie.get('path', '/')
    if path and path != '/':
        # Narrow path — good for scoping
        pass
    elif is_session and path == '/':
        # Session accessible from entire site — normal but worth noting
        pass

    # ── 8. Sensitive data in cookie value ──
    for pattern, description in SENSITIVE_PATTERNS:
        if re.search(pattern, name, re.IGNORECASE):
            issues.append({
                'cookie': name,
                'severity': 'high',
                'message': f'Cookie name suggests sensitive data: {description}',
            })
            break

    if value and len(value) < 200:
        # Check value for obvious sensitive data patterns
        if re.search(r'\b\d{3}-\d{2}-\d{4}\b', value):
            issues.append({
                'cookie': name,
                'severity': 'critical',
                'message': f'Cookie "{name}" may contain SSN-formatted data',
            })
        if re.search(r'\b\d{13,19}\b', value):
            issues.append({
                'cookie': name,
                'severity': 'critical',
                'message': f'Cookie "{name}" may contain credit card number',
            })

    # ── 9. Session fixation indicators ──
    if is_session and cookie.get('max_age') is None and cookie.get('expires') is None:
        issues.append({
            'cookie': name,
            'severity': 'info',
            'message': f'Session cookie "{name}" has no expiration — lives until browser close (session cookie)',
        })

    # ── 10. Excessive cookie size ──
    total_size = len(name) + len(value)
    if total_size > 4096:
        issues.append({
            'cookie': name,
            'severity': 'low',
            'message': f'Cookie "{name}" exceeds 4KB ({total_size} bytes) — may be truncated',
        })

    analysis['issues'] = issues
    return analysis


def _check_global_issues(results: dict, is_https: bool):
    """Check for cross-cookie global issues."""
    cookies = results.get('cookies', [])
    session_cookies = results.get('session_cookies', [])

    # Too many cookies
    if len(cookies) > 20:
        results['issues'].append({
            'cookie': '*',
            'severity': 'low',
            'message': f'Site sets {len(cookies)} cookies — potential privacy/performance concern',
        })

    # No session cookie found on a site that probably needs one
    if not session_cookies and cookies:
        results['issues'].append({
            'cookie': '*',
            'severity': 'info',
            'message': 'No recognized session cookie found — session management may use '
                       'a custom cookie name or token-based auth',
        })

    # Multiple session cookies (potential session fixation vector)
    if len(session_cookies) > 1:
        results['issues'].append({
            'cookie': '*',
            'severity': 'medium',
            'message': f'Multiple session cookies detected: {session_cookies} — '
                       f'potential session fixation or confusion',
        })

    # Check if any session cookie uses __Host- prefix (best practice)
    has_prefixed = any(
        c.get('has_prefix') for c in cookies if c.get('is_session')
    )
    if session_cookies and not has_prefixed:
        results['issues'].append({
            'cookie': '*',
            'severity': 'info',
            'message': 'Session cookies do not use __Host- prefix — consider using for strongest binding',
        })


def _compute_cookie_score(results: dict):
    """Compute cookie security score (0-100)."""
    score = 100
    deductions = {
        'critical': 25,
        'high': 15,
        'medium': 8,
        'low': 3,
        'info': 0,
    }

    seen = set()
    for issue in results['issues']:
        # Deduplicate same-severity same-message
        key = f"{issue.get('severity')}:{issue.get('message', '')[:50]}"
        if key not in seen:
            seen.add(key)
            score -= deductions.get(issue.get('severity', 'medium'), 5)

    results['score'] = max(0, min(100, score))
