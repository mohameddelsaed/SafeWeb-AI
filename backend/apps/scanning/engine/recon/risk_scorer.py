"""
Risk Scorer Module — Compute aggregate security risk scores.
Synthesizes all recon findings into weighted risk scores
across multiple categories with actionable prioritization.
"""
import logging
import time
from typing import Optional

from ._base import (
    create_result,
    add_finding,
    finalize_result,
)

logger = logging.getLogger(__name__)

# ── Category weights (must sum to 1.0) ─────────────────────────────────────

CATEGORY_WEIGHTS = {
    'infrastructure': 0.25,
    'application': 0.25,
    'information': 0.15,
    'network': 0.20,
    'compliance': 0.15,
}

# ── Grade thresholds ──────────────────────────────────────────────────────

GRADE_THRESHOLDS = [
    (90, 'A'),
    (75, 'B'),
    (60, 'C'),
    (40, 'D'),
    (0,  'F'),
]

# ── Risk level mapping ────────────────────────────────────────────────────

def _grade_for_score(score: int) -> str:
    """Return letter grade for a numeric score."""
    for threshold, grade in GRADE_THRESHOLDS:
        if score >= threshold:
            return grade
    return 'F'


def _risk_level_for_score(score: int) -> str:
    """Return risk level string from a 0-100 score."""
    if score >= 90:
        return 'low'
    elif score >= 75:
        return 'moderate'
    elif score >= 60:
        return 'elevated'
    elif score >= 40:
        return 'high'
    return 'critical'


# ── Category Scorers ──────────────────────────────────────────────────────

def _score_infrastructure(recon_data: dict) -> tuple:
    """
    Score infrastructure security: SSL/TLS, WAF, headers baseline, cloud config.
    Returns (score 0-100, list of deduction dicts).
    """
    score = 100
    deductions = []

    # ── SSL / Certificate ──────────────────────────────────────────────
    cert = recon_data.get('certificate', {}) or {}

    if not cert.get('has_ssl') and not cert.get('valid'):
        score -= 30
        deductions.append({
            'category': 'infrastructure',
            'severity': 'critical',
            'description': 'No valid SSL/TLS certificate detected',
            'recommendation': 'Install a valid TLS certificate (e.g. Let\'s Encrypt)',
            'points': 30,
        })

    if cert.get('self_signed'):
        score -= 15
        deductions.append({
            'category': 'infrastructure',
            'severity': 'high',
            'description': 'Self-signed certificate in use',
            'recommendation': 'Replace with a certificate from a trusted CA',
            'points': 15,
        })

    if cert.get('protocol') in ('SSLv3', 'TLSv1', 'TLSv1.1'):
        score -= 15
        deductions.append({
            'category': 'infrastructure',
            'severity': 'high',
            'description': f"Deprecated TLS version: {cert.get('protocol')}",
            'recommendation': 'Upgrade to TLS 1.2 or TLS 1.3',
            'points': 15,
        })

    days = cert.get('days_until_expiry')
    if isinstance(days, (int, float)) and days < 30:
        score -= 10
        deductions.append({
            'category': 'infrastructure',
            'severity': 'medium',
            'description': f'Certificate expires in {int(days)} days',
            'recommendation': 'Renew the TLS certificate before expiration',
            'points': 10,
        })

    # ── WAF ────────────────────────────────────────────────────────────
    waf = recon_data.get('waf', {}) or {}
    if not waf.get('detected') and not waf.get('findings'):
        score -= 15
        deductions.append({
            'category': 'infrastructure',
            'severity': 'medium',
            'description': 'No Web Application Firewall detected',
            'recommendation': 'Deploy a WAF (Cloudflare, AWS WAF, ModSecurity) to filter malicious traffic',
            'points': 15,
        })

    # ── Cloud misconfig ────────────────────────────────────────────────
    cloud = recon_data.get('cloud', {}) or {}
    cloud_issues = cloud.get('issues', cloud.get('findings', []))
    if cloud_issues:
        penalty = min(len(cloud_issues) * 5, 15)
        score -= penalty
        deductions.append({
            'category': 'infrastructure',
            'severity': 'medium',
            'description': f'{len(cloud_issues)} cloud configuration issue(s) found',
            'recommendation': 'Review cloud security posture — check storage ACLs, IAM, and network rules',
            'points': penalty,
        })

    return max(score, 0), deductions


def _score_application(recon_data: dict) -> tuple:
    """
    Score application security: CSP, cookies, CORS, exposed paths.
    Returns (score 0-100, list of deduction dicts).
    """
    score = 100
    deductions = []

    # ── Security headers ───────────────────────────────────────────────
    headers = recon_data.get('headers', {}) or {}

    # Build set of *missing* header names using the dedicated 'missing' list
    # populated by header_analyzer; fall back to scanning findings entries.
    critical_headers = {'content-security-policy', 'strict-transport-security',
                        'x-content-type-options', 'x-frame-options'}
    missing_header_list = headers.get('missing', [])
    if missing_header_list and isinstance(missing_header_list, list):
        missing_names = {m.get('header', '').lower() for m in missing_header_list if isinstance(m, dict)}
    else:
        # Fallback: scan findings for 'missing_header' type entries
        findings = headers.get('findings', headers.get('issues', []))
        missing_names = {
            f.get('header', '').lower()
            for f in (findings if isinstance(findings, list) else [])
            if isinstance(f, dict) and f.get('type') == 'missing_header'
        }

    missing_count = sum(1 for h in critical_headers if h in missing_names)

    if missing_count > 0:
        penalty = missing_count * 8
        score -= penalty
        deductions.append({
            'category': 'application',
            'severity': 'high' if missing_count >= 3 else 'medium',
            'description': f'{missing_count} critical security header(s) missing',
            'recommendation': 'Add Content-Security-Policy, HSTS, X-Content-Type-Options, and X-Frame-Options headers',
            'points': penalty,
        })

    # ── Cookies ────────────────────────────────────────────────────────
    cookies = recon_data.get('cookies', {}) or {}
    cookie_issues = cookies.get('findings', cookies.get('issues', []))
    if cookie_issues and isinstance(cookie_issues, list):
        penalty = min(len(cookie_issues) * 5, 20)
        score -= penalty
        deductions.append({
            'category': 'application',
            'severity': 'medium',
            'description': f'{len(cookie_issues)} cookie security issue(s) detected',
            'recommendation': 'Set Secure, HttpOnly, and SameSite attributes on all cookies',
            'points': penalty,
        })

    # ── CORS ───────────────────────────────────────────────────────────
    cors = recon_data.get('cors', {}) or {}
    cors_issues = cors.get('findings', cors.get('issues', []))
    if cors_issues and isinstance(cors_issues, list):
        penalty = min(len(cors_issues) * 8, 20)
        score -= penalty
        deductions.append({
            'category': 'application',
            'severity': 'high',
            'description': 'Overly permissive CORS configuration detected',
            'recommendation': 'Restrict Access-Control-Allow-Origin to specific trusted domains',
            'points': penalty,
        })

    # ── Exposed paths ─────────────────────────────────────────────────
    content = recon_data.get('content_discovery', {}) or {}
    discovered = content.get('findings', content.get('discovered_paths', []))
    if discovered and isinstance(discovered, list) and len(discovered) > 10:
        penalty = min((len(discovered) - 10) * 2, 15)
        score -= penalty
        deductions.append({
            'category': 'application',
            'severity': 'medium',
            'description': f'{len(discovered)} discoverable paths/files found',
            'recommendation': 'Restrict access to unnecessary files and disable directory listing',
            'points': penalty,
        })

    return max(score, 0), deductions


def _score_information(recon_data: dict) -> tuple:
    """
    Score information disclosure: tech fingerprinting, version leaks, emails.
    Returns (score 0-100, list of deduction dicts).
    """
    score = 100
    deductions = []

    # ── Technology disclosure ──────────────────────────────────────────
    techs = recon_data.get('technologies', {}) or {}
    tech_list = techs.get('technologies', techs.get('findings', []))

    versioned = 0
    for t in tech_list if isinstance(tech_list, list) else []:
        v = t.get('version', '') if isinstance(t, dict) else ''
        if v:
            versioned += 1

    if versioned > 0:
        penalty = min(versioned * 5, 20)
        score -= penalty
        deductions.append({
            'category': 'information',
            'severity': 'medium',
            'description': f'{versioned} technology version(s) publicly disclosed',
            'recommendation': 'Remove version information from Server headers, X-Powered-By, and generator meta tags',
            'points': penalty,
        })

    # ── Email exposure ─────────────────────────────────────────────────
    emails = recon_data.get('emails', recon_data.get('email_enum', {})) or {}
    email_list = emails.get('findings', emails.get('emails', []))
    if email_list and isinstance(email_list, list):
        penalty = min(len(email_list) * 3, 15)
        score -= penalty
        deductions.append({
            'category': 'information',
            'severity': 'medium',
            'description': f'{len(email_list)} email address(es) exposed',
            'recommendation': 'Use contact forms instead of publishing email addresses directly',
            'points': penalty,
        })

    # ── JS analysis (secrets, source maps) ─────────────────────────────
    js = recon_data.get('js_analysis', {}) or {}
    js_issues = js.get('findings', js.get('issues', []))
    if js_issues and isinstance(js_issues, list):
        penalty = min(len(js_issues) * 5, 20)
        score -= penalty
        deductions.append({
            'category': 'information',
            'severity': 'high',
            'description': f'{len(js_issues)} JavaScript security issue(s) found',
            'recommendation': 'Remove source maps, hardcoded secrets, and debug code from production JS',
            'points': penalty,
        })

    # ── Social media / OSINT exposure ──────────────────────────────────
    social = recon_data.get('social', recon_data.get('social_recon', {})) or {}
    social_findings = social.get('findings', [])
    if social_findings and isinstance(social_findings, list) and len(social_findings) > 5:
        score -= 5
        deductions.append({
            'category': 'information',
            'severity': 'low',
            'description': 'Extensive social media / OSINT footprint detected',
            'recommendation': 'Review public information for sensitive data that could aid social engineering',
            'points': 5,
        })

    return max(score, 0), deductions


def _score_network(recon_data: dict) -> tuple:
    """
    Score network security: open ports, DNS security, subdomains.
    Returns (score 0-100, list of deduction dicts).
    """
    score = 100
    deductions = []

    # ── Open ports ─────────────────────────────────────────────────────
    ports = recon_data.get('ports', {}) or {}
    open_ports = ports.get('findings', ports.get('open_ports', []))
    if isinstance(open_ports, list):
        non_standard = [
            p for p in open_ports
            if isinstance(p, dict) and p.get('port') not in (80, 443, None)
        ]
        if non_standard:
            penalty = min(len(non_standard) * 5, 25)
            score -= penalty
            deductions.append({
                'category': 'network',
                'severity': 'medium',
                'description': f'{len(non_standard)} non-standard port(s) open',
                'recommendation': 'Close unnecessary ports and restrict access via firewall rules',
                'points': penalty,
            })

    # ── DNS security ───────────────────────────────────────────────────
    dns = recon_data.get('dns', {}) or {}
    dns_findings = dns.get('findings', [])

    # Check for DNSSEC
    has_dnssec = False
    for df in dns_findings if isinstance(dns_findings, list) else []:
        if isinstance(df, dict) and 'dnssec' in str(df.get('type', '')).lower():
            has_dnssec = True
            break

    if not has_dnssec:
        score -= 10
        deductions.append({
            'category': 'network',
            'severity': 'medium',
            'description': 'DNSSEC not detected',
            'recommendation': 'Enable DNSSEC to protect against DNS spoofing attacks',
            'points': 10,
        })

    # Check for SPF/DMARC — dns_recon stores parsed results at dns['spf'] / dns['dmarc']
    # and raw TXT strings at dns['records']['txt']
    txt_records = (dns.get('records') or {}).get('txt', [])
    has_spf = bool(dns.get('spf')) or any('spf' in str(r).lower() for r in txt_records)
    has_dmarc = bool(dns.get('dmarc')) or any('dmarc' in str(r).lower() for r in txt_records)

    if not has_spf:
        score -= 8
        deductions.append({
            'category': 'network',
            'severity': 'medium',
            'description': 'No SPF record found',
            'recommendation': 'Add an SPF TXT record to prevent email spoofing',
            'points': 8,
        })

    if not has_dmarc:
        score -= 8
        deductions.append({
            'category': 'network',
            'severity': 'medium',
            'description': 'No DMARC record found',
            'recommendation': 'Add a DMARC TXT record to enforce email authentication policy',
            'points': 8,
        })

    # ── Subdomains ─────────────────────────────────────────────────────
    subs = recon_data.get('subdomains', {}) or {}
    sub_list = subs.get('findings', subs.get('subdomains', []))
    if isinstance(sub_list, list) and len(sub_list) > 20:
        score -= 10
        deductions.append({
            'category': 'network',
            'severity': 'low',
            'description': f'{len(sub_list)} subdomains discovered — large attack surface',
            'recommendation': 'Audit subdomains for unused services and consolidate where possible',
            'points': 10,
        })

    return max(score, 0), deductions


def _score_compliance(recon_data: dict) -> tuple:
    """
    Score compliance: HTTPS enforcement, HSTS, CT logs, security headers.
    Returns (score 0-100, list of deduction dicts).
    """
    score = 100
    deductions = []

    # ── HTTPS enforcement ──────────────────────────────────────────────
    cert = recon_data.get('certificate', {}) or {}
    if not cert.get('has_ssl'):
        score -= 30
        deductions.append({
            'category': 'compliance',
            'severity': 'critical',
            'description': 'HTTPS not enforced',
            'recommendation': 'Enable HTTPS and redirect all HTTP traffic to HTTPS',
            'points': 30,
        })

    # ── HSTS and other security headers ───────────────────────────────
    headers = recon_data.get('headers', {}) or {}
    # Build set of *missing* header names using the dedicated 'missing' list;
    # fall back to scanning findings for 'missing_header' type entries.
    missing_header_list = headers.get('missing', [])
    if missing_header_list and isinstance(missing_header_list, list):
        missing_hdr_names = {m.get('header', '').lower() for m in missing_header_list if isinstance(m, dict)}
    else:
        findings = headers.get('findings', headers.get('issues', []))
        missing_hdr_names = {
            f.get('header', '').lower()
            for f in (findings if isinstance(findings, list) else [])
            if isinstance(f, dict) and f.get('type') == 'missing_header'
        }

    if 'strict-transport-security' in missing_hdr_names:
        score -= 15
        deductions.append({
            'category': 'compliance',
            'severity': 'high',
            'description': 'HSTS (HTTP Strict Transport Security) not configured',
            'recommendation': 'Add Strict-Transport-Security header with includeSubDomains and preload',
            'points': 15,
        })

    # ── Certificate Transparency ───────────────────────────────────────
    ct = cert.get('ct_compliance')
    if ct is not None and not ct:
        score -= 10
        deductions.append({
            'category': 'compliance',
            'severity': 'medium',
            'description': 'Certificate Transparency compliance not verified',
            'recommendation': 'Use a CA that publishes to CT logs (e.g. Let\'s Encrypt, DigiCert)',
            'points': 10,
        })

    # ── Referrer-Policy ────────────────────────────────────────────────
    if 'referrer-policy' in missing_hdr_names:
        score -= 8
        deductions.append({
            'category': 'compliance',
            'severity': 'medium',
            'description': 'No Referrer-Policy header',
            'recommendation': 'Set Referrer-Policy to strict-origin-when-cross-origin',
            'points': 8,
        })

    # ── Permissions-Policy ─────────────────────────────────────────────
    if 'permissions-policy' in missing_hdr_names:
        score -= 8
        deductions.append({
            'category': 'compliance',
            'severity': 'low',
            'description': 'No Permissions-Policy header',
            'recommendation': 'Add Permissions-Policy to restrict browser feature access',
            'points': 8,
        })

    return max(score, 0), deductions


def _generate_recommendations(all_deductions: list) -> list:
    """Generate prioritized recommendations from all deductions."""
    severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

    sorted_deductions = sorted(
        all_deductions,
        key=lambda d: (severity_priority.get(d.get('severity', 'low'), 4), -d.get('points', 0)),
    )

    recommendations = []
    seen = set()
    for d in sorted_deductions:
        rec = d.get('recommendation', '')
        if rec and rec not in seen:
            seen.add(rec)
            recommendations.append({
                'priority': len(recommendations) + 1,
                'severity': d['severity'],
                'category': d['category'],
                'recommendation': rec,
                'impact_points': d.get('points', 0),
            })

    return recommendations


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_risk_scorer(target_url: str, recon_data: Optional[dict] = None) -> dict:
    """
    Compute aggregate security risk scores from all recon data.

    Args:
        target_url: The target URL being scanned.
        recon_data: Aggregated dict of all prior recon module results.

    Returns:
        Standardised result dict with legacy keys:
        ``overall_score``, ``overall_grade``, ``category_scores``,
        ``risk_level``, ``top_risks``, ``recommendations``, ``issues``.
    """
    start = time.time()
    result = create_result('risk_scorer', target_url)

    # Legacy keys
    result['overall_score'] = 0
    result['overall_grade'] = 'F'
    result['category_scores'] = {}
    result['risk_level'] = 'critical'
    result['top_risks'] = []
    result['recommendations'] = []
    result['issues'] = []

    if recon_data is None:
        recon_data = {}

    logger.info('Starting risk scoring for %s', target_url)

    all_deductions = []

    # ── Score each category ────────────────────────────────────────────
    scorers = {
        'infrastructure': _score_infrastructure,
        'application': _score_application,
        'information': _score_information,
        'network': _score_network,
        'compliance': _score_compliance,
    }

    for category, scorer_fn in scorers.items():
        result['stats']['total_checks'] += 1
        try:
            cat_score, cat_deductions = scorer_fn(recon_data)
            result['category_scores'][category] = {
                'score': cat_score,
                'grade': _grade_for_score(cat_score),
                'weight': CATEGORY_WEIGHTS[category],
                'deductions': len(cat_deductions),
            }
            all_deductions.extend(cat_deductions)

            for ded in cat_deductions:
                add_finding(result, {
                    'type': 'risk_deduction',
                    'category': category,
                    'severity': ded['severity'],
                    'description': ded['description'],
                    'recommendation': ded.get('recommendation', ''),
                    'points_deducted': ded.get('points', 0),
                })

            result['stats']['successful_checks'] += 1
            logger.debug('Category %s scored %d/100', category, cat_score)
        except Exception as exc:
            # Default to high-risk on failure
            result['category_scores'][category] = {
                'score': 50,
                'grade': 'D',
                'weight': CATEGORY_WEIGHTS[category],
                'deductions': 0,
                'error': str(exc),
            }
            result['stats']['failed_checks'] += 1
            result['errors'].append(f'{category} scoring error: {exc}')
            logger.error('Error scoring %s: %s', category, exc)

    # ── Compute weighted overall score ─────────────────────────────────
    try:
        weighted_sum = sum(
            result['category_scores'][cat]['score'] * CATEGORY_WEIGHTS[cat]
            for cat in CATEGORY_WEIGHTS
        )
        result['overall_score'] = round(weighted_sum)
        result['overall_grade'] = _grade_for_score(result['overall_score'])
        result['risk_level'] = _risk_level_for_score(result['overall_score'])
    except Exception as exc:
        logger.error('Weighted score calculation error: %s', exc)
        result['errors'].append(f'Score calculation: {exc}')

    # ── Generate top risks (highest impact deductions) ─────────────────
    severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    sorted_risks = sorted(
        all_deductions,
        key=lambda d: (severity_priority.get(d.get('severity', 'low'), 4), -d.get('points', 0)),
    )
    result['top_risks'] = [
        {
            'category': r['category'],
            'severity': r['severity'],
            'description': r['description'],
            'recommendation': r.get('recommendation', ''),
        }
        for r in sorted_risks[:10]
    ]

    # ── Generate prioritized recommendations ───────────────────────────
    result['recommendations'] = _generate_recommendations(all_deductions)

    # ── Populate legacy issues list ────────────────────────────────────
    for ded in all_deductions:
        result['issues'].append(
            f"{ded['severity'].upper()}: [{ded['category']}] {ded['description']}"
        )

    logger.info(
        'Risk scoring complete for %s — score %d/100, grade %s, level %s',
        target_url, result['overall_score'],
        result['overall_grade'], result['risk_level'],
    )

    return finalize_result(result, start)
