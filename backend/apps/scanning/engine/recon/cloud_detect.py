"""
Cloud Detection Module — Identify cloud hosting and services.

Detects: AWS, Azure, GCP, CloudFlare, DigitalOcean, Heroku, Vercel, Netlify,
and extracts cloud-specific metadata from headers, DNS, and response patterns.
Includes cloud storage bucket enumeration (S3, Azure Blob, GCS).
"""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Cloud Provider Signatures ──────────────────────────────────────────────

CLOUD_HEADER_SIGNATURES = {
    'AWS': {
        'patterns': {
            r'X-Amz-\w+': r'.+',
            r'x-amzn-\w+': r'.+',
            r'X-Amz-Cf-Id': r'.+',
            r'X-Amz-Request-Id': r'.+',
        },
        'server': [r'AmazonS3', r'amazon', r'awselb'],
    },
    'Azure': {
        'patterns': {
            r'X-Azure-\w+': r'.+',
            r'X-MS-\w+': r'.+',
            r'X-Powered-By': r'ASP\.NET|Azure',
        },
        'server': [r'Microsoft-IIS', r'Microsoft-Azure', r'Windows-Azure'],
    },
    'GCP': {
        'patterns': {
            r'X-Cloud-Trace-Context': r'.+',
            r'X-GFE-\w+': r'.+',
            r'X-Google-\w+': r'.+',
            r'X-Goog-\w+': r'.+',
        },
        'server': [r'gws', r'Google Frontend', r'GSE'],
    },
    'Cloudflare': {
        'patterns': {
            r'CF-RAY': r'.+',
            r'CF-Cache-Status': r'.+',
            r'cf-request-id': r'.+',
        },
        'server': [r'cloudflare'],
    },
    'Vercel': {
        'patterns': {
            r'X-Vercel-\w+': r'.+',
            r'X-Vercel-Id': r'.+',
        },
        'server': [r'Vercel'],
    },
    'Netlify': {
        'patterns': {
            r'X-NF-\w+': r'.+',
            r'X-Netlify-\w+': r'.+',
        },
        'server': [r'Netlify'],
    },
    'Heroku': {
        'patterns': {
            r'Via': r'vegur',
            r'X-Request-Id': r'.+',
        },
        'server': [r'heroku'],
    },
    'DigitalOcean': {
        'patterns': {
            r'X-DO-\w+': r'.+',
        },
        'server': [r'digitalocean'],
    },
    'Fastly': {
        'patterns': {
            r'X-Fastly-\w+': r'.+',
            r'Fastly-Debug-\w+': r'.+',
            r'X-Served-By': r'cache-',
        },
        'server': [r'Fastly'],
    },
}

# ── CDN Signatures ─────────────────────────────────────────────────────────

CDN_SIGNATURES = {
    'Cloudflare': {'headers': [r'CF-RAY', r'CF-Cache-Status'], 'server': r'cloudflare'},
    'Fastly': {'headers': [r'X-Fastly-Request-ID', r'Fastly-Debug-Digest'], 'server': r'Fastly'},
    'Akamai': {'headers': [r'X-Akamai-\w+', r'X-True-Cache-Key'], 'server': r'AkamaiGHost'},
    'AWS CloudFront': {'headers': [r'X-Amz-Cf-Id', r'X-Amz-Cf-Pop'], 'server': r'CloudFront'},
    'Azure CDN': {'headers': [r'X-Azure-Ref', r'X-EC-\w+'], 'server': ''},
    'Google Cloud CDN': {'headers': [r'X-GFE-\w+'], 'server': r'gws'},
    'KeyCDN': {'headers': [r'X-Pull', r'X-Edge-Location'], 'server': r'keycdn'},
    'StackPath': {'headers': [r'X-HW', r'X-SP-\w+'], 'server': r'StackPath'},
}

# ── DNS CNAME Patterns ─────────────────────────────────────────────────────

CNAME_CLOUD_PATTERNS = {
    r'\.amazonaws\.com$': 'AWS',
    r'\.elb\.amazonaws\.com$': 'AWS (ELB)',
    r'\.s3\.amazonaws\.com$': 'AWS (S3)',
    r'\.cloudfront\.net$': 'AWS (CloudFront)',
    r'\.azurewebsites\.net$': 'Azure (App Service)',
    r'\.azure-api\.net$': 'Azure (API Management)',
    r'\.azureedge\.net$': 'Azure (CDN)',
    r'\.blob\.core\.windows\.net$': 'Azure (Blob Storage)',
    r'\.trafficmanager\.net$': 'Azure (Traffic Manager)',
    r'\.cloudapp\.azure\.com$': 'Azure (Cloud App)',
    r'\.appspot\.com$': 'GCP (App Engine)',
    r'\.run\.app$': 'GCP (Cloud Run)',
    r'\.cloudfunctions\.net$': 'GCP (Cloud Functions)',
    r'\.storage\.googleapis\.com$': 'GCP (Cloud Storage)',
    r'\.herokuapp\.com$': 'Heroku',
    r'\.vercel\.app$': 'Vercel',
    r'\.netlify\.app$': 'Netlify',
    r'\.netlify\.com$': 'Netlify',
    r'\.digitaloceanspaces\.com$': 'DigitalOcean (Spaces)',
    r'\.ondigitalocean\.app$': 'DigitalOcean (App Platform)',
    r'\.firebaseapp\.com$': 'Firebase',
    r'\.web\.app$': 'Firebase',
    r'\.pages\.dev$': 'Cloudflare Pages',
    r'\.workers\.dev$': 'Cloudflare Workers',
    r'\.render\.com$': 'Render',
    r'\.fly\.dev$': 'Fly.io',
    r'\.railway\.app$': 'Railway',
}

# ── Takeover Risk Patterns ─────────────────────────────────────────────────

TAKEOVER_RISK_CNAMES = [
    r'\.s3\.amazonaws\.com$',
    r'\.herokuapp\.com$',
    r'\.azurewebsites\.net$',
    r'\.cloudapp\.azure\.com$',
    r'\.trafficmanager\.net$',
    r'\.blob\.core\.windows\.net$',
    r'\.netlify\.app$',
    r'\.ghost\.io$',
    r'\.surge\.sh$',
    r'\.firebaseapp\.com$',
    r'\.appspot\.com$',
    r'\.fly\.dev$',
    r'\.unbouncepages\.com$',
]

# ── Serverless Indicators ──────────────────────────────────────────────────

SERVERLESS_INDICATORS = {
    'AWS Lambda': {
        'headers': [r'X-Amzn-Trace-Id', r'X-Amz-Apigw-Id'],
        'cnames': [r'\.execute-api\.\w+-\w+-\d\.amazonaws\.com$'],
    },
    'Azure Functions': {
        'headers': [r'X-Azure-Functions-\w+', r'X-Powered-By.*Azure Functions'],
        'cnames': [r'\.azurewebsites\.net$'],
    },
    'GCP Cloud Functions': {
        'headers': [r'Function-Execution-Id'],
        'cnames': [r'\.cloudfunctions\.net$'],
    },
    'Vercel Serverless': {
        'headers': [r'X-Vercel-Id'],
        'cnames': [r'\.vercel\.app$'],
    },
    'Netlify Functions': {
        'headers': [r'X-NF-Request-ID'],
        'cnames': [r'\.netlify\.app$'],
    },
}


# ── Internal Helpers ───────────────────────────────────────────────────────

def _check_headers_for_cloud(headers: dict) -> list[dict]:
    """Match response headers against cloud provider signatures."""
    services = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for provider, sigs in CLOUD_HEADER_SIGNATURES.items():
        score = 0
        evidence = []

        # Check header name/value patterns
        for hdr_pattern, val_pattern in sigs.get('patterns', {}).items():
            for hdr_name, hdr_val in headers.items():
                if re.search(hdr_pattern, hdr_name, re.IGNORECASE):
                    if re.search(val_pattern, str(hdr_val), re.IGNORECASE):
                        score += 1
                        evidence.append(f'Header {hdr_name}: {hdr_val}')

        # Check Server header
        server_val = headers_lower.get('server', '')
        for pattern in sigs.get('server', []):
            if re.search(pattern, server_val, re.IGNORECASE):
                score += 2
                evidence.append(f'Server header matches: {server_val}')

        if score > 0:
            confidence = 'high' if score >= 3 else 'medium' if score >= 2 else 'low'
            services.append({
                'name': provider,
                'confidence': confidence,
                'evidence': evidence,
                'score': score,
            })

    return services


def _check_dns_for_cloud(dns_results: dict) -> list[dict]:
    """Inspect DNS records for cloud provider indicators."""
    services = []
    cnames = dns_results.get('records', {}).get('cname', [])
    dns_results.get('ip_addresses', [])

    for cname in cnames:
        cname_lower = cname.lower()
        for pattern, provider in CNAME_CLOUD_PATTERNS.items():
            if re.search(pattern, cname_lower):
                services.append({
                    'name': provider,
                    'confidence': 'high',
                    'evidence': [f'CNAME record: {cname}'],
                })

    return services


def _detect_cdn(headers: dict) -> str | None:
    """Identify the CDN from response headers."""
    headers_lower = {k.lower(): v for k, v in headers.items()}
    server_val = headers_lower.get('server', '')

    for cdn_name, sigs in CDN_SIGNATURES.items():
        # Check specific headers
        for hdr_pattern in sigs.get('headers', []):
            for hdr_name in headers:
                if re.search(hdr_pattern, hdr_name, re.IGNORECASE):
                    return cdn_name

        # Check Server header
        if sigs.get('server') and re.search(sigs['server'], server_val, re.IGNORECASE):
            return cdn_name

    return None


def _detect_serverless(headers: dict, dns_results: dict) -> list[dict]:
    """Detect serverless platform usage."""
    detected = []

    for platform, indicators in SERVERLESS_INDICATORS.items():
        evidence = []

        # Check headers
        for hdr_pattern in indicators.get('headers', []):
            for hdr_name, hdr_val in headers.items():
                if re.search(hdr_pattern, f'{hdr_name}: {hdr_val}', re.IGNORECASE):
                    evidence.append(f'Header {hdr_name}')

        # Check CNAME records
        cnames = dns_results.get('records', {}).get('cname', [])
        for cname in cnames:
            for cn_pattern in indicators.get('cnames', []):
                if re.search(cn_pattern, cname, re.IGNORECASE):
                    evidence.append(f'CNAME {cname}')

        if evidence:
            detected.append({
                'platform': platform,
                'evidence': evidence,
            })

    return detected


def _check_takeover_risk(dns_results: dict) -> list[dict]:
    """Flag dangling CNAMEs that may be vulnerable to subdomain takeover."""
    risks = []
    cnames = dns_results.get('records', {}).get('cname', [])
    # nxdomain_cnames is never populated by dns_recon; treat all pattern matches as low-risk
    nxdomain: list = []

    for cname in cnames:
        cname_lower = cname.lower()
        for pattern in TAKEOVER_RISK_CNAMES:
            if re.search(pattern, cname_lower):
                is_dangling = cname in nxdomain
                risks.append({
                    'cname': cname,
                    'risk': 'high' if is_dangling else 'low',
                    'dangling': is_dangling,
                    'detail': (
                        f'CNAME {cname} points to a takeover-prone service'
                        + (' and appears to be dangling (NXDOMAIN)' if is_dangling else '')
                    ),
                })

    return risks


# ── Bucket Enumeration ─────────────────────────────────────────────────────

# Bucket name permutations to try for a given domain
_BUCKET_SUFFIXES = [
    '', '-assets', '-backup', '-backups', '-cdn', '-content', '-data',
    '-dev', '-development', '-files', '-images', '-logs', '-media',
    '-private', '-prod', '-production', '-public', '-staging', '-static',
    '-storage', '-test', '-uploads', '-web',
]

_BUCKET_ENDPOINTS: list[tuple[str, str, str]] = [
    # (url_template, provider, check_method)
    # {bucket} will be replaced with the candidate name
    ('https://{bucket}.s3.amazonaws.com', 'AWS S3', 'head'),
    ('https://s3.amazonaws.com/{bucket}', 'AWS S3 (path-style)', 'head'),
    ('https://{bucket}.blob.core.windows.net', 'Azure Blob', 'head'),
    ('https://storage.googleapis.com/{bucket}', 'GCS', 'head'),
    ('https://{bucket}.storage.googleapis.com', 'GCS (subdomain)', 'head'),
]


def _enumerate_buckets(domain: str) -> list[dict]:
    """Try common bucket name permutations for the domain.

    Returns a list of dicts with keys: name, provider, status, public.
    Only returns buckets that actually exist (non-404).
    """
    # Strip TLD and www to get base name(s)
    parts = domain.lower().replace('www.', '').split('.')
    base_names = set()
    # e.g., "example" from "example.com"
    if parts:
        base_names.add(parts[0])
    # e.g., "example-com"
    if len(parts) >= 2:
        base_names.add(f'{parts[0]}-{parts[1]}')
        base_names.add(f'{parts[0]}.{parts[1]}')

    candidates = []
    for base in base_names:
        for suffix in _BUCKET_SUFFIXES:
            candidates.append(f'{base}{suffix}')

    results: list[dict] = []
    seen: set[str] = set()

    def _check_bucket(bucket_name: str, url_template: str, provider: str) -> dict | None:
        url = url_template.format(bucket=bucket_name)
        req = Request(url, method='HEAD')
        req.add_header('User-Agent', 'Mozilla/5.0 (compatible; SafeWebAI/1.0)')
        try:
            resp = urlopen(req, timeout=5)  # noqa: S310
            code = resp.getcode()
            if code and code < 400:
                return {
                    'name': bucket_name,
                    'provider': provider,
                    'url': url,
                    'status': code,
                    'public': True,
                }
        except HTTPError as exc:
            code = exc.code
            # 403 = exists but not public; 404 = not found
            if code == 403:
                return {
                    'name': bucket_name,
                    'provider': provider,
                    'url': url,
                    'status': 403,
                    'public': False,
                }
            # Any other non-404 = exists
            if code != 404:
                return {
                    'name': bucket_name,
                    'provider': provider,
                    'url': url,
                    'status': code,
                    'public': False,
                }
        except (URLError, OSError):
            pass
        return None

    futures = {}
    with ThreadPoolExecutor(max_workers=15) as pool:
        for cand in candidates:
            for url_tpl, provider, _ in _BUCKET_ENDPOINTS:
                key = f'{provider}:{cand}'
                if key in seen:
                    continue
                seen.add(key)
                futures[pool.submit(_check_bucket, cand, url_tpl, provider)] = key

        for future in as_completed(futures, timeout=30):
            try:
                hit = future.result()
                if hit:
                    results.append(hit)
            except Exception:
                pass

    return results


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_cloud_detect(
    target_url: str,
    response_headers: dict = None,
    dns_results: dict = None,
) -> dict:
    """Detect cloud hosting provider, CDN, and serverless platform usage.

    Args:
        target_url:       The target URL being scanned.
        response_headers: HTTP response headers dict (optional).
        dns_results:      DNS lookup results dict with keys like
                          ``cnames``, ``a_records``, ``nxdomain_cnames``
                          (optional).

    Returns:
        Standardised result dict with legacy keys:
        ``provider``, ``services``, ``cdn``, ``is_cloud``, ``issues``.
    """
    start = time.time()
    result = create_result('cloud_detect', target_url)

    # ── Legacy keys ──
    result['provider'] = None
    result['services'] = []
    result['cdn'] = None
    result['is_cloud'] = False
    result['buckets'] = []

    headers = response_headers or {}
    dns = dns_results or {}

    # ── 1. Header-based cloud detection ──
    if headers:
        result['stats']['total_checks'] += 1
        try:
            header_services = _check_headers_for_cloud(headers)
            result['stats']['successful_checks'] += 1

            for svc in header_services:
                result['services'].append(svc)
                add_finding(result, {
                    'type': 'cloud_provider_detected',
                    'provider': svc['name'],
                    'confidence': svc['confidence'],
                    'evidence': svc['evidence'],
                    'source': 'headers',
                })
        except Exception as exc:
            result['errors'].append(f'Header cloud check failed: {exc}')
            logger.debug('Header cloud check error: %s', exc, exc_info=True)

    # ── 2. DNS-based cloud detection ──
    if dns:
        result['stats']['total_checks'] += 1
        try:
            dns_services = _check_dns_for_cloud(dns)
            result['stats']['successful_checks'] += 1

            for svc in dns_services:
                result['services'].append(svc)
                add_finding(result, {
                    'type': 'cloud_provider_detected',
                    'provider': svc['name'],
                    'confidence': svc['confidence'],
                    'evidence': svc['evidence'],
                    'source': 'dns',
                })
        except Exception as exc:
            result['errors'].append(f'DNS cloud check failed: {exc}')
            logger.debug('DNS cloud check error: %s', exc, exc_info=True)

    # ── 3. CDN detection ──
    if headers:
        result['stats']['total_checks'] += 1
        try:
            cdn = _detect_cdn(headers)
            result['stats']['successful_checks'] += 1
            if cdn:
                result['cdn'] = cdn
                add_finding(result, {
                    'type': 'cdn_detected',
                    'cdn': cdn,
                    'source': 'headers',
                })
        except Exception as exc:
            result['errors'].append(f'CDN detection failed: {exc}')
            logger.debug('CDN detection error: %s', exc, exc_info=True)

    # ── 4. Serverless detection ──
    result['stats']['total_checks'] += 1
    try:
        serverless = _detect_serverless(headers, dns)
        result['stats']['successful_checks'] += 1
        for sless in serverless:
            add_finding(result, {
                'type': 'serverless_detected',
                'platform': sless['platform'],
                'evidence': sless['evidence'],
            })
    except Exception as exc:
        result['errors'].append(f'Serverless detection failed: {exc}')
        logger.debug('Serverless detection error: %s', exc, exc_info=True)

    # ── 5. Takeover risk assessment ──
    if dns:
        result['stats']['total_checks'] += 1
        try:
            risks = _check_takeover_risk(dns)
            result['stats']['successful_checks'] += 1
            for risk in risks:
                severity = 'critical' if risk['dangling'] else 'info'
                add_finding(result, {
                    'type': 'takeover_risk',
                    'cname': risk['cname'],
                    'risk_level': risk['risk'],
                    'dangling': risk['dangling'],
                    'detail': risk['detail'],
                })
                result['issues'].append({
                    'severity': severity,
                    'title': 'Subdomain takeover risk',
                    'detail': risk['detail'],
                })
        except Exception as exc:
            result['errors'].append(f'Takeover risk check failed: {exc}')
            logger.debug('Takeover risk check error: %s', exc, exc_info=True)

    # ── 6. Bucket enumeration ──
    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname) if hostname else ''
    if root_domain:
        result['stats']['total_checks'] += 1
        try:
            buckets = _enumerate_buckets(root_domain)
            result['stats']['successful_checks'] += 1
            result['buckets'] = buckets
            for bucket in buckets:
                severity = 'critical' if bucket.get('public') else 'medium'
                add_finding(result, {
                    'type': 'cloud_bucket_found',
                    'name': bucket['name'],
                    'provider': bucket['provider'],
                    'url': bucket.get('url', ''),
                    'public': bucket.get('public', False),
                    'status': bucket.get('status'),
                    'severity': severity,
                })
                if bucket.get('public'):
                    result['issues'].append({
                        'severity': 'critical',
                        'title': f'Publicly accessible {bucket["provider"]} bucket',
                        'detail': f'Bucket "{bucket["name"]}" at {bucket.get("url")} is publicly accessible',
                    })
        except Exception as exc:
            result['errors'].append(f'Bucket enumeration failed: {exc}')
            logger.debug('Bucket enumeration error: %s', exc, exc_info=True)

    # ── Determine primary provider ──
    if result['services']:
        result['is_cloud'] = True
        # Pick the highest-confidence service as primary provider
        best = max(result['services'], key=lambda s: s.get('score', 0))
        result['provider'] = best['name']

    logger.info(
        'Cloud detection complete for %s — provider=%s, cdn=%s, services=%d',
        target_url, result['provider'], result['cdn'], len(result['services']),
    )

    return finalize_result(result, start)
