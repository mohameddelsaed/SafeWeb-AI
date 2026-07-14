"""
Cloud Asset Discovery — Phase 36 enhancements.

New capabilities:
  - S3 bucket discovery from domain naming patterns
  - Azure Blob Storage enumeration
  - GCP bucket discovery
  - CloudFront / CDN origin hunting
  - Cloud function / Lambda endpoint discovery
  - Kubernetes / container registry detection
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# S3 Bucket Pattern Discovery
# ────────────────────────────────────────────────────────────────────────────

S3_BUCKET_PATTERNS = [
    '{domain}',
    '{name}',
    '{name}-assets',
    '{name}-static',
    '{name}-media',
    '{name}-uploads',
    '{name}-backup',
    '{name}-backups',
    '{name}-data',
    '{name}-dev',
    '{name}-staging',
    '{name}-prod',
    '{name}-production',
    '{name}-test',
    '{name}-public',
    '{name}-private',
    '{name}-logs',
    '{name}-cdn',
    '{name}-web',
    '{name}-images',
    '{name}-files',
    '{name}-docs',
    '{name}-archive',
    '{name}-config',
]

S3_URL_FORMATS = [
    'https://{bucket}.s3.amazonaws.com',
    'https://{bucket}.s3.us-east-1.amazonaws.com',
    'https://s3.amazonaws.com/{bucket}',
]


def generate_s3_candidates(domain: str) -> list[dict[str, str]]:
    """Generate potential S3 bucket names from a domain.

    Returns list of {bucket, url} dicts.
    """
    name = domain.split('.')[0]
    candidates: list[dict[str, str]] = []
    seen_buckets: set[str] = set()

    for pattern in S3_BUCKET_PATTERNS:
        bucket = pattern.replace('{domain}', domain.replace('.', '-'))
        bucket = bucket.replace('{name}', name)
        bucket = bucket.lower().strip('-')

        if bucket in seen_buckets or not bucket:
            continue
        seen_buckets.add(bucket)

        url = S3_URL_FORMATS[0].replace('{bucket}', bucket)
        candidates.append({'bucket': bucket, 'url': url})

    return candidates


# ────────────────────────────────────────────────────────────────────────────
# Azure Blob Enumeration
# ────────────────────────────────────────────────────────────────────────────

AZURE_BLOB_PATTERNS = [
    '{name}',
    '{name}storage',
    '{name}store',
    '{name}blob',
    '{name}data',
    '{name}assets',
    '{name}static',
    '{name}backup',
    '{name}dev',
    '{name}staging',
    '{name}prod',
    '{name}files',
    '{name}media',
    '{name}cdn',
    '{name}web',
]

AZURE_CONTAINER_NAMES = [
    '$web', 'assets', 'static', 'media', 'uploads',
    'images', 'files', 'data', 'backup', 'public',
    'logs', 'config', 'content', 'documents',
]


def generate_azure_candidates(domain: str) -> list[dict[str, str]]:
    """Generate potential Azure Blob Storage account names.

    Returns list of {account, container, url}.
    """
    name = domain.split('.')[0]
    # Azure storage accounts: 3-24 chars, lowercase alphanumeric only
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()

    for pattern in AZURE_BLOB_PATTERNS:
        account = pattern.replace('{name}', name)
        account = re.sub(r'[^a-z0-9]', '', account.lower())
        if len(account) < 3 or len(account) > 24:
            continue
        if account in seen:
            continue
        seen.add(account)

        for container in AZURE_CONTAINER_NAMES[:5]:
            url = f'https://{account}.blob.core.windows.net/{container}?restype=container&comp=list'
            candidates.append({
                'account': account,
                'container': container,
                'url': url,
            })

    return candidates


# ────────────────────────────────────────────────────────────────────────────
# GCP Bucket Discovery
# ────────────────────────────────────────────────────────────────────────────

GCP_BUCKET_PATTERNS = [
    '{name}',
    '{name}-bucket',
    '{name}-assets',
    '{name}-static',
    '{name}-backup',
    '{name}-data',
    '{name}-dev',
    '{name}-staging',
    '{name}-prod',
    '{name}-public',
    '{name}-uploads',
    '{domain}',
    'staging.{domain}',
]


def generate_gcp_candidates(domain: str) -> list[dict[str, str]]:
    """Generate potential GCP bucket names.

    Returns list of {bucket, url}.
    """
    name = domain.split('.')[0]
    candidates: list[dict[str, str]] = []
    seen: set[str] = set()

    for pattern in GCP_BUCKET_PATTERNS:
        bucket = pattern.replace('{name}', name)
        bucket = bucket.replace('{domain}', domain)
        bucket = bucket.lower()

        if bucket in seen or not bucket:
            continue
        seen.add(bucket)

        url = f'https://storage.googleapis.com/{bucket}'
        candidates.append({'bucket': bucket, 'url': url})

    return candidates


# ────────────────────────────────────────────────────────────────────────────
# CloudFront / CDN Origin Hunting
# ────────────────────────────────────────────────────────────────────────────

CDN_ORIGIN_PATTERNS = {
    'cloudfront': re.compile(r'[a-z0-9]+\.cloudfront\.net', re.I),
    'azure_cdn': re.compile(r'[a-z0-9-]+\.azureedge\.net', re.I),
    'fastly': re.compile(r'[a-z0-9-]+\.fastly\.net', re.I),
    'akamai': re.compile(r'[a-z0-9-]+\.akamaized\.net', re.I),
    'cloudflare': re.compile(r'[a-z0-9-]+\.cdn\.cloudflare\.net', re.I),
    'gcp_cdn': re.compile(r'[a-z0-9-]+\.storage\.googleapis\.com', re.I),
}

ORIGIN_DISCOVERY_HEADERS = [
    'X-Forwarded-Host',
    'X-Host',
    'X-Original-URL',
    'X-Rewrite-URL',
    'Host',
]


def detect_cdn_origin_from_cnames(cnames: list[str]) -> list[dict[str, str]]:
    """Identify CDN providers from CNAME chains.

    Returns list of {provider, cname}.
    """
    results: list[dict[str, str]] = []
    for cname in cnames:
        for provider, pattern in CDN_ORIGIN_PATTERNS.items():
            if pattern.search(cname):
                results.append({'provider': provider, 'cname': cname})
                break
    return results


def generate_origin_bypass_tests(domain: str) -> list[dict[str, str]]:
    """Generate header-based origin bypass test payloads.

    Returns list of {header, value, purpose}.
    """
    tests: list[dict[str, str]] = []
    for header in ORIGIN_DISCOVERY_HEADERS:
        tests.append({
            'header': header,
            'value': domain,
            'purpose': f'Origin discovery via {header} header manipulation',
        })
    return tests


# ────────────────────────────────────────────────────────────────────────────
# Cloud Function / Lambda Endpoint Discovery
# ────────────────────────────────────────────────────────────────────────────

LAMBDA_URL_PATTERNS = {
    'aws_lambda': re.compile(
        r'https?://[a-z0-9]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com', re.I
    ),
    'aws_lambda_url': re.compile(
        r'https?://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws', re.I
    ),
    'azure_function': re.compile(
        r'https?://[a-z0-9-]+\.azurewebsites\.net/api/', re.I
    ),
    'gcp_function': re.compile(
        r'https?://[a-z0-9-]+-[a-z0-9]+\.cloudfunctions\.net', re.I
    ),
    'gcp_cloud_run': re.compile(
        r'https?://[a-z0-9-]+\.run\.app', re.I
    ),
    'vercel_serverless': re.compile(
        r'https?://[a-z0-9-]+\.vercel\.app/api/', re.I
    ),
    'netlify_function': re.compile(
        r'https?://[a-z0-9-]+\.netlify\.app/\.netlify/functions/', re.I
    ),
}

COMMON_FUNCTION_PATHS = [
    '/api/', '/api/v1/', '/api/v2/',
    '/.netlify/functions/',
    '/api/serverless/',
    '/prod/', '/staging/', '/dev/',
    '/.well-known/',
]


def detect_serverless_endpoints(urls: list[str]) -> list[dict[str, str]]:
    """Identify serverless/cloud function endpoints from a list of URLs.

    Returns list of {url, provider, pattern_matched}.
    """
    results: list[dict[str, str]] = []
    for url in urls:
        for provider, pattern in LAMBDA_URL_PATTERNS.items():
            if pattern.search(url):
                results.append({
                    'url': url,
                    'provider': provider,
                    'pattern_matched': pattern.pattern,
                })
                break
    return results


def generate_function_candidates(domain: str) -> list[dict[str, str]]:
    """Generate potential serverless function endpoint URLs.

    Returns list of {url, type}.
    """
    name = domain.split('.')[0]
    candidates: list[dict[str, str]] = []

    # Azure Functions
    candidates.append({
        'url': f'https://{name}.azurewebsites.net/api/',
        'type': 'azure_function',
    })
    candidates.append({
        'url': f'https://{name}-func.azurewebsites.net/api/',
        'type': 'azure_function',
    })

    # GCP Cloud Run
    candidates.append({
        'url': f'https://{name}.run.app',
        'type': 'gcp_cloud_run',
    })

    # Vercel
    candidates.append({
        'url': f'https://{name}.vercel.app/api/',
        'type': 'vercel_serverless',
    })

    return candidates


# ────────────────────────────────────────────────────────────────────────────
# Container Registry Detection
# ────────────────────────────────────────────────────────────────────────────

REGISTRY_PATTERNS = {
    'dockerhub': re.compile(r'docker\.io|hub\.docker\.com', re.I),
    'ecr': re.compile(r'[0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com', re.I),
    'acr': re.compile(r'[a-z0-9]+\.azurecr\.io', re.I),
    'gcr': re.compile(r'gcr\.io|[a-z]+-docker\.pkg\.dev', re.I),
    'ghcr': re.compile(r'ghcr\.io', re.I),
    'quay': re.compile(r'quay\.io', re.I),
}


def detect_container_registries(urls: list[str]) -> list[dict[str, str]]:
    """Detect container registry references in URLs / text.

    Returns list of {url, registry, type}.
    """
    results: list[dict[str, str]] = []
    for url in urls:
        for reg_type, pattern in REGISTRY_PATTERNS.items():
            if pattern.search(url):
                results.append({
                    'url': url,
                    'registry': reg_type,
                    'type': 'container_registry',
                })
                break
    return results


# ────────────────────────────────────────────────────────────────────────────
# Aggregator: run full cloud asset discovery
# ────────────────────────────────────────────────────────────────────────────

def run_cloud_asset_discovery(domain: str, depth: str = 'medium',
                              cnames: list[str] | None = None,
                              discovered_urls: list[str] | None = None) -> dict[str, Any]:
    """Orchestrate all cloud asset discovery methods.

    Returns {s3, azure, gcp, cdn_origins, serverless, registries, stats}.
    """
    start = time.time()
    cnames = cnames or []
    discovered_urls = discovered_urls or []

    result: dict[str, Any] = {
        's3_candidates': [],
        'azure_candidates': [],
        'gcp_candidates': [],
        'cdn_origins': [],
        'serverless_endpoints': [],
        'function_candidates': [],
        'container_registries': [],
        'origin_bypass_tests': [],
        'stats': {
            'total_candidates': 0,
            'duration': 0.0,
        },
    }

    # S3 discovery
    result['s3_candidates'] = generate_s3_candidates(domain)

    if depth in ('medium', 'deep'):
        # Azure + GCP
        result['azure_candidates'] = generate_azure_candidates(domain)
        result['gcp_candidates'] = generate_gcp_candidates(domain)

        # CDN origins from CNAME chains
        result['cdn_origins'] = detect_cdn_origin_from_cnames(cnames)

        # Serverless detection
        result['serverless_endpoints'] = detect_serverless_endpoints(discovered_urls)
        result['function_candidates'] = generate_function_candidates(domain)

    if depth == 'deep':
        # Container registries
        result['container_registries'] = detect_container_registries(discovered_urls)

        # Origin bypass tests
        result['origin_bypass_tests'] = generate_origin_bypass_tests(domain)

    total = (len(result['s3_candidates']) + len(result['azure_candidates']) +
             len(result['gcp_candidates']) + len(result['function_candidates']))
    result['stats']['total_candidates'] = total
    result['stats']['duration'] = round(time.time() - start, 3)

    return result
