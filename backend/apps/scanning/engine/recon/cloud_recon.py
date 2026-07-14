"""
Cloud Recon — Cloud Storage & Infrastructure Enumeration.

Benchmarks: cloud_enum, S3Scanner, AWSBucketDump, GCPBucketBrute,
            CloudScraper, Prowler.

Actively discovers and checks cloud storage resources associated with
the target domain:
  - AWS S3 buckets
  - Azure Blob Storage accounts
  - Google Cloud Storage buckets
  - CloudFront / Azure CDN / CloudFlare origins
  - Publicly accessible cloud function / lambda endpoints

Distinct from ``cloud_detect.py`` (which fingerprints cloud providers
from response headers/DNS).  This module does *active enumeration* —
generating candidate resource names and probing them directly.

Depth tiering:
  shallow — 20 candidate names (core patterns only)
  medium  — 80 candidate names (+ env suffixes, word variations)
  deep    — 200+ candidate names (full combo matrix)
"""
from __future__ import annotations

import logging
import re
import time
from typing import Callable, Optional

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Candidate generation ──────────────────────────────────────────────────

# Common affixes added to the company name to generate bucket names
_PREFIXES = [
    '', 'www-', 'web-', 'app-', 'api-', 'cdn-', 'static-',
    'dev-', 'prod-', 'staging-', 'test-', 'qa-',
    'img-', 'media-', 'files-', 'data-', 'backup-',
    's3-', 'blob-', 'storage-', 'assets-',
]
_SUFFIXES = [
    '', '-backup', '-backups', '-bak', '-dev', '-development',
    '-staging', '-stage', '-stg', '-prod', '-production',
    '-test', '-qa', '-uat', '-data', '-db', '-database',
    '-assets', '-asset', '-static', '-media', '-uploads', '-upload',
    '-files', '-file', '-docs', '-download', '-downloads',
    '-public', '-private', '-internal', '-external',
    '-logs', '-log', '-config', '-configs',
    '-archive', '-old', '-legacy', '-new',
    '2', '2024', '2025',
    # Tech company naming patterns
    '-images', '-img', '-content', '-storage', '-store',
    '-webapp', '-frontend', '-backend', '-mobile', '-web',
    '-artifacts', '-builds', '-release', '-releases',
    '-raw', '-processed', '-temp', '-tmp', '-cache',
    '-secure', '-shared', '-sync', '-mirror',
    '-cdn', '-bucket', '-repo',
]

_SHALLOW_AFFIXES = _PREFIXES[:3] + _SUFFIXES[:6]    # ~20 names
_MEDIUM_AFFIXES  = _PREFIXES[:5] + _SUFFIXES[:16]   # ~80 names
_DEEP_AFFIXES    = _PREFIXES + _SUFFIXES             # full matrix

# ── Provider-specific probing ─────────────────────────────────────────────

_PROVIDERS: dict[str, dict] = {
    'aws_s3': {
        'template':       'https://{name}.s3.amazonaws.com/',
        'list_template':  'https://{name}.s3.amazonaws.com/?max-keys=5',
        'display':        'AWS S3',
    },
    'aws_s3_path': {
        'template':       'https://s3.amazonaws.com/{name}/',
        'list_template':  'https://s3.amazonaws.com/{name}/?max-keys=5',
        'display':        'AWS S3 (path-style)',
    },
    'azure_blob': {
        'template':       'https://{name}.blob.core.windows.net/',
        'list_template':  (
            'https://{name}.blob.core.windows.net/'
            '?restype=container&comp=list&maxresults=5'
        ),
        'display':        'Azure Blob Storage',
    },
    'gcp_storage': {
        'template':       'https://storage.googleapis.com/{name}/',
        'list_template':  'https://storage.googleapis.com/{name}/?max-keys=5',
        'display':        'Google Cloud Storage',
    },
    'digitalocean': {
        'template':       'https://{name}.nyc3.digitaloceanspaces.com/',
        'list_template':  'https://{name}.nyc3.digitaloceanspaces.com/?max-keys=5',
        'display':        'DigitalOcean Spaces',
    },
    'wasabi': {
        'template':       'https://s3.wasabisys.com/{name}/',
        'list_template':  'https://s3.wasabisys.com/{name}/?max-keys=5',
        'display':        'Wasabi Cloud Storage',
    },
    'linode': {
        'template':       'https://{name}.us-east-1.linodeobjects.com/',
        'list_template':  'https://{name}.us-east-1.linodeobjects.com/?max-keys=5',
        'display':        'Linode Object Storage',
    },
    'azure_static_web': {
        'template':       'https://{name}.z13.web.core.windows.net/',
        'list_template':  'https://{name}.z13.web.core.windows.net/',
        'display':        'Azure Static Website',
    },
    'azure_functions': {
        'template':       'https://{name}.azurewebsites.net/',
        'list_template':  'https://{name}.azurewebsites.net/api/',
        'display':        'Azure App Service / Functions',
    },
    'gcp_appengine': {
        'template':       'https://{name}.appspot.com/',
        'list_template':  'https://{name}.appspot.com/',
        'display':        'GCP App Engine',
    },
}


def _sanitise_name(name: str) -> str:
    """Normalise a potential bucket/account name."""
    name = re.sub(r'[^a-z0-9\-]', '-', name.lower())
    name = re.sub(r'-{2,}', '-', name).strip('-')
    return name[:63]  # S3 hard limit


def _generate_candidates(root_domain: str, depth: str) -> list[str]:
    """
    Generate bucket name candidates from *root_domain*.

    Strips TLD to get the organisation token, then applies affix matrix.
    """
    # Extract the second-level label (e.g. "example" from "example.com")
    parts = root_domain.split('.')
    core = parts[0] if parts else root_domain
    core = _sanitise_name(core)

    affixes: list[str]
    if depth == 'shallow':
        affixes = _SHALLOW_AFFIXES
    elif depth == 'medium':
        affixes = _MEDIUM_AFFIXES
    else:
        affixes = _DEEP_AFFIXES

    candidates: set[str] = set()
    # Use both prefix and suffix approach
    for pfx in _PREFIXES[:len(affixes) // 2 + 1]:
        for sfx in _SUFFIXES[:len(affixes) // 2 + 1]:
            name = _sanitise_name(f'{pfx}{core}{sfx}')
            if 3 <= len(name) <= 63:
                candidates.add(name)

    # Also try using the full domain label
    full = _sanitise_name(root_domain.replace('.', '-'))
    for sfx in _SUFFIXES[:8]:
        candidates.add(_sanitise_name(f'{full}{sfx}'))

    limit = {'shallow': 25, 'medium': 80, 'deep': 250}.get(depth, 80)
    return sorted(candidates)[:limit]


# ── Response interpretation ───────────────────────────────────────────────

def _interpret_response(
    status: int,
    body: str,
    provider_key: str,
) -> tuple[str, str]:
    """
    Map HTTP status + body to (access_level, description).

    Returns
    -------
    access_level : 'public_read' | 'public_list' | 'exists_no_read' |
                   'not_found' | 'error' | 'redirect'
    description  : human-readable string
    """
    if status == 200:
        if '<ListBucketResult' in body or '<EnumerationResults' in body:
            return 'public_list', 'Bucket exists and is publicly LISTABLE'
        return 'public_read', 'Bucket exists and allows public read'
    if status == 403:
        return 'exists_no_read', 'Bucket exists but access denied (403)'
    if status in (301, 302, 307, 308):
        return 'redirect', 'Redirect → possibly region-specific endpoint'
    if status == 404:
        return 'not_found', 'Bucket does not exist'
    if status == 400:
        return 'not_found', 'Bad request (bucket name invalid or absent)'
    if status == 503:
        return 'error', 'Service unavailable (slow-down / region issue)'
    return 'error', f'Unexpected status {status}'


# ── Core public function ──────────────────────────────────────────────────

def run_cloud_recon(
    target_url: str,
    depth: str = 'medium',
    make_request_fn: Optional[Callable] = None,
) -> dict:
    """
    Enumerate cloud storage buckets associated with *target_url*.

    Parameters
    ----------
    target_url      : Full URL or bare hostname.
    depth           : 'shallow' | 'medium' | 'deep'.
    make_request_fn : Callable(method, url, **kw) → requests.Response.

    Returns
    -------
    Standardised recon_data dict with keys:
      - findings            : list[dict]
      - buckets             : list[dict]  — all probed resources
      - exposed_buckets     : list[dict]  — public_read or public_list only
      - stats               : dict
    """
    import requests as _requests

    result = create_result('cloud_recon', target_url)
    result['buckets'] = []
    result['exposed_buckets'] = []

    if make_request_fn is None:
        def make_request_fn(method: str, url: str, **kw):
            kw.setdefault('timeout', 8)
            return _requests.request(method, url, **kw)

    root_domain = extract_root_domain(target_url)
    if not root_domain:
        result['errors'].append('Could not extract root domain')
        return finalize_result(result)

    candidates = _generate_candidates(root_domain, depth)
    logger.info(
        f'Cloud recon [{root_domain}]: probing {len(candidates)} candidates '
        f'across {len(_PROVIDERS)} providers'
    )

    probed = 0
    exposed_count = 0

    for name in candidates:
        for provider_key, provider in _PROVIDERS.items():
            # Limit probes to avoid extremely long scan times
            if probed > 500:
                break

            url = provider['list_template'].format(name=name)
            try:
                resp = make_request_fn('GET', url, allow_redirects=False)
                body = resp.text[:4000] if resp.text else ''
                access_level, description = _interpret_response(
                    resp.status_code, body, provider_key
                )
                probed += 1

                if access_level in ('not_found', 'error'):
                    # Fallback: some providers return 403 on HEAD but 200 on GET
                    # Skip recording to reduce noise
                    continue

                bucket_entry = {
                    'name':         name,
                    'provider':     provider['display'],
                    'url':          url,
                    'status':       resp.status_code,
                    'access_level': access_level,
                    'description':  description,
                }
                result['buckets'].append(bucket_entry)

                if access_level in ('public_read', 'public_list', 'redirect'):
                    if access_level == 'public_list':
                        severity = 'critical'
                        title = (
                            f'{provider["display"]} bucket "{name}" is publicly LISTABLE'
                        )
                    elif access_level == 'public_read':
                        severity = 'high'
                        title = f'{provider["display"]} bucket "{name}" allows public read'
                    else:
                        severity = 'medium'
                        title = f'{provider["display"]} resource "{name}" exists (redirect)'

                    add_finding(
                        result,
                        title=title,
                        severity=severity,
                        description=(
                            f'Cloud storage resource found at {url}. '
                            f'Access level: {access_level}. {description}'
                        ),
                        category='cloud_misconfiguration',
                        evidence={
                            'name':    name,
                            'url':     url,
                            'status':  resp.status_code,
                            'preview': body[:500],
                        },
                    )
                    result['exposed_buckets'].append(bucket_entry)
                    exposed_count += 1
                    logger.warning(
                        f'[EXPOSED] {provider["display"]} bucket "{name}" — '
                        f'{access_level} at {url}'
                    )

                elif access_level == 'exists_no_read':
                    # Bucket exists but is private (403) — still noteworthy
                    add_finding(
                        result,
                        title=f'{provider["display"]} bucket "{name}" exists (private)',
                        severity='info',
                        description=f'Bucket "{name}" exists but access is denied ({url}).',
                        category='cloud_asset_discovery',
                        evidence={'url': url, 'status': resp.status_code},
                    )

            except Exception as exc:
                logger.debug(f'Cloud probe failed [{provider_key}] {name}: {exc}')

            # Polite inter-request delay
            time.sleep(0.15)

    result['stats'] = {
        'candidates_generated': len(candidates),
        'probes_executed':      probed,
        'exposed_buckets':      exposed_count,
        'total_findings':       len(result['findings']),
    }

    logger.info(
        f'Cloud recon [{root_domain}]: {probed} probes, '
        f'{exposed_count} exposed resources, '
        f'{len(result["buckets"])} existing buckets'
    )
    return finalize_result(result)
