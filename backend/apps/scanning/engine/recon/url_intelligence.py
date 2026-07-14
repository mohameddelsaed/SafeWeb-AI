"""
URL Intelligence — Historical URL discovery from web archives.

Mines archived URLs from the Wayback Machine and CommonCrawl to uncover:
    • Forgotten endpoints and admin panels
    • Old API versions with known vulnerabilities
    • Leaked files (backups, configs, source code)
    • Parameter patterns for fuzzing
    • Technology evolution (framework migration clues)

Data sources (all free):
    1. Wayback Machine CDX API
    2. CommonCrawl Index API
    3. OTX AlienVault URL indicators

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time
from collections import Counter
from urllib.parse import urlparse, urlencode, quote

import requests

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# Interesting file extensions to flag
_INTERESTING_EXTENSIONS = {
    '.sql', '.bak', '.old', '.orig', '.backup', '.swp', '.sav',
    '.conf', '.config', '.cfg', '.ini', '.env', '.yml', '.yaml',
    '.json', '.xml', '.log', '.txt', '.csv',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.php~', '.asp~', '.jsp~',
    '.git', '.svn', '.hg',
    '.pem', '.key', '.crt', '.p12', '.pfx',
    '.sh', '.bash', '.ps1', '.bat', '.cmd',
    '.py', '.rb', '.pl', '.java', '.go',
    '.doc', '.docx', '.xls', '.xlsx', '.pdf',
    '.wsdl', '.wadl', '.graphql',
}

# Interesting path patterns
_INTERESTING_PATTERNS = [
    r'/admin', r'/wp-admin', r'/phpmyadmin', r'/cpanel',
    r'/api/v\d', r'/graphql', r'/swagger', r'/openapi',
    r'/debug', r'/test', r'/staging', r'/dev',
    r'/backup', r'/dump', r'/export',
    r'/\.git', r'/\.svn', r'/\.env',
    r'/config', r'/settings', r'/setup',
    r'/install', r'/upgrade', r'/migrate',
    r'/login', r'/auth', r'/oauth', r'/saml',
    r'/upload', r'/file', r'/download',
    r'/cgi-bin', r'/shell', r'/cmd',
]

_INTERESTING_RE = re.compile('|'.join(_INTERESTING_PATTERNS), re.IGNORECASE)


def _query_wayback(domain: str, depth: str) -> list[dict]:
    """Query Wayback Machine CDX API for archived URLs."""
    urls = []
    try:
        # Limit results based on depth
        limit = {'shallow': 500, 'medium': 2000, 'deep': 10000}.get(depth, 2000)

        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'original,timestamp,statuscode,mimetype',
            'collapse': 'urlkey',
            'limit': limit,
            'filter': 'statuscode:200',
        }
        url = f'https://web.archive.org/cdx/search/cdx?{urlencode(params)}'
        resp = requests.get(url, timeout=30, headers={'User-Agent': 'SafeWeb-AI/2.0'})

        if resp.status_code == 200:
            lines = resp.json()
            # First line is header: ["original", "timestamp", "statuscode", "mimetype"]
            if lines and len(lines) > 1:
                for row in lines[1:]:
                    if len(row) >= 4:
                        urls.append({
                            'url': row[0],
                            'timestamp': row[1],
                            'status': row[2],
                            'mimetype': row[3],
                            'source': 'wayback',
                        })
    except Exception as e:
        logger.debug('Wayback Machine query failed for %s: %s', domain, e)
    return urls


def _query_commoncrawl(domain: str) -> list[dict]:
    """Query CommonCrawl index for URLs."""
    urls = []
    try:
        # Get latest CommonCrawl index
        indices_url = 'https://index.commoncrawl.org/collinfo.json'
        resp = requests.get(indices_url, timeout=10)
        if resp.status_code != 200:
            return urls

        indices = resp.json()
        if not indices:
            return urls

        # Query the latest index
        latest = indices[0]
        api_url = latest.get('cdx-api', '')
        if not api_url:
            return urls

        params = {
            'url': f'*.{domain}',
            'output': 'json',
            'limit': 1000,
        }
        search_url = f'{api_url}?{urlencode(params)}'
        resp = requests.get(search_url, timeout=30, headers={'User-Agent': 'SafeWeb-AI/2.0'})

        if resp.status_code == 200:
            for line in resp.text.strip().splitlines():
                try:
                    import json
                    entry = json.loads(line)
                    urls.append({
                        'url': entry.get('url', ''),
                        'timestamp': entry.get('timestamp', ''),
                        'status': entry.get('status', ''),
                        'mimetype': entry.get('mime', ''),
                        'source': 'commoncrawl',
                    })
                except Exception:
                    continue
    except Exception as e:
        logger.debug('CommonCrawl query failed for %s: %s', domain, e)
    return urls


def _query_alienvault_urls(domain: str) -> list[dict]:
    """Query AlienVault OTX for URL list."""
    urls = []
    try:
        url = f'https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/url_list?limit=500'
        resp = requests.get(url, timeout=15, headers={'User-Agent': 'SafeWeb-AI/2.0'})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get('url_list', []):
                urls.append({
                    'url': entry.get('url', ''),
                    'timestamp': entry.get('date', ''),
                    'status': str(entry.get('httpcode', '')),
                    'mimetype': '',
                    'source': 'alienvault',
                })
    except Exception as e:
        logger.debug('AlienVault URL query failed for %s: %s', domain, e)
    return urls


def _classify_url(url: str) -> dict:
    """Analyze a URL for interesting characteristics."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    info = {
        'has_params': bool(parsed.query),
        'param_count': len(parsed.query.split('&')) if parsed.query else 0,
        'interesting': False,
        'categories': [],
    }

    # Check extension
    for ext in _INTERESTING_EXTENSIONS:
        if path.endswith(ext):
            info['interesting'] = True
            info['categories'].append(f'sensitive_file ({ext})')
            break

    # Check path patterns
    if _INTERESTING_RE.search(path):
        info['interesting'] = True
        for pattern in _INTERESTING_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                info['categories'].append(re.sub(r'[/\\]', '', pattern).strip('.'))

    # Check for technology indicators
    if any(tech in path for tech in ['.php', '.asp', '.jsp', '.cgi']):
        info['categories'].append('server_side_script')
    if any(api in path for api in ['/api/', '/rest/', '/graphql', '/v1/', '/v2/']):
        info['categories'].append('api_endpoint')

    return info


# ── Main Entry Point ─────────────────────────────────────────────────────────

def run_url_intelligence(target_url: str, depth: str = 'medium') -> dict:
    """
    Discover historical URLs from web archives and intelligence feeds.

    Returns standardised dict plus legacy keys:
        urls, interesting_urls, parameters, extensions, sources_queried
    """
    start = time.time()
    result = create_result('url_intelligence', target_url, depth)
    hostname = extract_hostname(target_url)
    domain = extract_root_domain(hostname)

    if not domain:
        result['errors'].append('Could not extract domain from target URL')
        return finalize_result(result, start)

    # Query sources
    all_urls = []
    sources_stats = {}

    # Wayback Machine (always)
    result['stats']['total_checks'] += 1
    wayback_urls = _query_wayback(domain, depth)
    all_urls.extend(wayback_urls)
    sources_stats['wayback'] = len(wayback_urls)
    if wayback_urls:
        result['stats']['successful_checks'] += 1
    else:
        result['stats']['failed_checks'] += 1

    # AlienVault (medium+)
    if depth in ('medium', 'deep'):
        result['stats']['total_checks'] += 1
        av_urls = _query_alienvault_urls(domain)
        all_urls.extend(av_urls)
        sources_stats['alienvault'] = len(av_urls)
        if av_urls:
            result['stats']['successful_checks'] += 1
        else:
            result['stats']['failed_checks'] += 1

    # CommonCrawl (deep only — slower)
    if depth == 'deep':
        result['stats']['total_checks'] += 1
        cc_urls = _query_commoncrawl(domain)
        all_urls.extend(cc_urls)
        sources_stats['commoncrawl'] = len(cc_urls)
        if cc_urls:
            result['stats']['successful_checks'] += 1
        else:
            result['stats']['failed_checks'] += 1

    # Deduplicate by URL
    seen = set()
    unique_urls = []
    for entry in all_urls:
        url_key = entry['url'].rstrip('/')
        if url_key not in seen:
            seen.add(url_key)
            unique_urls.append(entry)

    # Classify URLs
    interesting_urls = []
    param_names = Counter()
    extension_counts = Counter()

    for entry in unique_urls:
        parsed = urlparse(entry['url'])
        path = parsed.path.lower()

        # Count extensions
        if '.' in path.split('/')[-1]:
            ext = '.' + path.split('/')[-1].rsplit('.', 1)[-1]
            extension_counts[ext] += 1

        # Count parameter names
        if parsed.query:
            for param in parsed.query.split('&'):
                if '=' in param:
                    param_names[param.split('=')[0]] += 1

        # Classify
        classification = _classify_url(entry['url'])
        if classification['interesting']:
            interesting_urls.append({
                **entry,
                'categories': classification['categories'],
            })

    # Findings
    add_finding(result, {
        'type': 'url_summary',
        'total_raw': len(all_urls),
        'total_unique': len(unique_urls),
        'total_interesting': len(interesting_urls),
        'sources': sources_stats,
    })

    if interesting_urls:
        add_finding(result, {
            'type': 'interesting_urls',
            'urls': interesting_urls[:200],  # Cap at 200
        })

    if param_names:
        add_finding(result, {
            'type': 'discovered_parameters',
            'total_unique': len(param_names),
            'top_parameters': dict(param_names.most_common(50)),
        })

    if extension_counts:
        add_finding(result, {
            'type': 'extension_distribution',
            'extensions': dict(extension_counts.most_common(30)),
        })

    # Legacy keys
    result['urls'] = unique_urls[:5000]
    result['interesting_urls'] = interesting_urls[:200]
    result['parameters'] = dict(param_names.most_common(100))
    result['extensions'] = dict(extension_counts.most_common(30))
    result['sources_queried'] = sources_stats

    logger.info(
        'URL intelligence: %d unique URLs (%d interesting) from %d sources for %s',
        len(unique_urls), len(interesting_urls), len(sources_stats), domain,
    )

    return finalize_result(result, start)
