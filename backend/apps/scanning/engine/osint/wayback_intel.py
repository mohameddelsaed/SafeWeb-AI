"""
Wayback Machine Intelligence Module.

Queries the Internet Archive CDX API for:
- Historical URL discovery
- Old endpoints, admin pages, API routes
- Archived configuration files and parameters
- Content change detection

No API key required — uses the public CDX API.
"""
import logging
import time
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

WAYBACK_CDX_URL = 'https://web.archive.org/cdx/search/cdx'
REQUEST_TIMEOUT = 20
MAX_RESULTS = 5000

# File extensions that hint at sensitive or interesting content
INTERESTING_EXTENSIONS = {
    '.sql', '.bak', '.old', '.log', '.env', '.config', '.conf', '.ini',
    '.xml', '.json', '.yml', '.yaml', '.csv', '.txt', '.zip', '.tar',
    '.gz', '.dump', '.db', '.sqlite', '.key', '.pem', '.crt', '.p12',
}

INTERESTING_PATHS = {
    '/admin', '/login', '/api', '/graphql', '/debug', '/status',
    '/health', '/swagger', '/docs', '/phpinfo', '/wp-admin',
    '/console', '/dashboard', '/config', '/.git', '/.env',
    '/backup', '/test', '/staging', '/internal', '/panel',
}


def run_wayback_intel(target: str, *, depth: str = 'medium',
                      make_request_fn=None) -> Optional[dict]:
    """Query Wayback Machine CDX API for historical URL intelligence.

    Args:
        target: Target URL or domain.
        depth: Scan depth.

    Returns:
        Result dict with findings.  Always runs (no API key needed).
    """
    start_time = time.time()
    result = {
        'module': 'wayback_intel',
        'findings': [],
        'urls': [],
        'interesting_urls': [],
        'parameters': [],
        'errors': [],
        'stats': {'queries': 0, 'urls_found': 0, 'interesting_count': 0},
    }

    hostname = urlparse(target).hostname or target

    _fetch_urls(hostname, result, depth)
    _analyse_urls(result)

    result['stats']['duration_seconds'] = round(time.time() - start_time, 3)
    return result


def _fetch_urls(hostname: str, result: dict, depth: str):
    """Fetch historical URLs from Wayback CDX API."""
    limit = 500 if depth == 'shallow' else MAX_RESULTS

    try:
        params = {
            'url': f'{hostname}/*',
            'output': 'json',
            'fl': 'original,statuscode,mimetype,timestamp',
            'collapse': 'urlkey',
            'limit': limit,
        }

        resp = requests.get(
            WAYBACK_CDX_URL,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            # First row is header
            if len(data) > 1:
                rows = data[1:]
                result['stats']['urls_found'] = len(rows)

                seen = set()
                for row in rows:
                    if len(row) < 4:
                        continue
                    url = row[0]
                    if url in seen:
                        continue
                    seen.add(url)

                    result['urls'].append({
                        'url': url,
                        'status': row[1],
                        'mime': row[2],
                        'timestamp': row[3],
                    })
        else:
            result['errors'].append(f'Wayback CDX error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'Wayback CDX request failed: {str(e)}')


def _analyse_urls(result: dict):
    """Analyse discovered URLs for interesting patterns."""
    param_counter = Counter()

    for entry in result['urls']:
        url = entry['url']
        parsed = urlparse(url)
        path_lower = parsed.path.lower()

        # Check for interesting file extensions
        for ext in INTERESTING_EXTENSIONS:
            if path_lower.endswith(ext):
                finding = {
                    'type': 'interesting_file',
                    'url': url,
                    'extension': ext,
                    'source': 'wayback',
                }
                result['findings'].append(finding)
                result['interesting_urls'].append(url)
                break

        # Check for interesting paths
        for ipath in INTERESTING_PATHS:
            if ipath in path_lower:
                result['findings'].append({
                    'type': 'interesting_path',
                    'url': url,
                    'pattern': ipath,
                    'source': 'wayback',
                })
                result['interesting_urls'].append(url)
                break

        # Collect query parameters
        if parsed.query:
            for part in parsed.query.split('&'):
                key = part.split('=', 1)[0]
                if key:
                    param_counter[key] += 1

    # Store unique parameters (sorted by frequency)
    result['parameters'] = [
        {'name': name, 'count': count}
        for name, count in param_counter.most_common(100)
    ]
    result['stats']['interesting_count'] = len(result['interesting_urls'])
