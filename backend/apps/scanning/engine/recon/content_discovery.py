"""
Content Discovery Module — Find hidden files and directories.

Brute-forces common paths to discover admin panels, backup files,
configuration files, and development artifacts.
"""
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    load_data_lines,
)

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10
_REQUEST_TIMEOUT = 8

# ── Status codes considered "interesting" ──────────────────────────────────
_INTERESTING_STATUS = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# ── Extra extensions for deep scans ───────────────────────────────────────
_DEEP_EXTENSIONS = ['.bak', '.old', '.txt', '.log', '.zip', '.tar.gz',
                    '.sql', '.conf', '.cfg', '.ini', '.swp', '.orig']

# ── Path → Category mapping ──────────────────────────────────────────────

_CATEGORY_PATTERNS = {
    'admin_panel': [
        r'/admin', r'/administrator', r'/wp-admin', r'/cpanel',
        r'/dashboard', r'/manage', r'/panel', r'/control',
    ],
    'backup_file': [
        r'\.bak$', r'\.old$', r'\.backup$', r'\.zip$', r'\.tar',
        r'\.sql$', r'\.dump$', r'\.orig$',
    ],
    'config_file': [
        r'\.env', r'\.config', r'\.conf$', r'\.cfg$', r'\.ini$',
        r'\.yaml$', r'\.yml$', r'\.toml$', r'\.xml$',
        r'/web\.config', r'/wp-config', r'\.properties$',
    ],
    'dev_artifact': [
        r'\.git', r'\.svn', r'\.hg', r'\.DS_Store', r'/\.vscode',
        r'/Dockerfile', r'/docker-compose', r'\.editorconfig',
        r'/Makefile', r'/Vagrantfile', r'/\.idea',
        r'/package\.json', r'/composer\.json', r'/Gemfile',
    ],
    'info_disclosure': [
        r'/phpinfo', r'/server-status', r'/server-info',
        r'/debug', r'/trace', r'/test', r'/info',
        r'/elmah', r'/error_log', r'\.log$',
        r'/robots\.txt', r'/sitemap\.xml', r'/crossdomain\.xml',
        r'/humans\.txt', r'/security\.txt', r'\.well-known',
    ],
    'api_endpoint': [
        r'/api', r'/graphql', r'/swagger', r'/openapi', r'/rest',
    ],
}


def _categorize_path(path: str) -> str:
    """Return the category for a discovered path."""
    path_lower = path.lower()
    for category, patterns in _CATEGORY_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, path_lower):
                return category
    return 'other'


def _severity_for_category(category: str, status: int) -> str:
    """Return issue severity based on category and HTTP status."""
    if status == 200:
        severity_map = {
            'config_file': 'critical',
            'backup_file': 'high',
            'admin_panel': 'high',
            'dev_artifact': 'high',
            'info_disclosure': 'medium',
            'api_endpoint': 'info',
        }
    elif status == 403:
        severity_map = {
            'config_file': 'medium',
            'backup_file': 'medium',
            'admin_panel': 'low',
            'dev_artifact': 'low',
            'info_disclosure': 'low',
            'api_endpoint': 'info',
        }
    else:
        severity_map = {
            'config_file': 'low',
            'backup_file': 'low',
            'admin_panel': 'info',
            'dev_artifact': 'info',
            'info_disclosure': 'info',
            'api_endpoint': 'info',
        }
    return severity_map.get(category, 'info')


def _get_paths_for_depth(depth: str) -> list[str]:
    """Load and slice the wordlist according to scan depth."""
    all_paths = load_data_lines('content_wordlist_common.txt')
    if not all_paths:
        logger.warning('content_wordlist_common.txt is empty or missing')
        return []

    if depth == 'quick':
        base_paths = all_paths[:50]
    elif depth == 'deep':
        base_paths = list(all_paths)
        # Add common extensions for existing paths
        extended = []
        for p in all_paths:
            for ext in _DEEP_EXTENSIONS:
                extended.append(p + ext)
        base_paths.extend(extended)
    else:  # medium
        base_paths = list(all_paths)

    return base_paths


def _probe_path(make_request_fn, base_url: str, path: str) -> dict | None:
    """Send a request for a single path and return info if interesting."""
    url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
    try:
        response = make_request_fn('HEAD', url)

        # Some servers return 405 for HEAD — retry with GET
        if response is not None and getattr(response, 'status_code', 0) == 405:
            response = make_request_fn('GET', url)

        if response is None:
            return None

        status = getattr(response, 'status_code', 0)
        if status not in _INTERESTING_STATUS:
            return None

        # Read size from Content-Length or body
        size = 0
        if hasattr(response, 'headers') and response.headers:
            cl = response.headers.get('Content-Length', '0')
            try:
                size = int(cl)
            except (ValueError, TypeError):
                pass
        if size == 0 and hasattr(response, 'text'):
            size = len(response.text or '')

        return {
            'path': path,
            'url': url,
            'status': status,
            'size': size,
            'category': _categorize_path(path),
        }
    except Exception as exc:
        logger.debug('Content discovery probe failed for %s: %s', path, exc)
        return None


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_content_discovery(
    target_url: str,
    make_request_fn=None,
    depth: str = 'medium',
) -> dict:
    """Brute-force common paths to discover hidden content.

    Args:
        target_url:       The target URL (base) to scan.
        make_request_fn:  Callable ``fn(method, url, **kwargs) -> response``.
                          If ``None`` the module returns immediately.
        depth:            Scan depth — ``'quick'``, ``'medium'``, or ``'deep'``.

    Returns:
        Standardised result dict with legacy keys:
        ``discovered``, ``total_checked``, ``total_found``, ``issues``.
    """
    start = time.time()
    result = create_result('content_discovery', target_url, depth=depth)

    # ── Legacy keys ──
    result['discovered'] = []
    result['total_checked'] = 0
    result['total_found'] = 0

    if not make_request_fn:
        logger.info('Content discovery: no make_request_fn — skipping')
        return finalize_result(result, start)

    paths = _get_paths_for_depth(depth)
    if not paths:
        result['errors'].append('No paths loaded from wordlist')
        return finalize_result(result, start)

    result['stats']['total_checks'] = len(paths)
    result['total_checked'] = len(paths)

    logger.info(
        'Content discovery starting for %s — %d paths, depth=%s',
        target_url, len(paths), depth,
    )

    # ── Parallel probing ──
    found_items: list[dict] = []
    errors = 0

    try:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {
                pool.submit(_probe_path, make_request_fn, target_url, path): path
                for path in paths
            }
            for future in as_completed(futures):
                path = futures[future]
                try:
                    item = future.result()
                    if item:
                        found_items.append(item)
                        result['stats']['successful_checks'] += 1
                    else:
                        result['stats']['successful_checks'] += 1
                except Exception as exc:
                    errors += 1
                    result['stats']['failed_checks'] += 1
                    logger.debug('Probe error for %s: %s', path, exc)
    except Exception as exc:
        result['errors'].append(f'Thread pool execution failed: {exc}')
        logger.error('Content discovery pool error: %s', exc, exc_info=True)

    # ── Sort by significance: status 200 first, then 403, then redirects ──
    status_order = {200: 0, 201: 0, 204: 0, 401: 1, 403: 2, 301: 3, 302: 3, 307: 3, 308: 3}
    found_items.sort(key=lambda x: (status_order.get(x['status'], 9), x['path']))

    # ── Populate results ──
    for item in found_items:
        result['discovered'].append({
            'path': item['path'],
            'status': item['status'],
            'category': item['category'],
            'size': item['size'],
        })
        add_finding(result, {
            'type': 'content_discovered',
            'path': item['path'],
            'url': item['url'],
            'status': item['status'],
            'size': item['size'],
            'category': item['category'],
        })

        severity = _severity_for_category(item['category'], item['status'])
        if severity in ('critical', 'high', 'medium'):
            result['issues'].append({
                'severity': severity,
                'title': f'Discovered {item["category"]}: {item["path"]}',
                'detail': (
                    f'{item["path"]} returned HTTP {item["status"]} '
                    f'(size: {item["size"]} bytes, category: {item["category"]})'
                ),
            })

    result['total_found'] = len(found_items)

    logger.info(
        'Content discovery complete for %s — %d/%d paths found',
        target_url, result['total_found'], result['total_checked'],
    )

    # ── External content discovery augmentation (gobuster) ──
    try:
        from apps.scanning.engine.tools.wrappers.gobuster_wrapper import GobusterTool
        import os as _os
        _gb = GobusterTool()
        if _gb.is_available():
            _wl_candidates = [
                _os.path.join(
                    _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))),
                    'payloads', 'data', 'seclists', 'Discovery', 'Web-Content', 'common.txt',
                ),
                '/usr/share/wordlists/dirb/common.txt',
            ]
            _wl = next((_p for _p in _wl_candidates if _os.path.exists(_p)), None)
            if _wl:
                _known_paths = {item['path'] for item in result.get('discovered', [])}
                for _tr in _gb.run(target_url, wordlist=_wl, mode='dir', threads=20):
                    _path = _tr.metadata.get('path', '')
                    if _path and _path not in _known_paths:
                        _known_paths.add(_path)
                        result['discovered'].append({
                            'path': _path,
                            'status': _tr.metadata.get('status_code', 0),
                            'size': _tr.metadata.get('size', 0),
                            'category': 'gobuster',
                        })
                result['total_found'] = len(result['discovered'])
    except Exception:
        pass

    return finalize_result(result, start)
