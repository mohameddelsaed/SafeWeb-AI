"""
URL Harvester Module — Extract URLs and endpoints from HTML content
plus passive historical URL collection from external archives.

Sources:
  HTML parsing:    href, src, form actions, inline JS, HTML comments
  Wayback Machine: CDX API — http://web.archive.org/cdx/search/cdx
  Common Crawl:    CC Index API — https://index.commoncrawl.org/
  AlienVault OTX:  https://otx.alienvault.com/api/v1/indicators/domain/<d>/url_list
  URLScan.io:      https://urlscan.io/api/v1/search/?q=domain:<d>

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time
from urllib.parse import urljoin, urlparse

try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Regex patterns ─────────────────────────────────────────────────────────

# General URL pattern
_URL_RE = re.compile(
    r'(?:https?://[^\s\'"<>]+)',
    re.IGNORECASE,
)

# href / src / action attributes
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_ACTION_RE = re.compile(r'<form[^>]*action\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)

# Method on forms
_FORM_RE = re.compile(
    r'<form[^>]*?action\s*=\s*["\']([^"\']*)["\'][^>]*?'
    r'(?:method\s*=\s*["\']([^"\']*)["\'])?',
    re.IGNORECASE | re.DOTALL,
)
# Fallback: method before action
_FORM_RE_ALT = re.compile(
    r'<form[^>]*?method\s*=\s*["\']([^"\']*)["\'][^>]*?'
    r'action\s*=\s*["\']([^"\']*)["\']',
    re.IGNORECASE | re.DOTALL,
)

# HTML comment content
_COMMENT_RE = re.compile(r'<!--(.*?)-->', re.DOTALL)

# Inline JS string literals
_JS_STRING_RE = re.compile(r'["\'](\s*/[a-zA-Z0-9_/\-?.=&]+\s*)["\']')

# API-like path patterns
_API_PATTERN = re.compile(
    r'(?:/api/|/v[0-9]+/|/graphql|/rest/|/rpc/|/ws/|/webhook)',
    re.IGNORECASE,
)

# Admin / sensitive path patterns
_SENSITIVE_PATTERN = re.compile(
    r'(?:/admin|/dashboard|/config|/debug|/manage|/internal|'
    r'/\.env|/backup|/phpmyadmin|/wp-admin|/wp-login)',
    re.IGNORECASE,
)

# ── Passive source constants ───────────────────────────────────────────────

_WAYBACK_CDX_URL = 'http://web.archive.org/cdx/search/cdx'
_CC_INDEX_URL = 'https://index.commoncrawl.org/CC-MAIN-2024-10-index'
_OTX_URL = 'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list'
_URLSCAN_URL = 'https://urlscan.io/api/v1/search/'

# Extensions to discard (images, fonts, media)
_SKIP_EXTENSIONS = frozenset({
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp', '.avif',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.mp3', '.webm', '.wav', '.ogg',
    '.pdf', '.zip', '.gz', '.tar',
    '.css',
})

# Extensions considered interesting for endpoint harvesting
_KEEP_EXTENSIONS = frozenset({
    '', '.php', '.asp', '.aspx', '.jsp', '.jspx', '.cfm', '.cfc',
    '.html', '.htm', '.shtml',
    '.js', '.mjs', '.ts',
    '.json', '.xml', '.yaml', '.yml', '.toml', '.txt',
    '.env', '.config', '.conf', '.ini', '.bak', '.old', '.sql', '.log',
    '.do', '.action', '.service', '.asmx', '.axd',
})


# ── Passive URL collection helpers ────────────────────────────────────────

def _passive_session() -> '_requests.Session | None':
    """Return a short-timeout requests Session, or None if unavailable."""
    if not _HAS_REQUESTS:
        return None
    sess = _requests.Session()
    sess.headers['User-Agent'] = 'SafeWeb-AI-Recon/3.0'
    return sess


def _filter_url(url: str) -> bool:
    """Return True if the URL should be kept (interesting extension or no ext)."""
    try:
        path = urlparse(url).path.lower()
        ext = '.' + path.rsplit('.', 1)[-1] if '.' in path.split('/')[-1] else ''
        if ext in _SKIP_EXTENSIONS:
            return False
        return True
    except Exception:
        return True


def _query_wayback(domain: str, limit: int = 5000) -> set[str]:
    """Query Wayback Machine CDX API for all archived URLs of *domain*."""
    sess = _passive_session()
    if sess is None:
        return set()
    urls: set[str] = set()
    try:
        params = {
            'url': f'*.{domain}/*',
            'output': 'json',
            'fl': 'original',
            'collapse': 'urlkey',
            'limit': str(limit),
        }
        resp = sess.get(_WAYBACK_CDX_URL, params=params, timeout=20)
        if resp.status_code != 200:
            return urls
        data = resp.json()
        # First item is the header ['original']
        for item in data[1:]:
            if item and _filter_url(item[0]):
                urls.add(item[0])
    except Exception as exc:
        logger.debug('Wayback CDX query failed for %s: %s', domain, exc)
    finally:
        sess.close()
    return urls


def _query_common_crawl(domain: str, limit: int = 2000) -> set[str]:
    """Query Common Crawl index API for URLs matching *domain*."""
    sess = _passive_session()
    if sess is None:
        return set()
    urls: set[str] = set()
    try:
        params = {
            'url': f'*.{domain}',
            'output': 'json',
            'limit': str(limit),
            'fl': 'url',
        }
        resp = sess.get(_CC_INDEX_URL, params=params, timeout=25)
        if resp.status_code != 200:
            return urls
        for line in resp.text.strip().splitlines():
            try:
                import json as _json
                obj = _json.loads(line)
                url = obj.get('url', '')
                if url and _filter_url(url):
                    urls.add(url)
            except Exception:
                continue
    except Exception as exc:
        logger.debug('CommonCrawl query failed for %s: %s', domain, exc)
    finally:
        sess.close()
    return urls


def _query_otx(domain: str, limit: int = 1000) -> set[str]:
    """Query AlienVault OTX for URL list of *domain*."""
    sess = _passive_session()
    if sess is None:
        return set()
    urls: set[str] = set()
    try:
        page = 1
        while len(urls) < limit:
            url = _OTX_URL.format(domain=domain)
            resp = sess.get(url, params={'limit': '500', 'page': str(page)}, timeout=15)
            if resp.status_code != 200:
                break
            data = resp.json()
            url_list = data.get('url_list', [])
            if not url_list:
                break
            for entry in url_list:
                raw = entry.get('url', '')
                if raw and _filter_url(raw):
                    urls.add(raw)
            if not data.get('has_next'):
                break
            page += 1
    except Exception as exc:
        logger.debug('OTX query failed for %s: %s', domain, exc)
    finally:
        sess.close()
    return urls


def _query_urlscan(domain: str, limit: int = 1000) -> set[str]:
    """Query URLScan.io for URLs matching *domain*."""
    sess = _passive_session()
    if sess is None:
        return set()
    urls: set[str] = set()
    try:
        params = {
            'q': f'domain:{domain}',
            'size': '100',
        }
        collected = 0
        search_after = None
        while collected < limit:
            if search_after:
                params['search_after'] = search_after
            resp = sess.get(_URLSCAN_URL, params=params, timeout=15)
            if resp.status_code == 429:
                break  # Rate limited
            if resp.status_code != 200:
                break
            data = resp.json()
            results = data.get('results', [])
            if not results:
                break
            for item in results:
                task_url = item.get('task', {}).get('url', '')
                page_url = item.get('page', {}).get('url', '')
                for raw in (task_url, page_url):
                    if raw and _filter_url(raw):
                        urls.add(raw)
                collected += 1
            if not data.get('has_more'):
                break
            # Get search_after for pagination
            if results:
                search_after = results[-1].get('sort', [None])
                if isinstance(search_after, list):
                    search_after = ','.join(str(x) for x in search_after)
    except Exception as exc:
        logger.debug('URLScan query failed for %s: %s', domain, exc)
    finally:
        sess.close()
    return urls


def _extract_parameters(urls: set[str]) -> dict[str, set[str]]:
    """Extract unique query parameter names from a set of URLs."""
    params: dict[str, set[str]] = {}
    for url in urls:
        try:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            for part in parsed.query.split('&'):
                key = part.split('=')[0].strip()
                if key:
                    params.setdefault(key, set()).add(url)
        except Exception:
            continue
    return params


# ── Helpers ────────────────────────────────────────────────────────────────

def _normalise_url(base_url: str, raw: str) -> str | None:
    """Resolve *raw* against *base_url*, return absolute URL or None."""
    raw = raw.strip()
    if not raw or raw.startswith(('javascript:', 'mailto:', 'tel:', 'data:', '#')):
        return None
    try:
        absolute = urljoin(base_url, raw)
        parsed = urlparse(absolute)
        if parsed.scheme in ('http', 'https') and parsed.hostname:
            return absolute
    except Exception:
        pass
    return None


def _is_internal(url: str, target_hostname: str, root_domain: str) -> bool:
    """Return True if *url* belongs to the same root domain."""
    try:
        host = urlparse(url).hostname or ''
        return (
            host == target_hostname
            or host.endswith(f'.{root_domain}')
            or host == root_domain
        )
    except Exception:
        return False


def _extract_forms(html: str) -> list[dict]:
    """Extract form action/method pairs from HTML."""
    forms = []
    seen: set[str] = set()

    for match in _FORM_RE.finditer(html):
        action = match.group(1) or ''
        method = (match.group(2) or 'GET').upper()
        key = f'{method}:{action}'
        if key not in seen:
            seen.add(key)
            forms.append({'action': action, 'method': method})

    for match in _FORM_RE_ALT.finditer(html):
        method = (match.group(1) or 'GET').upper()
        action = match.group(2) or ''
        key = f'{method}:{action}'
        if key not in seen:
            seen.add(key)
            forms.append({'action': action, 'method': method})

    return forms


def _extract_scripts(html: str) -> list[str]:
    """Return all <script src="..."> URLs from HTML."""
    scripts: list[str] = []
    for match in _SRC_RE.finditer(html):
        src = match.group(1).strip()
        # Only scripts, not images etc.  Check if it's inside a <script> context
        # by looking back for the tag — use a simple heuristic: ends with .js or
        # has no extension (inline resource).
        if src.endswith(('.js', '.mjs', '.ts')) or '/js/' in src:
            scripts.append(src)
    # Also explicit script tags
    for match in re.finditer(r'<script[^>]+src\s*=\s*["\']([^"\']+)["\']', html, re.IGNORECASE):
        src = match.group(1).strip()
        if src not in scripts:
            scripts.append(src)
    return scripts


def _extract_urls_from_comments(html: str) -> list[str]:
    """Find URLs and paths inside HTML comments."""
    urls: list[str] = []
    for match in _COMMENT_RE.finditer(html):
        comment = match.group(1)
        for url_match in _URL_RE.finditer(comment):
            urls.append(url_match.group(0))
        # Also look for relative paths
        for path_match in _JS_STRING_RE.finditer(comment):
            path = path_match.group(1).strip()
            if path.startswith('/'):
                urls.append(path)
    return urls


def _extract_inline_js_urls(html: str) -> list[str]:
    """Find URL-like strings in inline <script> blocks."""
    urls: list[str] = []
    for match in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE):
        block = match.group(1)
        # Full URLs
        for url_match in _URL_RE.finditer(block):
            urls.append(url_match.group(0))
        # Relative paths in string literals
        for path_match in _JS_STRING_RE.finditer(block):
            path = path_match.group(1).strip()
            if path.startswith('/') and len(path) > 1:
                urls.append(path)
    return urls


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_url_harvester(
    target_url: str,
    response_body: str = '',
    depth: str = 'medium',
) -> dict:
    """Harvest URLs and endpoints from HTML content plus passive archives.

    Sources used by depth:
      quick:  HTML parsing only
      medium: HTML parsing + AlienVault OTX + URLScan.io
      deep:   HTML parsing + Wayback Machine CDX + CommonCrawl + OTX + URLScan

    Args:
        target_url:    The page URL (used as base for relative resolution).
        response_body: The raw HTML body to analyse.
        depth:         Scan depth — ``'quick'``, ``'medium'``, or ``'deep'``.

    Returns:
        Standardised result dict with legacy keys:
        ``internal_urls``, ``external_urls``, ``api_endpoints``,
        ``forms``, ``scripts``, ``passive_urls``, ``parameters``,
        ``total_urls``.
    """
    start = time.time()
    result = create_result('url_harvester', target_url, depth)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # ── Legacy top-level keys ──
    result['internal_urls'] = []
    result['external_urls'] = []
    result['api_endpoints'] = []
    result['forms'] = []
    result['scripts'] = []
    result['passive_urls'] = []
    result['parameters'] = {}
    result['total_urls'] = 0

    html = response_body or ''
    internal_set: set[str] = set()
    external_set: set[str] = set()
    api_set: set[str] = set()

    # ── HTML parsing (all depths) ──
    if html:
        # 1. href links
        result['stats']['total_checks'] += 1
        for match in _HREF_RE.finditer(html):
            url = _normalise_url(target_url, match.group(1))
            if url:
                if _is_internal(url, hostname, root_domain):
                    internal_set.add(url)
                else:
                    external_set.add(url)
        result['stats']['successful_checks'] += 1

        # 2. Form actions
        result['stats']['total_checks'] += 1
        result['forms'] = _extract_forms(html)
        result['stats']['successful_checks'] += 1

        # 3. Script sources
        result['stats']['total_checks'] += 1
        raw_scripts = _extract_scripts(html)
        for src in raw_scripts:
            url = _normalise_url(target_url, src)
            if url:
                result['scripts'].append(url)
                if _is_internal(url, hostname, root_domain):
                    internal_set.add(url)
                else:
                    external_set.add(url)
        result['stats']['successful_checks'] += 1

        # 4. Image/misc sources (medium & deep)
        if depth in ('medium', 'deep'):
            result['stats']['total_checks'] += 1
            for match in _SRC_RE.finditer(html):
                url = _normalise_url(target_url, match.group(1))
                if url:
                    if _is_internal(url, hostname, root_domain):
                        internal_set.add(url)
                    else:
                        external_set.add(url)
            result['stats']['successful_checks'] += 1

        # 5. Comment URLs (medium & deep)
        if depth in ('medium', 'deep'):
            result['stats']['total_checks'] += 1
            comment_urls = _extract_urls_from_comments(html)
            for raw in comment_urls:
                url = _normalise_url(target_url, raw)
                if url:
                    if _is_internal(url, hostname, root_domain):
                        internal_set.add(url)
                    else:
                        external_set.add(url)
            result['stats']['successful_checks'] += 1

        # 6. Inline JS URLs (deep only)
        if depth == 'deep':
            result['stats']['total_checks'] += 1
            js_urls = _extract_inline_js_urls(html)
            for raw in js_urls:
                url = _normalise_url(target_url, raw)
                if url:
                    if _is_internal(url, hostname, root_domain):
                        internal_set.add(url)
                    else:
                        external_set.add(url)
            result['stats']['successful_checks'] += 1
    else:
        logger.info('URL harvester: no HTML body — passive sources only')

    # ── Passive historical URL collection ─────────────────────────────────
    passive_all: set[str] = set()

    if root_domain and depth in ('medium', 'deep'):
        logger.info('URL harvester: querying passive sources for %s', root_domain)

        # AlienVault OTX (medium + deep)
        try:
            otx_urls = _query_otx(root_domain)
            passive_all.update(otx_urls)
            result['stats'].setdefault('passive_otx', len(otx_urls))
            logger.debug('OTX: %d URLs for %s', len(otx_urls), root_domain)
        except Exception as exc:
            logger.debug('OTX passive query error: %s', exc)

        # URLScan.io (medium + deep)
        try:
            urlscan_urls = _query_urlscan(root_domain)
            passive_all.update(urlscan_urls)
            result['stats'].setdefault('passive_urlscan', len(urlscan_urls))
            logger.debug('URLScan: %d URLs for %s', len(urlscan_urls), root_domain)
        except Exception as exc:
            logger.debug('URLScan passive query error: %s', exc)

    if root_domain and depth == 'deep':
        # Wayback Machine CDX (deep only — can return thousands)
        try:
            wayback_urls = _query_wayback(root_domain)
            passive_all.update(wayback_urls)
            result['stats'].setdefault('passive_wayback', len(wayback_urls))
            logger.debug('Wayback: %d URLs for %s', len(wayback_urls), root_domain)
        except Exception as exc:
            logger.debug('Wayback passive query error: %s', exc)

        # Common Crawl (deep only)
        try:
            cc_urls = _query_common_crawl(root_domain)
            passive_all.update(cc_urls)
            result['stats'].setdefault('passive_commoncrawl', len(cc_urls))
            logger.debug('CommonCrawl: %d URLs for %s', len(cc_urls), root_domain)
        except Exception as exc:
            logger.debug('CommonCrawl passive query error: %s', exc)

    # Merge passive URLs into internal/external sets
    for url in passive_all:
        if _is_internal(url, hostname, root_domain):
            internal_set.add(url)
        else:
            external_set.add(url)

    result['passive_urls'] = sorted(passive_all)

    # ── Classify API endpoints ──
    for url in internal_set:
        if _API_PATTERN.search(url):
            api_set.add(url)

    # ── Extract unique parameters from all harvested URLs ──
    all_urls = internal_set | external_set
    raw_params = _extract_parameters(all_urls)
    result['parameters'] = {k: len(v) for k, v in sorted(raw_params.items())}

    # ── Populate legacy keys ──
    result['internal_urls'] = sorted(internal_set)
    result['external_urls'] = sorted(external_set)
    result['api_endpoints'] = sorted(api_set)
    result['total_urls'] = len(internal_set) + len(external_set)

    # ── Add findings for interesting discoveries ──
    for url in sorted(api_set):
        add_finding(result, {
            'type': 'api_endpoint',
            'url': url,
            'source': 'html_harvest',
        })

    for url in sorted(internal_set):
        if _SENSITIVE_PATTERN.search(url):
            add_finding(result, {
                'type': 'sensitive_url',
                'url': url,
                'source': 'html_harvest',
            })
            result['issues'].append(f'Sensitive path discovered: {url}')

    for form in result['forms']:
        add_finding(result, {
            'type': 'form',
            'action': form['action'],
            'method': form['method'],
            'source': 'html_harvest',
        })

    # External domains summary
    ext_domains: set[str] = set()
    for url in external_set:
        try:
            ext_domains.add(urlparse(url).hostname or '')
        except Exception:
            pass
    ext_domains.discard('')
    if ext_domains:
        add_finding(result, {
            'type': 'external_domains',
            'domains': sorted(ext_domains),
            'count': len(ext_domains),
        })

    if passive_all:
        add_finding(result, {
            'type': 'passive_urls',
            'count': len(passive_all),
            'sources': [
                k for k in ('wayback', 'commoncrawl', 'otx', 'urlscan')
                if result['stats'].get(f'passive_{k}', 0) > 0
            ],
        })

    logger.info(
        'URL harvester complete for %s: %d internal, %d external, '
        '%d API endpoints, %d passive URLs',
        target_url, len(internal_set), len(external_set),
        len(api_set), len(passive_all),
    )
    return finalize_result(result, start)
