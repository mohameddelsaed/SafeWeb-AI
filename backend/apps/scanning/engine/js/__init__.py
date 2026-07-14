"""
JavaScript Intelligence v2 — Phase 37.

Source Map Analysis:
  - Detect .js.map file exposure
  - Download and parse source map JSON
  - Extract original source file names, routes, API endpoints, and secrets
  - Report source map exposure as a vulnerability

Public API
----------
  check_source_map_url(js_url)         -> str | None
  fetch_source_map(map_url, ...)        -> dict | None
  parse_source_map(raw_json)           -> dict
  extract_sources_info(source_map)     -> dict
  detect_secrets_in_sources(sources)   -> list[dict]
  run_source_map_analysis(page, depth) -> dict
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Source Map URL Detection
# ────────────────────────────────────────────────────────────────────────────

#: Regex to detect sourceMappingURL comment in JS source
_SOURCE_MAP_COMMENT_RE = re.compile(
    r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)',
    re.IGNORECASE,
)

#: Regex to detect X-SourceMap header (legacy)
_SOURCE_MAP_HEADER = 'x-sourcemap'
_SOURCE_MAP_HEADER_ALT = 'sourcemap'


def check_source_map_url(js_url: str, js_content: str = '',
                          headers: dict | None = None) -> str | None:
    """Return the absolute source map URL if one is detectable, else None.

    Detection order:
      1. X-SourceMap / SourceMap response header
      2. //# sourceMappingURL comment at the bottom of the JS content
      3. Conventional <js_url>.map suffix
    """
    headers = headers or {}

    # 1. Header-based detection
    for hdr in (_SOURCE_MAP_HEADER, _SOURCE_MAP_HEADER_ALT):
        val = headers.get(hdr, '').strip()
        if val:
            return _resolve_map_url(js_url, val)

    # 2. Comment-based detection
    if js_content:
        # Scan only the last 1 KB for speed
        tail = js_content[-1024:]
        m = _SOURCE_MAP_COMMENT_RE.search(tail)
        if m:
            map_ref = m.group(1).strip()
            # Data URIs are not exploitable (map is embedded)
            if not map_ref.startswith('data:'):
                return _resolve_map_url(js_url, map_ref)

    # 3. Conventional suffix
    if js_url.endswith('.js'):
        return js_url + '.map'
    if js_url.endswith('.js?') or '.js?' in js_url:
        base = js_url.split('?')[0]
        return base + '.map'

    return None


def _resolve_map_url(js_url: str, map_ref: str) -> str:
    """Resolve a map reference relative to the JS file URL."""
    if map_ref.startswith(('http://', 'https://')):
        return map_ref
    return urljoin(js_url, map_ref)


# ────────────────────────────────────────────────────────────────────────────
# Source Map Parsing
# ────────────────────────────────────────────────────────────────────────────

def parse_source_map(raw_json: str) -> dict:
    """Parse a source map JSON string.

    Returns a dict with keys:
      version, sources, sources_content, mappings_present, error
    """
    result: dict[str, Any] = {
        'version': None,
        'sources': [],
        'sources_content': [],
        'mappings_present': False,
        'error': None,
    }
    try:
        data = json.loads(raw_json)
        result['version'] = data.get('version')
        result['sources'] = data.get('sources', [])
        result['sources_content'] = data.get('sourcesContent', [])
        result['mappings_present'] = bool(data.get('mappings'))
    except (json.JSONDecodeError, ValueError) as exc:
        result['error'] = str(exc)
    return result


# ────────────────────────────────────────────────────────────────────────────
# Source Extraction & Analysis
# ────────────────────────────────────────────────────────────────────────────

#: Patterns that indicate interesting source file paths
_INTERESTING_PATH_PATTERNS = [
    re.compile(r'node_modules/', re.I),         # vendor code embedded
    re.compile(r'webpack:///', re.I),           # webpack internal
    re.compile(r'\binternal\b', re.I),          # internal modules
    re.compile(r'\.env', re.I),                 # env files
    re.compile(r'config[/\\]', re.I),           # config directory
    re.compile(r'api[/\\]', re.I),              # API directory
    re.compile(r'secret|password|token|key|credential', re.I),  # secrets
    re.compile(r'admin[/\\]', re.I),            # admin paths
    re.compile(r'auth[/\\]', re.I),             # auth paths
    re.compile(r'private[/\\]', re.I),          # private paths
]

#: Regex patterns to extract route-like strings from source content
_ROUTE_PATTERNS = [
    # Express/Koa style routes
    re.compile(r'''(?:router|app)\s*\.\s*(?:get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`\n]+)['"`]''', re.I),
    # Path.join or URL construction
    re.compile(r'''path\s*\.\s*join\s*\([^)]*['"`](/[^'"`]+)['"`]''', re.I),
    # API base URL constants
    re.compile(r'''(?:API_URL|BASE_URL|API_BASE|apiBase)\s*[=:]\s*['"`]([^'"`\n]{4,100})['"`]''', re.I),
]

#: API endpoint extraction from source content
_API_PATTERNS = [
    # fetch('/api/...')
    re.compile(r'''fetch\s*\(\s*['"`]((?:/|https?://)[^'"`\n]{2,100})['"`]''', re.I),
    # axios.get/post('/api/...')
    re.compile(r'''axios\s*\.?\s*(?:get|post|put|patch|delete|request)\s*\(\s*['"`]((?:/|https?://)[^'"`\n]{2,100})['"`]''', re.I),
    # $http.get/post
    re.compile(r'''\$http\s*\.\s*(?:get|post|put|patch|delete)\s*\(\s*['"`]((?:/|https?://)[^'"`\n]{2,100})['"`]''', re.I),
]


def extract_sources_info(source_map: dict) -> dict:
    """Analyse source map sources list and content.

    Returns:
      sources_total, interesting_sources, routes, api_endpoints,
      has_node_modules, original_structure
    """
    sources = source_map.get('sources', [])
    contents = source_map.get('sources_content', [])

    interesting: list[str] = []
    for src in sources:
        for pat in _INTERESTING_PATH_PATTERNS:
            if pat.search(src):
                interesting.append(src)
                break

    # Deduplicate while preserving order
    seen: set[str] = set()
    interesting_unique: list[str] = []
    for s in interesting:
        if s not in seen:
            seen.add(s)
            interesting_unique.append(s)

    routes: set[str] = set()
    api_endpoints: set[str] = set()

    for content in contents:
        if not content:
            continue
        for pat in _ROUTE_PATTERNS:
            for m in pat.finditer(content):
                routes.add(m.group(1))
        for pat in _API_PATTERNS:
            for m in pat.finditer(content):
                api_endpoints.add(m.group(1))

    has_node_modules = any('node_modules' in s for s in sources)

    # Reconstruct original app structure (top-level dirs from paths)
    structure: set[str] = set()
    for src in sources:
        # Remove webpack:// or similar protocol prefix
        clean = re.sub(r'^[a-z]+://+', '', src, flags=re.I)
        parts = clean.lstrip('./').split('/')
        if parts:
            structure.add(parts[0])

    return {
        'sources_total': len(sources),
        'interesting_sources': interesting_unique,
        'routes': sorted(routes),
        'api_endpoints': sorted(api_endpoints),
        'has_node_modules': has_node_modules,
        'original_structure': sorted(structure),
    }


# ────────────────────────────────────────────────────────────────────────────
# Secret Detection in Source Content
# ────────────────────────────────────────────────────────────────────────────

#: High-value secret patterns to search for in source content
SECRET_PATTERNS = [
    ('AWS Access Key',       re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('AWS Secret Key',       re.compile(r'''(?:aws[_\-. ]?secret[_\-. ]?(?:access[_\-. ]?)?key)\s*[=:]\s*['"`]?([A-Za-z0-9/+=]{40})['"`]?''', re.I)),
    ('Stripe API Key',       re.compile(r'\b(?:sk|rk)_(live|test)_[0-9a-zA-Z]{24,}\b')),
    ('Google API Key',       re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
    ('GitHub Token',         re.compile(r'\bgh[pousr]_[0-9a-zA-Z]{36,}\b')),
    ('Generic API Key',      re.compile(r'''(?:api[_\-. ]?key|apikey)\s*[=:]\s*['"`]([A-Za-z0-9_\-]{16,64})['"`]''', re.I)),
    ('JWT Token',            re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b')),
    ('Private Key Header',   re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----')),
    ('Password Assignment',  re.compile(r'''(?:password|passwd|pwd)\s*[=:]\s*['"`]([^'"`\n]{4,64})['"`]''', re.I)),
    ('Firebase Config',      re.compile(r'''apiKey\s*:\s*['"`](AIza[^'"`\n]+)['"`]''')),
    ('SendGrid API Key',     re.compile(r'\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b')),
    ('Twilio Key',           re.compile(r'\bAC[0-9a-f]{32}\b')),
]


def detect_secrets_in_sources(sources_content: list[str]) -> list[dict]:
    """Scan source map content entries for hard-coded secrets.

    Returns list of {name, pattern, match, source_index, line}.
    """
    findings: list[dict] = []
    for idx, content in enumerate(sources_content):
        if not content:
            continue
        for name, pat in SECRET_PATTERNS:
            for m in pat.finditer(content):
                # Compute approximate line number
                line_no = content.count('\n', 0, m.start()) + 1
                findings.append({
                    'name': name,
                    'match': m.group(0)[:80],  # truncate for safety
                    'source_index': idx,
                    'line': line_no,
                })
    return findings


# ────────────────────────────────────────────────────────────────────────────
# Aggregate Runner
# ────────────────────────────────────────────────────────────────────────────

def run_source_map_analysis(page: dict, depth: str = 'quick',
                             fetch_fn=None) -> dict:
    """Run full source map analysis for a page.

    Args:
        page: Crawled page dict with keys url, headers, content, scripts.
        depth: 'quick' | 'medium' | 'deep'.
        fetch_fn: Optional callable(url) -> str for fetching remote content.

    Returns dict with keys:
      map_urls_found, maps_parsed, sources_info, secrets, stats, error
    """
    start = time.monotonic()
    result: dict[str, Any] = {
        'map_urls_found': [],
        'maps_parsed': [],
        'sources_info': [],
        'secrets': [],
        'stats': {},
        'error': None,
    }

    url = page.get('url', '')
    headers = page.get('headers', {})
    content = page.get('content', '')
    scripts = page.get('scripts', [])

    # Build list of JS URLs to probe
    js_urls: list[str] = []

    # From script tags
    for script in scripts:
        src = script.get('src', '') if isinstance(script, dict) else str(script)
        if src and src.endswith('.js'):
            abs_src = urljoin(url, src)
            js_urls.append(abs_src)

    # The page itself (inline bundles sometimes served as .js)
    if url.endswith('.js'):
        js_urls.append(url)

    # For the page's own content, check sourceMappingURL
    if content:
        map_url = check_source_map_url(url, content, headers)
        if map_url and map_url not in result['map_urls_found']:
            result['map_urls_found'].append(map_url)

    # Check each JS URL
    for js_url in js_urls[:20]:  # cap at 20 to avoid runaway
        map_url = check_source_map_url(js_url, '', {})
        if map_url and map_url not in result['map_urls_found']:
            result['map_urls_found'].append(map_url)

    # For medium/deep: attempt to fetch and parse found maps
    if depth in ('medium', 'deep') and fetch_fn and result['map_urls_found']:
        for map_url in result['map_urls_found'][:10]:
            try:
                raw = fetch_fn(map_url)
                if raw:
                    parsed = parse_source_map(raw)
                    if not parsed['error']:
                        info = extract_sources_info(parsed)
                        secrets = detect_secrets_in_sources(
                            parsed.get('sources_content', [])
                        )
                        result['maps_parsed'].append({
                            'url': map_url,
                            'version': parsed['version'],
                            'sources_total': parsed['sources_total'] if 'sources_total' in parsed else len(parsed['sources']),
                        })
                        result['sources_info'].append({
                            'map_url': map_url,
                            **info,
                        })
                        result['secrets'].extend(secrets)
            except Exception as exc:
                logger.debug('Failed to fetch/parse source map %s: %s', map_url, exc)

    elapsed = time.monotonic() - start
    result['stats'] = {
        'maps_found': len(result['map_urls_found']),
        'maps_parsed': len(result['maps_parsed']),
        'secrets_found': len(result['secrets']),
        'elapsed_s': round(elapsed, 3),
    }
    return result
