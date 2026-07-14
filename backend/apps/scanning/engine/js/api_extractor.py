"""
API Endpoint Extractor — Phase 37 JS Intelligence v2.

Enhanced extraction of API endpoints from JavaScript source code:
  - fetch() / axios / XMLHttpRequest calls
  - REST API paths with HTTP methods
  - GraphQL operations (query, mutation, subscription)
  - WebSocket endpoint URLs (ws://, wss://)
  - URL construction from template literals

Public API
----------
  extract_fetch_calls(content)             -> list[dict]
  extract_axios_calls(content)             -> list[dict]
  extract_xhr_calls(content)               -> list[dict]
  extract_graphql_operations(content)      -> list[dict]
  extract_websocket_endpoints(content)     -> list[str]
  extract_template_literal_urls(content)   -> list[str]
  deduplicate_endpoints(endpoints)         -> list[dict]
  run_api_extraction(page, depth)          -> dict
"""
from __future__ import annotations

import logging
import re
import time

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# fetch() Call Extraction
# ────────────────────────────────────────────────────────────────────────────

# fetch('/api/users', { method: 'POST', ... })
_FETCH_SIMPLE_RE = re.compile(
    r'''fetch\s*\(\s*['"`]((?:/|https?://)[^'"`\n]{2,200})['"`]'''
    r'''(?:\s*,\s*\{[^}]{0,300}method\s*:\s*['"`]([A-Z]+)['"`])?''',
    re.I | re.DOTALL,
)

# fetch(apiBase + '/users')  — indirect URL
_FETCH_CONCAT_RE = re.compile(
    r'''fetch\s*\(\s*\w+\s*\+\s*['"`](/[^'"`\n]{1,100})['"`]''',
    re.I,
)


def extract_fetch_calls(content: str) -> list[dict]:
    """Extract fetch() API calls from JS content.

    Returns list of {url, method, type}.
    """
    results: list[dict] = []
    seen: set[str] = set()

    for m in _FETCH_SIMPLE_RE.finditer(content):
        url = m.group(1)
        method = (m.group(2) or 'GET').upper()
        key = f'{method}:{url}'
        if key not in seen:
            seen.add(key)
            results.append({'url': url, 'method': method, 'type': 'fetch'})

    for m in _FETCH_CONCAT_RE.finditer(content):
        url = m.group(1)
        key = f'GET:{url}'
        if key not in seen:
            seen.add(key)
            results.append({'url': url, 'method': 'GET', 'type': 'fetch-concat'})

    return results


# ────────────────────────────────────────────────────────────────────────────
# Axios Call Extraction
# ────────────────────────────────────────────────────────────────────────────

_AXIOS_RE = re.compile(
    r'''axios\s*(?:\.\s*(get|post|put|patch|delete|head|options|request))?\s*\(\s*'''
    r'''(?:\{[^}]{0,200}url\s*:\s*)?['"`]((?:/|https?://)[^'"`\n]{2,200})['"`]''',
    re.I | re.DOTALL,
)


def extract_axios_calls(content: str) -> list[dict]:
    """Extract axios API calls from JS content."""
    results: list[dict] = []
    seen: set[str] = set()

    for m in _AXIOS_RE.finditer(content):
        method = (m.group(1) or 'GET').upper()
        url = m.group(2)
        key = f'{method}:{url}'
        if key not in seen:
            seen.add(key)
            results.append({'url': url, 'method': method, 'type': 'axios'})

    return results


# ────────────────────────────────────────────────────────────────────────────
# XMLHttpRequest Extraction
# ────────────────────────────────────────────────────────────────────────────

# xhr.open('GET', '/api/users')
_XHR_OPEN_RE = re.compile(
    r'''\.open\s*\(\s*['"`]([A-Z]+)['"`]\s*,\s*['"`]((?:/|https?://)[^'"`\n]{2,200})['"`]''',
    re.I,
)


def extract_xhr_calls(content: str) -> list[dict]:
    """Extract XMLHttpRequest.open() calls from JS content."""
    results: list[dict] = []
    seen: set[str] = set()

    for m in _XHR_OPEN_RE.finditer(content):
        method = m.group(1).upper()
        url = m.group(2)
        key = f'{method}:{url}'
        if key not in seen:
            seen.add(key)
            results.append({'url': url, 'method': method, 'type': 'xhr'})

    return results


# ────────────────────────────────────────────────────────────────────────────
# GraphQL Operation Extraction
# ────────────────────────────────────────────────────────────────────────────

#: GraphQL operation name extraction
_GQL_OPERATION_RE = re.compile(
    r'''(?:query|mutation|subscription)\s+(\w+)\s*(?:\([^)]*\))?\s*\{''',
    re.I,
)

#: GraphQL endpoint URL
_GQL_ENDPOINT_RE = re.compile(
    r'''['"`]((?:/|https?://)[^'"`\n]*(?:graphql|gql|graph)[^'"`\n]{0,50})['"`]''',
    re.I,
)


def extract_graphql_operations(content: str) -> list[dict]:
    """Extract GraphQL operations and endpoint URLs from JS content.

    Returns list of {type, name, endpoint}.
    """
    results: list[dict] = []

    # Extract operation definitions
    for m in _GQL_OPERATION_RE.finditer(content):
        op_type = content[m.start():m.start() + 12].split()[0].lower()
        results.append({
            'type': op_type,
            'name': m.group(1),
            'endpoint': None,
        })

    # Extract GraphQL endpoint URLs
    gql_endpoints: list[str] = []
    for m in _GQL_ENDPOINT_RE.finditer(content):
        ep = m.group(1)
        if ep not in gql_endpoints:
            gql_endpoints.append(ep)

    # Attach first found endpoint to all operations, or create standalone entries
    for entry in results:
        if gql_endpoints:
            entry['endpoint'] = gql_endpoints[0]

    if not results and gql_endpoints:
        for ep in gql_endpoints:
            results.append({'type': 'endpoint', 'name': None, 'endpoint': ep})

    return results


# ────────────────────────────────────────────────────────────────────────────
# WebSocket Endpoint Extraction
# ────────────────────────────────────────────────────────────────────────────

_WS_URL_RE = re.compile(
    r'''['"`](wss?://[^'"`\n]{5,200})['"`]''',
    re.I,
)

# new WebSocket('/ws/chat')  — relative
_WS_RELATIVE_RE = re.compile(
    r'''new\s+WebSocket\s*\(\s*['"`](/[^'"`\n]{1,100})['"`]''',
    re.I,
)


def extract_websocket_endpoints(content: str) -> list[str]:
    """Extract WebSocket endpoint URLs from JS content."""
    seen: set[str] = set()
    results: list[str] = []

    for m in _WS_URL_RE.finditer(content):
        url = m.group(1)
        if url not in seen:
            seen.add(url)
            results.append(url)

    for m in _WS_RELATIVE_RE.finditer(content):
        url = m.group(1)
        if url not in seen:
            seen.add(url)
            results.append(url)

    return results


# ────────────────────────────────────────────────────────────────────────────
# Template Literal URL Extraction
# ────────────────────────────────────────────────────────────────────────────

# `${baseUrl}/api/users/${id}` or `/api/${resource}`
_TEMPLATE_URL_RE = re.compile(
    r'`((?:/|\$\{[^}]+\}/)[^`\n]{2,200})`',
)

# Simpler: any template literal starting with / and containing known API patterns
_TEMPLATE_API_RE = re.compile(
    r'`(/(?:api|v\d|rest|graphql|ws)[^`\n]{0,100})`',
    re.I,
)


def extract_template_literal_urls(content: str) -> list[str]:
    """Extract URL template literals from JS content."""
    seen: set[str] = set()
    results: list[str] = []

    for m in _TEMPLATE_API_RE.finditer(content):
        url = m.group(1)
        if url not in seen:
            seen.add(url)
            results.append(url)

    return results


# ────────────────────────────────────────────────────────────────────────────
# Deduplication & Normalization
# ────────────────────────────────────────────────────────────────────────────

def deduplicate_endpoints(endpoints: list[dict]) -> list[dict]:
    """Deduplicate endpoint list by (method, url) pair."""
    seen: set[str] = set()
    result: list[dict] = []
    for ep in endpoints:
        key = f'{ep.get("method", "GET")}:{ep.get("url", "")}'
        if key not in seen:
            seen.add(key)
            result.append(ep)
    return result


# ────────────────────────────────────────────────────────────────────────────
# Aggregate Runner
# ────────────────────────────────────────────────────────────────────────────

def run_api_extraction(page: dict, depth: str = 'quick') -> dict:
    """Run full API endpoint extraction for a page.

    Args:
        page: Crawled page dict with keys url, content, scripts.
        depth: 'quick' | 'medium' | 'deep'.

    Returns dict with:
      fetch_calls, axios_calls, xhr_calls, graphql, websockets,
      template_urls, all_endpoints, stats
    """
    start = time.monotonic()

    page.get('url', '')
    content = page.get('content', '')
    scripts = page.get('scripts', [])

    # Accumulate all JS text
    js_text = content or ''
    for script in scripts:
        if isinstance(script, dict):
            js_text += '\n' + script.get('content', '')
        elif isinstance(script, str):
            js_text += '\n' + script

    fetch_calls = extract_fetch_calls(js_text)
    xhr_calls = extract_xhr_calls(js_text)
    graphql_ops: list[dict] = []
    websockets: list[str] = []
    axios_calls: list[dict] = []
    template_urls: list[str] = []

    if depth in ('medium', 'deep'):
        axios_calls = extract_axios_calls(js_text)
        graphql_ops = extract_graphql_operations(js_text)
        websockets = extract_websocket_endpoints(js_text)

    if depth == 'deep':
        template_urls = extract_template_literal_urls(js_text)

    # Aggregate all REST endpoints
    all_endpoints = deduplicate_endpoints(fetch_calls + axios_calls + xhr_calls)

    elapsed = time.monotonic() - start
    return {
        'fetch_calls': fetch_calls,
        'axios_calls': axios_calls,
        'xhr_calls': xhr_calls,
        'graphql': graphql_ops,
        'websockets': websockets,
        'template_urls': template_urls,
        'all_endpoints': all_endpoints,
        'stats': {
            'total_endpoints': len(all_endpoints),
            'graphql_operations': len(graphql_ops),
            'websocket_endpoints': len(websockets),
            'elapsed_s': round(elapsed, 3),
        },
    }
