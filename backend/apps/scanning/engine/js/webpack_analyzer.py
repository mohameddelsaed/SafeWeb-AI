"""
Webpack / Build Tool Analyzer — Phase 37 JS Intelligence v2.

Detects webpack chunk structure, environment variables embedded in builds,
manifest-based route enumeration, and debug/development builds in production.

Public API
----------
  detect_webpack_chunks(content, url)         -> dict
  parse_webpack_manifest(manifest_json)        -> dict
  detect_env_vars_in_js(content)               -> list[dict]
  detect_debug_build(content, headers, url)    -> dict
  run_webpack_analysis(page, depth)            -> dict
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Webpack Chunk Detection
# ────────────────────────────────────────────────────────────────────────────

#: Webpack runtime fingerprints
_WEBPACK_FINGERPRINTS = [
    re.compile(r'\bwebpackJsonp\b'),                  # webpack v3/4 JSONP
    re.compile(r'\bwebpackChunk\w*\b'),               # webpack v5 chunk
    re.compile(r'__webpack_require__'),               # webpack require shim
    re.compile(r'__webpack_modules__'),               # webpack v5 module map
    re.compile(r'\bchunkLoadingGlobal\b'),            # webpack v5 config
    re.compile(r'webpack/bootstrap'),                 # legacy bootstrap comment
    re.compile(r'__webpack_public_path__'),           # publicPath var
]

#: Webpack chunk URL patterns in the runtime
_CHUNK_URL_PATTERN = re.compile(
    r'''['"]((?:[./]|https?://)[^'"]*(?:chunk|bundle|[0-9]+)\.[a-f0-9]+\.js)['"]''',
    re.I,
)

#: Manifest file path candidates
MANIFEST_PATHS = [
    '/asset-manifest.json',         # Create React App
    '/manifest.json',               # general
    '/webpack-manifest.json',       # custom
    '/_next/static/chunks/manifest*.js',  # Next.js (glob-like)
    '/static/js/manifest.*.js',     # CRA with hash
    '/webpack-stats.json',          # webpack-bundle-analyzer output
    '/bundle-manifest.json',        # generic
]


def detect_webpack_chunks(content: str, url: str = '') -> dict:
    """Detect webpack usage and enumerate chunk URLs from bundle content.

    Returns dict with:
      is_webpack, version_hint, chunk_urls, public_path, bootstrap_present
    """
    result: dict[str, Any] = {
        'is_webpack': False,
        'version_hint': None,
        'chunk_urls': [],
        'public_path': None,
        'bootstrap_present': False,
    }

    if not content:
        return result

    for pat in _WEBPACK_FINGERPRINTS:
        if pat.search(content):
            result['is_webpack'] = True
            break

    if not result['is_webpack']:
        return result

    # Version hint
    if '__webpack_modules__' in content or 'chunkLoadingGlobal' in content:
        result['version_hint'] = 'v5'
    elif 'webpackJsonp' in content:
        result['version_hint'] = 'v3/v4'
    else:
        result['version_hint'] = 'unknown'

    # Bootstrap comment
    result['bootstrap_present'] = bool(re.search(r'webpack/bootstrap', content))

    # Public path
    pp_match = re.search(
        r'__webpack_require__\s*\.\s*p\s*=\s*["\']([^"\']+)["\']',
        content,
    )
    if pp_match:
        result['public_path'] = pp_match.group(1)

    # Chunk URLs
    seen: set[str] = set()
    for m in _CHUNK_URL_PATTERN.finditer(content):
        chunk_path = m.group(1)
        abs_url = urljoin(url, chunk_path) if url else chunk_path
        if abs_url not in seen:
            seen.add(abs_url)
            result['chunk_urls'].append(abs_url)

    return result


# ────────────────────────────────────────────────────────────────────────────
# Webpack Manifest Parsing
# ────────────────────────────────────────────────────────────────────────────

def parse_webpack_manifest(manifest_json: str) -> dict:
    """Parse a webpack / CRA asset-manifest JSON.

    Returns dict with:
      entrypoints, chunks, routes_inferred, error
    """
    result: dict[str, Any] = {
        'entrypoints': [],
        'chunks': [],
        'routes_inferred': [],
        'error': None,
    }
    try:
        data = json.loads(manifest_json)

        # CRA asset-manifest.json format
        if 'entrypoints' in data:
            result['entrypoints'] = data['entrypoints']

        # Generic key→file mapping
        files = data.get('files', data)
        if isinstance(files, dict):
            for key, val in files.items():
                if isinstance(val, str) and val.endswith('.js'):
                    result['chunks'].append({'name': key, 'path': val})
                    # Infer route from named chunk (e.g. "pages/about.js")
                    route = _infer_route_from_chunk_name(key)
                    if route:
                        result['routes_inferred'].append(route)

    except (json.JSONDecodeError, ValueError) as exc:
        result['error'] = str(exc)
    return result


def _infer_route_from_chunk_name(name: str) -> str | None:
    """Convert a chunk name like 'pages/about' to a route '/about'."""
    name = name.strip().lstrip('/')
    # Remove common prefixes
    for prefix in ('pages/', 'routes/', 'views/', 'screens/'):
        if name.lower().startswith(prefix):
            name = name[len(prefix):]
            break
    # Remove extensions and hash suffixes
    name = re.sub(r'\.[a-f0-9]{8,}\.js$', '', name, flags=re.I)
    name = re.sub(r'\.chunk\.js$', '', name, flags=re.I)
    name = re.sub(r'\.js$', '', name, flags=re.I)
    # Skip generic names
    if name in ('main', 'runtime', 'vendor', 'bundle', 'index', 'app'):
        return None
    return '/' + name


# ────────────────────────────────────────────────────────────────────────────
# Environment Variable Detection
# ────────────────────────────────────────────────────────────────────────────

#: Patterns for environment variables often embedded by webpack DefinePlugin
_ENV_VAR_PATTERNS = [
    # process.env.VAR_NAME = "value"
    re.compile(r'process\.env\.([A-Z][A-Z0-9_]{2,})\s*[=:,)]\s*["\']([^"\']{1,200})["\']'),
    # REACT_APP_* or VUE_APP_* or NEXT_PUBLIC_*
    re.compile(r'''["']((?:REACT_APP_|VUE_APP_|NEXT_PUBLIC_|NUXT_PUBLIC_|VITE_)[A-Z0-9_]+)["']\s*:\s*["']([^"']{1,200})["']'''),
    # __ENV = { KEY: "value" }
    re.compile(r'''__(?:ENV|env)__\s*=\s*\{([^}]{1,2000})\}'''),
]

#: Sensitive variable name patterns (flag these specially)
_SENSITIVE_ENV_NAMES = re.compile(
    r'(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|AUTH|PRIVATE|ACCESS)',
    re.I,
)


def detect_env_vars_in_js(content: str) -> list[dict]:
    """Scan JS bundle content for embedded environment variable values.

    Returns list of {name, value, is_sensitive, pattern}.
    """
    findings: list[dict] = []
    seen_names: set[str] = set()

    for pat in _ENV_VAR_PATTERNS[:2]:  # per-variable patterns
        for m in pat.finditer(content):
            name = m.group(1)
            value = m.group(2)
            if name in seen_names:
                continue
            seen_names.add(name)
            is_sensitive = bool(_SENSITIVE_ENV_NAMES.search(name))
            findings.append({
                'name': name,
                'value': value[:100],
                'is_sensitive': is_sensitive,
                'pattern': 'process.env',
            })

    return findings


# ────────────────────────────────────────────────────────────────────────────
# Debug / Development Build Detection
# ────────────────────────────────────────────────────────────────────────────

#: Patterns indicating a development/debug build shipped to production
_DEBUG_INDICATORS = [
    (re.compile(r'\bprocess\.env\.NODE_ENV\s*[=:=!]+\s*["\']development["\']'), 'NODE_ENV=development'),
    (re.compile(r'\b__DEV__\s*=\s*true\b'), '__DEV__ = true'),
    (re.compile(r'webpack\.HotModuleReplacementPlugin'), 'HotModuleReplacementPlugin'),
    (re.compile(r'react-hot-loader'), 'react-hot-loader'),
    (re.compile(r'webpack-dev-server'), 'webpack-dev-server'),
    (re.compile(r'\bDEBUG\s*=\s*true\b', re.I), 'DEBUG=true'),
    (re.compile(r'//# sourceMappingURL='), 'sourceMappingURL present (unminified)'),
    (re.compile(r'eval\s*\(\s*["\']use strict["\']'), 'eval() source emulation (devtool)'),
    (re.compile(r'console\.(log|debug|warn)\s*\(', re.I), 'console.log statements'),
    (re.compile(r'\bvue-devtools\b', re.I), 'vue-devtools reference'),
]

#: Minification checks — absence of minification is suspicious in prod
_MINIFICATION_HEURISTIC_LENGTH = 500  # chars per line avg threshold


def detect_debug_build(content: str, headers: dict | None = None,
                        url: str = '') -> dict:
    """Detect whether a JS bundle appears to be a debug/development build.

    Returns dict with:
      is_debug, indicators, minified, source_map_present, evidence
    """
    headers = headers or {}
    result: dict[str, Any] = {
        'is_debug': False,
        'indicators': [],
        'minified': None,
        'source_map_present': False,
        'evidence': [],
    }

    if not content:
        return result

    for pat, label in _DEBUG_INDICATORS:
        if pat.search(content):
            result['indicators'].append(label)
            if label != 'console.log statements':  # too noisy on its own
                result['is_debug'] = True

    # Check minification heuristic (extremely long lines → minified)
    lines = content.split('\n')
    if lines:
        avg_len = sum(len(l) for l in lines) / max(len(lines), 1)
        result['minified'] = avg_len > _MINIFICATION_HEURISTIC_LENGTH

    # Source map presence
    result['source_map_present'] = bool(
        re.search(r'//[#@]\s*sourceMappingURL', content)
    )
    if result['source_map_present']:
        result['indicators'].append('sourceMappingURL present')

    result['evidence'] = result['indicators'][:5]  # top 5 for report
    return result


# ────────────────────────────────────────────────────────────────────────────
# Aggregate Runner
# ────────────────────────────────────────────────────────────────────────────

def run_webpack_analysis(page: dict, depth: str = 'quick',
                          manifest_content: str = '') -> dict:
    """Run full webpack analysis for a page.

    Args:
        page: Crawled page dict with keys url, headers, content, scripts.
        depth: 'quick' | 'medium' | 'deep'.
        manifest_content: Optional pre-fetched manifest JSON string.

    Returns dict with:
      is_webpack, version_hint, env_vars, debug_info, manifest_info,
      chunk_urls, stats
    """
    start = time.monotonic()
    url = page.get('url', '')
    headers = page.get('headers', {})
    content = page.get('content', '')

    # Collect all JS content (page content + inline scripts)
    js_content = content

    chunk_result = detect_webpack_chunks(js_content, url)
    env_vars = detect_env_vars_in_js(js_content) if depth in ('medium', 'deep') else []
    debug_info = detect_debug_build(js_content, headers, url)

    manifest_info: dict[str, Any] = {}
    if manifest_content:
        manifest_info = parse_webpack_manifest(manifest_content)

    elapsed = time.monotonic() - start
    return {
        'is_webpack': chunk_result['is_webpack'],
        'version_hint': chunk_result['version_hint'],
        'chunk_urls': chunk_result['chunk_urls'],
        'public_path': chunk_result['public_path'],
        'env_vars': env_vars,
        'debug_info': debug_info,
        'manifest_info': manifest_info,
        'stats': {
            'chunks_found': len(chunk_result['chunk_urls']),
            'env_vars_found': len(env_vars),
            'sensitive_env_vars': sum(1 for e in env_vars if e['is_sensitive']),
            'is_debug_build': debug_info['is_debug'],
            'elapsed_s': round(elapsed, 3),
        },
    }
