"""
Frontend Framework Detector — Phase 37 JS Intelligence v2.

Detects React, Angular, Vue, Next.js, Nuxt.js and exposes
framework-specific security checks:
  - React: DevTools exposure, component tree enumeration
  - Angular: Debug mode, route extraction
  - Vue: DevTools exposure, Vuex store exposure
  - Next.js: _next/data API extraction, build manifest
  - Nuxt.js: Server-side rendering detection, __nuxt state

Public API
----------
  detect_frameworks(content, headers, url)    -> dict
  check_react(content, headers)               -> dict
  check_angular(content, headers)             -> dict
  check_vue(content, headers)                 -> dict
  check_nextjs(content, headers, url)         -> dict
  check_nuxtjs(content, headers)              -> dict
  run_framework_detection(page, depth)        -> dict
"""
from __future__ import annotations

import logging
import re
import time
from typing import Any
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────────────
# Framework Fingerprints
# ────────────────────────────────────────────────────────────────────────────

_REACT_FINGERPRINTS = [
    re.compile(r'__REACT_DEVTOOLS_GLOBAL_HOOK__'),
    re.compile(r'\breact-dom\b', re.I),
    re.compile(r'\bReact\.createElement\b'),
    re.compile(r'\bReactDOM\.render\b'),
    re.compile(r'\bReactDOM\.hydrate\b'),
    re.compile(r'\bcreateRoot\s*\('),
    re.compile(r'data-reactroot'),
    re.compile(r'data-reactid'),
]

_ANGULAR_FINGERPRINTS = [
    re.compile(r'\bng-version\b', re.I),
    re.compile(r'\bng\.probe\b'),
    re.compile(r'\bngInjector\b'),
    re.compile(r'\bangular\.module\b'),
    re.compile(r'\bAllowedModuleTypes\b'),
    re.compile(r'ng-app\s*='),
    re.compile(r'\bzone\.js\b', re.I),
    re.compile(r'\b__ngContext__\b'),
]

_VUE_FINGERPRINTS = [
    re.compile(r'\b__vue_app__\b'),
    re.compile(r'\bVue\.config\b'),
    re.compile(r'\bnew Vue\s*\('),
    re.compile(r'\bcreateApp\s*\('),
    re.compile(r'data-v-[0-9a-f]{6,8}'),              # scoped CSS hash
    re.compile(r'\bvue-router\b', re.I),
    re.compile(r'\bvuex\b', re.I),
    re.compile(r'\bpinia\b', re.I),
]

_NEXTJS_FINGERPRINTS = [
    re.compile(r'__NEXT_DATA__'),
    re.compile(r'/_next/static'),
    re.compile(r'\bnext/router\b', re.I),
    re.compile(r'__next_css__', re.I),
    re.compile(r'_next/image'),
]

_NUXTJS_FINGERPRINTS = [
    re.compile(r'__nuxt\b'),
    re.compile(r'__NUXT__'),
    re.compile(r'window\.__NUXT_PAYLOAD__'),
    re.compile(r'_nuxt/'),
    re.compile(r'\bnuxt-link\b', re.I),
]


# ────────────────────────────────────────────────────────────────────────────
# React-specific Checks
# ────────────────────────────────────────────────────────────────────────────

_REACT_VERSION_RE = re.compile(r'''["\']react["\']\s*:\s*["\']([0-9][^"\']+)["\']''', re.I)
_REACT_DEVTOOLS_EXPOSED_RE = re.compile(r'__REACT_DEVTOOLS_GLOBAL_HOOK__')


def check_react(content: str, headers: dict | None = None) -> dict:
    """Detect React-specific security indicators."""
    headers = headers or {}
    result: dict[str, Any] = {
        'detected': False,
        'version': None,
        'devtools_hook_present': False,
        'devtools_enabled': False,
        'hydration_mode': False,
        'issues': [],
    }

    for pat in _REACT_FINGERPRINTS:
        if pat.search(content):
            result['detected'] = True
            break

    if not result['detected']:
        return result

    # Version
    vm = _REACT_VERSION_RE.search(content)
    if vm:
        result['version'] = vm.group(1)

    # DevTools hook
    if _REACT_DEVTOOLS_EXPOSED_RE.search(content):
        result['devtools_hook_present'] = True
        # Check if devtools are actually enabled (non-no-op)
        if 'isDisabled' not in content or re.search(r'isDisabled\s*:\s*false', content):
            result['devtools_enabled'] = True
            result['issues'].append('React DevTools hook is enabled in production')

    # Hydration mode (SSR)
    if re.search(r'ReactDOM\.hydrate|hydrateRoot\s*\(', content):
        result['hydration_mode'] = True

    return result


# ────────────────────────────────────────────────────────────────────────────
# Angular-specific Checks
# ────────────────────────────────────────────────────────────────────────────

_NG_PROD_MODE_RE = re.compile(r'enableProdMode\s*\(', re.I)
_NG_VERSION_RE = re.compile(r'ng-version=["\']([0-9][^"\']+)["\']')
_NG_ROUTE_RE = re.compile(r'''path\s*:\s*['"`]([^'"`\n]+)['"`]''')


def check_angular(content: str, headers: dict | None = None) -> dict:
    """Detect Angular-specific security indicators."""
    headers = headers or {}
    result: dict[str, Any] = {
        'detected': False,
        'version': None,
        'prod_mode_enabled': False,
        'debug_mode': False,
        'routes': [],
        'issues': [],
    }

    for pat in _ANGULAR_FINGERPRINTS:
        if pat.search(content):
            result['detected'] = True
            break

    if not result['detected']:
        return result

    # Version
    vm = _NG_VERSION_RE.search(content)
    if vm:
        result['version'] = vm.group(1)

    # Production mode
    result['prod_mode_enabled'] = bool(_NG_PROD_MODE_RE.search(content))
    if not result['prod_mode_enabled']:
        result['debug_mode'] = True
        result['issues'].append('Angular running in debug mode (enableProdMode() not called)')

    # Route extraction
    routes_seen: set[str] = set()
    for m in _NG_ROUTE_RE.finditer(content):
        path = m.group(1).strip()
        if path and path not in routes_seen and len(path) < 100:
            routes_seen.add(path)
            result['routes'].append(path)

    result['routes'] = sorted(result['routes'])[:50]  # cap at 50

    return result


# ────────────────────────────────────────────────────────────────────────────
# Vue-specific Checks
# ────────────────────────────────────────────────────────────────────────────

_VUE_VERSION_RE = re.compile(r'''Vue\s*\.\s*version\s*=\s*["\']([0-9][^"\']+)["\']''')
_VUEX_STORE_RE = re.compile(r'''new\s+Vuex\.Store\s*\(|createStore\s*\(''')
_VUE_DEVTOOLS_RE = re.compile(r'''Vue\s*\.\s*config\s*\.\s*devtools\s*=\s*(true|false)''')


def check_vue(content: str, headers: dict | None = None) -> dict:
    """Detect Vue-specific security indicators."""
    headers = headers or {}
    result: dict[str, Any] = {
        'detected': False,
        'version': None,
        'devtools_enabled': None,
        'vuex_present': False,
        'pinia_present': False,
        'issues': [],
    }

    for pat in _VUE_FINGERPRINTS:
        if pat.search(content):
            result['detected'] = True
            break

    if not result['detected']:
        return result

    # Version
    vm = _VUE_VERSION_RE.search(content)
    if vm:
        result['version'] = vm.group(1)

    # DevTools
    dv_match = _VUE_DEVTOOLS_RE.search(content)
    if dv_match:
        result['devtools_enabled'] = dv_match.group(1) == 'true'
        if result['devtools_enabled']:
            result['issues'].append('Vue DevTools explicitly enabled')

    # Vuex / Pinia
    result['vuex_present'] = bool(_VUEX_STORE_RE.search(content))
    result['pinia_present'] = bool(re.search(r'\bpinia\b', content, re.I))

    # State exposure
    if re.search(r'window\.__INITIAL_STATE__', content):
        result['issues'].append('Vuex/Pinia initial state serialized to window object (SSR exposure)')

    return result


# ────────────────────────────────────────────────────────────────────────────
# Next.js-specific Checks
# ────────────────────────────────────────────────────────────────────────────

_NEXTJS_DATA_RE = re.compile(r'__NEXT_DATA__\s*=\s*(\{.*?\})\s*<', re.DOTALL)
_NEXTJS_API_PATH_RE = re.compile(r'''['"`](/api/[^'"`\n]{2,100})['"`]''')
_NEXTJS_BUILD_ID_RE = re.compile(r'''buildId\s*[=:]\s*['"`]([^'"`\n]+)['"`]''')


def check_nextjs(content: str, headers: dict | None = None,
                  url: str = '') -> dict:
    """Detect Next.js-specific security indicators."""
    headers = headers or {}
    result: dict[str, Any] = {
        'detected': False,
        'build_id': None,
        'next_data_exposed': False,
        'api_routes': [],
        'data_fetch_urls': [],
        'issues': [],
    }

    for pat in _NEXTJS_FINGERPRINTS:
        if pat.search(content):
            result['detected'] = True
            break

    if not result['detected']:
        return result

    # Build ID
    bi_match = _NEXTJS_BUILD_ID_RE.search(content)
    if bi_match:
        result['build_id'] = bi_match.group(1)

    # __NEXT_DATA__ exposure
    nd_match = _NEXTJS_DATA_RE.search(content)
    if nd_match:
        result['next_data_exposed'] = True
        result['issues'].append('__NEXT_DATA__ embedded in HTML (may expose server props)')

    # API routes
    api_seen: set[str] = set()
    for m in _NEXTJS_API_PATH_RE.finditer(content):
        route = m.group(1)
        if route not in api_seen:
            api_seen.add(route)
            result['api_routes'].append(route)

    # _next/data fetch URLs
    urljoin(url, '/') if url else ''
    build_id = result['build_id'] or '*'
    if result['build_id'] and result['api_routes']:
        for route in result['api_routes'][:10]:
            data_url = f'/_next/data/{build_id}{route}.json'
            result['data_fetch_urls'].append(data_url)

    return result


# ────────────────────────────────────────────────────────────────────────────
# Nuxt.js-specific Checks
# ────────────────────────────────────────────────────────────────────────────

_NUXT_STATE_RE = re.compile(r'window\.__NUXT__\s*=\s*(\{.{0,5000}?\})\s*;', re.DOTALL)
_NUXT_PAYLOAD_RE = re.compile(r'window\.__NUXT_PAYLOAD__')


def check_nuxtjs(content: str, headers: dict | None = None) -> dict:
    """Detect Nuxt.js-specific security indicators."""
    headers = headers or {}
    result: dict[str, Any] = {
        'detected': False,
        'ssr_state_exposed': False,
        'payload_exposed': False,
        'issues': [],
    }

    for pat in _NUXTJS_FINGERPRINTS:
        if pat.search(content):
            result['detected'] = True
            break

    if not result['detected']:
        return result

    # SSR state exposure
    if _NUXT_STATE_RE.search(content):
        result['ssr_state_exposed'] = True
        result['issues'].append('Nuxt.js SSR state serialized to window.__NUXT__ (may leak server data)')

    if _NUXT_PAYLOAD_RE.search(content):
        result['payload_exposed'] = True
        result['issues'].append('Nuxt 3 payload exposed via window.__NUXT_PAYLOAD__')

    return result


# ────────────────────────────────────────────────────────────────────────────
# Aggregate Framework Detector
# ────────────────────────────────────────────────────────────────────────────

#: All framework names and their checker functions
FRAMEWORK_CHECKERS = {
    'react': check_react,
    'angular': check_angular,
    'vue': check_vue,
    'nextjs': check_nextjs,
    'nuxtjs': check_nuxtjs,
}


def detect_frameworks(content: str, headers: dict | None = None,
                       url: str = '') -> dict:
    """Run all framework detectors and return aggregated results.

    Returns dict with keys: detected_frameworks, details, all_issues.
    """
    headers = headers or {}
    details: dict[str, dict] = {}
    detected: list[str] = []
    all_issues: list[str] = []

    for name, checker in FRAMEWORK_CHECKERS.items():
        if name == 'nextjs':
            info = checker(content, headers, url)
        else:
            info = checker(content, headers)
        details[name] = info
        if info.get('detected'):
            detected.append(name)
        all_issues.extend(info.get('issues', []))

    return {
        'detected_frameworks': detected,
        'details': details,
        'all_issues': all_issues,
    }


# ────────────────────────────────────────────────────────────────────────────
# Aggregate Runner
# ────────────────────────────────────────────────────────────────────────────

def run_framework_detection(page: dict, depth: str = 'quick') -> dict:
    """Run framework detection for a crawled page.

    Args:
        page: Crawled page dict with keys url, headers, content.
        depth: 'quick' | 'medium' | 'deep'.

    Returns dict with:
      detected_frameworks, details, all_issues, stats
    """
    start = time.monotonic()

    url = page.get('url', '')
    headers = page.get('headers', {})
    content = page.get('content', '')

    detection = detect_frameworks(content, headers, url)

    elapsed = time.monotonic() - start
    detection['stats'] = {
        'frameworks_detected': len(detection['detected_frameworks']),
        'total_issues': len(detection['all_issues']),
        'elapsed_s': round(elapsed, 3),
    }
    return detection
