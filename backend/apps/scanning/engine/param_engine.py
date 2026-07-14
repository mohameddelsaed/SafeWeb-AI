"""
Phase 6 — Parameter Discovery Engine.

Aggregates and classifies every injectable parameter from all sources:
URL params, forms, JS analysis, API specs, and wordlist-based brute-force.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────────────
# Classification wordlists
# ────────────────────────────────────────────────────────────────────

_ID_NAMES = {
    'id', 'uid', 'pid', 'user_id', 'userId', 'account_id', 'accountId',
    'item_id', 'itemId', 'order_id', 'orderId', 'post_id', 'postId',
    'product_id', 'productId', 'doc_id', 'docId', 'record_id', 'recordId',
    'obj_id', 'objId', 'ref', 'reference', 'oid', 'guid', 'uuid', 'pk',
}

_REDIRECT_NAMES = {
    'url', 'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url',
    'returnUrl', 'next', 'nextUrl', 'next_url', 'continue', 'continueTo',
    'goto', 'go', 'target', 'dest', 'destination', 'redir', 'returnTo',
    'return_to', 'callback', 'callback_url', 'callbackUrl', 'to', 'out',
    'link', 'forward', 'from', 'from_url', 'site', 'view',
}

_FILE_NAMES = {
    'file', 'path', 'dir', 'directory', 'attachment', 'upload', 'src',
    'source', 'filename', 'filepath', 'document', 'include', 'template',
    'page', 'read', 'download', 'load', 'lang', 'locale',
}

_AUTH_NAMES = {
    'token', 'access_token', 'accessToken', 'session', 'auth', 'api_key',
    'apiKey', 'key', 'jwt', 'bearer', 'secret', 'password', 'passwd',
    'pwd', 'credential', 'apikey', 'authorization',
}

_SEARCH_NAMES = {
    'q', 'query', 'search', 'term', 'keyword', 'filter', 's', 'find',
    'text', 'lookup', 'contains', 'match', 'pattern', 'name',
}

_DEBUG_NAMES = {
    'debug', 'test', 'verbose', 'trace', 'admin', 'dev', 'mode',
    'internal', 'hidden', 'beta', 'staging', 'preview', 'env',
}

# Common parameter names for brute-force probing
_BRUTE_FORCE_WORDLIST = [
    'id', 'page', 'q', 'search', 'query', 'url', 'file', 'path',
    'redirect', 'next', 'return', 'callback', 'token', 'key', 'api_key',
    'user', 'username', 'email', 'password', 'name', 'type', 'action',
    'cmd', 'command', 'exec', 'code', 'lang', 'language', 'template',
    'view', 'include', 'module', 'plugin', 'theme', 'style', 'format',
    'output', 'content', 'data', 'json', 'xml', 'callback', 'jsonp',
    'debug', 'test', 'verbose', 'admin', 'mode', 'sort', 'order',
    'limit', 'offset', 'start', 'end', 'from', 'to', 'date',
    'category', 'tag', 'status', 'state', 'filter', 'fields',
    'select', 'where', 'table', 'column', 'db', 'database',
    'host', 'port', 'ip', 'domain', 'site', 'ref', 'source',
    'target', 'dest', 'dir', 'folder', 'upload', 'download',
    'attachment', 'doc', 'document', 'report', 'export', 'import',
    'config', 'setting', 'option', 'param', 'value',
]


@dataclass
class ParameterInfo:
    name: str
    param_type: str = 'generic'    # id, search, auth, file, redirect, debug, generic
    source: str = 'url'            # url, form, js, api_spec, wordlist
    locations: list = field(default_factory=list)
    risk_level: str = 'low'        # high, medium, low
    example_value: str = ''


class ParameterEngine:
    """Aggregates parameters from all recon/crawl sources."""

    def __init__(self, recon_data: dict, crawled_pages: list = None):
        self._recon = recon_data or {}
        self._pages = crawled_pages or []

    def discover_all(self, depth: str = 'medium') -> dict:
        all_params: dict[str, ParameterInfo] = {}

        # Mine from various sources
        for p in self._mine_url_params():
            self._merge_param(all_params, p)
        for p in self._mine_form_params():
            self._merge_param(all_params, p)
        for p in self._mine_js_params():
            self._merge_param(all_params, p)
        for p in self._mine_api_params():
            self._merge_param(all_params, p)

        # Deep: wordlist brute-force
        if depth == 'deep':
            urls = [pg.get('url', '') if isinstance(pg, dict) else getattr(pg, 'url', '')
                    for pg in self._pages[:5]]
            for p in self._brute_force_params(urls):
                self._merge_param(all_params, p)

        # Classify & score
        params = list(all_params.values())
        for p in params:
            p.param_type = self._classify_param(p.name)
            p.risk_level = self._risk_level(p.param_type)

        # Organize
        by_type: dict[str, list] = {}
        for p in params:
            by_type.setdefault(p.param_type, []).append(p)

        high_risk = [p for p in params if p.risk_level == 'high']

        return {
            'parameters': params,
            'param_by_type': {k: [_param_dict(p) for p in v] for k, v in by_type.items()},
            'high_risk_params': [_param_dict(p) for p in high_risk],
            'stats': {
                'total_params': len(params),
                'unique_names': len({p.name for p in params}),
                'high_risk_count': len(high_risk),
                'by_source': self._count_by_source(params),
            },
        }

    # ── Miners ──────────────────────────────────────────────────────

    def _mine_url_params(self) -> list[ParameterInfo]:
        params = []
        for page in self._pages:
            url = page.get('url', '') if isinstance(page, dict) else getattr(page, 'url', '')
            parsed = urlparse(url)
            for name, values in parse_qs(parsed.query).items():
                params.append(ParameterInfo(
                    name=name, source='url',
                    locations=[url],
                    example_value=values[0] if values else '',
                ))
        return params

    def _mine_form_params(self) -> list[ParameterInfo]:
        params = []
        for page in self._pages:
            url = page.get('url', '') if isinstance(page, dict) else getattr(page, 'url', '')
            forms = page.get('forms', []) if isinstance(page, dict) else getattr(page, 'forms', [])
            for form in forms:
                inputs = form.get('inputs', []) if isinstance(form, dict) else getattr(form, 'inputs', [])
                for inp in inputs:
                    name = inp.get('name', '') if isinstance(inp, dict) else getattr(inp, 'name', '')
                    if name:
                        params.append(ParameterInfo(
                            name=name, source='form',
                            locations=[url],
                            example_value=inp.get('value', '') if isinstance(inp, dict) else '',
                        ))
        return params

    def _mine_js_params(self) -> list[ParameterInfo]:
        params = []
        js_data = self._recon.get('js_analysis', {})
        # From JS analyzer findings
        endpoints = js_data.get('endpoints', [])
        for ep in endpoints:
            ep_str = ep if isinstance(ep, str) else ep.get('url', '')
            parsed = urlparse(ep_str)
            for name in parse_qs(parsed.query):
                params.append(ParameterInfo(
                    name=name, source='js',
                    locations=[ep_str],
                ))
        # From JS intelligence
        js_intel = self._recon.get('js_intelligence', {})
        for ep in js_intel.get('endpoints', []):
            if isinstance(ep, str) and '?' in ep:
                parsed = urlparse(ep)
                for name in parse_qs(parsed.query):
                    params.append(ParameterInfo(
                        name=name, source='js',
                        locations=[ep],
                    ))
        return params

    def _mine_api_params(self) -> list[ParameterInfo]:
        params = []
        api_data = self._recon.get('api_discovery', {})
        for ep in api_data.get('endpoints', []):
            if isinstance(ep, dict):
                for p_name in ep.get('parameters', []):
                    params.append(ParameterInfo(
                        name=p_name if isinstance(p_name, str) else str(p_name),
                        source='api_spec',
                        locations=[ep.get('url', '')],
                    ))
        return params

    def _brute_force_params(self, urls: list) -> list[ParameterInfo]:
        """Wordlist-based parameter probing (deep mode only)."""
        params = []
        if not urls:
            return params

        for url in urls[:3]:
            if not url:
                continue
            for name in _BRUTE_FORCE_WORDLIST:
                # We don't actually send requests here — just register as potential params
                params.append(ParameterInfo(
                    name=name, source='wordlist',
                    locations=[url],
                ))
        return params

    # ── Helpers ─────────────────────────────────────────────────────

    def _merge_param(self, all_params: dict, param: ParameterInfo):
        key = param.name.lower()
        if key in all_params:
            existing = all_params[key]
            for loc in param.locations:
                if loc not in existing.locations:
                    existing.locations.append(loc)
            if param.example_value and not existing.example_value:
                existing.example_value = param.example_value
        else:
            all_params[key] = param

    @staticmethod
    def _classify_param(name: str) -> str:
        lower = name.lower()
        re.sub(r'[-_\[\]]', '', lower)

        if lower in _ID_NAMES or lower.endswith('_id') or lower.startswith('id_'):
            return 'id'
        if lower in _REDIRECT_NAMES:
            return 'redirect'
        if lower in _FILE_NAMES:
            return 'file'
        if lower in _AUTH_NAMES:
            return 'auth'
        if lower in _SEARCH_NAMES:
            return 'search'
        if lower in _DEBUG_NAMES:
            return 'debug'
        return 'generic'

    @staticmethod
    def _risk_level(param_type: str) -> str:
        risk_map = {
            'id': 'high', 'redirect': 'high', 'file': 'high',
            'auth': 'high', 'debug': 'high',
            'search': 'medium',
            'generic': 'low',
        }
        return risk_map.get(param_type, 'low')

    @staticmethod
    def _count_by_source(params: list) -> dict:
        counts: dict[str, int] = {}
        for p in params:
            counts[p.source] = counts.get(p.source, 0) + 1
        return counts


def _param_dict(p: ParameterInfo) -> dict:
    return {
        'name': p.name,
        'param_type': p.param_type,
        'source': p.source,
        'locations': p.locations[:5],
        'risk_level': p.risk_level,
        'example_value': p.example_value,
    }
