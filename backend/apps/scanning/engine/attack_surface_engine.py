"""
Phase 3 — Attack Surface Discovery Engine.

Aggregates all recon findings into a unified model of every reachable
service, scored by attackability.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ────────────────────────────────────────────────────────────────────
# Data Models
# ────────────────────────────────────────────────────────────────────

@dataclass
class EntryPoint:
    url: str
    method: str = 'GET'          # GET, POST, PUT, DELETE, WS, GRAPHQL
    entry_type: str = 'page'     # form, api, graphql, websocket, upload, admin, debug, page
    parameters: list = field(default_factory=list)
    auth_required: bool = False
    attackability_score: int = 0  # 0-100
    technologies: list = field(default_factory=list)
    notes: str = ''


@dataclass
class AttackSurface:
    entry_points: list[EntryPoint] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)
    trust_boundaries: list[dict] = field(default_factory=list)
    technologies: list[dict] = field(default_factory=list)
    attack_vectors: list[dict] = field(default_factory=list)
    surface_score: int = 0
    critical_entry_points: list[EntryPoint] = field(default_factory=list)


# ────────────────────────────────────────────────────────────────────
# Classification helpers
# ────────────────────────────────────────────────────────────────────

_ADMIN_KEYWORDS = {
    'admin', 'dashboard', 'manage', 'panel', 'console', 'settings',
    'config', 'control', 'backend', 'cms', 'wp-admin', 'administrator',
}

_DEBUG_KEYWORDS = {
    'debug', 'trace', 'profiler', 'phpinfo', 'elmah', 'actuator',
    'healthcheck', '__debug__', 'swagger', 'graphiql', 'playground',
}

_API_INDICATORS = {
    '/api/', '/v1/', '/v2/', '/v3/', '/graphql', '/rest/', '/json',
    '/rpc', '/grpc', '/soap', '/odata',
}

_UPLOAD_INDICATORS = {
    'upload', 'attach', 'import', 'file', 'document', 'media',
}

_AUTH_INDICATORS = {
    'login', 'signin', 'auth', 'sso', 'oauth', 'token', 'session',
    'register', 'signup', 'password', 'forgot', 'reset',
}


def _classify_entry_type(url: str, method: str = 'GET',
                          has_file_input: bool = False) -> str:
    """Classify an entry point by URL path and context."""
    lower = url.lower()
    path = urlparse(lower).path

    if any(k in path for k in _DEBUG_KEYWORDS):
        return 'debug'
    if any(k in path for k in _ADMIN_KEYWORDS):
        return 'admin'
    if '/graphql' in path or '/graphiql' in path:
        return 'graphql'
    if path.startswith(('/ws/', '/wss/')) or 'websocket' in lower:
        return 'websocket'
    if has_file_input:
        return 'upload'
    if any(k in path for k in _API_INDICATORS):
        return 'api'
    if method in ('POST', 'PUT', 'PATCH', 'DELETE'):
        return 'api'
    return 'page'


def _score_attackability(entry_type: str, auth_required: bool,
                          param_count: int, technologies: list) -> int:
    """Compute 0-100 attackability score for an entry point."""
    score = 0

    # Base score by type
    type_scores = {
        'debug': 95, 'admin': 80, 'graphql': 75, 'upload': 70,
        'websocket': 65, 'api': 55, 'form': 50, 'page': 20,
    }
    score = type_scores.get(entry_type, 20)

    # Authentication modifier
    if not auth_required:
        score += 10
    else:
        score -= 5

    # Parameter richness
    if param_count >= 5:
        score += 15
    elif param_count >= 2:
        score += 8
    elif param_count >= 1:
        score += 3

    # Risky technologies
    risky_tech = {'php', 'wordpress', 'jquery', 'angular', 'java', 'tomcat',
                  'struts', 'spring', 'flask', 'django', 'rails', 'node'}
    for tech in technologies:
        name = tech if isinstance(tech, str) else tech.get('name', '')
        if name.lower() in risky_tech:
            score += 5
            break

    return max(0, min(100, score))


# ────────────────────────────────────────────────────────────────────
# Main Engine
# ────────────────────────────────────────────────────────────────────

class AttackSurfaceEngine:
    """Builds an :class:`AttackSurface` from aggregated recon data."""

    def __init__(self, recon_data: dict):
        self._recon = recon_data or {}

    # ── Public API ──────────────────────────────────────────────────

    def build(self) -> AttackSurface:
        surface = AttackSurface()

        # 1. Extract entry points from multiple recon sources
        self._extract_from_urls(surface)
        self._extract_from_api_discovery(surface)
        self._extract_from_content_discovery(surface)
        self._extract_from_param_discovery(surface)
        self._extract_from_crawl_pages(surface)
        self._extract_from_ports(surface)
        self._extract_from_subdomains(surface)

        # 2. Build services list from port scan + tech fingerprint
        self._build_services(surface)

        # 3. Build technology list
        self._build_technologies(surface)

        # 4. Identify trust boundaries
        self._build_trust_boundaries(surface)

        # 5. Score each entry point
        for ep in surface.entry_points:
            ep.attackability_score = _score_attackability(
                ep.entry_type, ep.auth_required,
                len(ep.parameters), ep.technologies,
            )

        # 6. Deduplicate
        seen = set()
        unique = []
        for ep in surface.entry_points:
            key = (ep.url, ep.method)
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        surface.entry_points = unique

        # 7. Sort by attackability (descending)
        surface.entry_points.sort(key=lambda e: e.attackability_score, reverse=True)

        # 8. Top-10 critical entry points
        surface.critical_entry_points = surface.entry_points[:10]

        # 9. Build attack vectors summary
        self._build_attack_vectors(surface)

        # 10. Compute overall surface score
        surface.surface_score = self._compute_surface_score(surface)

        logger.info(
            'Attack surface built: %d entry points, score=%d, critical=%d',
            len(surface.entry_points), surface.surface_score,
            len(surface.critical_entry_points),
        )
        return surface

    # ── Private extractors ──────────────────────────────────────────

    def _extract_from_urls(self, surface: AttackSurface):
        urls_data = self._recon.get('urls', {})
        for url in urls_data.get('urls', []):
            if isinstance(url, str):
                etype = _classify_entry_type(url)
                surface.entry_points.append(EntryPoint(
                    url=url, method='GET', entry_type=etype,
                ))

    def _extract_from_api_discovery(self, surface: AttackSurface):
        api_data = self._recon.get('api_discovery', {})
        for ep in api_data.get('endpoints', []):
            url = ep if isinstance(ep, str) else ep.get('url', '')
            method = 'GET' if isinstance(ep, str) else ep.get('method', 'GET')
            params = [] if isinstance(ep, str) else ep.get('parameters', [])
            surface.entry_points.append(EntryPoint(
                url=url, method=method, entry_type='api',
                parameters=params,
            ))

    def _extract_from_content_discovery(self, surface: AttackSurface):
        cd = self._recon.get('content_discovery', {})
        for item in cd.get('discovered', []):
            url = item if isinstance(item, str) else item.get('url', '')
            etype = _classify_entry_type(url)
            surface.entry_points.append(EntryPoint(
                url=url, method='GET', entry_type=etype,
            ))

    def _extract_from_param_discovery(self, surface: AttackSurface):
        pd = self._recon.get('param_discovery', {})
        for param_info in pd.get('parameters', []):
            url = param_info.get('url', '')
            params = param_info.get('params', [])
            surface.entry_points.append(EntryPoint(
                url=url, method='GET', entry_type='page',
                parameters=params,
            ))

    def _extract_from_crawl_pages(self, surface: AttackSurface):
        pages = self._recon.get('crawled_pages', [])
        for page in pages:
            url = page.get('url', '') if isinstance(page, dict) else str(page)
            forms = page.get('forms', []) if isinstance(page, dict) else []

            # Add the page itself
            etype = _classify_entry_type(url)
            auth = any(k in url.lower() for k in _AUTH_INDICATORS)
            surface.entry_points.append(EntryPoint(
                url=url, method='GET', entry_type=etype,
                auth_required=auth,
            ))

            # Add each form as a separate entry point
            for form in forms:
                action = form.get('action', url)
                method = form.get('method', 'POST').upper()
                inputs = [i.get('name', '') for i in form.get('inputs', []) if i.get('name')]
                has_file = any(i.get('type') == 'file' for i in form.get('inputs', []))
                ftype = _classify_entry_type(action, method, has_file)
                surface.entry_points.append(EntryPoint(
                    url=action, method=method, entry_type=ftype,
                    parameters=inputs,
                ))

    def _extract_from_ports(self, surface: AttackSurface):
        ports_data = self._recon.get('ports', {})
        for port_info in ports_data.get('open_ports', []):
            port = port_info.get('port', 0) if isinstance(port_info, dict) else port_info
            service = port_info.get('service', '') if isinstance(port_info, dict) else ''
            if isinstance(port, int) and port in (80, 443, 8080, 8443, 8000, 3000, 5000):
                surface.entry_points.append(EntryPoint(
                    url=f'http://{{host}}:{port}/',
                    method='GET', entry_type='page',
                    notes=f'Open port {port}: {service}',
                ))

    def _extract_from_subdomains(self, surface: AttackSurface):
        for key in ('subdomains', 'ct_logs', 'passive_subdomains'):
            sub_data = self._recon.get(key, {})
            for sub in sub_data.get('subdomains', [])[:50]:
                surface.entry_points.append(EntryPoint(
                    url=f'https://{sub}/' if isinstance(sub, str) else '',
                    method='GET', entry_type='page',
                ))

    # ── Builders ────────────────────────────────────────────────────

    def _build_services(self, surface: AttackSurface):
        from .service_classifier import classify_service

        ports_data = self._recon.get('ports', {})
        for port_info in ports_data.get('open_ports', []):
            if isinstance(port_info, dict):
                port = port_info.get('port', 0)
                banner = port_info.get('banner', '')
                headers = port_info.get('headers', {})
            else:
                port = port_info if isinstance(port_info, int) else 0
                banner = ''
                headers = {}
            classified = classify_service(port, banner, headers)
            surface.services.append(classified)

    def _build_technologies(self, surface: AttackSurface):
        tech_data = self._recon.get('technologies', {})
        for tech in tech_data.get('technologies', []):
            if isinstance(tech, dict):
                surface.technologies.append(tech)
            elif isinstance(tech, str):
                surface.technologies.append({'name': tech})

        # Also pull CMS info
        cms = self._recon.get('cms', {})
        if cms.get('detected'):
            surface.technologies.append({
                'name': cms.get('name', 'Unknown CMS'),
                'version': cms.get('version', ''),
                'category': 'cms',
            })

    def _build_trust_boundaries(self, surface: AttackSurface):
        # CORS boundaries
        cors = self._recon.get('cors', {})
        if cors.get('misconfigured') or cors.get('issues'):
            surface.trust_boundaries.append({
                'type': 'cors',
                'risk': 'high' if cors.get('misconfigured') else 'medium',
                'details': cors.get('issues', []),
            })

        # CDN boundary
        cloud = self._recon.get('cloud', {})
        if cloud.get('providers'):
            surface.trust_boundaries.append({
                'type': 'cdn',
                'risk': 'info',
                'providers': cloud.get('providers', []),
            })

        # Subdomain scope boundary
        subs = self._recon.get('subdomains', {}).get('subdomains', [])
        if len(subs) > 10:
            surface.trust_boundaries.append({
                'type': 'subdomain_scope',
                'risk': 'medium',
                'count': len(subs),
            })

    def _build_attack_vectors(self, surface: AttackSurface):
        vectors = []
        type_counts: dict[str, int] = {}
        for ep in surface.entry_points:
            type_counts[ep.entry_type] = type_counts.get(ep.entry_type, 0) + 1

        if type_counts.get('admin', 0) > 0:
            vectors.append({
                'vector': 'admin_panel_access',
                'risk': 'critical',
                'count': type_counts['admin'],
                'description': 'Admin panels detected — brute force / default credentials',
            })
        if type_counts.get('debug', 0) > 0:
            vectors.append({
                'vector': 'debug_endpoint_exposure',
                'risk': 'critical',
                'count': type_counts['debug'],
                'description': 'Debug/profiler endpoints exposed — information disclosure',
            })
        if type_counts.get('api', 0) > 0:
            vectors.append({
                'vector': 'api_attack',
                'risk': 'high',
                'count': type_counts['api'],
                'description': 'API endpoints — injection, auth bypass, BOLA',
            })
        if type_counts.get('upload', 0) > 0:
            vectors.append({
                'vector': 'file_upload_abuse',
                'risk': 'high',
                'count': type_counts['upload'],
                'description': 'File upload forms — webshell, path traversal',
            })
        if type_counts.get('graphql', 0) > 0:
            vectors.append({
                'vector': 'graphql_introspection',
                'risk': 'high',
                'count': type_counts['graphql'],
                'description': 'GraphQL endpoints — introspection, nested query DoS',
            })
        if type_counts.get('websocket', 0) > 0:
            vectors.append({
                'vector': 'websocket_injection',
                'risk': 'medium',
                'count': type_counts['websocket'],
                'description': 'WebSocket endpoints — CSWSH, injection',
            })

        # WAF bypass vector
        waf = self._recon.get('waf', {})
        if waf.get('detected'):
            vectors.append({
                'vector': 'waf_bypass',
                'risk': 'medium',
                'products': [p.get('name', '') for p in waf.get('products', [])],
                'description': 'WAF detected — evasion techniques applicable',
            })

        surface.attack_vectors = vectors

    def _compute_surface_score(self, surface: AttackSurface) -> int:
        """Weighted sum of entry point scores, normalized to 0-100."""
        if not surface.entry_points:
            return 0

        weights = {
            'debug': 5, 'admin': 4, 'graphql': 3.5, 'upload': 3,
            'websocket': 2.5, 'api': 2, 'form': 1.5, 'page': 0.5,
        }

        total_weighted = 0.0
        for ep in surface.entry_points:
            w = weights.get(ep.entry_type, 1)
            total_weighted += ep.attackability_score * w

        # Normalize: assume max realistic = 200 entry points × 100 score × 5 weight
        max_theoretical = min(len(surface.entry_points), 200) * 100 * 3
        if max_theoretical == 0:
            return 0

        score = int((total_weighted / max_theoretical) * 100)
        return max(0, min(100, score))
