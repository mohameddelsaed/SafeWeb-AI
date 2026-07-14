"""
API Discovery Module — Find API endpoints and documentation.

Discovers REST/GraphQL endpoints, OpenAPI/Swagger docs,
and API versioning patterns.
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
try:
    from ..payloads.seclists_manager import SecListsManager as _SecListsManager
    _SECLISTS = _SecListsManager()
except Exception:
    _SECLISTS = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

_MAX_WORKERS = 10

# ── Known API documentation paths ─────────────────────────────────────────

_API_DOC_PATHS = [
    # Swagger / OpenAPI
    {'path': '/swagger.json', 'type': 'swagger'},
    {'path': '/swagger.yaml', 'type': 'swagger'},
    {'path': '/swagger/v1/swagger.json', 'type': 'swagger'},
    {'path': '/swagger/v2/swagger.json', 'type': 'swagger'},
    {'path': '/swagger-ui.html', 'type': 'swagger_ui'},
    {'path': '/swagger-ui/', 'type': 'swagger_ui'},
    {'path': '/swagger-resources', 'type': 'swagger'},
    {'path': '/api-docs', 'type': 'swagger'},
    {'path': '/api-docs.json', 'type': 'swagger'},
    {'path': '/api/docs', 'type': 'docs'},
    {'path': '/api/swagger.json', 'type': 'swagger'},
    {'path': '/api/openapi.json', 'type': 'openapi'},
    {'path': '/api/v1/swagger.json', 'type': 'swagger'},
    {'path': '/api/v1/openapi.json', 'type': 'openapi'},
    {'path': '/api/schema', 'type': 'openapi'},
    {'path': '/api/schema.json', 'type': 'openapi'},
    {'path': '/v2/api-docs', 'type': 'swagger'},
    {'path': '/v3/api-docs', 'type': 'openapi'},
    {'path': '/openapi.json', 'type': 'openapi'},
    {'path': '/openapi.yaml', 'type': 'openapi'},
    {'path': '/openapi/v3', 'type': 'openapi'},
    {'path': '/docs', 'type': 'docs'},
    {'path': '/redoc', 'type': 'redoc'},
    {'path': '/rapidoc', 'type': 'redoc'},
    {'path': '/scalar', 'type': 'redoc'},
    {'path': '/elements', 'type': 'redoc'},
    # GraphQL
    {'path': '/graphql', 'type': 'graphql'},
    {'path': '/graphiql', 'type': 'graphql_ide'},
    {'path': '/api/graphql', 'type': 'graphql'},
    {'path': '/playground', 'type': 'graphql_ide'},
    {'path': '/altair', 'type': 'graphql_ide'},
    {'path': '/explorer', 'type': 'graphql_ide'},
    {'path': '/voyager', 'type': 'graphql_ide'},
    # WADL / WSDL / gRPC
    {'path': '/application.wadl', 'type': 'wadl'},
    {'path': '/?wsdl', 'type': 'wsdl'},
    {'path': '/grpc.json', 'type': 'grpc'},
]

# ── GraphQL introspection query ───────────────────────────────────────────

# Full introspection query — reveals query/mutation/subscription types + all fields
_GRAPHQL_INTROSPECTION_QUERY = (
    '{"query":"{__schema{queryType{name}mutationType{name}'
    'subscriptionType{name}types{name kind description '
    'fields(includeDeprecated:true){name description '
    'type{name kind ofType{name kind}} args{name type{name kind}}} '
    'enumValues(includeDeprecated:true){name description}}}}"}'  
)

# ── API detection heuristics ──────────────────────────────────────────────

_JSON_CONTENT_TYPES = [
    'application/json',
    'application/hal+json',
    'application/vnd.api+json',
    'application/problem+json',
]

_API_ERROR_PATTERNS = [
    r'"error"',
    r'"message"',
    r'"status"',
    r'"code"',
    r'"detail"',
    r'"errors"\s*:',
    r'"data"\s*:',
    r'"results"\s*:',
    r'"items"\s*:',
    r'"pagination"',
    r'"meta"\s*:',
    r'"timestamp"',
    r'"path"\s*:',
    r'"method"\s*:',
    r'"version"\s*:',
]


def _is_json_response(response) -> bool:
    """Check if the response has a JSON content type."""
    ct = ''
    if hasattr(response, 'headers') and response.headers:
        ct = response.headers.get('Content-Type', '').lower()
    return any(jct in ct for jct in _JSON_CONTENT_TYPES)


def _looks_like_api(response) -> bool:
    """Heuristic check: does the response look like an API response?"""
    if _is_json_response(response):
        return True

    body = ''
    if hasattr(response, 'text'):
        body = (response.text or '')[:2000]

    if not body:
        return False

    # Check for JSON-like structure
    stripped = body.strip()
    if stripped.startswith('{') or stripped.startswith('['):
        match_count = sum(
            1 for pat in _API_ERROR_PATTERNS
            if re.search(pat, body, re.IGNORECASE)
        )
        return match_count >= 2

    return False


def _get_content_type(response) -> str:
    """Extract the Content-Type header value."""
    if hasattr(response, 'headers') and response.headers:
        return response.headers.get('Content-Type', '')
    return ''


def _probe_route(make_request_fn, base_url: str, path: str) -> dict | None:
    """Probe a single API route and return info if it responds."""
    url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))
    try:
        response = make_request_fn('GET', url)
        if response is None:
            return None

        status = getattr(response, 'status_code', 0)

        # Skip clear non-matches
        if status in (404, 502, 503, 504):
            return None

        is_api = _looks_like_api(response)
        content_type = _get_content_type(response)

        # Only include 200-range, 401, 403, and 405 (method not allowed = endpoint exists)
        if status not in (200, 201, 204, 301, 302, 401, 403, 405):
            return None

        return {
            'path': path,
            'url': url,
            'status': status,
            'content_type': content_type,
            'is_api': is_api,
        }
    except Exception as exc:
        logger.debug('API probe failed for %s: %s', path, exc)
        return None


def _parse_swagger_endpoints(body: str) -> list[dict]:
    """Parse a Swagger/OpenAPI JSON spec body and extract defined paths with HTTP methods."""
    import json as _json
    try:
        spec = _json.loads(body)
    except Exception:
        return []
    paths = spec.get('paths', {})
    if not isinstance(paths, dict):
        return []

    _HTTP_VERBS = frozenset(('get', 'post', 'put', 'delete', 'patch', 'head', 'options'))
    endpoints: list[dict] = []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        methods = [m.upper() for m in path_item if m.lower() in _HTTP_VERBS]
        if not methods:
            continue
        first_verb = next((m for m in path_item if m.lower() in _HTTP_VERBS), None)
        summary = ''
        tags: list[str] = []
        if first_verb and isinstance(path_item.get(first_verb), dict):
            op = path_item[first_verb]
            summary = op.get('summary', op.get('operationId', ''))
            tags = op.get('tags', [])
        endpoints.append({
            'path': path,
            'methods': methods,
            'summary': summary,
            'tags': tags,
        })

    return endpoints[:500]  # cap to avoid processing huge specs


def _check_api_doc(make_request_fn, base_url: str, doc_info: dict) -> dict | None:
    """Check for a specific API documentation endpoint."""
    path = doc_info['path']
    doc_type = doc_info['type']
    url = urljoin(base_url.rstrip('/') + '/', path.lstrip('/'))

    try:
        response = make_request_fn('GET', url)
        if response is None:
            return None

        status = getattr(response, 'status_code', 0)
        if status != 200:
            return None

        # Read more body for spec files to allow full endpoint parsing
        max_body = 200_000 if doc_type in ('swagger', 'openapi') else 5000
        body = ''
        if hasattr(response, 'text'):
            body = (response.text or '')[:max_body]

        # Validate it's actually API docs
        if doc_type in ('swagger', 'openapi'):
            if not ('"swagger"' in body or '"openapi"' in body or
                    '"paths"' in body or '"info"' in body or
                    'swagger:' in body or 'openapi:' in body):
                return None
        elif doc_type == 'swagger_ui':
            if not ('swagger' in body.lower() and ('<html' in body.lower() or '<div' in body.lower())):
                return None
        elif doc_type == 'redoc':
            if 'redoc' not in body.lower() and '<html' not in body.lower():
                return None

        # Parse spec endpoints for swagger/openapi
        spec_endpoints: list[dict] = []
        if doc_type in ('swagger', 'openapi') and '"paths"' in body:
            spec_endpoints = _parse_swagger_endpoints(body)

        return {
            'path': path,
            'url': url,
            'type': doc_type,
            'status': status,
            'spec_endpoints': spec_endpoints,
        }
    except Exception as exc:
        logger.debug('API doc check failed for %s: %s', path, exc)
        return None


def _test_graphql_introspection(make_request_fn, base_url: str) -> dict:
    """Test for GraphQL introspection at common paths."""
    graphql_info = {
        'found': False,
        'introspection_enabled': False,
        'path': None,
    }

    graphql_paths = [
        '/graphql', '/graphiql', '/api/graphql', '/query',
        '/graphql/v1', '/api/v1/graphql', '/api/v2/graphql',
        '/gql', '/api/gql', '/__graphql',
    ]

    for gql_path in graphql_paths:
        url = urljoin(base_url.rstrip('/') + '/', gql_path.lstrip('/'))
        try:
            response = make_request_fn(
                'POST', url,
                headers={'Content-Type': 'application/json'},
                data=_GRAPHQL_INTROSPECTION_QUERY,
            )
            if response is None:
                continue

            status = getattr(response, 'status_code', 0)
            if status != 200:
                continue

            body = ''
            if hasattr(response, 'text'):
                body = response.text or ''

            if '"__schema"' in body or '"types"' in body:
                graphql_info['found'] = True
                graphql_info['introspection_enabled'] = True
                graphql_info['path'] = gql_path
                # Extract schema metadata from introspection response
                try:
                    import json as _json
                    gql_data = _json.loads(body)
                    schema = gql_data.get('data', {}).get('__schema', {})
                    all_types = schema.get('types', [])
                    graphql_info['type_names'] = [
                        t['name'] for t in all_types
                        if isinstance(t, dict) and not t.get('name', '').startswith('__')
                    ][:50]
                    qt = schema.get('queryType') or {}
                    mt = schema.get('mutationType') or {}
                    st = schema.get('subscriptionType') or {}
                    if qt.get('name'):
                        graphql_info['query_type'] = qt['name']
                    if mt.get('name'):
                        graphql_info['mutation_type'] = mt['name']
                    if st.get('name'):
                        graphql_info['subscription_type'] = st['name']
                except Exception:
                    graphql_info['type_names'] = []
                break
            elif _is_json_response(response):
                # GraphQL endpoint exists but introspection may be disabled
                graphql_info['found'] = True
                graphql_info['path'] = gql_path
                # Don't break — try other paths for introspection
        except Exception as exc:
            logger.debug('GraphQL introspection test failed for %s: %s', gql_path, exc)

    return graphql_info


def _get_routes_for_depth(depth: str) -> list[str]:
    """Load and slice the API route wordlist according to scan depth."""
    all_routes = load_data_lines('api_route_wordlist.txt')
    if not all_routes:
        logger.warning('api_route_wordlist.txt is empty or missing')
        all_routes = []

    # Supplement with SecLists API paths when available
    if _SECLISTS and _SECLISTS.is_installed:
        sl_routes = _SECLISTS.read_payloads(
            'api_paths',
            max_lines=0 if depth == 'deep' else (500 if depth == 'medium' else 100),
        )
        if sl_routes:
            combined: set[str] = set(all_routes)
            combined.update(sl_routes)
            all_routes = list(combined)
            logger.info('SecLists api_paths added route candidates (total %d)', len(all_routes))

    if not all_routes:
        return []

    if depth == 'quick':
        return all_routes[:50]
    elif depth == 'deep':
        return list(all_routes)
    else:  # medium
        return list(all_routes)


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_api_discovery(
    target_url: str,
    make_request_fn=None,
    depth: str = 'medium',
) -> dict:
    """Discover API endpoints, documentation, and GraphQL services.

    Args:
        target_url:       The target URL (base) to scan.
        make_request_fn:  Callable ``fn(method, url, **kwargs) -> response``.
                          If ``None`` the module returns immediately.
        depth:            Scan depth — ``'quick'``, ``'medium'``, or ``'deep'``.

    Returns:
        Standardised result dict with legacy keys:
        ``endpoints``, ``documentation``, ``graphql``,
        ``total_checked``, ``total_found``, ``issues``.
    """
    start = time.time()
    result = create_result('api_discovery', target_url, depth=depth)

    # ── Legacy keys ──
    result['endpoints'] = []
    result['documentation'] = []
    result['graphql'] = {'found': False, 'introspection_enabled': False}
    result['spec_endpoints'] = []
    result['total_checked'] = 0
    result['total_found'] = 0

    if not make_request_fn:
        logger.info('API discovery: no make_request_fn — skipping')
        return finalize_result(result, start)

    # ── 1. Check API documentation endpoints ──
    logger.info('API discovery: checking documentation endpoints...')
    for doc_info in _API_DOC_PATHS:
        result['stats']['total_checks'] += 1
        doc_result = _check_api_doc(make_request_fn, target_url, doc_info)
        if doc_result:
            result['stats']['successful_checks'] += 1
            result['documentation'].append({
                'path': doc_result['path'],
                'type': doc_result['type'],
            })
            spec_eps = doc_result.get('spec_endpoints', [])
            add_finding(result, {
                'type': 'api_documentation_found',
                'path': doc_result['path'],
                'doc_type': doc_result['type'],
                'url': doc_result['url'],
                'endpoint_count': len(spec_eps),
            })
            if spec_eps:
                result['spec_endpoints'].extend(spec_eps)
                add_finding(result, {
                    'type': 'swagger_spec_parsed',
                    'path': doc_result['path'],
                    'endpoint_count': len(spec_eps),
                    'endpoints': [e['path'] for e in spec_eps[:20]],
                })

            severity = 'high' if doc_result['type'] in ('swagger', 'openapi') else 'medium'
            detail = (
                f'{doc_result["type"].upper()} documentation found at '
                f'{doc_result["path"]} — may reveal internal API structure'
            )
            if spec_eps:
                detail += f'. Spec contains {len(spec_eps)} endpoint definitions.'
            result['issues'].append({
                'severity': severity,
                'title': f'API documentation exposed: {doc_result["path"]}',
                'detail': detail,
            })
        else:
            result['stats']['successful_checks'] += 1

    # ── 2. Test GraphQL introspection ──
    result['stats']['total_checks'] += 1
    try:
        gql = _test_graphql_introspection(make_request_fn, target_url)
        result['stats']['successful_checks'] += 1
        result['graphql'] = gql

        if gql['found']:
            add_finding(result, {
                'type': 'graphql_detected',
                'path': gql['path'],
                'introspection_enabled': gql['introspection_enabled'],
                'type_names': gql.get('type_names', []),
                'query_type': gql.get('query_type'),
                'mutation_type': gql.get('mutation_type'),
                'subscription_type': gql.get('subscription_type'),
            })
            if gql['introspection_enabled']:
                result['issues'].append({
                    'severity': 'high',
                    'title': 'GraphQL introspection enabled',
                    'detail': (
                        f'GraphQL endpoint at {gql["path"]} has introspection '
                        f'enabled — full schema disclosure'
                    ),
                })
            else:
                result['issues'].append({
                    'severity': 'info',
                    'title': 'GraphQL endpoint found',
                    'detail': f'GraphQL endpoint detected at {gql["path"]}',
                })
    except Exception as exc:
        result['stats']['failed_checks'] += 1
        result['errors'].append(f'GraphQL introspection test failed: {exc}')

    # ── 3. Brute-force API routes ──
    routes = _get_routes_for_depth(depth)
    result['stats']['total_checks'] += len(routes)
    result['total_checked'] = len(routes) + len(_API_DOC_PATHS) + 1  # +1 for graphql

    logger.info(
        'API discovery: probing %d routes for %s (depth=%s)',
        len(routes), target_url, depth,
    )

    found_endpoints: list[dict] = []

    try:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {
                pool.submit(_probe_route, make_request_fn, target_url, route): route
                for route in routes
            }
            for future in as_completed(futures):
                route = futures[future]
                try:
                    item = future.result()
                    result['stats']['successful_checks'] += 1
                    if item:
                        found_endpoints.append(item)
                except Exception as exc:
                    result['stats']['failed_checks'] += 1
                    logger.debug('API probe error for %s: %s', route, exc)
    except Exception as exc:
        result['errors'].append(f'Thread pool execution failed: {exc}')
        logger.error('API discovery pool error: %s', exc, exc_info=True)

    # ── Sort: API-confirmed first, then by status ──
    found_endpoints.sort(key=lambda x: (0 if x['is_api'] else 1, x['status'], x['path']))

    # ── Populate results ──
    for ep in found_endpoints:
        result['endpoints'].append({
            'path': ep['path'],
            'status': ep['status'],
            'content_type': ep['content_type'],
            'is_api': ep['is_api'],
        })
        add_finding(result, {
            'type': 'api_endpoint_discovered',
            'path': ep['path'],
            'url': ep['url'],
            'status': ep['status'],
            'content_type': ep['content_type'],
            'is_api': ep['is_api'],
        })

        # Flag unauthenticated or sensitive endpoints
        if ep['status'] == 200 and ep['is_api']:
            path_lower = ep['path'].lower()
            if any(kw in path_lower for kw in ('user', 'admin', 'config', 'internal', 'debug')):
                result['issues'].append({
                    'severity': 'medium',
                    'title': f'Sensitive API endpoint accessible: {ep["path"]}',
                    'detail': (
                        f'API endpoint {ep["path"]} returns status {ep["status"]} '
                        f'with API-like response — may expose sensitive data'
                    ),
                })

    result['total_found'] = (
        len(found_endpoints) + len(result['documentation'])
        + (1 if result['graphql']['found'] else 0)
    )

    logger.info(
        'API discovery complete for %s — %d endpoints, %d docs, graphql=%s',
        target_url, len(found_endpoints), len(result['documentation']),
        result['graphql']['found'],
    )

    return finalize_result(result, start)
