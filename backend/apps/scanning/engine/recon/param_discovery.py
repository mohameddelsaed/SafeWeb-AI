"""
Parameter Discovery Module — Find hidden/undocumented URL parameters.

Tests common parameter names to discover hidden functionality,
debug modes, and injection points.
"""
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

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
_CANARY_VALUE = 'safeweb_test_xq9k2'
_LENGTH_DIFF_THRESHOLD = 50  # bytes

# ── Parameter categories ──────────────────────────────────────────────────

_PARAM_CATEGORIES = {
    'auth': [
        'token', 'api_key', 'apikey', 'api-key', 'access_token',
        'auth', 'authorization', 'session', 'jwt', 'secret',
        'password', 'passwd', 'pwd', 'key', 'credentials',
    ],
    'debug': [
        'debug', 'test', 'verbose', 'trace', 'dev',
        'development', 'staging', 'internal', 'admin',
        'diagnostics', 'profiler', 'log_level',
    ],
    'redirect': [
        'url', 'redirect', 'redirect_url', 'redirect_uri',
        'return', 'return_url', 'next', 'goto', 'continue',
        'dest', 'destination', 'rurl', 'target', 'link',
    ],
    'injection': [
        'id', 'user_id', 'uid', 'pid', 'item', 'category',
        'file', 'path', 'dir', 'folder', 'page', 'template',
        'include', 'require', 'load', 'read', 'fetch',
        'query', 'search', 'q', 'cmd', 'exec', 'command',
    ],
    'display': [
        'format', 'output', 'type', 'view', 'mode',
        'lang', 'language', 'locale', 'theme', 'style',
        'callback', 'jsonp', 'content_type',
    ],
}

# Pre-build reverse lookup
_PARAM_TO_CATEGORY: dict[str, str] = {}
for _cat, _params in _PARAM_CATEGORIES.items():
    for _p in _params:
        _PARAM_TO_CATEGORY[_p] = _cat


def _categorize_param(name: str) -> str:
    """Return the category for a parameter name."""
    name_lower = name.lower().strip()
    if name_lower in _PARAM_TO_CATEGORY:
        return _PARAM_TO_CATEGORY[name_lower]
    # Fuzzy match — check if param contains a category keyword
    for cat, keywords in _PARAM_CATEGORIES.items():
        for kw in keywords:
            if kw in name_lower or name_lower in kw:
                return cat
    return 'other'


def _get_params_for_depth(depth: str) -> list[str]:
    """Load and slice the parameter wordlist according to scan depth."""
    all_params = load_data_lines('param_wordlist.txt')
    if not all_params:
        logger.warning('param_wordlist.txt is empty or missing')
        all_params = []

    # Supplement with SecLists web-content wordlist when available
    if _SECLISTS and _SECLISTS.is_installed:
        sl_params = _SECLISTS.read_payloads(
            'discovery_web',
            max_lines=0 if depth == 'deep' else (500 if depth == 'medium' else 100),
        )
        if sl_params:
            combined: set[str] = set(all_params)
            combined.update(sl_params)
            all_params = list(combined)
            logger.info('SecLists discovery_web added param candidates (total %d)', len(all_params))

    if not all_params:
        return []

    if depth == 'quick':
        return all_params[:50]
    else:
        return list(all_params)


def _get_baseline(make_request_fn, target_url: str) -> dict | None:
    """Fetch the baseline response for comparison."""
    try:
        response = make_request_fn('GET', target_url)
        if response is None:
            return None
        body = ''
        if hasattr(response, 'text'):
            body = response.text or ''
        return {
            'status': getattr(response, 'status_code', 0),
            'length': len(body),
            'body': body,
        }
    except Exception as exc:
        logger.debug('Baseline request failed: %s', exc)
        return None


def _test_param(
    make_request_fn,
    target_url: str,
    param_name: str,
    canary: str,
    baseline: dict,
) -> dict | None:
    """Test a single parameter and return discovery info if found."""
    separator = '&' if '?' in target_url else '?'
    test_url = f'{target_url}{separator}{urlencode({param_name: canary})}'

    try:
        response = make_request_fn('GET', test_url)
        if response is None:
            return None

        status = getattr(response, 'status_code', 0)
        body = ''
        if hasattr(response, 'text'):
            body = response.text or ''

        resp_length = len(body)
        reflected = canary in body
        length_diff = abs(resp_length - baseline['length'])
        status_changed = status != baseline['status']
        changes_response = length_diff > _LENGTH_DIFF_THRESHOLD or status_changed

        # Only report if the parameter produces an observable difference
        if not reflected and not changes_response:
            return None

        evidence_parts = []
        if reflected:
            # Find context around reflection
            idx = body.find(canary)
            ctx_start = max(0, idx - 30)
            ctx_end = min(len(body), idx + len(canary) + 30)
            evidence_parts.append(f'Value reflected in response: ...{body[ctx_start:ctx_end]}...')
        if status_changed:
            evidence_parts.append(
                f'Status changed: {baseline["status"]} → {status}'
            )
        if length_diff > _LENGTH_DIFF_THRESHOLD:
            evidence_parts.append(
                f'Response length changed by {length_diff} bytes '
                f'({baseline["length"]} → {resp_length})'
            )

        category = _categorize_param(param_name)

        return {
            'name': param_name,
            'reflected': reflected,
            'changes_response': changes_response,
            'status_changed': status_changed,
            'length_diff': length_diff,
            'category': category,
            'evidence': '; '.join(evidence_parts),
        }
    except Exception as exc:
        logger.debug('Parameter test failed for %s: %s', param_name, exc)
        return None


def _severity_for_param(param_info: dict) -> str:
    """Determine severity based on parameter characteristics."""
    category = param_info.get('category', 'other')

    if param_info.get('reflected'):
        if category == 'injection':
            return 'high'
        if category in ('auth', 'redirect'):
            return 'high'
        return 'medium'

    if param_info.get('status_changed'):
        if category in ('auth', 'debug'):
            return 'medium'

    if category == 'debug' and param_info.get('changes_response'):
        return 'medium'

    return 'low'


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_param_discovery(
    target_url: str,
    make_request_fn=None,
    depth: str = 'medium',
) -> dict:
    """Discover hidden/undocumented URL parameters.

    Args:
        target_url:       The target URL to test.
        make_request_fn:  Callable ``fn(method, url, **kwargs) -> response``.
                          If ``None`` the module returns immediately.
        depth:            Scan depth — ``'quick'``, ``'medium'``, or ``'deep'``.

    Returns:
        Standardised result dict with legacy keys:
        ``discovered``, ``total_checked``, ``total_found``, ``issues``.
    """
    start = time.time()
    result = create_result('param_discovery', target_url, depth=depth)

    # ── Legacy keys ──
    result['discovered'] = []
    result['total_checked'] = 0
    result['total_found'] = 0

    if not make_request_fn:
        logger.info('Parameter discovery: no make_request_fn — skipping')
        return finalize_result(result, start)

    params = _get_params_for_depth(depth)
    if not params:
        result['errors'].append('No parameters loaded from wordlist')
        return finalize_result(result, start)

    # ── Get baseline response ──
    baseline = _get_baseline(make_request_fn, target_url)
    if baseline is None:
        result['errors'].append('Failed to get baseline response')
        return finalize_result(result, start)

    result['stats']['total_checks'] = len(params)
    result['total_checked'] = len(params)

    logger.info(
        'Parameter discovery starting for %s — %d params, depth=%s, '
        'baseline status=%d length=%d',
        target_url, len(params), depth,
        baseline['status'], baseline['length'],
    )

    # ── Parallel testing ──
    found_items: list[dict] = []

    try:
        with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
            futures = {
                pool.submit(
                    _test_param, make_request_fn, target_url,
                    param, _CANARY_VALUE, baseline,
                ): param
                for param in params
            }
            for future in as_completed(futures):
                param = futures[future]
                try:
                    item = future.result()
                    result['stats']['successful_checks'] += 1
                    if item:
                        found_items.append(item)
                except Exception as exc:
                    result['stats']['failed_checks'] += 1
                    logger.debug('Param test error for %s: %s', param, exc)
    except Exception as exc:
        result['errors'].append(f'Thread pool execution failed: {exc}')
        logger.error('Parameter discovery pool error: %s', exc, exc_info=True)

    # ── Sort: reflected first, then by category importance ──
    category_order = {'auth': 0, 'injection': 1, 'debug': 2, 'redirect': 3, 'display': 4, 'other': 5}
    found_items.sort(key=lambda x: (
        0 if x['reflected'] else 1,
        category_order.get(x['category'], 9),
        x['name'],
    ))

    # ── Populate results ──
    for item in found_items:
        result['discovered'].append({
            'name': item['name'],
            'reflected': item['reflected'],
            'changes_response': item['changes_response'],
            'evidence': item['evidence'],
        })
        add_finding(result, {
            'type': 'param_discovered',
            'name': item['name'],
            'reflected': item['reflected'],
            'changes_response': item['changes_response'],
            'status_changed': item['status_changed'],
            'length_diff': item['length_diff'],
            'category': item['category'],
            'evidence': item['evidence'],
        })

        severity = _severity_for_param(item)
        if severity in ('high', 'medium'):
            result['issues'].append({
                'severity': severity,
                'title': f'Hidden parameter discovered: {item["name"]}',
                'detail': item['evidence'],
            })

    result['total_found'] = len(found_items)

    logger.info(
        'Parameter discovery complete for %s — %d/%d params discovered '
        '(%d reflected)',
        target_url, result['total_found'], result['total_checked'],
        sum(1 for i in found_items if i['reflected']),
    )

    return finalize_result(result, start)
