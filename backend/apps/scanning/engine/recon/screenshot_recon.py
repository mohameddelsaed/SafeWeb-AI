"""
Screenshot Recon — Playwright-based visual reconnaissance.

Takes screenshots and classifies page types heuristically
(login, admin, error, API explorer, maintenance, normal).
"""
import hashlib
import logging
import re
import time

from ._base import create_result, add_finding, finalize_result

logger = logging.getLogger(__name__)

# Page type classification keywords
PAGE_CLASSIFIERS = {
    'login_page': {
        'title_keywords': ['login', 'sign in', 'log in', 'signin', 'authenticate'],
        'body_indicators': ['type="password"', 'input[type=password]'],
    },
    'admin_panel': {
        'title_keywords': ['admin', 'dashboard', 'panel', 'console', 'control panel', 'management'],
        'body_indicators': [],
    },
    'api_explorer': {
        'title_keywords': ['swagger', 'redoc', 'graphql', 'playground', 'api docs', 'api explorer'],
        'body_indicators': ['swagger-ui', 'redoc', 'graphiql', 'graphql-playground'],
    },
    'error_page': {
        'title_keywords': ['error', 'not found', '404', '500', '403', 'forbidden'],
        'body_indicators': ['stack trace', 'traceback', 'exception'],
    },
    'maintenance': {
        'title_keywords': ['maintenance', 'coming soon', 'under construction', 'temporarily unavailable'],
        'body_indicators': [],
    },
}


def run_screenshot_recon(target_url: str, depth: str = 'medium',
                         extra_urls: list = None, make_request_fn=None,
                         **kwargs) -> dict:
    """
    Playwright-based visual recon with page type classification.

    shallow : Classify target URL only (no screenshot)
    medium  : + up to 5 extra URLs
    deep    : + up to 25 extra URLs
    """
    start = time.time()
    result = create_result('screenshot_recon', target_url, depth)

    urls_to_check = [target_url]
    if extra_urls:
        if depth == 'shallow':
            pass  # Only target URL
        elif depth == 'medium':
            urls_to_check.extend(extra_urls[:5])
        else:
            urls_to_check.extend(extra_urls[:25])

    # Deduplicate
    urls_to_check = list(dict.fromkeys(urls_to_check))

    classified_pages = []
    content_hashes = {}
    duplicates = []

    for url in urls_to_check:
        result['stats']['total_checks'] += 1

        if not make_request_fn:
            result['errors'].append('No HTTP client provided')
            break

        try:
            response = make_request_fn('GET', url, timeout=15)
            if not response or not response.text:
                result['stats']['failed_checks'] += 1
                continue

            body = response.text
            status = response.status_code

            # Extract title and h1
            title = ''
            title_match = re.search(r'<title[^>]*>(.*?)</title>', body,
                                    re.IGNORECASE | re.DOTALL)
            if title_match:
                title = title_match.group(1).strip()[:200]

            h1_text = ''
            h1_match = re.search(r'<h1[^>]*>(.*?)</h1>', body,
                                 re.IGNORECASE | re.DOTALL)
            if h1_match:
                h1_text = re.sub(r'<[^>]+>', '', h1_match.group(1)).strip()[:200]

            # Classify page
            page_type = _classify_page(title, body, status)

            # Content hash for dedup
            normalized_body = re.sub(r'\s+', ' ', body).strip()
            content_hash = hashlib.sha256(normalized_body.encode('utf-8', errors='ignore')).hexdigest()[:16]

            # Check for duplicate
            is_duplicate = False
            dup_key = f'{title}|{content_hash}'
            if dup_key in content_hashes:
                is_duplicate = True
                duplicates.append({
                    'url': url,
                    'duplicate_of': content_hashes[dup_key],
                })
            else:
                content_hashes[dup_key] = url

            page_info = {
                'url': url,
                'title': title,
                'h1': h1_text,
                'status_code': status,
                'page_type': page_type,
                'content_hash': content_hash,
                'is_duplicate': is_duplicate,
            }
            classified_pages.append(page_info)
            result['stats']['successful_checks'] += 1

        except Exception as exc:
            result['stats']['failed_checks'] += 1
            logger.debug('Screenshot recon failed for %s: %s', url, exc)

    # Add findings
    if classified_pages:
        add_finding(result, {
            'type': 'page_classification',
            'severity': 'info',
            'title': f'Classified {len(classified_pages)} pages',
            'details': classified_pages,
        })

    # Highlight interesting pages
    [p for p in classified_pages if p['page_type'] == 'login_page']
    admin_pages = [p for p in classified_pages if p['page_type'] == 'admin_panel']
    api_pages = [p for p in classified_pages if p['page_type'] == 'api_explorer']
    error_pages = [p for p in classified_pages if p['page_type'] == 'error_page']

    if admin_pages:
        add_finding(result, {
            'type': 'admin_panel_found',
            'severity': 'medium',
            'title': f'{len(admin_pages)} admin panel(s) discovered',
            'details': admin_pages,
        })

    if api_pages:
        add_finding(result, {
            'type': 'api_explorer_found',
            'severity': 'medium',
            'title': f'{len(api_pages)} API explorer(s) discovered',
            'details': api_pages,
        })

    if error_pages:
        add_finding(result, {
            'type': 'error_pages_found',
            'severity': 'low',
            'title': f'{len(error_pages)} error page(s) found',
            'details': error_pages,
        })

    if duplicates:
        add_finding(result, {
            'type': 'duplicate_pages',
            'severity': 'info',
            'title': f'{len(duplicates)} duplicate page(s) detected',
            'details': duplicates,
        })

    return finalize_result(result, start)


def _classify_page(title: str, body: str, status_code: int) -> str:
    """Classify page type based on title, body, and status code."""
    title_lower = title.lower()
    body_lower = body.lower()

    # Error page by status code
    if status_code >= 400:
        return 'error_page'

    for page_type, classifier in PAGE_CLASSIFIERS.items():
        # Check title keywords
        for kw in classifier['title_keywords']:
            if kw in title_lower:
                return page_type

        # Check body indicators
        for indicator in classifier['body_indicators']:
            if indicator.lower() in body_lower:
                return page_type

    return 'normal'
