"""
GitHub Intelligence Module.

Searches GitHub code for:
- Leaked secrets / hardcoded credentials referencing the target
- API endpoints and internal URLs
- Configuration files mentioning the target domain

Requires GITHUB_TOKEN environment variable.
"""
import logging
import re
import time
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

GITHUB_API_BASE = 'https://api.github.com'
REQUEST_TIMEOUT = 15

# Patterns that hint at sensitive data near the target domain
SENSITIVE_PATTERNS = [
    (re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*\S+', re.I), 'hardcoded_password'),
    (re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*\S+', re.I), 'api_key_leak'),
    (re.compile(r'(?:secret|token)\s*[=:]\s*\S+', re.I), 'secret_leak'),
    (re.compile(r'(?:aws_access_key_id|aws_secret)\s*[=:]\s*\S+', re.I), 'aws_key_leak'),
    (re.compile(r'(?:jdbc:|mysql://|postgres://|mongodb://)\S+', re.I), 'connection_string'),
    (re.compile(r'(?:Bearer|Basic)\s+[A-Za-z0-9+/=]{20,}', re.I), 'auth_token'),
]


def _get_token() -> str:
    """Retrieve GitHub token."""
    try:
        from django.conf import settings
        return getattr(settings, 'GITHUB_TOKEN', '') or ''
    except Exception:
        import os
        return os.getenv('GITHUB_TOKEN', '')


def run_github_intel(target: str, *, depth: str = 'medium',
                     make_request_fn=None) -> Optional[dict]:
    """Search GitHub code for intelligence about the target.

    Args:
        target: Target URL or domain.
        depth: Scan depth.

    Returns:
        Result dict with findings, or None if no token configured.
    """
    token = _get_token()
    if not token:
        logger.debug('GitHub Intel: No GITHUB_TOKEN configured, skipping')
        return None

    start_time = time.time()
    result = {
        'module': 'github_intel',
        'findings': [],
        'code_results': [],
        'repos': [],
        'errors': [],
        'stats': {'queries': 0, 'results_found': 0, 'leaks_found': 0},
    }

    hostname = urlparse(target).hostname or target
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.v3+json',
    }

    _search_code(hostname, headers, result, depth)

    result['stats']['duration_seconds'] = round(time.time() - start_time, 3)
    return result


def _search_code(hostname: str, headers: dict, result: dict, depth: str):
    """Search GitHub code index for the target domain."""
    per_page = 30 if depth == 'shallow' else 100

    try:
        resp = requests.get(
            f'{GITHUB_API_BASE}/search/code',
            params={'q': hostname, 'per_page': per_page},
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        result['stats']['queries'] += 1

        if resp.status_code == 200:
            data = resp.json()
            items = data.get('items', [])
            result['stats']['results_found'] = data.get('total_count', len(items))

            seen_repos = set()
            for item in items:
                repo = item.get('repository', {})
                repo_full = repo.get('full_name', '')

                code_entry = {
                    'name': item.get('name', ''),
                    'path': item.get('path', ''),
                    'repo': repo_full,
                    'url': item.get('html_url', ''),
                    'score': item.get('score', 0),
                }
                result['code_results'].append(code_entry)

                if repo_full and repo_full not in seen_repos:
                    seen_repos.add(repo_full)
                    result['repos'].append({
                        'full_name': repo_full,
                        'private': repo.get('private', False),
                        'description': repo.get('description', ''),
                    })

                # Check for sensitive patterns in the file content snippet
                text_matches = item.get('text_matches', [])
                for tm in text_matches:
                    fragment = tm.get('fragment', '')
                    _check_sensitive(fragment, code_entry, result)

                # Also flag based on filename
                name_lower = item.get('name', '').lower()
                if any(k in name_lower for k in ('.env', 'credentials', 'secrets', '.pem', '.key')):
                    result['findings'].append({
                        'type': 'sensitive_file',
                        'file': item.get('name', ''),
                        'path': item.get('path', ''),
                        'repo': repo_full,
                        'url': item.get('html_url', ''),
                        'source': 'github',
                    })
                    result['stats']['leaks_found'] += 1

        elif resp.status_code == 401:
            result['errors'].append('Invalid GitHub token')
        elif resp.status_code == 422:
            result['errors'].append('GitHub code search validation error')
        elif resp.status_code == 403:
            result['errors'].append('GitHub API rate limit exceeded or forbidden')
        else:
            result['errors'].append(f'GitHub search error {resp.status_code}')

    except requests.RequestException as e:
        result['errors'].append(f'GitHub code search failed: {str(e)}')


def _check_sensitive(fragment: str, code_entry: dict, result: dict):
    """Check a code fragment for sensitive patterns."""
    if not fragment:
        return
    for pattern, leak_type in SENSITIVE_PATTERNS:
        if pattern.search(fragment):
            result['findings'].append({
                'type': leak_type,
                'file': code_entry.get('name', ''),
                'repo': code_entry.get('repo', ''),
                'url': code_entry.get('url', ''),
                'source': 'github',
            })
            result['stats']['leaks_found'] += 1
            break
