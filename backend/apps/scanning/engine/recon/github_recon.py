"""
GitHub Reconnaissance — Discover leaked secrets, code, and infrastructure
details from public GitHub/GitLab repositories.

Techniques (no API key required for basic search):
    • GitHub code search via web scraping (rate-limited)
    • GitHub commit message search
    • Common dork patterns for secrets, configs, credentials
    • GitLab snippets search
    • .git directory exposure check on target

This module does NOT require a GitHub API token for basic dorking.
Results are limited but still highly valuable for finding:
    - Hardcoded API keys and tokens
    - Internal hostnames and IPs
    - Database connection strings
    - AWS/Azure/GCP credentials
    - Configuration files

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time
from urllib.parse import quote

import requests

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Dork Templates ────────────────────────────────────────────────────────────
# {domain} is replaced with the target domain

_GITHUB_DORKS = [
    # Credentials & secrets
    '"{domain}" password',
    '"{domain}" secret',
    '"{domain}" api_key',
    '"{domain}" apikey',
    '"{domain}" token',
    '"{domain}" AWS_SECRET',
    '"{domain}" PRIVATE KEY',
    # Config files
    '"{domain}" filename:.env',
    '"{domain}" filename:.htpasswd',
    '"{domain}" filename:wp-config.php',
    '"{domain}" filename:configuration.php',
    '"{domain}" filename:config.php',
    '"{domain}" filename:web.config',
    '"{domain}" filename:appsettings.json',
    '"{domain}" filename:.gitignore',
    # Infrastructure
    '"{domain}" filename:docker-compose',
    '"{domain}" filename:Dockerfile',
    '"{domain}" filename:terraform',
    '"{domain}" filename:ansible',
    # Database
    '"{domain}" filename:.sql',
    '"{domain}" jdbc:',
    '"{domain}" mongodb://',
    '"{domain}" redis://',
]

# Dorks for finding the org's repos directly
_ORG_DORKS = [
    'org:{domain_no_tld}',
]


def _check_git_exposure(target_url: str) -> dict | None:
    """Check if .git directory is exposed on the target web server."""
    git_paths = [
        '/.git/config',
        '/.git/HEAD',
        '/.git/index',
    ]
    for path in git_paths:
        try:
            url = target_url.rstrip('/') + path
            resp = requests.get(url, timeout=8, verify=False, allow_redirects=False,
                                headers={'User-Agent': 'SafeWeb-AI/2.0'})
            if resp.status_code == 200:
                body = resp.text.lower()
                # Verify it's actually git content
                if path.endswith('config') and ('[core]' in body or '[remote' in body):
                    return {
                        'exposed_path': path,
                        'status_code': resp.status_code,
                        'content_preview': resp.text[:500],
                        'severity': 'critical',
                    }
                elif path.endswith('HEAD') and 'ref:' in body:
                    return {
                        'exposed_path': path,
                        'status_code': resp.status_code,
                        'content_preview': resp.text[:200],
                        'severity': 'critical',
                    }
        except Exception:
            continue
    return None


def _search_github_code(domain: str, dork: str) -> list[dict]:
    """Search GitHub code via the web interface (no API key needed).

    Note: GitHub rate-limits unauthenticated searches aggressively.
    This function makes a best-effort attempt.
    """
    results = []
    try:
        query = dork.format(domain=domain)
        url = f'https://github.com/search?q={quote(query)}&type=code'
        resp = requests.get(url, timeout=15, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml',
        })
        if resp.status_code == 200:
            # Extract repo links from search results
            repo_pattern = r'href="(/[^/]+/[^/]+/blob/[^"]+)"'
            matches = re.findall(repo_pattern, resp.text)
            seen = set()
            for match in matches[:10]:  # Cap per dork
                if match not in seen:
                    seen.add(match)
                    results.append({
                        'url': f'https://github.com{match}',
                        'dork': query,
                        'source': 'github_code',
                    })

        # Be respectful — don't hammer GitHub
        time.sleep(2)
    except Exception as e:
        logger.debug('GitHub code search failed for dork "%s": %s', dork, e)
    return results


def _search_github_repos(domain: str) -> list[dict]:
    """Search for GitHub repositories related to the domain."""
    results = []
    try:
        query = quote(domain)
        url = f'https://api.github.com/search/repositories?q={query}&per_page=10&sort=updated'
        resp = requests.get(url, timeout=10, headers={
            'User-Agent': 'SafeWeb-AI/2.0',
            'Accept': 'application/vnd.github.v3+json',
        })
        if resp.status_code == 200:
            data = resp.json()
            for repo in data.get('items', [])[:10]:
                results.append({
                    'name': repo.get('full_name', ''),
                    'url': repo.get('html_url', ''),
                    'description': repo.get('description', ''),
                    'language': repo.get('language', ''),
                    'stars': repo.get('stargazers_count', 0),
                    'updated': repo.get('updated_at', ''),
                    'visibility': 'public',
                })
    except Exception as e:
        logger.debug('GitHub repo search failed: %s', e)
    return results


# ── Main Entry Point ─────────────────────────────────────────────────────────

def run_github_recon(target_url: str) -> dict:
    """
    Perform GitHub/GitLab reconnaissance for the target.

    Returns standardised dict plus legacy keys:
        git_exposed, github_repos, code_results, dorks_searched
    """
    start = time.time()
    result = create_result('github_recon', target_url, 'deep')
    hostname = extract_hostname(target_url)
    domain = extract_root_domain(hostname)

    if not domain:
        result['errors'].append('Could not extract domain from target URL')
        return finalize_result(result, start)

    # 1. Check .git exposure on target (critical finding)
    result['stats']['total_checks'] += 1
    git_exposure = _check_git_exposure(target_url)
    if git_exposure:
        result['stats']['successful_checks'] += 1
        add_finding(result, {
            'type': 'git_exposure',
            'severity': 'critical',
            **git_exposure,
        })
    else:
        result['stats']['successful_checks'] += 1  # No exposure is a "success"

    # 2. Search for related GitHub repositories
    result['stats']['total_checks'] += 1
    repos = _search_github_repos(domain)
    if repos:
        result['stats']['successful_checks'] += 1
        add_finding(result, {
            'type': 'related_repositories',
            'total': len(repos),
            'repos': repos,
        })
    else:
        result['stats']['failed_checks'] += 1

    # 3. GitHub dork searches (limited to avoid rate limiting)
    # Select subset of most impactful dorks
    high_priority_dorks = _GITHUB_DORKS[:8]  # Top 8 dorks
    all_code_results = []

    for dork in high_priority_dorks:
        result['stats']['total_checks'] += 1
        try:
            code_results = _search_github_code(domain, dork)
            all_code_results.extend(code_results)
            if code_results:
                result['stats']['successful_checks'] += 1
            else:
                result['stats']['failed_checks'] += 1
        except Exception as e:
            result['stats']['failed_checks'] += 1
            logger.debug('Dork search failed: %s', e)

    if all_code_results:
        # Deduplicate by URL
        seen = set()
        unique = []
        for r in all_code_results:
            if r['url'] not in seen:
                seen.add(r['url'])
                unique.append(r)

        add_finding(result, {
            'type': 'code_search_results',
            'total': len(unique),
            'results': unique[:50],
            'dorks_with_results': len(set(r['dork'] for r in unique)),
        })

    # Summary finding
    add_finding(result, {
        'type': 'summary',
        'git_exposed': git_exposure is not None,
        'repos_found': len(repos),
        'code_leaks_found': len(all_code_results),
        'dorks_searched': len(high_priority_dorks),
    })

    # Legacy keys
    result['git_exposed'] = git_exposure
    result['github_repos'] = repos
    result['code_results'] = all_code_results[:50]
    result['dorks_searched'] = len(high_priority_dorks)

    logger.info(
        'GitHub recon: git_exposed=%s, %d repos, %d code results for %s',
        git_exposure is not None, len(repos), len(all_code_results), domain,
    )

    return finalize_result(result, start)
