"""
Google Dorking / Search Engine Intelligence Module.

Benchmarks: GoogleDorker, Jhaddix TBHM dorking methodology,
            PentestTools dork engine.

Generates and executes targeted search engine dork queries to discover:
  - Exposed sensitive files (env, sql, bak, config, log)
  - Admin / login panels
  - Subdomains listed in search engine indexes
  - Sensitive parameter patterns
  - Third-party leaks (Pastebin, GitHub, GitLab, Trello)

Uses Bing (HTML scraping) as primary engine with DuckDuckGo HTML as
fallback — neither requires an API key.  Google is NOT scraped directly
to avoid instant captcha gating; results are supplemented via
DuckDuckGo's ``!g`` / instant-answers JSON API where available.

Depth tiering:
  shallow  — site: + basic filetype dorks (10 queries)
  medium   — + inurl/intitle/intext dorks (25 queries)
  deep     — + third-party leaks, GitHub, Pastebin, extended (45 queries)
"""
from __future__ import annotations

import logging
import re
import time
import urllib.parse
from typing import Callable, Optional

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Dork catalogue ────────────────────────────────────────────────────────

# Each entry: (category, severity, dork_template, description)
# Templates use {domain} placeholder.
_DORK_CATALOGUE: list[tuple[str, str, str, str]] = [
    # ── Core site: queries ─────────────────────────────────────────────
    ('subdomain_enum', 'info', 'site:*.{domain}', 'Index of all subdomains'),
    ('site_index',     'info', 'site:{domain}',   'All indexed pages'),

    # ── Sensitive file extensions ──────────────────────────────────────
    ('sensitive_file', 'high',   'site:{domain} filetype:env',    '.env files exposed'),
    ('sensitive_file', 'high',   'site:{domain} filetype:sql',    'SQL dump files exposed'),
    ('sensitive_file', 'high',   'site:{domain} filetype:log',    'Log files exposed'),
    ('sensitive_file', 'high',   'site:{domain} filetype:bak',    'Backup files exposed'),
    ('sensitive_file', 'medium', 'site:{domain} filetype:config', 'Config files exposed'),
    ('sensitive_file', 'medium', 'site:{domain} filetype:xml',    'XML files in index'),
    ('sensitive_file', 'medium', 'site:{domain} filetype:json',   'JSON files in index'),
    ('sensitive_file', 'medium', 'site:{domain} filetype:pdf',    'PDF documents exposed'),
    ('sensitive_file', 'low',    'site:{domain} filetype:doc',    'Word documents exposed'),
    ('sensitive_file', 'low',    'site:{domain} filetype:xls',    'Excel spreadsheets exposed'),
    ('sensitive_file', 'medium', 'site:{domain} filetype:txt',    'Text files in index'),

    # ── Admin / auth panels ───────────────────────────────────────────
    ('admin_panel', 'high', 'site:{domain} inurl:admin',       'Admin path in URL'),
    ('admin_panel', 'high', 'site:{domain} inurl:login',       'Login path in URL'),
    ('admin_panel', 'high', 'site:{domain} inurl:dashboard',   'Dashboard path in URL'),
    ('admin_panel', 'medium', 'site:{domain} inurl:panel',     'Panel path in URL'),
    ('admin_panel', 'medium', 'site:{domain} inurl:console',   'Console path in URL'),
    ('admin_panel', 'medium', 'site:{domain} inurl:manage',    'Manage path in URL'),
    ('admin_panel', 'medium', 'site:{domain} inurl:portal',    'Portal path in URL'),
    ('admin_panel', 'medium', 'site:{domain} inurl:cpanel',    'cPanel interface'),
    ('admin_panel', 'medium', 'site:{domain} inurl:wp-admin',  'WordPress admin'),

    # ── Interesting URL parameters ────────────────────────────────────
    ('param_discovery', 'medium', 'site:{domain} ext:php inurl:?',  'PHP pages with parameters'),
    ('param_discovery', 'medium', 'site:{domain} ext:asp inurl:?',  'ASP pages with parameters'),
    ('param_discovery', 'medium', 'site:{domain} ext:aspx inurl:?', 'ASPX pages with parameters'),
    ('param_discovery', 'medium', 'site:{domain} ext:jsp inurl:?',  'JSP pages with parameters'),

    # ── Error / info disclosure ───────────────────────────────────────
    ('info_disclosure', 'medium', 'site:{domain} intext:"sql syntax near"',       'SQL error exposure'),
    ('info_disclosure', 'medium', 'site:{domain} intext:"mysql_fetch_array"',     'PHP MySQL error'),
    ('info_disclosure', 'medium', 'site:{domain} intext:"Warning: include()"',    'PHP include error'),
    ('info_disclosure', 'high',   'site:{domain} intitle:"index of"',             'Directory listing'),
    ('info_disclosure', 'medium', 'site:{domain} intitle:"phpinfo()"',            'PHPInfo exposed'),
    ('info_disclosure', 'high',   'site:{domain} intext:"Not a valid MySQL"',     'DB error disclosed'),
    ('info_disclosure', 'medium', 'site:{domain} intext:"Stack Trace"',           'Stack trace exposed'),
    ('info_disclosure', 'medium', 'site:{domain} intext:"Traceback (most recent"','Python traceback'),

    # ── API / integration endpoints ───────────────────────────────────
    ('api_discovery', 'medium', 'site:{domain} inurl:api',     'API path in URL'),
    ('api_discovery', 'medium', 'site:{domain} inurl:v1',      'Versioned API path'),
    ('api_discovery', 'medium', 'site:{domain} inurl:swagger', 'Swagger endpoint'),
    ('api_discovery', 'medium', 'site:{domain} inurl:graphql', 'GraphQL endpoint'),

    # ── Third-party leaks (deep only) ─────────────────────────────────
    ('third_party_leak', 'critical', 'site:pastebin.com {domain}',  '{domain} leaked on Pastebin'),
    ('third_party_leak', 'critical', 'site:github.com {domain}',    '{domain} found on GitHub'),
    ('third_party_leak', 'critical', 'site:gitlab.com {domain}',    '{domain} found on GitLab'),
    ('third_party_leak', 'high',     'site:trello.com {domain}',    '{domain} Trello cards'),
    ('third_party_leak', 'high',     'site:jira.atlassian.com {domain}', '{domain} Jira issues'),
    ('third_party_leak', 'high',     'site:docs.google.com {domain}',    'Google Docs leak'),
    ('third_party_leak', 'high',     'site:s3.amazonaws.com {domain}',   'S3 data exposure'),
    ('third_party_leak', 'medium',   'site:linkedin.com inurl:"company" {domain}', 'LinkedIn org page'),
    ('third_party_leak', 'medium',   '"{domain}" password',              'Domain + password'),
    ('third_party_leak', 'critical', '"{domain}" api_key OR api_secret', 'API key exposure'),
    ('third_party_leak', 'critical', '"{domain}" secret OR token',       'Secret/token exposure'),
    ('third_party_leak', 'high',     '"{domain}" username AND password',  'Credential exposure'),
]

# Depth → number of dorks to execute
_DEPTH_LIMITS = {
    'shallow': 10,
    'medium':  25,
    'deep':    len(_DORK_CATALOGUE),
}

# ── URL extraction regex ──────────────────────────────────────────────────
_BING_RESULT_URL_RE = re.compile(r'<cite[^>]*>([^<]+)</cite>', re.IGNORECASE)
_HREF_RE = re.compile(r'href="(https?://[^"&]+)"', re.IGNORECASE)
_URL_RE = re.compile(
    r'https?://[a-zA-Z0-9.\-_/%?&=#@:+]+',
    re.IGNORECASE,
)


# ── Search engine query helpers ───────────────────────────────────────────

def _bing_search(query: str, make_req: Callable, max_results: int = 15) -> list[str]:
    """
    Query Bing Web Search (HTML, no API key).

    Returns a list of result URLs (up to *max_results*).
    """
    encoded = urllib.parse.quote_plus(query)
    url = f'https://www.bing.com/search?q={encoded}&count={max_results}'
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/122.0.0.0 Safari/537.36'
        ),
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }
    try:
        resp = make_req('GET', url, headers=headers, timeout=12)
        if resp.status_code != 200:
            return []
        # Extract <cite> blocks (Bing puts URLs there)
        cites = _BING_RESULT_URL_RE.findall(resp.text)
        # Also grab href attributes from result links
        hrefs = [h for h in _HREF_RE.findall(resp.text)
                 if 'bing.com' not in h and 'microsoft.com' not in h]
        urls = list({*cites, *hrefs})[:max_results]
        return urls
    except Exception as exc:
        logger.debug(f'Bing query failed for "{query[:60]}": {exc}')
        return []


def _ddg_search(query: str, make_req: Callable, max_results: int = 10) -> list[str]:
    """
    DuckDuckGo HTML search fallback.

    Returns a list of result URLs.
    """
    encoded = urllib.parse.quote_plus(query)
    url = f'https://html.duckduckgo.com/html/?q={encoded}'
    headers = {
        'User-Agent': (
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) '
            'Gecko/20100101 Firefox/115.0'
        ),
    }
    try:
        resp = make_req('GET', url, headers=headers, timeout=12)
        if resp.status_code != 200:
            return []
        hrefs = [h for h in _HREF_RE.findall(resp.text)
                 if 'duckduckgo.com' not in h]
        return hrefs[:max_results]
    except Exception as exc:
        logger.debug(f'DDG query failed for "{query[:60]}": {exc}')
        return []


# ── Core public function ──────────────────────────────────────────────────

def run_google_dorking(
    target_url: str,
    depth: str = 'medium',
    make_request_fn: Optional[Callable] = None,
) -> dict:
    """
    Execute search engine dork queries against *target_url*.

    Parameters
    ----------
    target_url      : Full URL or bare hostname.
    depth           : 'shallow' | 'medium' | 'deep'.
    make_request_fn : Callable(method, url, **kwargs) → requests.Response.
                      If omitted, uses plain ``requests``.

    Returns
    -------
    Standardised recon_data dict with keys:
      - findings        : list[dict] — vulnerability/info findings
      - dorks_executed  : list[dict] — {dork, category, severity, urls}
      - total_urls      : int
      - categories      : dict[str, list[str]]
      - errors/stats
    """
    import requests as _requests

    result = create_result('google_dorking', target_url)
    result['dorks_executed'] = []
    result['total_urls'] = 0
    result['categories'] = {}

    if make_request_fn is None:
        def make_request_fn(method: str, url: str, **kw):
            kw.setdefault('timeout', 12)
            return _requests.request(method, url, **kw)

    root_domain = extract_root_domain(target_url)
    if not root_domain:
        result['errors'].append('Could not extract root domain')
        return finalize_result(result)

    limit = _DEPTH_LIMITS.get(depth, _DEPTH_LIMITS['medium'])
    dork_subset = _DORK_CATALOGUE[:limit]

    all_urls: set[str] = set()
    category_urls: dict[str, list[str]] = {}

    for idx, (category, severity, dork_tpl, description) in enumerate(dork_subset):
        dork_query = dork_tpl.format(domain=root_domain)

        # Alternate primary engine to reduce rate-limit risk
        if idx % 3 == 0:
            urls = _bing_search(dork_query, make_request_fn)
            if not urls:
                urls = _ddg_search(dork_query, make_request_fn)
        else:
            urls = _bing_search(dork_query, make_request_fn)

        result['dorks_executed'].append({
            'dork':        dork_query,
            'category':    category,
            'severity':    severity,
            'description': description.format(domain=root_domain),
            'urls_found':  len(urls),
            'urls':        urls[:10],
        })

        if urls:
            all_urls.update(urls)
            category_urls.setdefault(category, []).extend(urls)
            sev_map = {
                'critical': 'critical',
                'high':     'high',
                'medium':   'medium',
                'low':      'low',
            }
            dork_severity = sev_map.get(severity, 'info')
            if dork_severity not in ('info', 'low'):
                add_finding(
                    result,
                    title=f'Dork hit: {description.format(domain=root_domain)}',
                    severity=dork_severity,
                    description=(
                        f'Search engine dork "{dork_query}" returned '
                        f'{len(urls)} result(s). First URL: {urls[0]}'
                    ),
                    category=category,
                    evidence={'dork': dork_query, 'sample_urls': urls[:3]},
                )

        # Polite delay between queries (avoid rate-limiting)
        time.sleep(2.0 if depth != 'shallow' else 1.0)

    result['total_urls'] = len(all_urls)
    result['categories'] = {cat: list(set(urls)) for cat, urls in category_urls.items()}

    # Summarise third-party leaks as a single finding if found
    leak_urls = category_urls.get('third_party_leak', [])
    if leak_urls:
        add_finding(
            result,
            title='Third-party data leaks found via search engines',
            severity='critical',
            description=(
                f'Search engine queries found {len(leak_urls)} URL(s) '
                f'on third-party sites (Pastebin, GitHub, etc.) '
                f'potentially exposing {root_domain} data.'
            ),
            category='information_disclosure',
            evidence={'urls': leak_urls[:10]},
        )

    logger.info(
        f'Google dorking [{root_domain}]: {len(result["dorks_executed"])} dorks, '
        f'{result["total_urls"]} unique URLs'
    )
    return finalize_result(result)
