"""
Social Reconnaissance Module — Discover social media and external presence.

Finds: social profiles, linked services, open-source repos,
job postings, and other external footprint.

Pure HTML parsing — no external network requests required.

Uses ``_base`` helpers for the standardised return format.
"""
import logging
import re
import time

from ._base import (
    create_result,
    add_finding,
    finalize_result,
    extract_hostname,
    extract_root_domain,
)

logger = logging.getLogger(__name__)

# ── Platform patterns ──────────────────────────────────────────────────────

# (url_pattern, platform_name) — matched against href values in HTML
_SOCIAL_PLATFORMS: list[tuple[str, str]] = [
    (r'(?:https?://)?(?:www\.)?twitter\.com/[\w\-]+', 'Twitter'),
    (r'(?:https?://)?(?:www\.)?x\.com/[\w\-]+', 'X (Twitter)'),
    (r'(?:https?://)?(?:www\.)?facebook\.com/[\w.\-]+', 'Facebook'),
    (r'(?:https?://)?(?:www\.)?linkedin\.com/(?:company|in)/[\w\-]+', 'LinkedIn'),
    (r'(?:https?://)?(?:www\.)?github\.com/[\w\-]+', 'GitHub'),
    (r'(?:https?://)?(?:www\.)?gitlab\.com/[\w\-]+', 'GitLab'),
    (r'(?:https?://)?(?:www\.)?bitbucket\.org/[\w\-]+', 'Bitbucket'),
    (r'(?:https?://)?(?:www\.)?instagram\.com/[\w.\-]+', 'Instagram'),
    (r'(?:https?://)?(?:www\.)?youtube\.com/(?:@|channel/|c/)[\w\-]+', 'YouTube'),
    (r'(?:https?://)?(?:www\.)?tiktok\.com/@[\w.\-]+', 'TikTok'),
    (r'(?:https?://)?(?:www\.)?pinterest\.com/[\w\-]+', 'Pinterest'),
    (r'(?:https?://)?(?:www\.)?reddit\.com/r/[\w\-]+', 'Reddit'),
    (r'(?:https?://)?(?:www\.)?medium\.com/@?[\w\-]+', 'Medium'),
    (r'(?:https?://)?[\w\-]+\.medium\.com', 'Medium'),
    (r'(?:https?://)?(?:www\.)?dev\.to/[\w\-]+', 'Dev.to'),
    (r'(?:https?://)?(?:www\.)?mastodon\.[\w.]+/@[\w]+', 'Mastodon'),
    (r'(?:https?://)?(?:www\.)?threads\.net/@[\w.\-]+', 'Threads'),
    (r'(?:https?://)?(?:www\.)?crunchbase\.com/organization/[\w\-]+', 'Crunchbase'),
    (r'(?:https?://)?(?:www\.)?angel\.co/company/[\w\-]+', 'AngelList'),
    (r'(?:https?://)?(?:www\.)?glassdoor\.com/[\w\-/]+', 'Glassdoor'),
]

# Service indicators (href or src patterns)
_LINKED_SERVICES: list[tuple[str, str]] = [
    (r'slack\.com', 'Slack'),
    (r'discord\.(?:gg|com)', 'Discord'),
    (r'atlassian\.net|jira\.', 'Jira/Atlassian'),
    (r'trello\.com', 'Trello'),
    (r'notion\.so', 'Notion'),
    (r'zendesk\.com', 'Zendesk'),
    (r'intercom\.(?:com|io)', 'Intercom'),
    (r'freshdesk\.com', 'Freshdesk'),
    (r'hubspot\.com', 'HubSpot'),
    (r'mailchimp\.com', 'Mailchimp'),
    (r'docs\.google\.com', 'Google Docs'),
    (r'drive\.google\.com', 'Google Drive'),
    (r'calendly\.com', 'Calendly'),
    (r'zoom\.us', 'Zoom'),
    (r'figma\.com', 'Figma'),
    (r'miro\.com', 'Miro'),
    (r'sentry\.io', 'Sentry'),
    (r'statuspage\.io|status\.', 'Status Page'),
    (r'teachable\.com', 'Teachable'),
]

# Compiled regexes (built once)
_SOCIAL_RES = [(re.compile(p, re.IGNORECASE), name) for p, name in _SOCIAL_PLATFORMS]
_SERVICE_RES = [(re.compile(p, re.IGNORECASE), name) for p, name in _LINKED_SERVICES]

# HTML href extractor
_HREF_RE = re.compile(r'href\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)
_SRC_RE = re.compile(r'src\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE)

# OpenGraph / schema.org patterns
_OG_SITE_NAME_RE = re.compile(
    r'<meta\s+[^>]*property\s*=\s*["\']og:site_name["\']\s+[^>]*content\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE,
)
_SCHEMA_SOCIAL_RE = re.compile(
    r'"sameAs"\s*:\s*\[([^\]]+)\]',
    re.IGNORECASE,
)
_SCHEMA_URL_RE = re.compile(r'"(https?://[^"]+)"')

# Repository path patterns in HTML (e.g. GitHub links that look like repos)
_REPO_RE = re.compile(
    r'(?:https?://)?(?:www\.)?github\.com/([\w\-]+/[\w.\-]+)',
    re.IGNORECASE,
)


# ── Extractors ─────────────────────────────────────────────────────────────

def _extract_social_profiles(body: str) -> list[dict]:
    """Find social media profile links in HTML."""
    profiles: list[dict] = []
    seen_urls: set[str] = set()
    urls = set(_HREF_RE.findall(body))
    for url in urls:
        for regex, platform in _SOCIAL_RES:
            if regex.search(url):
                normalised = url.strip().rstrip('/')
                if normalised not in seen_urls:
                    seen_urls.add(normalised)
                    profiles.append({
                        'platform': platform,
                        'url': normalised,
                        'confidence': 'high',
                    })
                break
    return profiles


def _extract_schema_social(body: str) -> list[dict]:
    """Extract social links from schema.org ``sameAs`` arrays."""
    profiles: list[dict] = []
    for block in _SCHEMA_SOCIAL_RE.finditer(body):
        for url_match in _SCHEMA_URL_RE.finditer(block.group(1)):
            url = url_match.group(1).rstrip('/')
            platform = 'Unknown'
            for regex, name in _SOCIAL_RES:
                if regex.search(url):
                    platform = name
                    break
            profiles.append({
                'platform': platform,
                'url': url,
                'confidence': 'high',
            })
    return profiles


def _extract_linked_services(body: str) -> list[str]:
    """Detect third-party services referenced in the page."""
    services: set[str] = set()
    all_urls = set(_HREF_RE.findall(body)) | set(_SRC_RE.findall(body))
    for url in all_urls:
        for regex, service in _SERVICE_RES:
            if regex.search(url):
                services.add(service)
    return sorted(services)


def _extract_repositories(body: str) -> list[str]:
    """Find GitHub-style repository references."""
    repos: set[str] = set()
    for m in _REPO_RE.finditer(body):
        repo_path = m.group(1).rstrip('/')
        # Filter out profile-only links (no slash → not a repo)
        if '/' in repo_path:
            repos.add(f'https://github.com/{repo_path}')
    return sorted(repos)


def _extract_og_site_name(body: str) -> str | None:
    """Get og:site_name if present."""
    m = _OG_SITE_NAME_RE.search(body)
    return m.group(1) if m else None


# ── Main Entry Point ──────────────────────────────────────────────────────

def run_social_recon(target_url: str, response_body: str = '') -> dict:
    """Discover social media and external presence from HTML content.

    Args:
        target_url:    Target URL.
        response_body: HTML body of the target page (optional).

    Returns:
        Standardised result dict with legacy keys:
        ``social_profiles``, ``linked_services``, ``repositories``,
        ``total_found``, ``issues``.
    """
    start = time.time()
    result = create_result('social_recon', target_url)

    hostname = extract_hostname(target_url)
    root_domain = extract_root_domain(hostname)

    # Legacy top-level keys
    result['social_profiles'] = []
    result['linked_services'] = []
    result['repositories'] = []
    result['total_found'] = 0

    if not root_domain:
        result['errors'].append('Could not extract root domain from target URL')
        return finalize_result(result, start)

    logger.info('Starting social recon for %s', root_domain)
    checks = 0

    if not response_body:
        result['errors'].append('No HTML body provided — social recon requires page content')
        return finalize_result(result, start)

    # 1. Social profiles from hrefs
    checks += 1
    try:
        profiles = _extract_social_profiles(response_body)
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        profiles = []
        result['errors'].append(f'Social profile extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 2. Schema.org sameAs profiles
    checks += 1
    try:
        schema_profiles = _extract_schema_social(response_body)
        result['stats']['successful_checks'] += 1
        # Merge without duplicates
        seen = {p['url'] for p in profiles}
        for sp in schema_profiles:
            if sp['url'] not in seen:
                profiles.append(sp)
                seen.add(sp['url'])
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'Schema.org extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 3. Linked services
    checks += 1
    try:
        services = _extract_linked_services(response_body)
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        services = []
        result['errors'].append(f'Service detection error: {exc}')
        result['stats']['failed_checks'] += 1

    # 4. Repositories
    checks += 1
    try:
        repos = _extract_repositories(response_body)
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        repos = []
        result['errors'].append(f'Repository extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    # 5. OG site name
    checks += 1
    try:
        site_name = _extract_og_site_name(response_body)
        if site_name:
            result['metadata']['og_site_name'] = site_name
        result['stats']['successful_checks'] += 1
    except Exception as exc:  # noqa: BLE001
        result['errors'].append(f'OG extraction error: {exc}')
        result['stats']['failed_checks'] += 1

    result['stats']['total_checks'] = checks

    # Populate legacy keys
    result['social_profiles'] = profiles
    result['linked_services'] = services
    result['repositories'] = repos
    result['total_found'] = len(profiles) + len(services) + len(repos)

    # Findings
    for profile in profiles:
        add_finding(result, {
            'type': 'social_profile',
            'platform': profile['platform'],
            'url': profile['url'],
            'confidence': profile['confidence'],
        })
    for svc in services:
        add_finding(result, {
            'type': 'linked_service',
            'service': svc,
        })
    for repo in repos:
        add_finding(result, {
            'type': 'repository',
            'url': repo,
        })

    # Security observations
    if any(p['platform'] == 'GitHub' for p in profiles):
        result['issues'].append(
            'GitHub profile linked — check for exposed source code or secrets'
        )
    if any(s in services for s in ('Jira/Atlassian', 'Sentry', 'Status Page')):
        result['issues'].append(
            'Internal development/operations service detected in public page'
        )

    logger.info(
        'Social recon complete for %s: %d profiles, %d services, %d repos',
        root_domain, len(profiles), len(services), len(repos),
    )
    return finalize_result(result, start)
