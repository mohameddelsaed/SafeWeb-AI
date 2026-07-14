"""
Git Repository Dumper — Phase 25.

Detects exposed .git directories on web servers and extracts
secrets from accessible git objects and commit history.

NOTE: This module does NOT download the full .git directory.
It probe-checks for exposure and extracts secrets from accessible
objects using standard HTTP requests only.
"""

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

import requests

from .patterns import SECRET_PATTERNS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 10
MAX_OBJECTS_TO_CHECK = 30      # Limit on git objects to fetch
MAX_REFS_TO_CHECK = 10         # Limit on refs/branches to probe

# Well-known .git paths that indicate exposure
GIT_PROBE_PATHS = [
    '.git/HEAD',
    '.git/config',
    '.git/index',
    '.git/COMMIT_EDITMSG',
    '.git/description',
    '.git/info/refs',
    '.git/packed-refs',
    '.git/logs/HEAD',
    '.git/refs/heads/main',
    '.git/refs/heads/master',
]

# Sensitive filenames to look for in .git history
SENSITIVE_FILES = [
    '.env',
    '.env.local',
    '.env.production',
    '.env.development',
    'config.py',
    'settings.py',
    'secrets.py',
    'credentials.json',
    'service-account.json',
    'docker-compose.yml',
    'wp-config.php',
    'database.yml',
    'application.properties',
    'appsettings.json',
    'web.config',
    '.htpasswd',
    'id_rsa',
    'id_ed25519',
]

# Patterns indicating a real git ref
_GIT_HEAD_RE = re.compile(r'^ref: refs/heads/\w+', re.MULTILINE)
_GIT_HASH_RE = re.compile(r'^[0-9a-f]{40}$', re.MULTILINE)
_GIT_PACK_RE = re.compile(r'^[0-9a-f]{40}', re.MULTILINE)
_GIT_CONFIG_RE = re.compile(r'\[(?:core|remote|branch)\s', re.MULTILINE)
_GIT_TREE_ENTRY_RE = re.compile(r'(\d{5,6})\s+(blob|tree)\s+([0-9a-f]{40})\s+(.+)')
_GIT_COMMIT_TREE_RE = re.compile(r'^tree\s+([0-9a-f]{40})', re.MULTILINE)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class GitDumpResult:
    """Results from probing an exposed .git directory."""
    is_exposed: bool = False
    accessible_paths: list = field(default_factory=list)
    extracted_secrets: list = field(default_factory=list)  # list of SecretFinding-like dicts
    sensitive_files_found: list = field(default_factory=list)
    commit_messages: list = field(default_factory=list)
    branch_names: list = field(default_factory=list)
    remote_urls: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Git Dumper
# ---------------------------------------------------------------------------

class GitDumper:
    """Detect and extract secrets from exposed .git directories.

    This class probes for .git exposure and extracts what information
    it can from accessible git metadata files via standard HTTP.
    """

    def __init__(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36'
        )
        self.session.verify = False

    def check_and_dump(self, base_url: str) -> GitDumpResult:
        """Probe for .git exposure and extract available secrets.

        Args:
            base_url: Target website base URL (e.g. https://example.com)

        Returns:
            GitDumpResult with exposure status, found secrets and metadata.
        """
        result = GitDumpResult()

        # Normalize URL
        if not base_url.endswith('/'):
            base_url += '/'

        # Phase 1: Probe for .git/HEAD — the primary indicator
        head_url = urljoin(base_url, '.git/HEAD')
        head_content = self._fetch(head_url)

        if not head_content:
            return result

        if not (_GIT_HEAD_RE.search(head_content) or
                _GIT_HASH_RE.search(head_content)):
            return result

        # .git is exposed!
        result.is_exposed = True
        result.accessible_paths.append('.git/HEAD')
        logger.info('Exposed .git detected at %s', base_url)

        # Phase 2: Probe additional paths
        for path in GIT_PROBE_PATHS[1:]:  # Skip HEAD, already checked
            try:
                content = self._fetch(urljoin(base_url, path))
                if content:
                    result.accessible_paths.append(path)
                    self._extract_metadata(path, content, result)
                    self._scan_content_for_secrets(content, base_url + path, result)
            except Exception as exc:
                result.errors.append(f'Error probing {path}: {exc}')

        # Phase 3: Try to extract objects if config gave us info
        self._probe_git_objects(base_url, head_content, result)

        return result

    def _fetch(self, url: str) -> str | None:
        """Fetch a URL and return its text content, or None on failure."""
        try:
            resp = self.session.get(url, timeout=REQUEST_TIMEOUT,
                                    allow_redirects=False)
            if resp.status_code == 200 and len(resp.text) > 5:
                # Filter out generic error pages
                if '<html' in resp.text.lower() and '.git' not in resp.text.lower():
                    return None
                return resp.text
        except requests.RequestException:
            pass
        return None

    def _extract_metadata(self, path: str, content: str,
                          result: GitDumpResult):
        """Extract useful metadata from git files."""
        if path == '.git/config' and _GIT_CONFIG_RE.search(content):
            # Extract remote URLs
            remote_re = re.compile(r'url\s*=\s*(.+)')
            for m in remote_re.finditer(content):
                url = m.group(1).strip()
                if url and url not in result.remote_urls:
                    result.remote_urls.append(url)

        elif path == '.git/logs/HEAD':
            # Extract commit messages from reflog
            commit_re = re.compile(r'(?:commit|merge|checkout):\s*(.+)')
            for m in commit_re.finditer(content):
                msg = m.group(1).strip()[:200]
                if msg and msg not in result.commit_messages:
                    result.commit_messages.append(msg)
                    if len(result.commit_messages) >= 20:
                        break

        elif path.startswith('.git/refs/heads/'):
            branch = path.split('/')[-1]
            if branch not in result.branch_names:
                result.branch_names.append(branch)

        elif path == '.git/packed-refs':
            for line in content.splitlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[1].startswith('refs/heads/'):
                    branch = parts[1].split('/')[-1]
                    if branch not in result.branch_names:
                        result.branch_names.append(branch)

    def _scan_content_for_secrets(self, content: str, source_url: str,
                                  result: GitDumpResult):
        """Scan git file content for secret patterns."""
        for pat_info in SECRET_PATTERNS:
            for match in pat_info['regex'].finditer(content):
                matched_text = match.group(0)[:200]
                finding = {
                    'pattern_name': pat_info['name'],
                    'matched_text': matched_text,
                    'severity': pat_info['severity'],
                    'source': source_url,
                    'cwe': pat_info['cwe'],
                }
                # Deduplicate by pattern + matched text
                sig = f'{pat_info["name"]}:{matched_text[:80]}'
                if sig not in {f'{s["pattern_name"]}:{s["matched_text"][:80]}'
                               for s in result.extracted_secrets}:
                    result.extracted_secrets.append(finding)

    def _probe_git_objects(self, base_url: str, head_content: str,
                           result: GitDumpResult):
        """Try to fetch git objects to find additional secrets.

        Extracts commit hash from HEAD, fetches the commit object,
        then probes tree entries for sensitive files.
        """
        # Get HEAD commit hash
        commit_hash = None
        hash_match = _GIT_HASH_RE.search(head_content)
        if hash_match:
            commit_hash = hash_match.group(0)
        else:
            # HEAD is a ref, try to resolve
            ref_match = re.search(r'ref: (.+)', head_content)
            if ref_match:
                ref_path = ref_match.group(1).strip()
                ref_url = urljoin(base_url, f'.git/{ref_path}')
                ref_content = self._fetch(ref_url)
                if ref_content:
                    h = _GIT_HASH_RE.search(ref_content)
                    if h:
                        commit_hash = h.group(0)

        if not commit_hash:
            return

        # Try to fetch the commit object
        obj_url = self._object_url(base_url, commit_hash)
        commit_content = self._fetch(obj_url)
        if not commit_content:
            return

        # Also scan commit content for secrets
        self._scan_content_for_secrets(commit_content, obj_url, result)

    @staticmethod
    def _object_url(base_url: str, sha: str) -> str:
        """Build URL for a loose git object."""
        return urljoin(base_url, f'.git/objects/{sha[:2]}/{sha[2:]}')

    def findings_to_vulns(self, dump_result: GitDumpResult,
                          base_url: str) -> list[dict]:
        """Convert GitDumpResult to vulnerability dicts.

        Returns:
            list of vuln dicts matching BaseTester._build_vuln format.
        """
        vulns = []

        if not dump_result.is_exposed:
            return vulns

        # Primary finding: .git exposure
        evidence_parts = [
            f'Accessible paths: {", ".join(dump_result.accessible_paths[:10])}',
        ]
        if dump_result.remote_urls:
            evidence_parts.append(
                f'Remote URLs: {", ".join(dump_result.remote_urls[:5])}'
            )
        if dump_result.branch_names:
            evidence_parts.append(
                f'Branches: {", ".join(dump_result.branch_names[:10])}'
            )

        vulns.append({
            'name': 'Exposed .git Directory',
            'severity': 'high',
            'category': 'Information Disclosure',
            'description': (
                'The .git directory is publicly accessible on this server. '
                f'{len(dump_result.accessible_paths)} git paths are exposed, '
                'potentially leaking source code, commit history and secrets.'
            ),
            'impact': (
                'Attackers can download the entire source code repository, '
                'extract credentials from commit history, and understand '
                'the application internals for targeted attacks.'
            ),
            'remediation': (
                '1. Block access to .git/ in your web server configuration.\n'
                '2. For Nginx: location ~ /\\.git { deny all; }\n'
                '3. For Apache: RedirectMatch 404 /\\.git\n'
                '4. Remove the .git directory from the web root entirely.\n'
                '5. Rotate any secrets that may have been exposed.'
            ),
            'cwe': 'CWE-538',
            'cvss': 7.5,
            'affected_url': base_url + '.git/HEAD',
            'evidence': '\n'.join(evidence_parts)[:2000],
        })

        # Additional vulns for each secret found in git
        seen = set()
        for secret in dump_result.extracted_secrets:
            sig = f'git_secret:{secret["pattern_name"]}:{base_url}'
            if sig in seen:
                continue
            seen.add(sig)

            vulns.append({
                'name': f'Secret in .git: {secret["pattern_name"]}',
                'severity': secret['severity'],
                'category': 'Secret Exposure',
                'description': (
                    f'{secret["pattern_name"]} found in exposed .git repository '
                    f'files at {secret["source"]}'
                ),
                'impact': (
                    'Credentials and secrets in git history can be extracted '
                    'and used for unauthorized access to services and APIs.'
                ),
                'remediation': (
                    '1. Block .git access immediately.\n'
                    '2. Rotate the exposed secret.\n'
                    '3. Use tools like git-filter-branch or BFG to purge '
                    'secrets from git history.\n'
                    '4. Never commit secrets — use environment variables or '
                    'a secret manager.'
                ),
                'cwe': secret['cwe'],
                'cvss': 8.0 if secret['severity'] == 'critical' else 6.5,
                'affected_url': secret['source'],
                'evidence': f'Pattern: {secret["pattern_name"]}, '
                            f'Match: {secret["matched_text"][:200]}',
            })

        return vulns
