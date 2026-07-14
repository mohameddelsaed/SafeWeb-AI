"""
TemplateManager — Clone, index, filter, and cache nuclei-templates.

Manages the local template repository: clones or updates from GitHub,
builds an in-memory index by tags/severity/type, filters templates for
a given scan profile, and supports TTL-based cache refresh.
"""
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Where templates are stored on disk
DEFAULT_TEMPLATES_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'templates_repo',
)

NUCLEI_TEMPLATES_REPO = 'https://github.com/projectdiscovery/nuclei-templates.git'

# Default TTL for template cache (24 hours)
DEFAULT_CACHE_TTL = 86400

# Tag categories used across nuclei-templates
TAG_CATEGORIES = {
    'vulnerability': ['cve', 'cves', 'rce', 'sqli', 'xss', 'ssrf', 'lfi', 'rfi',
                      'xxe', 'ssti', 'idor', 'injection'],
    'misconfiguration': ['misconfig', 'misconfiguration', 'cors', 'crlf'],
    'exposure': ['exposure', 'config', 'debug', 'env', 'backup'],
    'panel': ['panel', 'login', 'admin', 'dashboard'],
    'default-login': ['default-login', 'default-credentials'],
    'takeover': ['takeover', 'subdomain-takeover'],
    'tech': ['wordpress', 'joomla', 'drupal', 'apache', 'nginx', 'iis',
             'tomcat', 'jenkins', 'grafana', 'kibana', 'docker', 'kubernetes'],
}

# Scan profile presets — which tag groups to include
SCAN_PROFILES = {
    'quick': {'vulnerability', 'misconfiguration'},
    'standard': {'vulnerability', 'misconfiguration', 'exposure', 'panel'},
    'full': {'vulnerability', 'misconfiguration', 'exposure', 'panel',
             'default-login', 'takeover', 'tech'},
    'cve-only': {'vulnerability'},
}


class TemplateIndex:
    """In-memory index of nuclei template file paths."""

    def __init__(self):
        self.by_tag: Dict[str, List[str]] = {}
        self.by_severity: Dict[str, List[str]] = {}
        self.by_type: Dict[str, List[str]] = {}
        self.all_paths: List[str] = []
        self._build_time: float = 0

    @property
    def total(self) -> int:
        return len(self.all_paths)


class TemplateManager:
    """Manages nuclei-templates on disk with indexing and filtering."""

    def __init__(self, templates_dir: str = None, cache_ttl: int = DEFAULT_CACHE_TTL):
        self.templates_dir = templates_dir or DEFAULT_TEMPLATES_DIR
        self.cache_ttl = cache_ttl
        self._index: Optional[TemplateIndex] = None
        self._last_index_time: float = 0
        self._available = False

    @property
    def is_available(self) -> bool:
        return self._available

    @property
    def index(self) -> Optional[TemplateIndex]:
        return self._index

    # ── Repository Management ────────────────────────────────────────────

    def setup(self, clone: bool = False) -> bool:
        """Initialize templates — clone repo if requested, then index.

        Args:
            clone: If True, clone/pull from GitHub. If False, only index
                   existing templates on disk (useful for tests/offline).

        Returns:
            True if templates are indexed and ready.
        """
        try:
            if clone:
                self._clone_or_update()
            if os.path.isdir(self.templates_dir):
                self._build_index()
                self._available = True
            else:
                logger.warning('Templates directory not found: %s', self.templates_dir)
                self._available = False
            return self._available
        except Exception as exc:
            logger.error('Failed to setup nuclei templates: %s', exc)
            self._available = False
            return False

    def _clone_or_update(self):
        """Clone nuclei-templates repo, or git-pull if already present."""
        import subprocess

        if os.path.isdir(os.path.join(self.templates_dir, '.git')):
            logger.info('Updating nuclei-templates via git pull')
            subprocess.run(
                ['git', 'pull', '--depth=1'],
                cwd=self.templates_dir,
                capture_output=True, timeout=120,
            )
        else:
            logger.info('Cloning nuclei-templates repo (shallow)')
            os.makedirs(os.path.dirname(self.templates_dir), exist_ok=True)
            subprocess.run(
                ['git', 'clone', '--depth=1', NUCLEI_TEMPLATES_REPO, self.templates_dir],
                capture_output=True, timeout=300,
            )

    # ── Indexing ─────────────────────────────────────────────────────────

    def _build_index(self):
        """Walk the templates directory and index all YAML files."""
        import yaml

        idx = TemplateIndex()
        start = time.monotonic()
        templates_path = Path(self.templates_dir)

        for yaml_file in templates_path.rglob('*.yaml'):
            rel_path = str(yaml_file)
            try:
                with open(yaml_file, 'r', encoding='utf-8', errors='ignore') as f:
                    # Only read the first 2KB for indexing (fast)
                    header = f.read(2048)

                data = yaml.safe_load(header)
                if not isinstance(data, dict):
                    continue
                info = data.get('info', {})
                if not info:
                    continue

                idx.all_paths.append(rel_path)

                # Index by severity
                severity = info.get('severity', 'unknown').lower()
                idx.by_severity.setdefault(severity, []).append(rel_path)

                # Index by tags
                tags_raw = info.get('tags', '')
                if isinstance(tags_raw, str):
                    tags = [t.strip().lower() for t in tags_raw.split(',') if t.strip()]
                elif isinstance(tags_raw, list):
                    tags = [t.strip().lower() for t in tags_raw if isinstance(t, str)]
                else:
                    tags = []
                for tag in tags:
                    idx.by_tag.setdefault(tag, []).append(rel_path)

                # Index by type (http, dns, network, etc.)
                for ttype in ('http', 'dns', 'network', 'tcp', 'headless', 'file'):
                    if ttype in data:
                        idx.by_type.setdefault(ttype, []).append(rel_path)

            except Exception:
                continue

        idx._build_time = round(time.monotonic() - start, 2)
        self._index = idx
        self._last_index_time = time.monotonic()
        logger.info('Indexed %d nuclei templates in %.2fs', idx.total, idx._build_time)

    def needs_refresh(self) -> bool:
        """Check if the index needs to be rebuilt (TTL expired)."""
        if self._index is None:
            return True
        return (time.monotonic() - self._last_index_time) > self.cache_ttl

    # ── Filtering ────────────────────────────────────────────────────────

    def get_templates_by_tags(self, tags: List[str]) -> List[str]:
        """Return template paths matching any of the given tags."""
        if not self._index:
            return []
        result_set: Set[str] = set()
        for tag in tags:
            result_set.update(self._index.by_tag.get(tag.lower(), []))
        return list(result_set)

    def get_templates_by_severity(self, severities: List[str]) -> List[str]:
        """Return template paths matching any of the given severities."""
        if not self._index:
            return []
        result_set: Set[str] = set()
        for sev in severities:
            result_set.update(self._index.by_severity.get(sev.lower(), []))
        return list(result_set)

    def get_templates_by_type(self, template_type: str) -> List[str]:
        """Return template paths for a specific template type (http, dns, etc.)."""
        if not self._index:
            return []
        return list(self._index.by_type.get(template_type.lower(), []))

    def get_templates_for_profile(self, profile: str = 'standard') -> List[str]:
        """Return template paths for a predefined scan profile."""
        if not self._index:
            return []
        tag_groups = SCAN_PROFILES.get(profile, SCAN_PROFILES['standard'])
        tags: List[str] = []
        for group in tag_groups:
            tags.extend(TAG_CATEGORIES.get(group, [group]))
        return self.get_templates_by_tags(tags)

    def get_filtered_templates(
        self,
        tags: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        template_type: str = 'http',
        max_templates: int = 500,
    ) -> List[str]:
        """Return a filtered, capped list of template paths."""
        if not self._index:
            return []

        # Start with type filter
        type_set = set(self._index.by_type.get(template_type, self._index.all_paths))

        # Intersect with tag filter
        if tags:
            tag_set: Set[str] = set()
            for tag in tags:
                tag_set.update(self._index.by_tag.get(tag.lower(), []))
            type_set = type_set & tag_set

        # Intersect with severity filter
        if severities:
            sev_set: Set[str] = set()
            for sev in severities:
                sev_set.update(self._index.by_severity.get(sev.lower(), []))
            type_set = type_set & sev_set

        result = list(type_set)[:max_templates]
        return result

    def get_stats(self) -> dict:
        """Return a summary of the indexed template collection."""
        if not self._index:
            return {
                'available': False,
                'total': 0,
                'templates_dir': self.templates_dir,
            }
        top_tags = sorted(
            ((tag, len(paths)) for tag, paths in self._index.by_tag.items()),
            key=lambda x: x[1],
            reverse=True,
        )[:20]
        return {
            'available': self._available,
            'total': self._index.total,
            'index_time_seconds': self._index._build_time,
            'by_severity': {k: len(v) for k, v in self._index.by_severity.items()},
            'by_type': {k: len(v) for k, v in self._index.by_type.items()},
            'top_tags': dict(top_tags),
            'templates_dir': self.templates_dir,
        }
