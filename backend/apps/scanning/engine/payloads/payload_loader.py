"""
Payload Loader — Lazy-loading, generator-based payload library.

Loads payloads from text files in the data/ directory tree.
Supports depth-aware filtering, WAF-specific payloads, tech-specific
filtering, and context-aware selection.

Usage:
    loader = PayloadLoader()
    payloads = loader.get_payloads('sqli', depth='medium')
    payloads = loader.get_payloads('xss', context='html_attr', depth='deep',
                                    waf='cloudflare', tech='php')
"""
import os
import re
from typing import Generator, List, Optional

# SecLists integration — graceful import
try:
    from .seclists_manager import SecListsManager as _SecListsManager
    _SECLISTS = _SecListsManager()
except Exception:
    _SECLISTS = None  # type: ignore[assignment]


# Resolve data/ directory relative to this file
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

# Depth limits
DEPTH_LIMITS = {
    'shallow': 100,
    'medium': 1000,
    'deep': None,  # No limit — return all
}

# Mapping from vuln_type to subdirectory and file list
VULN_TYPE_FILES = {
    'sqli': {
        'dir': 'sqli',
        'files': ['error_based.txt', 'union_based.txt', 'blind_boolean.txt',
                  'blind_time.txt', 'stacked.txt'],
        'tamper_dir': 'sqli/tamper',
    },
    'xss': {
        'dir': 'xss',
        'files': ['reflected.txt', 'dom.txt', 'filter_bypass.txt', 'csp_bypass.txt'],
        'context_dir': 'xss/context',
    },
    'cmdi': {
        'dir': 'cmdi',
        'files': ['unix.txt', 'windows.txt', 'blind.txt'],
    },
    'ssti': {
        'dir': 'ssti',
        'files': ['generic.txt', 'jinja2.txt', 'twig.txt'],
    },
    'ssrf': {
        'dir': 'ssrf',
        'files': ['cloud_metadata.txt', 'internal.txt', 'protocols.txt', 'bypass.txt'],
    },
    'traversal': {
        'dir': 'traversal',
        'files': ['unix.txt', 'windows.txt'],
    },
    'xxe': {
        'dir': 'xxe',
        'files': ['inband.txt', 'oob.txt', 'parameter_entity.txt'],
    },
    'nosql': {
        'dir': 'nosql',
        'files': ['mongodb.txt'],
    },
    'open_redirect': {
        'dir': 'redirect',
        'files': ['open_redirect.txt'],
    },
}

# Tech stack → SSTI engine mapping
TECH_SSTI_MAP = {
    'python': 'jinja2',
    'flask': 'jinja2',
    'django': 'jinja2',
    'jinja': 'jinja2',
    'php': 'twig',
    'twig': 'twig',
    'symfony': 'twig',
    'laravel': 'twig',
}

# WAF name normalization
WAF_NAME_MAP = {
    'cloudflare': 'cloudflare',
    'cloud flare': 'cloudflare',
    'modsecurity': 'modsecurity',
    'mod_security': 'modsecurity',
    'mod security': 'modsecurity',
    'imperva': 'imperva',
    'incapsula': 'imperva',
    'aws waf': 'aws_waf',
    'aws_waf': 'aws_waf',
    'amazon': 'aws_waf',
    'akamai': 'akamai',
}


class PayloadLoader:
    """Lazy-loading, generator-based payload library.

    Loads payloads from text files on demand, supports depth-based
    limiting, WAF-specific payloads, tech-specific filtering, and
    context-aware selection.
    """

    def __init__(self, data_dir: str = None):
        self._data_dir = data_dir or _DATA_DIR
        self._cache = {}  # path -> list of payloads

    def get_payloads(self, vuln_type: str, context: str = None,
                     depth: str = 'medium', waf: str = None,
                     tech: str = None) -> List[str]:
        """Get payloads for a vulnerability type with optional filtering.

        Args:
            vuln_type:  Vulnerability type key (sqli, xss, cmdi, etc.)
            context:    Optional context filter (html_attr, js_string, etc.)
            depth:      'shallow' (top 100), 'medium' (top 1000), 'deep' (all)
            waf:        Optional WAF product name for tamper payloads
            tech:       Optional technology for tech-specific payloads

        Returns:
            List of payload strings, limited by depth.
        """
        return list(self.iter_payloads(vuln_type, context=context,
                                       depth=depth, waf=waf, tech=tech))

    def iter_payloads(self, vuln_type: str, context: str = None,
                      depth: str = 'medium', waf: str = None,
                      tech: str = None) -> Generator[str, None, None]:
        """Generator that yields payloads lazily.

        Same interface as get_payloads but memory-efficient for large sets.
        """
        limit = DEPTH_LIMITS.get(depth, DEPTH_LIMITS['medium'])
        count = 0

        config = VULN_TYPE_FILES.get(vuln_type)
        if not config:
            return

        # If context specified and context_dir exists, load context-specific
        if context and 'context_dir' in config:
            context_file = os.path.join(config['context_dir'], f'{context}.txt')
            for payload in self._iter_file(context_file):
                if limit is not None and count >= limit:
                    return
                yield payload
                count += 1

        # Load main files
        for filename in config['files']:
            filepath = os.path.join(config['dir'], filename)

            # Tech-specific filtering for SSTI
            if vuln_type == 'ssti' and tech:
                engine = TECH_SSTI_MAP.get(tech.lower())
                if engine and filename != 'generic.txt' and filename != f'{engine}.txt':
                    continue

            for payload in self._iter_file(filepath):
                if limit is not None and count >= limit:
                    return
                yield payload
                count += 1

        # Load WAF-specific tamper payloads if WAF specified
        if waf:
            yield from self._iter_waf_payloads(vuln_type, waf, limit, count)

        # Supplement with SecLists payloads when installed
        if _SECLISTS and _SECLISTS.is_installed:
            seen = None  # build seen set lazily
            for sl_payload in _SECLISTS.iter_payloads(vuln_type, max_lines=limit or 1000):
                if limit is not None and count >= limit:
                    return
                # Avoid duplicates with a lazy set
                if seen is None:
                    seen = set()
                if sl_payload not in seen:
                    seen.add(sl_payload)
                    yield sl_payload
                    count += 1

    def _iter_waf_payloads(self, vuln_type: str, waf: str,
                           limit: Optional[int], count: int) -> Generator[str, None, None]:
        """Yield WAF-specific bypass payloads."""
        waf_key = WAF_NAME_MAP.get(waf.lower(), waf.lower().replace(' ', '_'))

        # Check vuln-type-specific tamper dir (e.g., sqli/tamper/cloudflare.txt)
        config = VULN_TYPE_FILES.get(vuln_type, {})
        tamper_dir = config.get('tamper_dir')
        if tamper_dir:
            tamper_file = os.path.join(tamper_dir, f'{waf_key}.txt')
            for payload in self._iter_file(tamper_file):
                if limit is not None and count >= limit:
                    return
                yield payload
                count += 1

        # Check generic waf_bypass dir
        waf_file = os.path.join('waf_bypass', f'{waf_key}.txt')
        for payload in self._iter_file(waf_file):
            if limit is not None and count >= limit:
                return
            yield payload
            count += 1

    def _iter_file(self, relative_path: str) -> Generator[str, None, None]:
        """Yield non-empty, non-comment lines from a payload file."""
        full_path = os.path.join(self._data_dir, relative_path)
        if not os.path.isfile(full_path):
            return
        # Verify the resolved path is within the data directory
        real_path = os.path.realpath(full_path)
        real_data = os.path.realpath(self._data_dir)
        if not real_path.startswith(real_data):
            return

        if full_path in self._cache:
            yield from self._cache[full_path]
            return

        payloads = []
        with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.rstrip('\n\r')
                if not stripped or stripped.startswith('#'):
                    continue
                payloads.append(stripped)
                yield stripped

        self._cache[full_path] = payloads

    def load_file(self, relative_path: str) -> List[str]:
        """Load all payloads from a specific file.

        Args:
            relative_path: Path relative to data/ directory.

        Returns:
            List of payload strings.
        """
        return list(self._iter_file(relative_path))

    def load_wordlist(self, name: str) -> List[str]:
        """Load a wordlist by name.

        Args:
            name: Wordlist name (e.g., 'content_common', 'api_routes',
                  'params_common', 'subdomains').

        Returns:
            List of wordlist entries.
        """
        return self.load_file(os.path.join('wordlists', f'{name}.txt'))

    def load_secret_patterns(self) -> List[tuple]:
        """Load secret detection patterns.

        Returns:
            List of (name, compiled_regex) tuples.
        """
        patterns = []
        for line in self._iter_file(os.path.join('secrets', 'patterns.txt')):
            if ':::' in line:
                name, regex_str = line.split(':::', 1)
                try:
                    compiled = re.compile(regex_str)
                    patterns.append((name.strip(), compiled))
                except re.error:
                    continue
        return patterns

    def get_payload_count(self, vuln_type: str) -> int:
        """Get total number of payloads available for a vuln type.

        Args:
            vuln_type: Vulnerability type key.

        Returns:
            Total payload count across all files for this type.
        """
        config = VULN_TYPE_FILES.get(vuln_type)
        if not config:
            return 0
        total = 0
        for filename in config['files']:
            filepath = os.path.join(config['dir'], filename)
            total += len(self.load_file(filepath))
        return total

    def get_available_types(self) -> List[str]:
        """Return list of available vulnerability types."""
        return list(VULN_TYPE_FILES.keys())

    def clear_cache(self):
        """Clear the internal file cache."""
        self._cache.clear()


# Module-level singleton for convenience
_default_loader = None


def get_loader() -> PayloadLoader:
    """Get or create the default PayloadLoader singleton."""
    global _default_loader
    if _default_loader is None:
        _default_loader = PayloadLoader()
    return _default_loader


def get_payloads(vuln_type: str, context: str = None, depth: str = 'medium',
                 waf: str = None, tech: str = None) -> List[str]:
    """Module-level convenience function. Delegates to default loader."""
    return get_loader().get_payloads(vuln_type, context=context, depth=depth,
                                     waf=waf, tech=tech)
