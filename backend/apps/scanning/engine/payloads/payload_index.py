"""
Payload Index — Unified index over both built-in payloads (data/) and
SecLists, providing smart payload selection based on scan context.

Acts as the single entry-point for all payload needs in the scanner.
"""
from __future__ import annotations

import logging
from typing import Iterator

from .payload_loader import PayloadLoader
from .seclists_manager import SecListsManager

logger = logging.getLogger(__name__)

# Mapping from internal vuln types to SecLists categories
_VULN_TO_SECLISTS = {
    'sqli':              'sqli',
    'xss':               'xss',
    'lfi':               'lfi',
    'xxe':               'xxe',
    'ssrf':              'ssrf',
    'cmdi':              'command_injection',
    'traversal':         'traversal',
    'ssti':              'ssti',
    'discovery_web':     'discovery_web',
    'discovery_dns':     'discovery_dns',
    'passwords':         'passwords',
    'default_creds':     'default_creds',
    'common_passwords':  'common_passwords',
    'usernames':         'usernames',
    'fuzzing':           'fuzzing',
    'raft_dirs':         'raft_dirs',
    'raft_files':        'raft_files',
    'api_paths':         'api_paths',
    'backup_files':      'backup_files',
}


class PayloadIndex:
    """Unified payload provider merging built-in payloads + SecLists."""

    def __init__(self):
        self._loader = PayloadLoader()
        self._seclists = SecListsManager()

    @property
    def seclists_available(self) -> bool:
        return self._seclists.is_installed

    def ensure_seclists(self) -> bool:
        """Install SecLists if not already present."""
        return self._seclists.install()

    def get_payloads(self, vuln_type: str, context: str = '',
                     depth: str = 'medium', waf: str = '',
                     tech: str = '', prefer_seclists: bool = False,
                     max_payloads: int = 0) -> list[str]:
        """Get payloads from the best available source.

        If SecLists is installed, merges built-in + SecLists payloads.
        Deduplicates and respects depth limits.
        """
        payloads: list[str] = []
        seen: set[str] = set()

        # 1. Built-in payloads first (unless preferring SecLists)
        if not prefer_seclists:
            for p in self._loader.iter_payloads(vuln_type, context=context,
                                                 depth=depth, waf=waf, tech=tech):
                if p not in seen:
                    seen.add(p)
                    payloads.append(p)

        # 2. SecLists payloads
        if self._seclists.is_installed:
            sl_cat = _VULN_TO_SECLISTS.get(vuln_type, vuln_type)
            sl_payloads = self._seclists.get_payloads_for_context(
                sl_cat, tech_stack=tech, depth=depth,
                max_payloads=max_payloads or (100 if depth == 'shallow' else 500),
            )
            for p in sl_payloads:
                if p not in seen:
                    seen.add(p)
                    payloads.append(p)

        # 3. If prefer_seclists but we also want built-in
        if prefer_seclists:
            for p in self._loader.iter_payloads(vuln_type, context=context,
                                                 depth=depth, waf=waf, tech=tech):
                if p not in seen:
                    seen.add(p)
                    payloads.append(p)

        # Apply max cap
        if max_payloads and len(payloads) > max_payloads:
            payloads = payloads[:max_payloads]

        return payloads

    def iter_payloads(self, vuln_type: str, **kwargs) -> Iterator[str]:
        """Lazy iterator version of get_payloads."""
        seen: set[str] = set()
        max_payloads = kwargs.pop('max_payloads', 0)
        count = 0
        for p in self._loader.iter_payloads(vuln_type, **kwargs):
            if p not in seen:
                seen.add(p)
                yield p
                count += 1
                if max_payloads and count >= max_payloads:
                    return

        if self._seclists.is_installed:
            sl_cat = _VULN_TO_SECLISTS.get(vuln_type, vuln_type)
            for p in self._seclists.iter_payloads(sl_cat):
                if p not in seen:
                    seen.add(p)
                    yield p
                    count += 1
                    if max_payloads and count >= max_payloads:
                        return

    def get_wordlist(self, category: str, name: str = '') -> list[str]:
        """Get a wordlist — try SecLists first, fallback to built-in."""
        if self._seclists.is_installed:
            payloads = self._seclists.read_payloads(category, name)
            if payloads:
                return payloads
        return self._loader.load_wordlist(name or category)

    def summary(self) -> dict:
        """Summary of available payload sources."""
        result = {
            'builtin_types': list(_VULN_TO_SECLISTS.keys()),
            'seclists_installed': self._seclists.is_installed,
        }
        if self._seclists.is_installed:
            result['seclists_categories'] = self._seclists.summary()
        return result
