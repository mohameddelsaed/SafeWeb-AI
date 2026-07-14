"""
Phase 45 — Scope Manager
========================
Validates URLs/targets against a ScopeDefinition's in-scope/out-of-scope
pattern lists.  Supports:
  - exact domain match        e.g. "example.com"
  - wildcard subdomain match  e.g. "*.example.com"  → sub.example.com
  - CIDR range                e.g. "10.0.0.0/8"
  - path prefix               e.g. "example.com/api/"
"""
from __future__ import annotations

import fnmatch
import ipaddress
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class ScopeManager:
    """
    Evaluate whether a target URL is within an engagement's scope.

    Usage::

        sm = ScopeManager(
            in_scope=["*.example.com", "192.168.1.0/24"],
            out_of_scope=["admin.example.com"],
        )
        sm.is_in_scope("https://app.example.com/login")   # True
        sm.is_in_scope("https://admin.example.com/")       # False  (excluded)
        sm.is_in_scope("https://other.com/")               # False
    """

    def __init__(
        self,
        in_scope: List[str],
        out_of_scope: List[str] | None = None,
    ) -> None:
        self.in_scope: List[str] = [p.strip() for p in (in_scope or []) if str(p).strip()]
        self.out_of_scope: List[str] = [p.strip() for p in (out_of_scope or []) if str(p).strip()]

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _extract_host(target: str) -> str:
        """Return the hostname (or IP) from a URL or bare host string."""
        stripped = target.strip()
        if '://' in stripped:
            parsed = urlparse(stripped)
            return parsed.hostname or ''
        # bare host: possibly host/path or host:port
        return stripped.split('/')[0].split(':')[0]

    @staticmethod
    def _normalise_pattern(pattern: str) -> str:
        """
        Strip leading '*.' so '*.example.com' and 'example.com' both turn into
        'example.com' for the exact/suffix check portion.
        Returns the cleaned pattern unchanged if it doesn't start with '*.'.
        """
        if pattern.startswith('*.'):
            return pattern[2:]
        return pattern

    def _matches_pattern(self, host: str, pattern: str) -> bool:
        """
        Return *True* if *host* matches *pattern* using one of:
          1. CIDR — pattern is a valid IP network
          2. fnmatch wildcard — pattern contains '*' or '?'
          3. Exact or sub-domain suffix match  (also covers '*.example.com')
        """
        if not host or not pattern:
            return False

        # 1. CIDR
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(host)
            return addr in network
        except ValueError:
            pass

        # 2. fnmatch (handles *.example.com natively)
        if '*' in pattern or '?' in pattern:
            return fnmatch.fnmatch(host, pattern)

        # 3. Exact or subdomain-suffix
        cleaned = self._normalise_pattern(pattern)
        return host == cleaned or host.endswith('.' + cleaned)

    # ------------------------------------------------------------------ public

    def is_in_scope(self, target: str) -> bool:
        """Return *True* if *target* is within scope and not excluded."""
        host = self._extract_host(target)
        if not host:
            return False

        # Phase B2 QA Scope Enforcement: Hardcode isolated target network refusal
        import os
        if os.environ.get('ENFORCE_QA_SCOPE', '').lower() == 'true':
            allowed_qa_hosts = ['127.0.0.1', 'localhost', 'target-dvwa', 'target-juiceshop', 'target-webgoat', 'dvwa', 'juiceshop', 'webgoat']
            if not any(host == h or host.startswith(h + ':') or host.endswith('.' + h) for h in allowed_qa_hosts):
                return False

        # No rules → everything passes
        if self.in_scope:
            in_match = any(self._matches_pattern(host, p) for p in self.in_scope)
            if not in_match:
                return False

        # Excluded?
        if self.out_of_scope:
            if any(self._matches_pattern(host, p) for p in self.out_of_scope):
                return False

        return True

    def validate_targets(self, targets: List[str]) -> Tuple[List[str], List[str]]:
        """
        Partition *targets* into (in_scope, out_of_scope) tuples.
        Returns two lists; order is preserved.
        """
        in_s: List[str] = []
        out_s: List[str] = []
        for t in targets:
            (in_s if self.is_in_scope(t) else out_s).append(t)
        return in_s, out_s

    def filter_in_scope(self, targets: List[str]) -> List[str]:
        """Return only the targets that pass the scope check."""
        return [t for t in targets if self.is_in_scope(t)]

    def check_target(self, target: str) -> Dict[str, object]:
        """
        Return a dict with ``{in_scope: bool, host: str, matched_pattern: str | None}``.
        Useful for the ``/scopes/<id>/validate/`` API endpoint.
        """
        host = self._extract_host(target)
        result: Dict[str, object] = {'in_scope': False, 'host': host, 'matched_pattern': None}

        if not host:
            result['reason'] = 'Could not extract host from target'
            return result

        if self.in_scope:
            for p in self.in_scope:
                if self._matches_pattern(host, p):
                    result['matched_pattern'] = p
                    break
            else:
                result['reason'] = 'Host does not match any in-scope pattern'
                return result

        if self.out_of_scope:
            for p in self.out_of_scope:
                if self._matches_pattern(host, p):
                    result['reason'] = f'Host matched out-of-scope pattern: {p}'
                    result['matched_pattern'] = p
                    return result

        result['in_scope'] = True
        result['reason'] = 'Target is in scope'
        return result

    @classmethod
    def from_scope_definition(cls, scope_def) -> 'ScopeManager':
        """
        Build a ScopeManager from a ``ScopeDefinition`` model instance.
        Both ``in_scope`` and ``out_of_scope`` are lists of plain strings
        *or* dicts of the form ``{"type": "domain", "value": "*.example.com"}``.
        """
        def _extract(entries):
            result = []
            for e in entries:
                if isinstance(e, dict):
                    result.append(e.get('value', ''))
                else:
                    result.append(str(e))
            return [x for x in result if x]

        return cls(
            in_scope=_extract(scope_def.in_scope),
            out_of_scope=_extract(scope_def.out_of_scope),
        )
