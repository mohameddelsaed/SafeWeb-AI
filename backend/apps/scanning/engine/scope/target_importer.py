"""
Phase 45 — Target Importer
===========================
Parse target lists from various sources:
  - plain-text (newline / comma / semicolon delimited)
  - HackerOne program JSON (structured_scopes)
  - Bugcrowd program JSON (target_groups)

Also provides ``classify_asset`` to tag a URL as web_app / api / etc.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse


class TargetImporter:
    """
    Collection of static helpers for importing targets from different sources.
    """

    # ------------------------------------------------------------------ text

    @staticmethod
    def from_text(text: str) -> List[str]:
        """
        Parse a block of text containing URLs or domain names, one per line
        (also accepts comma- or semicolon-separated values).

        Lines starting with ``#`` are treated as comments.
        Bare hostnames are wrapped in ``https://``.
        Duplicates are removed while preserving order.
        """
        targets: List[str] = []
        for raw in re.split(r'[\n,;]+', text or ''):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if not re.match(r'^https?://', line, re.IGNORECASE):
                line = 'https://' + line
            if line not in targets:
                targets.append(line)
        return targets

    # ------------------------------------------------------------------ HackerOne

    @staticmethod
    def from_hackerone(program_data: dict) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Parse a HackerOne program API response dict.

        Expected shape (simplified)::

            {
              "relationships": {
                "structured_scopes": {
                  "data": [
                    {
                      "attributes": {
                        "asset_identifier": "*.example.com",
                        "asset_type": "URL",
                        "eligible_for_submission": true
                      }
                    }
                  ]
                }
              }
            }

        Returns ``(target_urls, scope_dict)`` where *scope_dict* has
        ``"in_scope"`` and ``"out_of_scope"`` string lists.
        """
        in_scope: List[str] = []
        out_of_scope: List[str] = []
        target_urls: List[str] = []

        scopes_data = (
            program_data
            .get('relationships', {})
            .get('structured_scopes', {})
            .get('data', [])
        )

        for entry in scopes_data:
            attrs = entry.get('attributes', {})
            identifier: str = attrs.get('asset_identifier', '').strip()
            asset_type: str = attrs.get('asset_type', 'URL')
            eligible: bool = attrs.get('eligible_for_submission', True)

            if not identifier:
                continue

            if eligible:
                in_scope.append(identifier)
                # Only web-reachable types become scan targets
                if asset_type.upper() in ('URL', 'WILDCARD', 'DOMAIN', 'IP_ADDRESS'):
                    clean = identifier.lstrip('*.')
                    url = clean if re.match(r'^https?://', clean) else 'https://' + clean
                    if url not in target_urls:
                        target_urls.append(url)
            else:
                out_of_scope.append(identifier)

        return target_urls, {'in_scope': in_scope, 'out_of_scope': out_of_scope}

    # ------------------------------------------------------------------ Bugcrowd

    @staticmethod
    def from_bugcrowd(program_data: dict) -> Tuple[List[str], Dict[str, List[str]]]:
        """
        Parse a Bugcrowd program dict.

        Expected shape (simplified)::

            {
              "target_groups": [
                {
                  "targets": [
                    {
                      "uri": "https://example.com",
                      "category": "website",
                      "in_scope": true
                    }
                  ]
                }
              ]
            }

        Returns ``(target_urls, scope_dict)``.
        """
        in_scope: List[str] = []
        out_of_scope: List[str] = []
        target_urls: List[str] = []

        for group in program_data.get('target_groups', []):
            for t in group.get('targets', []):
                uri: str = t.get('uri', '').strip()
                category: str = t.get('category', 'website').lower()
                scoped: bool = t.get('in_scope', True)

                if not uri:
                    continue

                if scoped:
                    in_scope.append(uri)
                    if category in ('website', 'api', 'webservice'):
                        url = uri if re.match(r'^https?://', uri) else 'https://' + uri
                        if url not in target_urls:
                            target_urls.append(url)
                else:
                    out_of_scope.append(uri)

        return target_urls, {'in_scope': in_scope, 'out_of_scope': out_of_scope}

    # ------------------------------------------------------------------ asset type

    @staticmethod
    def classify_asset(url: str) -> str:
        """
        Heuristically classify a URL as one of the ``DiscoveredAsset.ASSET_TYPES``:
        ``web_app`` | ``api`` | ``mobile_api`` | ``cdn`` | ``subdomain`` | ``ip`` | ``other``.
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return 'other'

        host: str = (parsed.netloc or '').lower().split(':')[0]
        path: str = (parsed.path or '').lower()

        # IP address → ip asset
        try:
            import ipaddress as _ip
            _ip.ip_address(host)
            return 'ip'
        except ValueError:
            pass

        # API indicators
        api_path_patterns = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/v3/']
        api_host_prefixes = ('api.', 'rest.', 'graphql.', 'api-', 'gateway.')
        if any(path.startswith(p) or p in path for p in api_path_patterns):
            return 'api'
        if any(host.startswith(pfx) for pfx in api_host_prefixes):
            return 'api'

        # Mobile API
        if 'mobile' in host or '/mobile/' in path:
            return 'mobile_api'

        # CDN / static
        cdn_prefixes = ('cdn.', 'static.', 'assets.', 'media.', 'img.', 'images.')
        if any(host.startswith(p) for p in cdn_prefixes):
            return 'cdn'

        # Everything else is a web app (subdomain included)
        return 'web_app'

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def deduplicate(targets: List[str]) -> List[str]:
        """Remove duplicates, normalising trailing slashes."""
        seen: set = set()
        result: List[str] = []
        for t in targets:
            key = t.rstrip('/')
            if key not in seen:
                seen.add(key)
                result.append(t)
        return result
