"""
CallbackServer — Lightweight fallback OOB callback detection.

Provides canary-based DNS callback detection when Interactsh is unavailable.
Uses unique canary tokens embedded in payloads that can be matched against
DNS query logs or HTTP request logs.

This is a fallback mechanism — the primary OOB infrastructure uses InteractshClient.
"""
import hashlib
import logging
import secrets
from typing import Optional

logger = logging.getLogger(__name__)


class CanaryToken:
    """A unique canary token for tracking OOB callbacks."""

    __slots__ = ('token', 'vuln_type', 'param_name', 'target_url', 'created_at')

    def __init__(self, token: str, vuln_type: str, param_name: str, target_url: str):
        self.token = token
        self.vuln_type = vuln_type
        self.param_name = param_name
        self.target_url = target_url
        self.created_at = None


class CallbackServer:
    """Fallback canary-based OOB detection.

    Generates unique canary tokens for each payload injection.
    Does NOT run an actual server — instead generates identifiable tokens
    that can be matched against external monitoring (DNS logs, etc.).

    Usage:
        server = CallbackServer(base_domain='callback.example.com')
        token = server.generate_canary('sqli', 'id', 'https://target.com/page')
        # ... inject token.token into payload ...
        # ... check DNS logs for token ...
    """

    def __init__(self, base_domain: str = 'oast.live'):
        self.base_domain = base_domain
        self._canaries: dict[str, CanaryToken] = {}

    def generate_canary(self, vuln_type: str, param_name: str,
                        target_url: str) -> CanaryToken:
        """Generate a unique canary token for OOB tracking.

        Args:
            vuln_type: Vulnerability type being tested.
            param_name: Parameter name being tested.
            target_url: Target URL.

        Returns:
            CanaryToken with a unique subdomain-safe token.
        """
        raw = f'{vuln_type}:{param_name}:{target_url}:{secrets.token_hex(8)}'
        token_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]
        token_str = f'{vuln_type[:4]}-{token_hash}.{self.base_domain}'

        canary = CanaryToken(
            token=token_str,
            vuln_type=vuln_type,
            param_name=param_name,
            target_url=target_url,
        )
        self._canaries[token_hash] = canary
        return canary

    def check_canary(self, received_domain: str) -> Optional[CanaryToken]:
        """Check if a received domain matches a generated canary.

        Args:
            received_domain: Domain from a DNS query log or HTTP log.

        Returns:
            CanaryToken if matched, None otherwise.
        """
        received_lower = received_domain.lower()
        for token_hash, canary in self._canaries.items():
            if token_hash in received_lower:
                return canary
        return None

    @property
    def canary_count(self) -> int:
        return len(self._canaries)

    def clear(self):
        """Clear all tracked canaries."""
        self._canaries.clear()
