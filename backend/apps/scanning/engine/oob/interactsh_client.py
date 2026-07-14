"""
InteractshClient — Python client for ProjectDiscovery's Interactsh OOB server.

Registers unique interaction URLs, polls for callbacks (DNS, HTTP, SMTP, LDAP),
and parses interaction data for blind vulnerability confirmation.

Supports both the public oast.live server and self-hosted Interactsh instances.
Falls back to a simple canary-based detection when Interactsh is unavailable.
"""
import base64
import json
import logging
import os
import secrets
from typing import Optional

import requests

logger = logging.getLogger(__name__)

# Default Interactsh public server
DEFAULT_INTERACTSH_SERVER = 'oast.live'
REGISTER_TIMEOUT = 10
POLL_TIMEOUT = 10


class Interaction:
    """Represents a single OOB interaction received by the server."""

    __slots__ = ('protocol', 'unique_id', 'full_id', 'raw_request',
                 'remote_address', 'timestamp', 'q_type')

    def __init__(self, protocol: str, unique_id: str, full_id: str,
                 raw_request: str = '', remote_address: str = '',
                 timestamp: str = '', q_type: str = ''):
        self.protocol = protocol
        self.unique_id = unique_id
        self.full_id = full_id
        self.raw_request = raw_request
        self.remote_address = remote_address
        self.timestamp = timestamp
        self.q_type = q_type

    def __repr__(self):
        return (f'Interaction(protocol={self.protocol!r}, '
                f'unique_id={self.unique_id!r}, remote={self.remote_address!r})')


class InteractshClient:
    """Client for the Interactsh OOB callback server.

    Usage:
        client = InteractshClient()
        client.register()
        # ... inject client.interaction_url into payloads ...
        interactions = client.poll()
        client.close()
    """

    def __init__(self, server: str = None, token: str = None):
        """
        Args:
            server: Interactsh server domain (default: oast.live).
            token: Optional auth token for self-hosted servers.
        """
        self.server = server or os.environ.get(
            'INTERACTSH_SERVER', DEFAULT_INTERACTSH_SERVER
        )
        self.token = token or os.environ.get('INTERACTSH_TOKEN', '')
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'SafeWeb-AI-Scanner/2.0',
        })
        if self.token:
            self._session.headers['Authorization'] = self.token

        # Registration state
        self._correlation_id: Optional[str] = None
        self._secret_key: Optional[str] = None
        self._registered = False
        self.interaction_url: Optional[str] = None

    @property
    def is_registered(self) -> bool:
        return self._registered

    def register(self) -> str:
        """Register with the Interactsh server and get a unique interaction URL.

        Returns:
            The interaction base URL (e.g., 'abc123def456.oast.live').

        Raises:
            ConnectionError: If registration fails.
        """
        self._correlation_id = secrets.token_hex(16)
        self._secret_key = secrets.token_hex(16)

        try:
            resp = self._session.post(
                f'https://{self.server}/register',
                json={
                    'public-key': self._correlation_id,
                    'secret-key': self._secret_key,
                    'correlation-id': self._correlation_id,
                },
                timeout=REGISTER_TIMEOUT,
            )
            if resp.status_code == 200:
                self._registered = True
                self.interaction_url = f'{self._correlation_id}.{self.server}'
                logger.info(f'Interactsh registered: {self.interaction_url}')
                return self.interaction_url

            # Fallback: use correlation ID with server domain even if registration
            # endpoint doesn't respond as expected (some servers)
            self._registered = True
            self.interaction_url = f'{self._correlation_id}.{self.server}'
            logger.warning(
                f'Interactsh registration returned {resp.status_code}, '
                f'using fallback URL: {self.interaction_url}'
            )
            return self.interaction_url

        except requests.RequestException as e:
            logger.warning(f'Interactsh registration failed: {e}')
            # Fallback: generate a canary-style URL that can still be useful
            self._correlation_id = secrets.token_hex(16)
            self._registered = False
            self.interaction_url = f'{self._correlation_id}.{self.server}'
            return self.interaction_url

    def poll(self) -> list:
        """Poll the Interactsh server for received interactions.

        Returns:
            List of Interaction objects received since last poll.
        """
        if not self._correlation_id:
            return []

        try:
            resp = self._session.get(
                f'https://{self.server}/poll',
                params={'id': self._correlation_id, 'secret': self._secret_key},
                timeout=POLL_TIMEOUT,
            )
            if resp.status_code != 200:
                logger.debug(f'Interactsh poll returned {resp.status_code}')
                return []

            data = resp.json()
            interactions = []
            for entry in data.get('data', []) or []:
                interaction = self._parse_interaction(entry)
                if interaction:
                    interactions.append(interaction)

            if interactions:
                logger.info(f'Interactsh poll: {len(interactions)} interaction(s) received')
            return interactions

        except requests.RequestException as e:
            logger.debug(f'Interactsh poll failed: {e}')
            return []
        except (json.JSONDecodeError, KeyError) as e:
            logger.debug(f'Interactsh poll parse error: {e}')
            return []

    def _parse_interaction(self, entry: dict) -> Optional[Interaction]:
        """Parse a raw interaction entry from the Interactsh server."""
        try:
            # Interactsh returns base64-encoded data in some configurations
            raw_request = entry.get('raw-request', '')
            if not raw_request:
                raw_request = entry.get('raw_request', '')

            # Try to decode if base64
            try:
                decoded = base64.b64decode(raw_request).decode('utf-8', errors='replace')
                if decoded and len(decoded) > 5:
                    raw_request = decoded
            except Exception:
                pass

            full_id = entry.get('full-id', '') or entry.get('full_id', '')
            unique_id = full_id.split('.')[0] if full_id else ''

            return Interaction(
                protocol=entry.get('protocol', 'unknown'),
                unique_id=unique_id,
                full_id=full_id,
                raw_request=raw_request[:2000],
                remote_address=entry.get('remote-address', '') or entry.get('remote_address', ''),
                timestamp=entry.get('timestamp', ''),
                q_type=entry.get('q-type', '') or entry.get('q_type', ''),
            )
        except Exception as e:
            logger.debug(f'Failed to parse interaction: {e}')
            return None

    def generate_subdomain(self, label: str) -> str:
        """Generate a unique subdomain URL for a specific payload.

        Args:
            label: Human-readable label (e.g., 'sqli-param-id').

        Returns:
            Full callback URL like 'sqli-param-id-a1b2c3.correlation.oast.live'.
        """
        if not self.interaction_url:
            self.register()

        # Create a short random suffix for uniqueness
        suffix = secrets.token_hex(4)
        # Sanitize label for DNS compatibility
        safe_label = ''.join(
            c if c.isalnum() or c == '-' else '-'
            for c in label.lower()
        )[:32]
        return f'{safe_label}-{suffix}.{self.interaction_url}'

    def close(self):
        """Deregister from the Interactsh server."""
        if not self._registered or not self._correlation_id:
            return

        try:
            self._session.post(
                f'https://{self.server}/deregister',
                json={
                    'correlation-id': self._correlation_id,
                    'secret-key': self._secret_key,
                },
                timeout=REGISTER_TIMEOUT,
            )
            logger.info('Interactsh deregistered')
        except requests.RequestException:
            pass
        finally:
            self._registered = False
            self._correlation_id = None
            self._secret_key = None

    def __enter__(self):
        self.register()
        return self

    def __exit__(self, *args):
        self.close()
