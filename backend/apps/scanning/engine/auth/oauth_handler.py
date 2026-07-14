"""
OAuth / SSO Authentication Handler — Automated OAuth2 and SSO flow execution.

Supports:
  - OAuth2 Authorization Code Grant (with PKCE)
  - OAuth2 Client Credentials Grant
  - SAML SSO redirect chains
  - OpenID Connect (OIDC) discovery + auth
  - Token refresh and lifecycle management
"""
from __future__ import annotations

import base64
import hashlib
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from urllib.parse import urlencode

import requests

logger = logging.getLogger(__name__)


@dataclass
class OAuthConfig:
    """Configuration for an OAuth2/OIDC provider."""
    auth_url: str = ''
    token_url: str = ''
    client_id: str = ''
    client_secret: str = ''
    redirect_uri: str = 'http://localhost:8888/callback'
    scopes: list[str] = field(default_factory=lambda: ['openid', 'profile'])
    use_pkce: bool = True
    # OIDC discovery
    discovery_url: str = ''  # e.g. https://provider/.well-known/openid-configuration
    # SAML
    saml_login_url: str = ''
    saml_assertion_consumer: str = ''


@dataclass
class OAuthTokens:
    """Holds the result of an OAuth flow."""
    access_token: str = ''
    refresh_token: str = ''
    id_token: str = ''
    token_type: str = 'Bearer'
    expires_at: float = 0.0
    scopes: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    @property
    def expired(self) -> bool:
        return self.expires_at > 0 and time.time() > self.expires_at


class OAuthHandler:
    """Handles OAuth2 / OIDC / SAML authentication flows for the scanner."""

    REQUEST_TIMEOUT = 15

    def __init__(self, config: OAuthConfig | None = None):
        self.config = config or OAuthConfig()
        self.tokens = OAuthTokens()
        self._pkce_verifier = ''
        self._pkce_challenge = ''
        self._state = ''

    # ── OAuth2 Authorization Code Grant ───────────────────────────────────

    def build_auth_url(self) -> str:
        """Build the authorization URL for the user to visit."""
        self._state = secrets.token_urlsafe(32)
        params: dict[str, str] = {
            'response_type': 'code',
            'client_id': self.config.client_id,
            'redirect_uri': self.config.redirect_uri,
            'scope': ' '.join(self.config.scopes),
            'state': self._state,
        }
        if self.config.use_pkce:
            self._pkce_verifier = secrets.token_urlsafe(64)
            digest = hashlib.sha256(self._pkce_verifier.encode()).digest()
            self._pkce_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
            params['code_challenge'] = self._pkce_challenge
            params['code_challenge_method'] = 'S256'

        auth_url = self.config.auth_url
        if not auth_url and self.config.discovery_url:
            auth_url = self._discover('authorization_endpoint')
        return f'{auth_url}?{urlencode(params)}'

    def exchange_code(self, code: str, session: requests.Session | None = None) -> OAuthTokens:
        """Exchange authorization code for tokens."""
        sess = session or requests.Session()
        token_url = self.config.token_url
        if not token_url and self.config.discovery_url:
            token_url = self._discover('token_endpoint')

        data: dict[str, str] = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.config.redirect_uri,
            'client_id': self.config.client_id,
        }
        if self.config.client_secret:
            data['client_secret'] = self.config.client_secret
        if self._pkce_verifier:
            data['code_verifier'] = self._pkce_verifier

        resp = sess.post(token_url, data=data, timeout=self.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return self._parse_token_response(resp.json())

    # ── Client Credentials Grant ──────────────────────────────────────────

    def client_credentials(self, session: requests.Session | None = None) -> OAuthTokens:
        """Obtain token via Client Credentials grant."""
        sess = session or requests.Session()
        token_url = self.config.token_url
        if not token_url and self.config.discovery_url:
            token_url = self._discover('token_endpoint')

        data = {
            'grant_type': 'client_credentials',
            'client_id': self.config.client_id,
            'client_secret': self.config.client_secret,
            'scope': ' '.join(self.config.scopes),
        }
        resp = sess.post(token_url, data=data, timeout=self.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return self._parse_token_response(resp.json())

    # ── Token Refresh ─────────────────────────────────────────────────────

    def refresh(self, session: requests.Session | None = None) -> OAuthTokens:
        """Refresh the access token using the refresh_token."""
        if not self.tokens.refresh_token:
            raise ValueError('No refresh token available')

        sess = session or requests.Session()
        token_url = self.config.token_url
        if not token_url and self.config.discovery_url:
            token_url = self._discover('token_endpoint')

        data = {
            'grant_type': 'refresh_token',
            'refresh_token': self.tokens.refresh_token,
            'client_id': self.config.client_id,
        }
        if self.config.client_secret:
            data['client_secret'] = self.config.client_secret

        resp = sess.post(token_url, data=data, timeout=self.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return self._parse_token_response(resp.json())

    # ── SAML SSO Flow ─────────────────────────────────────────────────────

    def follow_saml_redirect(self, session: requests.Session,
                             start_url: str = '') -> bool:
        """Follow a SAML SSO redirect chain, auto-submitting forms.

        Returns True if the chain completes with an HTTP 200 at the end.
        """
        url = start_url or self.config.saml_login_url
        max_redirects = 10
        for _ in range(max_redirects):
            resp = session.get(url, timeout=self.REQUEST_TIMEOUT, allow_redirects=False)
            if resp.status_code in (301, 302, 303, 307):
                url = resp.headers.get('Location', '')
                if not url:
                    return False
                continue
            if resp.status_code == 200:
                # Check for SAML auto-post form
                saml_match = re.search(
                    r'name=["\']SAMLResponse["\']\s+value=["\']([^"\']+)',
                    resp.text,
                )
                if saml_match:
                    action = re.search(r'action=["\']([^"\']+)', resp.text)
                    post_url = action.group(1) if action else self.config.saml_assertion_consumer
                    form_data = {'SAMLResponse': saml_match.group(1)}
                    relay = re.search(r'name=["\']RelayState["\']\s+value=["\']([^"\']+)', resp.text)
                    if relay:
                        form_data['RelayState'] = relay.group(1)
                    resp = session.post(post_url, data=form_data,
                                        timeout=self.REQUEST_TIMEOUT, allow_redirects=True)
                    return resp.status_code == 200
                return True
        return False

    # ── Apply to Session ──────────────────────────────────────────────────

    def apply_to_session(self, session: requests.Session) -> None:
        """Apply the current tokens to a requests session as Authorization header."""
        if self.tokens.access_token:
            session.headers['Authorization'] = (
                f'{self.tokens.token_type} {self.tokens.access_token}'
            )

    # ── Helpers ───────────────────────────────────────────────────────────

    def _discover(self, key: str) -> str:
        """Fetch from OIDC discovery endpoint."""
        resp = requests.get(self.config.discovery_url, timeout=self.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get(key, '')

    def _parse_token_response(self, data: dict) -> OAuthTokens:
        expires_in = data.get('expires_in', 3600)
        self.tokens = OAuthTokens(
            access_token=data.get('access_token', ''),
            refresh_token=data.get('refresh_token', self.tokens.refresh_token),
            id_token=data.get('id_token', ''),
            token_type=data.get('token_type', 'Bearer'),
            expires_at=time.time() + expires_in if expires_in else 0,
            scopes=data.get('scope', '').split(),
            raw=data,
        )
        return self.tokens
