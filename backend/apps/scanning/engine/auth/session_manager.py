"""
AuthSessionManager — Maintain authenticated session state across scanning phases.

Supports cookie-based, bearer token, API key, and custom header auth.
Provides session health monitoring, auto re-authentication, and multi-role testing.
"""
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class AuthType(str, Enum):
    """Supported authentication types."""
    FORM = 'form'
    API = 'api'
    COOKIE = 'cookie'
    BEARER = 'bearer'
    CUSTOM = 'custom'


@dataclass
class AuthCredentials:
    """Credentials for a single authentication role."""
    username: str = ''
    password: str = ''
    role: str = 'user'             # admin, user, low-privilege
    token: str = ''                # Pre-existing bearer/API token
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_config(cls, config: dict) -> 'AuthCredentials':
        """Build credentials from a config_data dict."""
        return cls(
            username=config.get('username', ''),
            password=config.get('password', ''),
            role=config.get('role', 'user'),
            token=config.get('token', ''),
            cookies=config.get('cookies', {}),
            headers=config.get('headers', {}),
            extra=config.get('extra', {}),
        )


@dataclass
class SessionState:
    """Tracks the health and identity of an authenticated session."""
    session: requests.Session
    role: str = 'user'
    auth_type: str = 'form'
    authenticated: bool = False
    last_verified: float = 0.0
    auth_time: float = 0.0
    consecutive_failures: int = 0
    verify_url: str = ''           # URL to hit for health check
    verify_indicator: str = ''     # String that must be present in healthy response
    logout_indicator: str = ''     # String that signals session death (e.g. "login")

    @property
    def age(self) -> float:
        """Seconds since authentication."""
        return time.monotonic() - self.auth_time if self.auth_time else 0

    @property
    def is_stale(self) -> bool:
        """True if session hasn't been verified in >5 min."""
        return (time.monotonic() - self.last_verified) > 300


# Default session TTL before forced re-auth (30 min)
SESSION_MAX_AGE = 1800
# Health check interval
HEALTH_CHECK_INTERVAL = 120


class AuthSessionManager:
    """Manages authenticated sessions for the scanner."""

    def __init__(
        self,
        login_fn: Optional[Callable] = None,
        max_age: int = SESSION_MAX_AGE,
    ):
        self._sessions: Dict[str, SessionState] = {}   # role → SessionState
        self._login_fn = login_fn                       # Callable(session, credentials) → bool
        self._max_age = max_age
        self._credentials: Dict[str, AuthCredentials] = {}

    # ── Public API ────────────────────────────────────────────────────────

    def add_credentials(self, credentials: AuthCredentials) -> None:
        """Register credentials for a role."""
        self._credentials[credentials.role] = credentials

    def get_session(self, role: str = 'user') -> Optional[requests.Session]:
        """Get an authenticated session for a role. Returns None if not available."""
        state = self._sessions.get(role)
        if state and state.authenticated:
            return state.session
        return None

    def get_all_sessions(self) -> Dict[str, requests.Session]:
        """Get all authenticated sessions indexed by role."""
        return {
            role: state.session
            for role, state in self._sessions.items()
            if state.authenticated
        }

    def authenticate(self, role: str = 'user') -> bool:
        """Authenticate a specific role. Returns True on success."""
        creds = self._credentials.get(role)
        if not creds:
            logger.warning(f'No credentials for role: {role}')
            return False

        session = self._create_session()
        state = SessionState(
            session=session,
            role=role,
            authenticated=False,
        )

        success = self._perform_login(state, creds)
        if success:
            state.authenticated = True
            state.auth_time = time.monotonic()
            state.last_verified = time.monotonic()
            self._sessions[role] = state
            logger.info(f'Authenticated as role={role}')
        else:
            logger.warning(f'Authentication failed for role={role}')

        return success

    def authenticate_all(self) -> Dict[str, bool]:
        """Authenticate all registered roles. Returns role → success map."""
        results = {}
        for role in self._credentials:
            results[role] = self.authenticate(role)
        return results

    def check_health(self, role: str = 'user') -> bool:
        """Verify the session is still alive."""
        state = self._sessions.get(role)
        if not state or not state.authenticated:
            return False

        # Skip if recently verified
        if (time.monotonic() - state.last_verified) < HEALTH_CHECK_INTERVAL:
            return True

        # Age-based expiry
        if state.age > self._max_age:
            logger.info(f'Session for {role} exceeded max age, re-authenticating')
            return self._reauthenticate(role)

        # Active verification via verify_url
        if state.verify_url:
            try:
                resp = state.session.get(
                    state.verify_url, timeout=10, allow_redirects=False,
                )
                # Check for logout indicators
                if state.logout_indicator and state.logout_indicator in resp.text:
                    logger.info(f'Session for {role} expired (logout indicator detected)')
                    return self._reauthenticate(role)
                # Check for positive indicator
                if state.verify_indicator:
                    if state.verify_indicator in resp.text:
                        state.last_verified = time.monotonic()
                        state.consecutive_failures = 0
                        return True
                    else:
                        return self._reauthenticate(role)
                # No indicator — accept 2xx/3xx as healthy
                if resp.status_code < 400:
                    state.last_verified = time.monotonic()
                    return True
            except requests.RequestException:
                state.consecutive_failures += 1
                if state.consecutive_failures >= 3:
                    return self._reauthenticate(role)
                return True  # Temporary failure, assume still valid

        # No verify_url — trust age
        state.last_verified = time.monotonic()
        return True

    def inject_auth(self, target_session: requests.Session, role: str = 'user') -> bool:
        """Copy auth state (cookies + headers) into another session."""
        state = self._sessions.get(role)
        if not state or not state.authenticated:
            return False

        # Copy cookies
        target_session.cookies.update(state.session.cookies)

        # Copy auth headers (Authorization, X-API-Key, etc.)
        for key, val in state.session.headers.items():
            lower = key.lower()
            if lower in ('authorization', 'x-api-key', 'x-auth-token'):
                target_session.headers[key] = val

        # Copy any custom headers from credentials
        creds = self._credentials.get(role)
        if creds and creds.headers:
            target_session.headers.update(creds.headers)

        return True

    def apply_cookie_auth(self, session: requests.Session, cookies: Dict[str, str]) -> None:
        """Directly inject cookies into a session (cookie auth mode)."""
        for name, value in cookies.items():
            session.cookies.set(name, value)

    def apply_bearer_auth(self, session: requests.Session, token: str) -> None:
        """Set Bearer token on a session."""
        session.headers['Authorization'] = f'Bearer {token}'

    def apply_custom_header_auth(self, session: requests.Session, headers: Dict[str, str]) -> None:
        """Set arbitrary auth headers on a session."""
        session.headers.update(headers)

    @property
    def is_authenticated(self) -> bool:
        """True if at least one role is authenticated."""
        return any(s.authenticated for s in self._sessions.values())

    @property
    def roles(self) -> List[str]:
        """List of authenticated roles."""
        return [r for r, s in self._sessions.items() if s.authenticated]

    # ── Internal ──────────────────────────────────────────────────────────

    def _create_session(self) -> requests.Session:
        """Create a base session for scanning."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                          'AppleWebKit/537.36 (KHTML, like Gecko) '
                          'Chrome/120.0.0.0 Safari/537.36',
        })
        session.verify = False
        return session

    def _perform_login(self, state: SessionState, creds: AuthCredentials) -> bool:
        """Execute login using the registered login function or direct injection."""
        auth_type = creds.extra.get('auth_type', 'form')
        state.auth_type = auth_type

        # Direct injection modes (no login_fn needed)
        if auth_type == AuthType.COOKIE:
            if creds.cookies:
                self.apply_cookie_auth(state.session, creds.cookies)
                return True
            return False

        if auth_type == AuthType.BEARER:
            if creds.token:
                self.apply_bearer_auth(state.session, creds.token)
                return True
            return False

        if auth_type == AuthType.CUSTOM:
            if creds.headers:
                self.apply_custom_header_auth(state.session, creds.headers)
                return True
            return False

        # Login function required for form/API auth
        if self._login_fn:
            login_url = creds.extra.get('login_url', '/login')
            return self._login_fn(
                state.session,
                login_url,
                creds.username,
                creds.password,
            )

        return False

    def _reauthenticate(self, role: str) -> bool:
        """Re-authenticate a role."""
        logger.info(f'Re-authenticating role: {role}')
        return self.authenticate(role)
