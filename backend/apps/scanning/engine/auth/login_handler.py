"""
LoginHandler — Automated authentication for web applications.

Supports form-based login, API/bearer token login, OAuth2 flows,
cookie injection, custom header auth, CSRF token extraction, and MFA/TOTP.
"""
import logging
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)


class LoginHandler:
    """Handles automated login to web applications."""

    # Common indicators that login succeeded
    SUCCESS_INDICATORS = [
        'dashboard', 'welcome', 'logout', 'sign out', 'my account',
        'profile', 'settings', 'home',
    ]

    # Common indicators that login failed
    FAILURE_INDICATORS = [
        'invalid', 'incorrect', 'wrong', 'denied', 'failed', 'error',
        'try again', 'bad credentials', 'unauthorized',
    ]

    REQUEST_TIMEOUT = 15

    def __init__(self, base_url: str = ''):
        self.base_url = base_url.rstrip('/')
        self._csrf_field_names = [
            'csrf_token', 'csrfmiddlewaretoken', '_csrf', 'csrf',
            'authenticity_token', '_token', 'XSRF-TOKEN', '__RequestVerificationToken',
        ]

    # ── Form-Based Login ──────────────────────────────────────────────────

    def form_login(
        self,
        session: requests.Session,
        login_url: str,
        username: str,
        password: str,
        username_field: str = 'username',
        password_field: str = 'password',
        extra_fields: Optional[Dict[str, str]] = None,
    ) -> bool:
        """
        Perform form-based login with automatic CSRF token extraction.

        1. GET the login page → extract CSRF token
        2. POST credentials + CSRF → follow redirect
        3. Detect success/failure from response
        """
        login_url = self._resolve_url(login_url)

        try:
            # Step 1: Fetch login page
            get_resp = session.get(login_url, timeout=self.REQUEST_TIMEOUT, allow_redirects=True)
            if get_resp.status_code >= 400:
                logger.debug(f'Login page returned {get_resp.status_code}')
                return False

            # Step 2: Extract CSRF token
            csrf_token, csrf_field = self._extract_csrf_token(get_resp.text)

            # Step 3: Build POST data
            post_data = {
                username_field: username,
                password_field: password,
            }
            if csrf_token and csrf_field:
                post_data[csrf_field] = csrf_token
            if extra_fields:
                post_data.update(extra_fields)

            # Step 4: Submit login form
            post_resp = session.post(
                login_url,
                data=post_data,
                timeout=self.REQUEST_TIMEOUT,
                allow_redirects=True,
            )

            return self._detect_login_success(post_resp, session)

        except requests.RequestException as exc:
            logger.debug(f'Form login failed: {exc}')
            return False

    # ── API/Token Login ───────────────────────────────────────────────────

    def api_login(
        self,
        session: requests.Session,
        login_url: str,
        username: str,
        password: str,
        token_field: str = 'access_token',
        username_field: str = 'username',
        password_field: str = 'password',
    ) -> bool:
        """
        Login via JSON API endpoint. Extracts bearer token from response
        and sets it as the Authorization header.
        """
        login_url = self._resolve_url(login_url)

        try:
            payload = {username_field: username, password_field: password}
            resp = session.post(
                login_url,
                json=payload,
                timeout=self.REQUEST_TIMEOUT,
            )

            if resp.status_code >= 400:
                return False

            data = resp.json()
            token = self._extract_token(data, token_field)
            if token:
                session.headers['Authorization'] = f'Bearer {token}'
                logger.info('API login successful — bearer token set')
                return True

            return False
        except (requests.RequestException, ValueError) as exc:
            logger.debug(f'API login failed: {exc}')
            return False

    # ── OAuth2 Flows ──────────────────────────────────────────────────────

    def oauth2_client_credentials(
        self,
        session: requests.Session,
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str = '',
    ) -> bool:
        """OAuth2 client_credentials grant flow."""
        try:
            data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
            }
            if scope:
                data['scope'] = scope

            resp = session.post(token_url, data=data, timeout=self.REQUEST_TIMEOUT)
            if resp.status_code >= 400:
                return False

            token_data = resp.json()
            token = token_data.get('access_token', '')
            if token:
                session.headers['Authorization'] = f'Bearer {token}'
                logger.info('OAuth2 client_credentials login successful')
                return True
            return False
        except (requests.RequestException, ValueError) as exc:
            logger.debug(f'OAuth2 login failed: {exc}')
            return False

    # ── MFA / TOTP ────────────────────────────────────────────────────────

    def submit_totp(
        self,
        session: requests.Session,
        mfa_url: str,
        totp_secret: str,
        code_field: str = 'totp_code',
    ) -> bool:
        """Submit a TOTP MFA code after initial login."""
        try:
            import pyotp
            totp = pyotp.TOTP(totp_secret)
            code = totp.now()
        except ImportError:
            logger.warning('pyotp not installed — MFA TOTP support unavailable')
            return False
        except Exception as exc:
            logger.debug(f'TOTP generation failed: {exc}')
            return False

        mfa_url = self._resolve_url(mfa_url)
        try:
            # GET MFA page for CSRF
            get_resp = session.get(mfa_url, timeout=self.REQUEST_TIMEOUT)
            csrf_token, csrf_field = self._extract_csrf_token(get_resp.text)

            post_data = {code_field: code}
            if csrf_token and csrf_field:
                post_data[csrf_field] = csrf_token

            resp = session.post(
                mfa_url, data=post_data,
                timeout=self.REQUEST_TIMEOUT, allow_redirects=True,
            )
            return self._detect_login_success(resp, session)
        except requests.RequestException as exc:
            logger.debug(f'TOTP submission failed: {exc}')
            return False

    # ── CSRF Extraction ───────────────────────────────────────────────────

    def _extract_csrf_token(self, html: str) -> Tuple[str, str]:
        """Extract CSRF token from HTML form. Returns (token_value, field_name)."""
        for field_name in self._csrf_field_names:
            # Check hidden input
            pattern = (
                rf'<input[^>]*name=["\']?{re.escape(field_name)}["\']?'
                rf'[^>]*value=["\']?([^"\'\s>]+)["\']?'
            )
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1), field_name

            # Reverse order: value before name
            pattern2 = (
                rf'<input[^>]*value=["\']?([^"\'\s>]+)["\']?'
                rf'[^>]*name=["\']?{re.escape(field_name)}["\']?'
            )
            match2 = re.search(pattern2, html, re.IGNORECASE)
            if match2:
                return match2.group(1), field_name

        # Check meta tag (common in SPAs)
        meta_match = re.search(
            r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']+)["\']',
            html, re.IGNORECASE,
        )
        if meta_match:
            return meta_match.group(1), 'csrf-token'

        return '', ''

    # ── Success Detection ─────────────────────────────────────────────────

    def _detect_login_success(
        self,
        response: requests.Response,
        session: requests.Session,
    ) -> bool:
        """Determine if login was successful based on response characteristics."""
        body_lower = response.text.lower()

        # Check for explicit failure indicators
        for indicator in self.FAILURE_INDICATORS:
            if indicator in body_lower:
                # If failure indicator found along with a login form, likely failed
                if '<form' in body_lower and ('password' in body_lower or 'login' in body_lower):
                    return False

        # Check for success indicators
        for indicator in self.SUCCESS_INDICATORS:
            if indicator in body_lower:
                return True

        # Check if we got session cookies set
        if session.cookies:
            session_cookie_names = {'session', 'sessionid', 'session_id', 'sid',
                                     'phpsessid', 'jsessionid', 'connect.sid'}
            for cookie_name in session.cookies.keys():
                if cookie_name.lower() in session_cookie_names:
                    return True

        # 3xx redirect after login is often success
        if response.history and response.history[-1].status_code in (301, 302, 303):
            return True

        # If status is 200 and no failure indicators, consider success
        if response.status_code == 200:
            return True

        return False

    # ── Helpers ───────────────────────────────────────────────────────────

    def _resolve_url(self, url: str) -> str:
        """Resolve a possibly relative URL against base_url."""
        if url.startswith(('http://', 'https://')):
            return url
        return urljoin(self.base_url + '/', url.lstrip('/'))

    def _extract_token(self, data: Any, token_field: str) -> str:
        """Extract token from JSON response, supporting nested paths."""
        if isinstance(data, dict):
            # Direct field
            if token_field in data:
                return str(data[token_field])
            # Nested: try dot-separated path
            parts = token_field.split('.')
            current = data
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return ''
            return str(current) if current else ''
        return ''
