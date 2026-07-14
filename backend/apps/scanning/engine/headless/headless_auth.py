"""
Headless Auth Flow — Playwright-based authentication for SPAs.

Handles login flows that require JavaScript execution:
  - SPA login forms (React/Angular/Vue login pages)
  - Multi-step MFA flows
  - OAuth2 redirect chains in browser
  - Cookie/localStorage extraction after auth
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

try:
    from playwright.sync_api import BrowserContext, Page
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@dataclass
class HeadlessAuthResult:
    """Result of a headless authentication attempt."""
    success: bool = False
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict[str, str] = field(default_factory=dict)
    session_storage: dict[str, str] = field(default_factory=dict)
    auth_headers: dict[str, str] = field(default_factory=dict)
    final_url: str = ''
    error: str = ''


class HeadlessAuthFlow:
    """Execute authentication flows via Playwright headless browser."""

    DEFAULT_TIMEOUT = 15000

    def __init__(self):
        if not HAS_PLAYWRIGHT:
            logger.warning('Playwright not installed — HeadlessAuthFlow disabled')

    def login_form(
        self,
        context: 'BrowserContext',
        login_url: str,
        username: str,
        password: str,
        username_selector: str = '',
        password_selector: str = '',
        submit_selector: str = '',
        success_indicator: str = '',
    ) -> HeadlessAuthResult:
        """Login via form in a headless browser.

        Auto-detects field selectors if not provided.
        """
        result = HeadlessAuthResult()
        if not HAS_PLAYWRIGHT:
            result.error = 'Playwright not available'
            return result

        page = None
        try:
            page = context.new_page()
            page.goto(login_url, wait_until='networkidle',
                      timeout=self.DEFAULT_TIMEOUT)

            # Auto-detect selectors
            if not username_selector:
                username_selector = self._find_username_field(page)
            if not password_selector:
                password_selector = self._find_password_field(page)
            if not submit_selector:
                submit_selector = self._find_submit_button(page)

            if not username_selector or not password_selector:
                result.error = 'Could not detect login form fields'
                return result

            # Fill and submit
            page.fill(username_selector, username, timeout=5000)
            page.fill(password_selector, password, timeout=5000)

            if submit_selector:
                page.click(submit_selector, timeout=5000)
            else:
                page.press(password_selector, 'Enter')

            page.wait_for_load_state('networkidle', timeout=self.DEFAULT_TIMEOUT)
            time.sleep(1)

            # Check success
            result.final_url = page.url
            if success_indicator:
                result.success = success_indicator in page.content()
            else:
                result.success = self._detect_login_success(page, login_url)

            # Extract auth state
            if result.success:
                result.cookies = context.cookies()
                result.local_storage = self._get_storage(page, 'localStorage')
                result.session_storage = self._get_storage(page, 'sessionStorage')
                result.auth_headers = self._extract_auth_headers(result)

        except Exception as e:
            result.error = str(e)
            logger.debug('Headless login error: %s', e)
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
        return result

    def oauth_browser_flow(
        self,
        context: 'BrowserContext',
        auth_url: str,
        expected_redirect: str,
        credentials: dict[str, str] | None = None,
    ) -> HeadlessAuthResult:
        """Follow an OAuth2 flow in the browser, capturing the redirect.

        Args:
            context: Playwright browser context.
            auth_url: Full authorization URL with params.
            expected_redirect: URL prefix to watch for (redirect_uri).
            credentials: Optional {'username': ..., 'password': ...} to auto-fill IdP login.
        """
        result = HeadlessAuthResult()
        if not HAS_PLAYWRIGHT:
            result.error = 'Playwright not available'
            return result

        page = None
        try:
            page = context.new_page()
            page.goto(auth_url, wait_until='networkidle',
                      timeout=self.DEFAULT_TIMEOUT)

            # If credentials provided, try to fill IdP login form
            if credentials:
                time.sleep(1)
                user_sel = self._find_username_field(page)
                pass_sel = self._find_password_field(page)
                if user_sel and pass_sel:
                    page.fill(user_sel, credentials.get('username', ''))
                    page.fill(pass_sel, credentials.get('password', ''))
                    submit = self._find_submit_button(page)
                    if submit:
                        page.click(submit, timeout=5000)
                    else:
                        page.press(pass_sel, 'Enter')
                    page.wait_for_load_state('networkidle',
                                             timeout=self.DEFAULT_TIMEOUT)

            # Wait for redirect to our callback
            for _ in range(20):
                if page.url.startswith(expected_redirect):
                    result.success = True
                    result.final_url = page.url
                    break
                time.sleep(0.5)

            if result.success:
                result.cookies = context.cookies()
                result.local_storage = self._get_storage(page, 'localStorage')
                result.session_storage = self._get_storage(page, 'sessionStorage')

        except Exception as e:
            result.error = str(e)
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
        return result

    def apply_to_session(self, session, auth_result: HeadlessAuthResult) -> None:
        """Apply browser auth state to a requests.Session."""
        for cookie in auth_result.cookies:
            session.cookies.set(
                cookie['name'], cookie['value'],
                domain=cookie.get('domain', ''),
                path=cookie.get('path', '/'),
            )
        for k, v in auth_result.auth_headers.items():
            session.headers[k] = v

    # ── Auto-detection helpers ────────────────────────────────────────────

    def _find_username_field(self, page: 'Page') -> str:
        selectors = [
            'input[type="email"]',
            'input[name*="user" i]', 'input[name*="email" i]',
            'input[name*="login" i]', 'input[id*="user" i]',
            'input[id*="email" i]', 'input[autocomplete="username"]',
            'input[type="text"]:first-of-type',
        ]
        for sel in selectors:
            try:
                if page.query_selector(sel):
                    return sel
            except Exception:
                continue
        return ''

    def _find_password_field(self, page: 'Page') -> str:
        selectors = [
            'input[type="password"]',
            'input[name*="pass" i]', 'input[id*="pass" i]',
            'input[autocomplete="current-password"]',
        ]
        for sel in selectors:
            try:
                if page.query_selector(sel):
                    return sel
            except Exception:
                continue
        return ''

    def _find_submit_button(self, page: 'Page') -> str:
        selectors = [
            'button[type="submit"]',
            'input[type="submit"]',
            'button:has-text("Log in")', 'button:has-text("Sign in")',
            'button:has-text("Login")', 'button:has-text("Submit")',
            'form button',
        ]
        for sel in selectors:
            try:
                if page.query_selector(sel):
                    return sel
            except Exception:
                continue
        return ''

    def _detect_login_success(self, page: 'Page', login_url: str) -> bool:
        """Heuristic: did we navigate away from login? Are there auth cookies?"""
        # URL changed
        if page.url != login_url and '/login' not in page.url.lower():
            return True
        # Success indicators in page
        content = page.content().lower()
        for indicator in ('dashboard', 'welcome', 'logout', 'sign out', 'profile'):
            if indicator in content:
                return True
        return False

    def _get_storage(self, page: 'Page', storage_type: str) -> dict[str, str]:
        """Extract localStorage or sessionStorage."""
        try:
            return page.evaluate(f'''() => {{
                const data = {{}};
                for (let i = 0; i < {storage_type}.length; i++) {{
                    const key = {storage_type}.key(i);
                    data[key] = {storage_type}.getItem(key);
                }}
                return data;
            }}''')
        except Exception:
            return {}

    def _extract_auth_headers(self, result: HeadlessAuthResult) -> dict[str, str]:
        """Build auth headers from cookies/storage (look for JWT tokens)."""
        headers: dict[str, str] = {}
        # Check localStorage for tokens
        for key, val in result.local_storage.items():
            key_lower = key.lower()
            if any(t in key_lower for t in ('token', 'jwt', 'auth', 'access')):
                if val and len(val) > 20:
                    headers['Authorization'] = f'Bearer {val}'
                    break
        # Check session_storage
        if 'Authorization' not in headers:
            for key, val in result.session_storage.items():
                key_lower = key.lower()
                if any(t in key_lower for t in ('token', 'jwt', 'auth', 'access')):
                    if val and len(val) > 20:
                        headers['Authorization'] = f'Bearer {val}'
                        break
        return headers

    def run_auto_login(
        self,
        login_url: str,
        username: str = '',
        password: str = '',
    ) -> HeadlessAuthResult:
        """Create standalone Playwright browser context and execute form login."""
        result = HeadlessAuthResult()
        if not HAS_PLAYWRIGHT:
            result.error = 'Playwright not available'
            return result
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context()
                result = self.login_form(context, login_url, username, password)
                browser.close()
        except Exception as e:
            result.error = str(e)
        return result
