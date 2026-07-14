"""
AuthSequence — Define and execute multi-step authentication flows.

Supports complex auth patterns: login → CSRF → MFA → dashboard verification,
SSO redirect chains, and custom state-machine auth flows.
"""
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


class StepType(str, Enum):
    """Types of authentication steps."""
    GET = 'get'              # Fetch a page (e.g. login form, MFA page)
    POST_FORM = 'post_form'  # Submit form data
    POST_JSON = 'post_json'  # Submit JSON payload
    EXTRACT = 'extract'      # Extract a value from previous response
    SET_HEADER = 'set_header' # Set a header on the session
    WAIT = 'wait'            # Wait (e.g. for redirect processing)
    VERIFY = 'verify'        # Verify auth succeeded


@dataclass
class AuthStep:
    """A single step in an authentication sequence."""
    name: str
    step_type: StepType
    url: str = ''
    data: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    # Extraction config
    extract_from: str = 'body'   # body, header, cookie, json
    extract_pattern: str = ''    # Regex or JSON key
    extract_store_as: str = ''   # Variable name to store result
    # Verification config
    success_pattern: str = ''    # Regex that indicates success
    failure_pattern: str = ''    # Regex that indicates failure
    # Flow control
    follow_redirects: bool = True
    required: bool = True        # If False, failure doesn't abort sequence
    timeout: int = 15


class AuthSequenceState(Enum):
    """State of the auth sequence execution."""
    NOT_STARTED = 'not_started'
    IN_PROGRESS = 'in_progress'
    SUCCESS = 'success'
    FAILED = 'failed'


class AuthSequence:
    """Execute a multi-step authentication flow."""

    def __init__(self, steps: Optional[List[AuthStep]] = None):
        self.steps: List[AuthStep] = steps or []
        self.state = AuthSequenceState.NOT_STARTED
        self.variables: Dict[str, str] = {}
        self.last_response: Optional[requests.Response] = None
        self.completed_steps: List[str] = []
        self.error_message: str = ''

    def add_step(self, step: AuthStep) -> None:
        """Append a step to the sequence."""
        self.steps.append(step)

    def execute(self, session: requests.Session) -> bool:
        """
        Execute the full authentication sequence.
        Returns True if auth succeeded.
        """
        self.state = AuthSequenceState.IN_PROGRESS
        self.variables = {}
        self.completed_steps = []

        for step in self.steps:
            logger.debug(f'Auth sequence step: {step.name} ({step.step_type})')
            success = self._execute_step(session, step)
            if success:
                self.completed_steps.append(step.name)
            elif step.required:
                self.state = AuthSequenceState.FAILED
                self.error_message = f'Required step failed: {step.name}'
                logger.warning(f'Auth sequence failed at step: {step.name}')
                return False
            else:
                logger.debug(f'Optional step failed: {step.name}')

        self.state = AuthSequenceState.SUCCESS
        logger.info(f'Auth sequence complete ({len(self.completed_steps)}/{len(self.steps)} steps)')
        return True

    # ── Step Execution ────────────────────────────────────────────────────

    def _execute_step(self, session: requests.Session, step: AuthStep) -> bool:
        """Execute a single auth step."""
        url = self._substitute_variables(step.url)
        data = {k: self._substitute_variables(str(v)) for k, v in step.data.items()}

        try:
            if step.step_type == StepType.GET:
                return self._step_get(session, step, url)
            elif step.step_type == StepType.POST_FORM:
                return self._step_post_form(session, step, url, data)
            elif step.step_type == StepType.POST_JSON:
                return self._step_post_json(session, step, url, data)
            elif step.step_type == StepType.EXTRACT:
                return self._step_extract(step)
            elif step.step_type == StepType.SET_HEADER:
                return self._step_set_header(session, step, data)
            elif step.step_type == StepType.VERIFY:
                return self._step_verify(session, step, url)
            elif step.step_type == StepType.WAIT:
                return True  # No-op step
            else:
                logger.warning(f'Unknown step type: {step.step_type}')
                return False
        except requests.RequestException as exc:
            logger.debug(f'Step {step.name} request error: {exc}')
            return False

    def _step_get(self, session: requests.Session, step: AuthStep, url: str) -> bool:
        """GET a URL, optionally extract values."""
        resp = session.get(
            url, timeout=step.timeout,
            allow_redirects=step.follow_redirects,
            headers=step.headers or None,
        )
        self.last_response = resp
        if resp.status_code >= 500:
            return False

        # Auto-extract if configured
        if step.extract_pattern and step.extract_store_as:
            self._extract_value(step, resp)

        return True

    def _step_post_form(
        self, session: requests.Session, step: AuthStep,
        url: str, data: dict,
    ) -> bool:
        """POST form data."""
        resp = session.post(
            url, data=data, timeout=step.timeout,
            allow_redirects=step.follow_redirects,
            headers=step.headers or None,
        )
        self.last_response = resp

        # Check success/failure patterns
        if step.failure_pattern and re.search(step.failure_pattern, resp.text, re.IGNORECASE):
            return False
        if step.success_pattern and not re.search(step.success_pattern, resp.text, re.IGNORECASE):
            return False

        # Extract if configured
        if step.extract_pattern and step.extract_store_as:
            self._extract_value(step, resp)

        return resp.status_code < 400 or (resp.history and resp.history[-1].status_code in (301, 302, 303))

    def _step_post_json(
        self, session: requests.Session, step: AuthStep,
        url: str, data: dict,
    ) -> bool:
        """POST JSON data."""
        resp = session.post(
            url, json=data, timeout=step.timeout,
            allow_redirects=step.follow_redirects,
            headers=step.headers or None,
        )
        self.last_response = resp

        # Extract if configured
        if step.extract_pattern and step.extract_store_as:
            self._extract_value(step, resp)

        if step.failure_pattern and re.search(step.failure_pattern, resp.text, re.IGNORECASE):
            return False

        return resp.status_code < 400

    def _step_extract(self, step: AuthStep) -> bool:
        """Extract a value from the last response."""
        if not self.last_response:
            return False
        return self._extract_value(step, self.last_response)

    def _step_set_header(self, session: requests.Session, step: AuthStep, data: dict) -> bool:
        """Set a header on the session from variables or data."""
        for key, val_template in data.items():
            resolved = self._substitute_variables(val_template)
            session.headers[key] = resolved
        return True

    def _step_verify(self, session: requests.Session, step: AuthStep, url: str) -> bool:
        """Verify that auth succeeded by checking a protected page."""
        if not url:
            # Verify from last response
            if self.last_response and step.success_pattern:
                return bool(re.search(step.success_pattern, self.last_response.text, re.IGNORECASE))
            return self.last_response is not None and self.last_response.status_code < 400

        resp = session.get(url, timeout=step.timeout, allow_redirects=step.follow_redirects)
        self.last_response = resp

        if step.failure_pattern and re.search(step.failure_pattern, resp.text, re.IGNORECASE):
            return False
        if step.success_pattern:
            return bool(re.search(step.success_pattern, resp.text, re.IGNORECASE))
        return resp.status_code < 400

    # ── Variable Substitution ─────────────────────────────────────────────

    def _substitute_variables(self, text: str) -> str:
        """Replace {{variable}} placeholders with stored values."""
        if not text or '{{' not in text:
            return text
        for var_name, var_value in self.variables.items():
            text = text.replace('{{' + var_name + '}}', var_value)
        return text

    def _extract_value(self, step: AuthStep, response: requests.Response) -> bool:
        """Extract a value from a response and store it in variables."""
        if not step.extract_pattern or not step.extract_store_as:
            return False

        source = ''
        if step.extract_from == 'body':
            source = response.text
        elif step.extract_from == 'header':
            source = '\r\n'.join(f'{k}: {v}' for k, v in response.headers.items())
        elif step.extract_from == 'cookie':
            # Extract a specific cookie value
            cookie_val = response.cookies.get(step.extract_pattern, '')
            if cookie_val:
                self.variables[step.extract_store_as] = cookie_val
                return True
            return False
        elif step.extract_from == 'json':
            try:
                data = response.json()
                value = self._json_extract(data, step.extract_pattern)
                if value:
                    self.variables[step.extract_store_as] = value
                    return True
            except (ValueError, TypeError):
                pass
            return False

        # Regex extraction from body/header
        match = re.search(step.extract_pattern, source)
        if match:
            # Use group 1 if available, else group 0
            value = match.group(1) if match.lastindex else match.group(0)
            self.variables[step.extract_store_as] = value
            return True

        return False

    @staticmethod
    def _json_extract(data: Any, path: str) -> str:
        """Extract a value from JSON using dot-path notation."""
        parts = path.split('.')
        current = data
        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            elif isinstance(current, list) and part.isdigit():
                idx = int(part)
                current = current[idx] if idx < len(current) else None
            else:
                return ''
        return str(current) if current is not None else ''

    # ── Builder helpers ───────────────────────────────────────────────────

    @classmethod
    def form_login_sequence(
        cls,
        login_url: str,
        username: str,
        password: str,
        csrf_field: str = '',
        username_field: str = 'username',
        password_field: str = 'password',
        verify_url: str = '',
        success_pattern: str = '',
    ) -> 'AuthSequence':
        """Create a standard form login sequence."""
        steps = [
            AuthStep(
                name='fetch_login_page',
                step_type=StepType.GET,
                url=login_url,
                extract_from='body',
                extract_pattern=(
                    rf'<input[^>]*name=["\']?{re.escape(csrf_field)}["\']?'
                    rf'[^>]*value=["\']?([^"\'\s>]+)["\']?'
                ) if csrf_field else '',
                extract_store_as='csrf_token' if csrf_field else '',
            ),
            AuthStep(
                name='submit_login',
                step_type=StepType.POST_FORM,
                url=login_url,
                data={
                    username_field: username,
                    password_field: password,
                    **(({csrf_field: '{{csrf_token}}'}) if csrf_field else {}),
                },
                success_pattern=success_pattern,
            ),
        ]
        if verify_url:
            steps.append(AuthStep(
                name='verify_auth',
                step_type=StepType.VERIFY,
                url=verify_url,
                success_pattern=success_pattern or 'dashboard|welcome|logout',
            ))
        return cls(steps=steps)

    @classmethod
    def api_login_sequence(
        cls,
        login_url: str,
        username: str,
        password: str,
        token_field: str = 'access_token',
        username_field: str = 'username',
        password_field: str = 'password',
    ) -> 'AuthSequence':
        """Create a standard API login sequence."""
        return cls(steps=[
            AuthStep(
                name='api_login',
                step_type=StepType.POST_JSON,
                url=login_url,
                data={username_field: username, password_field: password},
                extract_from='json',
                extract_pattern=token_field,
                extract_store_as='auth_token',
            ),
            AuthStep(
                name='set_bearer',
                step_type=StepType.SET_HEADER,
                data={'Authorization': 'Bearer {{auth_token}}'},
            ),
        ])
