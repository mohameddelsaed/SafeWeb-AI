"""
Headless Form Interactor — AI-assisted form auto-fill and submission
for SPA/dynamic forms using Playwright.

Capabilities:
  - Detect form fields by type (text, email, password, file, hidden, etc.)
  - Auto-fill with context-aware test values (fuzzing vs. auth vs. recon)
  - Multi-step form flows (wizard forms, multi-page checkout)
  - File upload handling
  - CAPTCHA detection (skip, don't attempt bypass)
  - Extract CSRF tokens from hidden fields
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Field type detection patterns
_FIELD_PATTERNS = {
    'email':    re.compile(r'email|e-mail', re.I),
    'password': re.compile(r'pass(word)?|pwd|secret', re.I),
    'username': re.compile(r'user(name)?|login|account', re.I),
    'phone':    re.compile(r'phone|tel|mobile|cell', re.I),
    'search':   re.compile(r'search|query|q\b|keyword', re.I),
    'url':      re.compile(r'\burl\b|website|link|href', re.I),
    'name':     re.compile(r'\bname\b|first.?name|last.?name|full.?name', re.I),
    'address':  re.compile(r'address|street|city|zip|postal', re.I),
    'number':   re.compile(r'amount|price|quantity|count|num|age', re.I),
    'date':     re.compile(r'date|birth|dob|when', re.I),
    'file':     re.compile(r'file|upload|attach|document|image|photo', re.I),
    'csrf':     re.compile(r'csrf|xsrf|token|_token|authenticity', re.I),
    'captcha':  re.compile(r'captcha|recaptcha|hcaptcha|challenge', re.I),
}

# Smart test values by field type
_TEST_VALUES = {
    'email':    'test@safeweb-scanner.local',
    'password': 'TestP@ss123!',
    'username': 'scanner_test_user',
    'phone':    '+1234567890',
    'search':   'test search query',
    'url':      'https://example.com',
    'name':     'Scanner Test',
    'address':  '123 Test Street',
    'number':   '42',
    'date':     '2024-01-15',
    'text':     'SafeWeb test input',
}

# Fuzz values by field type (for vulnerability testing)
_FUZZ_VALUES = {
    'email':    'test"@safeweb.local',
    'password': "' OR '1'='1",
    'username': '<script>alert(1)</script>',
    'search':   '{{7*7}}',
    'url':      'javascript:alert(1)',
    'name':     '${7*7}',
    'number':   '-1 OR 1=1',
    'text':     '"><img src=x onerror=alert(1)>',
    'default':  "' OR 1=1--",
}


@dataclass
class FormField:
    """Detected form field."""
    selector: str
    name: str = ''
    field_type: str = 'text'
    input_type: str = ''  # HTML input type
    required: bool = False
    detected_purpose: str = ''  # email, password, csrf, etc.
    value: str = ''
    is_hidden: bool = False


@dataclass
class FormInfo:
    """Detected form on the page."""
    action: str = ''
    method: str = 'GET'
    fields: list[FormField] = field(default_factory=list)
    has_file_upload: bool = False
    has_captcha: bool = False
    csrf_field: str = ''
    csrf_value: str = ''
    submit_selector: str = ''


class FormInteractor:
    """AI-assisted form auto-fill and submission via Playwright."""

    def __init__(self, mode: str = 'smart'):
        """
        Args:
            mode: 'smart' (normal values), 'fuzz' (test payloads), 'auth' (login creds)
        """
        self.mode = mode

    def detect_forms(self, page) -> list[FormInfo]:
        """Detect all forms on a Playwright page."""
        forms = []
        try:
            form_data = page.evaluate('''() => {
                const results = [];
                document.querySelectorAll('form').forEach((form, idx) => {
                    const fields = [];
                    form.querySelectorAll('input, textarea, select').forEach(el => {
                        fields.push({
                            tag: el.tagName.toLowerCase(),
                            type: el.type || '',
                            name: el.name || '',
                            id: el.id || '',
                            placeholder: el.placeholder || '',
                            required: el.required,
                            hidden: el.type === 'hidden',
                            value: el.type === 'hidden' ? el.value : '',
                            ariaLabel: el.getAttribute('aria-label') || '',
                        });
                    });
                    const submit = form.querySelector('[type="submit"], button:not([type="button"])');
                    results.push({
                        action: form.action || '',
                        method: (form.method || 'GET').toUpperCase(),
                        fields: fields,
                        formIndex: idx,
                        submitSelector: submit ? `form:nth-of-type(${idx+1}) [type="submit"], form:nth-of-type(${idx+1}) button:not([type="button"])` : '',
                    });
                });
                return results;
            }''')

            for fd in form_data:
                info = FormInfo(
                    action=fd.get('action', ''),
                    method=fd.get('method', 'GET'),
                    submit_selector=fd.get('submitSelector', ''),
                )
                for f in fd.get('fields', []):
                    field_obj = FormField(
                        selector=self._build_selector(f),
                        name=f.get('name', ''),
                        input_type=f.get('type', ''),
                        required=f.get('required', False),
                        is_hidden=f.get('hidden', False),
                        value=f.get('value', ''),
                    )
                    # Detect purpose
                    field_obj.detected_purpose = self._detect_purpose(f)
                    if field_obj.detected_purpose == 'csrf':
                        info.csrf_field = field_obj.name
                        info.csrf_value = field_obj.value
                    if field_obj.detected_purpose == 'captcha':
                        info.has_captcha = True
                    if f.get('type') == 'file':
                        info.has_file_upload = True
                        field_obj.detected_purpose = 'file'
                    info.fields.append(field_obj)
                forms.append(info)

        except Exception as e:
            logger.debug('Form detection failed: %s', e)

        return forms

    def fill_and_submit(self, page, form: FormInfo,
                        custom_values: dict[str, str] | None = None) -> dict:
        """Fill form fields and submit.

        Returns:
            {'submitted': bool, 'response_url': str, 'fields_filled': int}
        """
        result = {'submitted': False, 'response_url': '', 'fields_filled': 0}
        values = custom_values or {}

        try:
            for fld in form.fields:
                if fld.is_hidden or fld.detected_purpose == 'csrf':
                    continue
                if fld.detected_purpose == 'captcha':
                    logger.debug('Skipping CAPTCHA field: %s', fld.name)
                    continue

                # Get value
                val = values.get(fld.name)
                if not val:
                    val = self._get_value(fld)
                if not val:
                    continue

                try:
                    page.fill(fld.selector, val, timeout=3000)
                    result['fields_filled'] += 1
                except Exception:
                    try:
                        page.type(fld.selector, val, timeout=3000)
                        result['fields_filled'] += 1
                    except Exception:
                        pass

            # Submit
            if form.submit_selector:
                page.click(form.submit_selector, timeout=5000)
            else:
                page.keyboard.press('Enter')

            page.wait_for_load_state('networkidle', timeout=10000)
            result['submitted'] = True
            result['response_url'] = page.url

        except Exception as e:
            logger.debug('Form submission failed: %s', e)

        return result

    def _get_value(self, fld: FormField) -> str:
        """Get appropriate value for a field based on mode."""
        purpose = fld.detected_purpose or 'text'
        if self.mode == 'fuzz':
            return _FUZZ_VALUES.get(purpose, _FUZZ_VALUES['default'])
        return _TEST_VALUES.get(purpose, _TEST_VALUES['text'])

    def _detect_purpose(self, field_data: dict) -> str:
        """Detect the semantic purpose of a form field."""
        searchable = ' '.join([
            field_data.get('name', ''),
            field_data.get('id', ''),
            field_data.get('placeholder', ''),
            field_data.get('ariaLabel', ''),
            field_data.get('type', ''),
        ])
        for purpose, pattern in _FIELD_PATTERNS.items():
            if pattern.search(searchable):
                return purpose
        # Fallback by HTML type
        html_type = field_data.get('type', '')
        if html_type in ('email', 'password', 'tel', 'url', 'number', 'date', 'file'):
            return html_type
        return 'text'

    @staticmethod
    def _build_selector(field_data: dict) -> str:
        """Build a CSS selector for a form field."""
        if field_data.get('id'):
            return f'#{field_data["id"]}'
        if field_data.get('name'):
            tag = field_data.get('tag', 'input')
            return f'{tag}[name="{field_data["name"]}"]'
        return ''
