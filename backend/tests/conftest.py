"""Pytest configuration and shared fixtures for scanning engine tests."""
import pytest
from dataclasses import dataclass, field
from unittest.mock import MagicMock


@dataclass
class MockFormInput:
    name: str
    input_type: str
    value: str = ''


@dataclass
class MockForm:
    action: str
    method: str
    inputs: list = field(default_factory=list)


@dataclass
class MockPage:
    """Lightweight page fixture matching the crawler.Page dataclass."""
    url: str
    status_code: int = 200
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    body: str = ''
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    js_rendered: bool = False


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def simple_page():
    """A minimal HTML page with a form and query parameters."""
    return MockPage(
        url='https://example.com/search?q=test&page=1',
        status_code=200,
        headers={
            'Content-Type': 'text/html',
            'Server': 'Apache/2.4.41',
        },
        cookies={'session_id': 'abc123'},
        body='''
        <html>
        <head><title>Test</title></head>
        <body>
            <form action="/search" method="GET">
                <input type="text" name="q" value="">
                <input type="submit" value="Search">
            </form>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
        </body>
        </html>
        ''',
        forms=[MockForm(
            action='/search',
            method='GET',
            inputs=[
                MockFormInput(name='q', input_type='text'),
            ],
        )],
        links=['/about', '/contact'],
        parameters={'q': 'test', 'page': '1'},
    )


@pytest.fixture
def login_page():
    """A login page with username/password form."""
    return MockPage(
        url='https://example.com/login',
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='''
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" value="">
                <input type="password" name="password" value="" autocomplete="on">
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
        ''',
        forms=[MockForm(
            action='/login',
            method='POST',
            inputs=[
                MockFormInput(name='username', input_type='text'),
                MockFormInput(name='password', input_type='password'),
            ],
        )],
    )


@pytest.fixture
def api_page():
    """An API endpoint returning JSON."""
    return MockPage(
        url='https://api.example.com/v1/users?id=1',
        status_code=200,
        headers={
            'Content-Type': 'application/json',
            'X-Powered-By': 'Express',
        },
        body='{"id": 1, "name": "test", "email": "test@example.com"}',
        parameters={'id': '1'},
    )


@pytest.fixture
def empty_page():
    """An empty page with no body or forms."""
    return MockPage(
        url='https://example.com/',
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='<html><body></body></html>',
    )


@pytest.fixture
def mock_response():
    """Factory fixture to create mock requests.Response objects."""
    def _make(status_code=200, text='', headers=None, url='https://example.com'):
        resp = MagicMock()
        resp.status_code = status_code
        resp.text = text
        resp.content = text.encode() if isinstance(text, str) else text
        resp.headers = headers or {}
        resp.url = url
        resp.elapsed = MagicMock()
        resp.elapsed.total_seconds.return_value = 0.1
        resp.cookies = {}
        resp.ok = 200 <= status_code < 400
        return resp
    return _make
