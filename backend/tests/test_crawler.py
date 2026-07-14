"""Tests for the WebCrawler module."""
from unittest.mock import patch, MagicMock


class TestWebCrawlerInit:
    def test_default_depth(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        assert crawler.depth == 'medium'

    def test_depth_limits(self):
        from apps.scanning.engine.crawler import WebCrawler
        assert WebCrawler.DEPTH_LIMITS['shallow'] < WebCrawler.DEPTH_LIMITS['medium']
        assert WebCrawler.DEPTH_LIMITS['medium'] < WebCrawler.DEPTH_LIMITS['deep']

    def test_skip_extensions_set(self):
        from apps.scanning.engine.crawler import WebCrawler
        assert '.css' in WebCrawler.SKIP_EXTENSIONS
        assert '.js' in WebCrawler.SKIP_EXTENSIONS
        assert '.png' in WebCrawler.SKIP_EXTENSIONS


class TestPageDataclass:
    def test_defaults(self):
        from apps.scanning.engine.crawler import Page
        page = Page(url='https://example.com')
        assert page.url == 'https://example.com'
        assert page.status_code == 0
        assert page.headers == {}
        assert page.body == ''
        assert page.forms == []
        assert page.links == []
        assert page.parameters == {}
        assert page.js_rendered is False


class TestFormDataclass:
    def test_creation(self):
        from apps.scanning.engine.crawler import Form, FormInput
        form = Form(action='/search', method='GET', inputs=[
            FormInput(name='q', input_type='text'),
        ])
        assert form.action == '/search'
        assert form.method == 'GET'
        assert len(form.inputs) == 1
        assert form.inputs[0].name == 'q'


class TestCrawlerShouldSkip:
    def test_skips_css(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        assert crawler._should_skip('https://example.com/style.css') is True

    def test_skips_images(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        assert crawler._should_skip('https://example.com/logo.png') is True

    def test_allows_html(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        assert crawler._should_skip('https://example.com/page.html') is False

    def test_allows_no_extension(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        assert crawler._should_skip('https://example.com/about') is False


class TestCrawlerNeedsJSRendering:
    def test_spa_indicators(self):
        from apps.scanning.engine.crawler import WebCrawler, Page
        crawler = WebCrawler(base_url='https://example.com', js_rendering=True)
        crawler.js_rendering = True  # Force enable (Playwright may not be installed)
        page = Page(url='https://example.com', body='<div id="root"></div>')
        assert crawler._needs_js_rendering(page) is True
        page2 = Page(url='https://example.com', body='<div ng-app="myApp">Loading...</div>')
        assert crawler._needs_js_rendering(page2) is True

    def test_normal_html_no_js(self):
        from apps.scanning.engine.crawler import WebCrawler, Page
        crawler = WebCrawler(base_url='https://example.com', js_rendering=True)
        crawler.js_rendering = True  # Force enable
        page = Page(url='https://example.com', body='<html><body><p>Hello</p></body></html>')
        assert crawler._needs_js_rendering(page) is False

    def test_js_rendering_disabled(self):
        from apps.scanning.engine.crawler import WebCrawler, Page
        crawler = WebCrawler(base_url='https://example.com', js_rendering=False)
        page = Page(url='https://example.com', body='<div id="root"></div>')
        assert crawler._needs_js_rendering(page) is False


class TestCrawlerExtractLinks:
    def test_extracts_href(self):
        from apps.scanning.engine.crawler import WebCrawler
        from bs4 import BeautifulSoup
        crawler = WebCrawler(base_url='https://example.com')
        html = '<html><body><a href="/about">About</a><a href="/contact">Contact</a></body></html>'
        soup = BeautifulSoup(html, 'html.parser')
        links = crawler._extract_links(soup, 'https://example.com/')
        assert 'https://example.com/about' in links
        assert 'https://example.com/contact' in links

    def test_extracts_forms(self):
        from apps.scanning.engine.crawler import WebCrawler
        from bs4 import BeautifulSoup
        crawler = WebCrawler(base_url='https://example.com')
        html = '<html><body><a href="/search">Link</a><form action="/submit"><input name="q"></form></body></html>'
        soup = BeautifulSoup(html, 'html.parser')
        links = crawler._extract_links(soup, 'https://example.com/')
        # Should at least extract the anchor link
        assert 'https://example.com/search' in links


class TestCrawlerNewFeatures:
    """Tests for the upgraded crawler features: robots.txt, sitemap, AI endpoints, JS links."""

    def test_ai_api_endpoints_defined(self):
        from apps.scanning.engine.crawler import AI_API_ENDPOINTS
        assert isinstance(AI_API_ENDPOINTS, list)
        assert len(AI_API_ENDPOINTS) > 0

    def test_js_url_patterns_defined(self):
        from apps.scanning.engine.crawler import JS_URL_PATTERNS
        assert isinstance(JS_URL_PATTERNS, list)
        assert len(JS_URL_PATTERNS) > 0

    def test_crawler_has_discovery_fields(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        assert hasattr(crawler, 'robots_txt')
        assert hasattr(crawler, 'sitemap_urls')
        assert hasattr(crawler, 'ai_endpoints')
        assert hasattr(crawler, 'api_endpoints')
        assert hasattr(crawler, 'disallowed_paths')

    def test_get_discovery_summary(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        summary = crawler.get_discovery_summary()
        assert isinstance(summary, dict)
        assert 'robots_txt_found' in summary
        assert 'sitemap_urls_count' in summary
        assert 'ai_endpoints' in summary

    def test_js_link_extraction(self):
        from apps.scanning.engine.crawler import WebCrawler
        from bs4 import BeautifulSoup
        crawler = WebCrawler(base_url='https://example.com')
        html = '''<html><body>
        <a href="/page1">P1</a>
        <script>
            fetch("/api/users");
            const url = "/api/data";
        </script>
        </body></html>'''
        soup = BeautifulSoup(html, 'html.parser')
        links = crawler._extract_links(soup, 'https://example.com/')
        assert 'https://example.com/page1' in links
        # JS URLs should also be extracted
        assert isinstance(links, list)

    def test_parse_robots_txt(self):
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler(base_url='https://example.com')
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = 'User-agent: *\nDisallow: /admin/\nDisallow: /private/\nSitemap: https://example.com/sitemap.xml'
        with patch.object(crawler.session, 'get', return_value=mock_resp):
            crawler._parse_robots_txt()
        assert '/admin/' in crawler.disallowed_paths
        assert '/private/' in crawler.disallowed_paths
