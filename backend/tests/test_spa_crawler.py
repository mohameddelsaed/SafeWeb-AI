"""
Tests for Phase 24 — Advanced Crawling & SPA Support.

All Playwright interactions are mocked.
"""
from unittest.mock import patch, MagicMock


# ────────────────────────────────────────────────────────────────────────────
#  Browser Pool Tests
# ────────────────────────────────────────────────────────────────────────────

class TestBrowserPool:
    """Tests for headless.browser_pool.BrowserPool."""

    @patch('apps.scanning.engine.headless.browser_pool.HAS_PLAYWRIGHT', False)
    def test_start_fails_without_playwright(self):
        from apps.scanning.engine.headless.browser_pool import BrowserPool
        pool = BrowserPool(pool_size=2)
        assert pool.start() is False
        assert pool.available is False

    def test_start_creates_contexts(self):
        from apps.scanning.engine.headless import browser_pool

        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_ctx_1, mock_ctx_2, mock_ctx_3 = MagicMock(), MagicMock(), MagicMock()
        mock_browser.new_context.side_effect = [mock_ctx_1, mock_ctx_2, mock_ctx_3]

        mock_sync_pw = MagicMock()
        mock_sync_pw.return_value.start.return_value = mock_pw

        original_has = browser_pool.HAS_PLAYWRIGHT
        browser_pool.HAS_PLAYWRIGHT = True
        browser_pool.sync_playwright = mock_sync_pw
        try:
            pool = browser_pool.BrowserPool(pool_size=3)
            assert pool.start() is True
            assert pool.available is True
            assert pool.pool_size == 3
            assert mock_browser.new_context.call_count == 3
            pool.shutdown()
        finally:
            browser_pool.HAS_PLAYWRIGHT = original_has
            if hasattr(browser_pool, 'sync_playwright'):
                delattr(browser_pool, 'sync_playwright')

    def test_acquire_and_release(self):
        from apps.scanning.engine.headless import browser_pool

        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_ctx = MagicMock()
        mock_ctx.pages = []
        mock_browser.new_context.return_value = mock_ctx

        mock_sync_pw = MagicMock()
        mock_sync_pw.return_value.start.return_value = mock_pw

        original_has = browser_pool.HAS_PLAYWRIGHT
        browser_pool.HAS_PLAYWRIGHT = True
        browser_pool.sync_playwright = mock_sync_pw
        try:
            pool = browser_pool.BrowserPool(pool_size=1)
            pool.start()

            ctx = pool.acquire(timeout=5.0)
            assert ctx is mock_ctx

            pool.release(ctx)
            mock_ctx.clear_cookies.assert_called_once()

            ctx2 = pool.acquire(timeout=5.0)
            assert ctx2 is mock_ctx

            pool.release(ctx2)
            pool.shutdown()
        finally:
            browser_pool.HAS_PLAYWRIGHT = original_has
            if hasattr(browser_pool, 'sync_playwright'):
                delattr(browser_pool, 'sync_playwright')

    @patch('apps.scanning.engine.headless.browser_pool.HAS_PLAYWRIGHT', False)
    def test_acquire_returns_none_when_not_started(self):
        from apps.scanning.engine.headless.browser_pool import BrowserPool
        pool = BrowserPool(pool_size=1)
        assert pool.acquire(timeout=0.1) is None

    def test_shutdown_closes_all(self):
        from apps.scanning.engine.headless import browser_pool

        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_ctx = MagicMock()
        mock_browser.new_context.return_value = mock_ctx

        mock_sync_pw = MagicMock()
        mock_sync_pw.return_value.start.return_value = mock_pw

        original_has = browser_pool.HAS_PLAYWRIGHT
        browser_pool.HAS_PLAYWRIGHT = True
        browser_pool.sync_playwright = mock_sync_pw
        try:
            pool = browser_pool.BrowserPool(pool_size=2)
            pool.start()
            pool.shutdown()

            assert not pool.available
            assert mock_ctx.close.call_count == 2
            mock_browser.close.assert_called_once()
            mock_pw.stop.assert_called_once()
        finally:
            browser_pool.HAS_PLAYWRIGHT = original_has
            if hasattr(browser_pool, 'sync_playwright'):
                delattr(browser_pool, 'sync_playwright')

    def test_context_manager(self):
        from apps.scanning.engine.headless import browser_pool

        mock_pw = MagicMock()
        mock_browser = MagicMock()
        mock_pw.chromium.launch.return_value = mock_browser
        mock_browser.new_context.return_value = MagicMock()

        mock_sync_pw = MagicMock()
        mock_sync_pw.return_value.start.return_value = mock_pw

        original_has = browser_pool.HAS_PLAYWRIGHT
        browser_pool.HAS_PLAYWRIGHT = True
        browser_pool.sync_playwright = mock_sync_pw
        try:
            with browser_pool.BrowserPool(pool_size=1) as pool:
                assert pool.available
            mock_browser.close.assert_called_once()
        finally:
            browser_pool.HAS_PLAYWRIGHT = original_has
            if hasattr(browser_pool, 'sync_playwright'):
                delattr(browser_pool, 'sync_playwright')

    def test_pool_size_clamped(self):
        from apps.scanning.engine.headless.browser_pool import BrowserPool
        pool = BrowserPool(pool_size=100)
        assert pool.pool_size == 8  # MAX_POOL_SIZE

        pool2 = BrowserPool(pool_size=-5)
        assert pool2.pool_size == 1


# ────────────────────────────────────────────────────────────────────────────
#  SPA Crawler Tests
# ────────────────────────────────────────────────────────────────────────────

class TestSPACrawler:
    """Tests for headless.spa_crawler.SPACrawler."""

    def test_detect_spa_react(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler
        html = '<html><body><div id="root"></div><script src="react.min.js"></script></body></html>'
        assert SPACrawler.detect_spa_from_html(html) == 'react'

    def test_detect_spa_angular(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler
        html = '<html><body><app-root ng-version="16"></app-root></body></html>'
        assert SPACrawler.detect_spa_from_html(html) == 'angular'

    def test_detect_spa_vue(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler
        html = '<html><body><div id="app" data-v-abc></div></body></html>'
        assert SPACrawler.detect_spa_from_html(html) == 'vue'

    def test_detect_spa_nextjs(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler
        html = '<html><body><div id="__next"><script id="__NEXT_DATA__">{}</script></div></body></html>'
        assert SPACrawler.detect_spa_from_html(html) == 'nextjs'

    def test_detect_spa_nuxt(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler
        html = '<html><body><div id="__nuxt">__NUXT__</div></body></html>'
        assert SPACrawler.detect_spa_from_html(html) == 'nuxt'

    def test_detect_spa_none(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler
        html = '<html><body><h1>Hello World</h1><p>Normal page</p></body></html>'
        assert SPACrawler.detect_spa_from_html(html) == ''

    def test_crawl_page_full_flow(self):
        """Test full SPA crawl with mocked Playwright page."""
        from apps.scanning.engine.headless.spa_crawler import SPACrawler

        crawler = SPACrawler('https://example.com', depth='medium')

        # Mock context and page
        mock_ctx = MagicMock()
        mock_page = MagicMock()
        mock_ctx.new_page.return_value = mock_page

        # Mock navigation
        mock_response = MagicMock()
        mock_response.status = 200
        mock_page.goto.return_value = mock_response

        # Mock content for framework detection
        mock_page.content.return_value = '<html><body><div id="root"></div></body></html>'

        # Mock evaluate calls
        def mock_evaluate(script, *args):
            if 'script:not([src])' in script:
                return ['const apiUrl = "/api/v1/users";']
            if 'a[href]' in script and 'Set()' in script:
                return ['/about', '/contact', 'https://example.com/dashboard']
            if 'form' in script.lower():
                return [{'action': 'https://example.com/login', 'method': 'POST',
                         'inputs': [{'name': 'email', 'type': 'email', 'value': ''}]}]
            if 'scrollHeight' in script:
                return 500
            return []

        mock_page.evaluate.side_effect = mock_evaluate

        # Mock interactive elements (for click discovery)
        mock_page.query_selector_all.return_value = []

        result = crawler.crawl_page(mock_ctx, 'https://example.com')

        assert result.url == 'https://example.com'
        assert result.framework == 'react'
        assert len(result.errors) == 0
        mock_page.close.assert_called_once()

    def test_crawl_page_navigation_error(self):
        """Test SPA crawl when navigation fails."""
        from apps.scanning.engine.headless.spa_crawler import SPACrawler

        crawler = SPACrawler('https://example.com')
        mock_ctx = MagicMock()
        mock_page = MagicMock()
        mock_ctx.new_page.return_value = mock_page
        mock_page.goto.return_value = None  # No response

        result = crawler.crawl_page(mock_ctx, 'https://example.com')
        assert len(result.errors) > 0
        assert 'no response' in result.errors[0].lower()

    def test_crawl_page_exception(self):
        """Test SPA crawl handles exceptions gracefully."""
        from apps.scanning.engine.headless.spa_crawler import SPACrawler

        crawler = SPACrawler('https://example.com')
        mock_ctx = MagicMock()
        mock_ctx.new_page.side_effect = Exception('Browser crashed')

        result = crawler.crawl_page(mock_ctx, 'https://example.com/page')
        assert len(result.errors) > 0
        assert 'Browser crashed' in result.errors[0]

    def test_is_same_origin(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler

        crawler = SPACrawler('https://example.com')
        assert crawler._is_same_origin('https://example.com/page') is True
        assert crawler._is_same_origin('https://sub.example.com/page') is True
        assert crawler._is_same_origin('https://evil.com/page') is False

    def test_extract_api_endpoints_dedup(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawler

        crawler = SPACrawler('https://example.com')
        requests_list = [
            {'url': 'https://example.com/api/users?page=1', 'method': 'GET', 'resource_type': 'fetch', 'headers': {}},
            {'url': 'https://example.com/api/users?page=2', 'method': 'GET', 'resource_type': 'fetch', 'headers': {}},
            {'url': 'https://example.com/api/users', 'method': 'POST', 'resource_type': 'xhr', 'headers': {}},
        ]
        endpoints = crawler._extract_api_endpoints(requests_list)
        # Same path GET deduplicated, POST is separate
        assert len(endpoints) == 2
        methods = {ep['method'] for ep in endpoints}
        assert 'GET' in methods
        assert 'POST' in methods

    def test_network_interception(self):
        """Test the request capture callback."""
        from apps.scanning.engine.headless.spa_crawler import SPACrawler

        crawler = SPACrawler('https://example.com')
        captured = []

        # XHR request — should be captured
        xhr_req = MagicMock()
        xhr_req.url = 'https://example.com/api/data'
        xhr_req.method = 'GET'
        xhr_req.resource_type = 'xhr'
        xhr_req.headers = {}
        crawler._on_request(xhr_req, captured)
        assert len(captured) == 1

        # Image request — should NOT be captured
        img_req = MagicMock()
        img_req.url = 'https://example.com/logo.png'
        img_req.method = 'GET'
        img_req.resource_type = 'image'
        img_req.headers = {}
        crawler._on_request(img_req, captured)
        assert len(captured) == 1  # Still 1

    def test_js_route_patterns(self):
        """Test JS URL pattern regex matching."""
        from apps.scanning.engine.headless.spa_crawler import JS_URL_PATTERNS

        test_cases = [
            ("fetch('/api/v1/users')", '/api/v1/users'),
            ('axios.get("/api/data")', '/api/data'),
            ("path: '/dashboard/settings'", '/dashboard/settings'),
            ("baseURL: 'https://api.example.com'", 'https://api.example.com'),
        ]

        for text, expected in test_cases:
            found = False
            for pattern in JS_URL_PATTERNS:
                match = pattern.search(text)
                if match:
                    url = match.group(match.lastindex)
                    if url == expected:
                        found = True
                        break
            assert found, f'Pattern not matched: {text} → expected {expected}'


# ────────────────────────────────────────────────────────────────────────────
#  SPA Result Dataclass
# ────────────────────────────────────────────────────────────────────────────

class TestSPACrawlResult:
    """Tests for the SPACrawlResult dataclass."""

    def test_defaults(self):
        from apps.scanning.engine.headless.spa_crawler import SPACrawlResult
        result = SPACrawlResult(url='https://example.com')
        assert result.url == 'https://example.com'
        assert result.framework == ''
        assert result.discovered_urls == []
        assert result.api_endpoints == []
        assert result.network_requests == []
        assert result.errors == []
        assert result.dom_mutations == 0

    def test_field_independence(self):
        """Ensure mutable default fields are independent between instances."""
        from apps.scanning.engine.headless.spa_crawler import SPACrawlResult
        r1 = SPACrawlResult(url='https://a.com')
        r2 = SPACrawlResult(url='https://b.com')
        r1.discovered_urls.append('https://a.com/page')
        assert len(r2.discovered_urls) == 0


# ────────────────────────────────────────────────────────────────────────────
#  Crawler Integration
# ────────────────────────────────────────────────────────────────────────────

class TestCrawlerSPAIntegration:
    """Tests for crawler.py Phase 24 integration."""

    def test_imports_available(self):
        """Verify Phase 24 modules are importable."""
        from apps.scanning.engine.headless.spa_crawler import SPA_FRAMEWORKS
        assert 'react' in SPA_FRAMEWORKS
        assert 'angular' in SPA_FRAMEWORKS
        assert 'vue' in SPA_FRAMEWORKS

    def test_spa_framework_constants(self):
        """Verify all framework definitions have required keys."""
        from apps.scanning.engine.headless.spa_crawler import SPA_FRAMEWORKS
        for name, info in SPA_FRAMEWORKS.items():
            assert 'indicators' in info, f'{name} missing indicators'
            assert 'router_selectors' in info, f'{name} missing router_selectors'
            assert len(info['indicators']) > 0

    def test_crawler_has_spa_attributes(self):
        """Verify crawler class has Phase 24 attributes."""
        from apps.scanning.engine.crawler import WebCrawler
        crawler = WebCrawler('https://example.com', js_rendering=False)
        assert hasattr(crawler, '_browser_pool')
        assert hasattr(crawler, '_spa_crawler')
        assert hasattr(crawler, '_spa_pages_crawled')
        assert crawler._browser_pool is None  # Not initialized when js_rendering=False
