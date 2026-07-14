"""
SPA-Aware Crawler — Phase 24.

Provides advanced crawling capabilities for single-page applications:
- SPA framework detection (React, Angular, Vue, Next.js, Nuxt, Svelte)
- Network interception (XHR/fetch) to discover hidden API endpoints
- Event-driven discovery (click buttons, expand menus, fill forms)
- Scroll-triggered lazy loading
- DOM mutation monitoring for dynamically added content
- JavaScript link extraction (route definitions, webpack chunks)

Designed to be used alongside the main WebCrawler when SPA content is detected.
"""
import logging
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
#  SPA Framework detection patterns
# ──────────────────────────────────────────────────────────────────────────────

SPA_FRAMEWORKS = {
    'react': {
        'indicators': ['id="root"', 'data-reactroot', '_reactRootContainer', 'react.production.min.js',
                        'react-dom', '__REACT_DEVTOOLS'],
        'router_selectors': ['[data-href]', 'a[href^="/"]'],
    },
    'angular': {
        'indicators': ['ng-app', 'ng-version', 'angular.min.js', 'zone.js',
                        'ng-controller', '<app-root'],
        'router_selectors': ['[routerLink]', '[ng-href]'],
    },
    'vue': {
        'indicators': ['v-app', 'v-cloak', 'data-v-', '__VUE__', 'vue.global.prod.js',
                        'id="app"', 'vue-router'],
        'router_selectors': ['[to]', 'router-link'],
    },
    'nextjs': {
        'indicators': ['__NEXT_DATA__', '_next/static', 'id="__next"', 'next/router'],
        'router_selectors': ['a[href^="/"]'],
    },
    'nuxt': {
        'indicators': ['__NUXT__', '_nuxt/', 'nuxt-link', 'data-n-head'],
        'router_selectors': ['nuxt-link', 'a[href^="/"]'],
    },
    'svelte': {
        'indicators': ['svelte-', '__svelte', 'SvelteKit'],
        'router_selectors': ['a[href^="/"]', 'a[data-sveltekit'],
    },
}

# Clickable element selectors for event-driven discovery
INTERACTIVE_SELECTORS = [
    'button:not([disabled])',
    '[role="button"]',
    '[role="tab"]',
    '[role="menuitem"]',
    '.accordion-header',
    '.dropdown-toggle',
    '[data-toggle]',
    '[data-bs-toggle]',
    'details > summary',
    'nav a',
    '.nav-link',
    '.tab-link',
    '[aria-expanded="false"]',
]

# JS patterns that contain URLs/routes
JS_URL_PATTERNS = [
    # String URLs: '/api/v1/users', "/admin/dashboard"
    re.compile(r'''(['"])(\/(?:api|v\d|admin|auth|internal|dashboard|graphql|ws)\b[^'"]{0,200})\1'''),
    # fetch/axios calls: fetch('/api/...'), axios.get('/api/...')
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"]([^'"]{3,200})['"]'''),
    # Route definitions: path: '/dashboard', route: '/admin'
    re.compile(r'''(?:path|route|url|href|to|endpoint)\s*[:=]\s*['"]([/][^'"]{1,200})['"]'''),
    # API base: baseURL: 'https://...', apiUrl: 'https://...'
    re.compile(r'''(?:base[Uu][Rr][Ll]|api[Uu]rl|apiBase|API_URL)\s*[:=]\s*['"](https?://[^'"]{3,200})['"]'''),
]

# Maximum interactions per page to avoid infinite loops
MAX_CLICKS_PER_PAGE = 30
MAX_SCROLL_ITERATIONS = 10
INTERACTION_TIMEOUT_MS = 3000
PAGE_TIMEOUT_MS = 30000


@dataclass
class SPACrawlResult:
    """Result of SPA crawling a single page."""
    url: str
    framework: str = ''
    discovered_urls: list = field(default_factory=list)
    api_endpoints: list = field(default_factory=list)
    forms_found: list = field(default_factory=list)
    network_requests: list = field(default_factory=list)
    dom_mutations: int = 0
    js_routes: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class SPACrawler:
    """SPA-aware crawler using Playwright browser contexts.

    Uses a BrowserPool context (or a standalone context) to:
    1. Detect SPA framework
    2. Intercept network requests
    3. Click interactive elements
    4. Scroll to trigger lazy loading
    5. Extract JS-defined routes
    """

    def __init__(self, base_url: str, depth: str = 'medium'):
        self.base_url = base_url.rstrip('/')
        self.depth = depth
        self._base_domain = urlparse(base_url).hostname or ''

    def crawl_page(self, context, url: str) -> SPACrawlResult:
        """Crawl a single page with SPA awareness.

        Args:
            context: Playwright BrowserContext (from pool or standalone).
            url: The URL to crawl.

        Returns:
            SPACrawlResult with discovered content.
        """
        result = SPACrawlResult(url=url)
        page = None

        try:
            page = context.new_page()
            page.set_default_timeout(PAGE_TIMEOUT_MS)

            # Set up network interception
            captured_requests = []
            page.on('request', lambda req: self._on_request(req, captured_requests))

            # Navigate
            response = page.goto(url, wait_until='networkidle')
            if not response:
                result.errors.append('Navigation returned no response')
                return result

            page.wait_for_load_state('networkidle')
            time.sleep(0.5)

            # Detect framework
            result.framework = self._detect_framework(page)

            # Extract JS routes from page source
            result.js_routes = self._extract_js_routes(page, url)

            # Event-driven discovery
            if self.depth in ('medium', 'deep'):
                self._click_interactive_elements(page, result)

            # Scroll-triggered lazy loading
            if self.depth == 'deep':
                self._trigger_lazy_loading(page, result)

            # Collect all network requests into result
            result.network_requests = captured_requests

            # Extract API endpoints from intercepted requests
            result.api_endpoints = self._extract_api_endpoints(captured_requests)

            # Extract all links from final DOM state
            result.discovered_urls = self._extract_all_links(page, url)

            # Extract forms from rendered DOM
            result.forms_found = self._extract_rendered_forms(page, url)

        except Exception as e:
            result.errors.append(str(e))
            logger.debug('SPACrawler error on %s: %s', url, e)
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass

        return result

    # ──────────────────────────────────────────────────────────────────────
    #  Framework Detection
    # ──────────────────────────────────────────────────────────────────────

    def _detect_framework(self, page) -> str:
        """Detect which SPA framework the page uses."""
        try:
            html = page.content()
            for name, info in SPA_FRAMEWORKS.items():
                for indicator in info['indicators']:
                    if indicator in html:
                        return name
        except Exception:
            pass
        return ''

    @staticmethod
    def detect_spa_from_html(html: str) -> str:
        """Static method: detect SPA framework from raw HTML (no browser needed)."""
        for name, info in SPA_FRAMEWORKS.items():
            for indicator in info['indicators']:
                if indicator in html:
                    return name
        return ''

    # ──────────────────────────────────────────────────────────────────────
    #  Network Interception
    # ──────────────────────────────────────────────────────────────────────

    def _on_request(self, request, captured: list):
        """Capture network requests for API discovery."""
        url = request.url
        resource_type = request.resource_type

        # Only capture XHR/fetch/websocket — not images, css, fonts
        if resource_type in ('xhr', 'fetch', 'websocket'):
            captured.append({
                'url': url,
                'method': request.method,
                'resource_type': resource_type,
                'headers': dict(request.headers) if request.headers else {},
            })

    def _extract_api_endpoints(self, requests_list: list) -> list:
        """Deduplicate and filter API endpoints from captured requests."""
        seen = set()
        endpoints = []
        for req in requests_list:
            url = req['url']
            # Normalize: strip query/fragment for dedup
            parsed = urlparse(url)
            key = f"{req['method']}:{parsed.scheme}://{parsed.netloc}{parsed.path}"

            if key in seen:
                continue
            seen.add(key)

            endpoints.append({
                'url': url,
                'method': req['method'],
                'type': req['resource_type'],
            })

        return endpoints

    # ──────────────────────────────────────────────────────────────────────
    #  Event-Driven Discovery
    # ──────────────────────────────────────────────────────────────────────

    def _click_interactive_elements(self, page, result: SPACrawlResult):
        """Click buttons, tabs, toggles to discover hidden content."""
        clicks = 0
        urls_before = set(self._get_current_links(page))

        for selector in INTERACTIVE_SELECTORS:
            if clicks >= MAX_CLICKS_PER_PAGE:
                break
            try:
                elements = page.query_selector_all(selector)
                for elem in elements[:5]:  # Max 5 per selector
                    if clicks >= MAX_CLICKS_PER_PAGE:
                        break
                    try:
                        if elem.is_visible() and elem.is_enabled():
                            elem.click(timeout=INTERACTION_TIMEOUT_MS)
                            page.wait_for_load_state('networkidle', timeout=INTERACTION_TIMEOUT_MS)
                            clicks += 1
                    except Exception:
                        continue
            except Exception:
                continue

        urls_after = set(self._get_current_links(page))
        new_urls = urls_after - urls_before
        result.dom_mutations = len(new_urls)

    def _get_current_links(self, page) -> list:
        """Extract current links from DOM."""
        try:
            return page.evaluate('''() => {
                const links = new Set();
                document.querySelectorAll('a[href]').forEach(a => {
                    if (a.href && !a.href.startsWith('javascript:') && !a.href.startsWith('#')) {
                        links.add(a.href);
                    }
                });
                return [...links];
            }''')
        except Exception:
            return []

    # ──────────────────────────────────────────────────────────────────────
    #  Scroll-Triggered Lazy Loading
    # ──────────────────────────────────────────────────────────────────────

    def _trigger_lazy_loading(self, page, result: SPACrawlResult):
        """Scroll down page to trigger infinite scroll / lazy components."""
        try:
            previous_height = 0
            for _ in range(MAX_SCROLL_ITERATIONS):
                current_height = page.evaluate('() => document.body.scrollHeight')
                if current_height <= previous_height:
                    break
                page.evaluate('() => window.scrollTo(0, document.body.scrollHeight)')
                time.sleep(0.5)
                try:
                    page.wait_for_load_state('networkidle', timeout=3000)
                except Exception:
                    pass
                previous_height = current_height
        except Exception as e:
            result.errors.append(f'Lazy loading scroll failed: {e}')

    # ──────────────────────────────────────────────────────────────────────
    #  JS Route Extraction
    # ──────────────────────────────────────────────────────────────────────

    def _extract_js_routes(self, page, base_url: str) -> list:
        """Extract URLs from inline and external JavaScript."""
        routes = set()
        try:
            # Inline scripts
            scripts = page.evaluate('''() => {
                const scripts = [];
                document.querySelectorAll('script:not([src])').forEach(s => {
                    if (s.textContent.length > 10 && s.textContent.length < 500000) {
                        scripts.push(s.textContent);
                    }
                });
                return scripts;
            }''')

            for script_text in scripts:
                for pattern in JS_URL_PATTERNS:
                    for match in pattern.finditer(script_text):
                        # Get last group (the URL)
                        url = match.group(match.lastindex)
                        if url and len(url) > 1:
                            full = urljoin(base_url, url)
                            if self._is_same_origin(full):
                                routes.add(full)

        except Exception as e:
            logger.debug('JS route extraction failed: %s', e)

        return list(routes)

    # ──────────────────────────────────────────────────────────────────────
    #  Link & Form Extraction from Rendered DOM
    # ──────────────────────────────────────────────────────────────────────

    def _extract_all_links(self, page, base_url: str) -> list:
        """Extract all links from the fully rendered DOM."""
        try:
            raw_links = page.evaluate('''() => {
                const links = new Set();
                // Standard hrefs
                document.querySelectorAll('a[href]').forEach(a => {
                    const h = a.getAttribute('href');
                    if (h && !h.startsWith('javascript:') && !h.startsWith('#') && h !== '') {
                        links.add(h);
                    }
                });
                // Router links
                document.querySelectorAll('[to], [data-href], [routerLink], [ng-href]').forEach(el => {
                    for (const attr of ['to', 'data-href', 'routerLink', 'ng-href']) {
                        const v = el.getAttribute(attr);
                        if (v) links.add(v);
                    }
                });
                // iframes
                document.querySelectorAll('iframe[src]').forEach(f => {
                    if (f.src && !f.src.startsWith('about:')) links.add(f.src);
                });
                return [...links];
            }''')

            resolved = []
            seen = set()
            for link in raw_links:
                full = urljoin(base_url, link).split('#')[0]
                if full not in seen and self._is_same_origin(full):
                    seen.add(full)
                    resolved.append(full)
            return resolved

        except Exception:
            return []

    def _extract_rendered_forms(self, page, base_url: str) -> list:
        """Extract forms from the rendered DOM."""
        try:
            return page.evaluate('''(baseUrl) => {
                const forms = [];
                document.querySelectorAll('form').forEach(form => {
                    const inputs = [];
                    form.querySelectorAll('input, textarea, select').forEach(inp => {
                        if (inp.name) {
                            inputs.push({
                                name: inp.name,
                                type: inp.type || 'text',
                                value: inp.value || '',
                            });
                        }
                    });
                    forms.push({
                        action: form.action || baseUrl,
                        method: (form.method || 'GET').toUpperCase(),
                        inputs: inputs,
                    });
                });
                return forms;
            }''', base_url)
        except Exception:
            return []

    # ──────────────────────────────────────────────────────────────────────
    #  Helpers
    # ──────────────────────────────────────────────────────────────────────

    def _is_same_origin(self, url: str) -> bool:
        """Check if URL belongs to the same domain."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            return host == self._base_domain or host.endswith(f'.{self._base_domain}')
        except Exception:
            return False
