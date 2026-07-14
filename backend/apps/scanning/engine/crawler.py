"""
WebCrawler — Discovers pages, forms, inputs, and links on a target website.
Uses BFS crawling with configurable depth limits.
Supports optional Playwright-based JS rendering for SPA crawling.
Enhanced: robots.txt parsing, sitemap.xml discovery, JS link extraction,
AI/API endpoint detection, and comprehensive content discovery.
Phase 14: parallel fetching, response size guard, content-hash deduplication.
"""
import hashlib
import logging
import re
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, parse_qsl
from dataclasses import dataclass, field
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Respect rate limiting — delay between requests (seconds)
CRAWL_DELAY = 0.5

# Phase 14: max response body size (5 MB); larger pages are skipped
MAX_RESPONSE_BYTES = 5 * 1024 * 1024

# Phase 14: number of parallel fetch workers
CRAWL_PARALLEL_WORKERS = 5

# Check Playwright availability
try:
    from playwright.sync_api import sync_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.info('Playwright not installed — JS rendering disabled')

# Phase 24: SPA crawler & browser pool
try:
    from apps.scanning.engine.headless.browser_pool import BrowserPool
    from apps.scanning.engine.headless.spa_crawler import SPACrawler
    HAS_SPA_CRAWLER = True
except ImportError:
    HAS_SPA_CRAWLER = False

# ──────────────────────────────────────────────────────
# AI/API endpoint patterns to probe
# ──────────────────────────────────────────────────────
AI_API_ENDPOINTS = [
    '/api/v1/chat/completions', '/api/v1/models', '/api/v1/embeddings',
    '/v1/chat/completions', '/v1/models', '/v1/completions',
    '/api/generate', '/api/chat', '/api/embeddings',
    '/inference', '/predict', '/api/predict',
    '/gradio/api/', '/api/queue/push',
    '/docs', '/redoc', '/swagger.json', '/openapi.json',
    '/graphql', '/graphiql',
    '/.well-known/openid-configuration',
    '/.well-known/ai-plugin.json',
]

# Common API version prefixes
API_VERSIONS = ['/api/v1', '/api/v2', '/api/v3', '/v1', '/v2', '/v3']

# JS patterns for extracting URLs from JavaScript code
JS_URL_PATTERNS = [
    r'''(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*['"](\/[^'"]+)['"]''',
    r'''(?:url|endpoint|apiUrl|baseUrl|API_URL)\s*[:=]\s*['"](\/[^'"]+)['"]''',
    r'''\.(?:get|post|put|delete|patch)\s*\(\s*['"](\/[^'"]+)['"]''',
    r'''(?:href|src|action)\s*[:=]\s*['"](\/[^'"]+)['"]''',
    r'''window\.location\s*=\s*['"](\/[^'"]+)['"]''',
    r'''Router\.\w+\(\s*['"]([^'"]+)['"]''',
    r'''path\s*:\s*['"]([^'"]+)['"]''',
]


@dataclass
class FormInput:
    """Represents an HTML form input field."""
    name: str
    input_type: str
    value: str = ''


@dataclass
class Form:
    """Represents an HTML form."""
    action: str
    method: str
    inputs: list = field(default_factory=list)

    def get(self, key, default=None):
        return getattr(self, key, default)

    def __getitem__(self, key):
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __contains__(self, key):
        return hasattr(self, key)


@dataclass
class Page:
    """Represents a crawled web page."""
    url: str
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    cookies: dict = field(default_factory=dict)
    body: str = ''
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    js_rendered: bool = False
    # Phase 4 additions
    api_calls: list = field(default_factory=list)          # {method, url, body, headers}
    websockets: list = field(default_factory=list)          # ws:// endpoints found
    event_listeners: list = field(default_factory=list)     # {event, selector}
    technologies: list = field(default_factory=list)        # per-page detected tech
    authentication_required: bool = False
    content_hash: str = ''                                   # SHA-256 of normalized body

    def get(self, key, default=None):
        """Support dict-style .get() access for backward compatibility."""
        return getattr(self, key, default)

    def __getitem__(self, key):
        """Support dict-style [] access for backward compatibility."""
        try:
            return getattr(self, key)
        except AttributeError:
            raise KeyError(key)

    def __contains__(self, key):
        """Support 'key in page' checks."""
        return hasattr(self, key)


class WebCrawler:
    """BFS web crawler for vulnerability scanning with optional JS rendering."""

    DEPTH_LIMITS = {'shallow': 50, 'medium': 250, 'deep': 1000}

    # File extensions to skip
    SKIP_EXTENSIONS = {
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar',
        '.gz', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv',
    }

    def __init__(self, base_url: str, depth: str = 'medium',
                 follow_redirects: bool = True, include_subdomains: bool = False,
                 js_rendering: bool = False):
        self.base_url = base_url.rstrip('/')
        self.depth = depth
        self.max_pages = self.DEPTH_LIMITS.get(depth, 50)
        self.follow_redirects = follow_redirects
        self.include_subdomains = include_subdomains
        self.js_rendering = js_rendering and HAS_PLAYWRIGHT
        self.visited = set()
        self.pages = []
        # Extra seeds injected before crawl() starts (e.g. recon-discovered subdomains)
        self._additional_seeds: list[str] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SafeWeb AI Scanner/2.0 (Security Assessment Tool)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        self.session.verify = False  # Allow self-signed certs for scanning
        self.parsed_base = urlparse(self.base_url)
        self._playwright = None
        self._browser = None
        self._pw_context = None
        # New: content discovery results
        self.robots_txt = None
        self.sitemap_urls = []
        self.ai_endpoints = []
        self.api_endpoints = []
        self.disallowed_paths = []
        # Phase 24: SPA crawler support
        self._browser_pool = None
        self._spa_crawler = None
        self._spa_pages_crawled = set()

    def set_additional_seeds(self, urls: list) -> None:
        """Register extra seed URLs discovered by the recon phase (subdomains, API endpoints, etc.)."""
        self._additional_seeds = [u for u in urls if u and isinstance(u, str)]
        logger.info('Crawler: %d additional recon seeds registered', len(self._additional_seeds))

    def crawl(self) -> list:
        """BFS crawl starting from base_url. Returns list of Page objects."""
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Initialize Playwright if needed
        if self.js_rendering:
            self._init_playwright()

        # Phase 24: Initialize browser pool for SPA crawling
        if self.js_rendering and HAS_SPA_CRAWLER:
            self._browser_pool = BrowserPool(pool_size=3)
            if self._browser_pool.start():
                self._spa_crawler = SPACrawler(self.base_url, depth=self.depth)
                logger.info('Phase 24 SPA crawler enabled')
            else:
                self._browser_pool = None

        # Phase 14: track seen content hashes to avoid processing duplicate pages
        seen_hashes: set = set()

        try:
            # ── Pre-crawl discovery ──
            self._parse_robots_txt()
            self._parse_sitemap()
            self._probe_ai_endpoints()

            # Seed queue: base URL + sitemap + injected recon seeds
            queue = [self.base_url]
            for surl in self.sitemap_urls[:20]:  # Cap sitemap seeds
                if surl not in self.visited:
                    queue.append(surl)
            for seed in self._additional_seeds:
                if seed and seed not in self.visited:
                    queue.append(seed)
            self.visited.add(self.base_url)

            while queue and len(self.pages) < self.max_pages:
                # Phase 14: fetch a batch of up to CRAWL_PARALLEL_WORKERS URLs in parallel
                batch = []
                while queue and len(batch) < CRAWL_PARALLEL_WORKERS:
                    url = queue.pop(0)
                    if not self._should_skip(url):
                        batch.append(url)

                if not batch:
                    continue

                # Fetch batch in parallel
                fetched_pages = self._fetch_batch(batch)

                for page in fetched_pages:
                    if page is None:
                        continue

                    # Phase 14: content-hash deduplication — skip identical pages
                    if page.content_hash and page.content_hash in seen_hashes:
                        logger.debug(f'Skipping duplicate content at {page.url}')
                        continue
                    if page.content_hash:
                        seen_hashes.add(page.content_hash)

                    self.pages.append(page)

                    # If JS rendering and the initial fetch had minimal content,
                    # try rendering with Playwright
                    if (self.js_rendering and not page.js_rendered and
                            self._needs_js_rendering(page)):
                        js_page = self._fetch_with_playwright(page.url)
                        if js_page and len(js_page.forms) > len(page.forms):
                            # Replace with JS-rendered version
                            self.pages[-1] = js_page

                        page = self.pages[-1]

                    # Phase 24: SPA deep crawl for detected SPA pages
                    if (self._spa_crawler and self._browser_pool
                            and page.url not in self._spa_pages_crawled
                            and self._needs_js_rendering(page)):
                        self._spa_pages_crawled.add(page.url)
                        spa_result = self._run_spa_crawl(page.url)
                        if spa_result:
                            # Merge SPA-discovered URLs into crawl queue
                            for link in spa_result.discovered_urls:
                                if (link not in self.visited
                                        and self._is_in_scope(link)
                                        and len(self.pages) < self.max_pages):
                                    self.visited.add(link)
                                    queue.append(link)
                            # Merge API endpoints
                            for ep in spa_result.api_endpoints:
                                if ep['url'] not in self.api_endpoints:
                                    self.api_endpoints.append(ep['url'])
                            # Enrich Page with SPA data
                            page.api_calls.extend(spa_result.api_endpoints)
                            page.technologies.append(spa_result.framework) if spa_result.framework else None

                    # Add discovered links to queue
                    for link in page.links:
                        if link not in self.visited and len(self.pages) < self.max_pages:
                            if self._is_in_scope(link):
                                self.visited.add(link)
                                queue.append(link)

                # Rate limiting between batches
                time.sleep(CRAWL_DELAY)

        finally:
            self._cleanup_playwright()
            # Phase 24: Cleanup browser pool
            if self._browser_pool:
                self._browser_pool.shutdown()
                self._browser_pool = None

        logger.info(f'Crawl complete: {len(self.pages)} pages discovered '
                    f'(JS rendering: {"enabled" if self.js_rendering else "disabled"}, '
                    f'AI endpoints: {len(self.ai_endpoints)}, '
                    f'sitemap URLs: {len(self.sitemap_urls)})')
        return self.pages

    def _fetch_batch(self, urls: list) -> list:
        """Fetch a batch of URLs in parallel. Returns list of Page|None."""
        if len(urls) == 1:
            return [self._fetch_page(urls[0])]

        results = [None] * len(urls)
        with ThreadPoolExecutor(max_workers=min(len(urls), CRAWL_PARALLEL_WORKERS)) as executor:
            future_to_idx = {executor.submit(self._fetch_page, url): i
                             for i, url in enumerate(urls)}
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    results[idx] = future.result()
                except Exception as e:
                    logger.warning(f'Batch fetch error for {urls[idx]}: {e}')
        return results

    def _fetch_page(self, url: str) -> 'Page | None':
        """Fetch a single page and extract its components."""
        try:
            response = self.session.get(
                url,
                allow_redirects=self.follow_redirects,
                timeout=15,
                stream=True,  # Phase 14: stream to check size before full download
            )

            # Phase 14: response size guard — skip pages larger than MAX_RESPONSE_BYTES
            content_length = int(response.headers.get('Content-Length', 0))
            if content_length > MAX_RESPONSE_BYTES:
                logger.debug(f'Skipping oversized page ({content_length} bytes): {url}')
                response.close()
                return None

            # Read up to limit + 1 byte to detect oversized streaming responses
            chunks = []
            total = 0
            for chunk in response.iter_content(65536):
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    logger.debug(f'Skipping oversized streaming page (>{MAX_RESPONSE_BYTES} bytes): {url}')
                    response.close()
                    return None
                chunks.append(chunk)
            raw_bytes = b''.join(chunks)
            body_text = raw_bytes.decode('utf-8', errors='replace')

            page = Page(
                url=url,
                status_code=response.status_code,
                headers=dict(response.headers),
                cookies=dict(response.cookies),
                body=body_text[:200000],
            )

            # Parse URL parameters
            parsed = urlparse(url)
            page.parameters = parse_qs(parsed.query)

            # Content hash for dedup
            page.content_hash = self._content_hash(page.body)

            # Detect auth requirements
            lower_url = url.lower()
            lower_body = page.body[:5000].lower()
            _auth_hints = ('login', 'signin', 'auth', 'password', '401', 'unauthorized')
            if response.status_code == 401 or any(h in lower_url for h in _auth_hints):
                page.authentication_required = True
            elif response.status_code == 200 and any(h in lower_body for h in _auth_hints[:3]):
                page.authentication_required = True

            # Parse HTML for forms and links
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type or 'application/xhtml' in content_type:
                soup = BeautifulSoup(body_text, 'html.parser')
                page.forms = self._extract_forms(soup, url)
                page.links = self._extract_links(soup, url)

            return page

        except requests.exceptions.Timeout:
            logger.warning(f'Timeout fetching {url}')
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f'Connection error for {url}')
            return None
        except Exception as e:
            logger.warning(f'Error fetching {url}: {e}')
            return None

    def _fetch_with_playwright(self, url: str) -> 'Page | None':
        """Fetch page with Playwright for JS rendering."""
        if not self._pw_context:
            return None

        try:
            pw_page = self._pw_context.new_page()
            pw_page.set_default_timeout(30000)

            response = pw_page.goto(url, wait_until='networkidle')

            if not response:
                pw_page.close()
                return None

            # Wait for dynamic content
            pw_page.wait_for_load_state('networkidle')
            time.sleep(1)  # Extra wait for late-loading JS

            body = pw_page.content()

            page = Page(
                url=url,
                status_code=response.status if response else 200,
                headers={},
                cookies={c['name']: c['value'] for c in self._pw_context.cookies()},
                body=body[:200000],
                js_rendered=True,
            )

            # Parse rendered HTML
            soup = BeautifulSoup(body, 'html.parser')
            page.forms = self._extract_forms(soup, url)
            page.links = self._extract_links(soup, url)

            # Also extract links from JS-created elements
            js_links = pw_page.evaluate('''() => {
                const links = [];
                document.querySelectorAll('a[href]').forEach(a => {
                    if (a.href && !a.href.startsWith('javascript:')) {
                        links.push(a.href);
                    }
                });
                // Also check router links (React Router, Vue Router)
                document.querySelectorAll('[data-href], [to]').forEach(el => {
                    const href = el.getAttribute('data-href') || el.getAttribute('to');
                    if (href) links.push(href);
                });
                return links;
            }''')

            for link in js_links:
                full_url = urljoin(url, link).split('#')[0]
                if self._is_in_scope(full_url) and full_url not in page.links:
                    page.links.append(full_url)

            pw_page.close()
            return page

        except Exception as e:
            logger.warning(f'Playwright rendering failed for {url}: {e}')
            return None

    def _needs_js_rendering(self, page: Page) -> bool:
        """Determine if a page likely needs JS rendering."""
        if not self.js_rendering:
            return False
        body = page.body or ''

        # SPA indicators
        spa_indicators = [
            'id="root"', 'id="app"', 'id="__next"',
            'ng-app', 'v-app', 'data-reactroot',
            '__NEXT_DATA__', '__NUXT__',
            'Loading...', 'loading...', 'Please wait',
            'noscript',
        ]

        # Check for minimal HTML content with JS framework indicators
        if len(body) < 2000 and any(ind in body for ind in spa_indicators):
            return True

        # Check if page has very few forms/links (SPA may render them later)
        if not page.forms and 'script src=' in body.lower():
            return True

        return False

    def _run_spa_crawl(self, url: str):
        """Run SPA crawl on a page using the browser pool.

        Returns SPACrawlResult or None.
        """
        ctx = self._browser_pool.acquire(timeout=15.0)
        if not ctx:
            return None
        try:
            return self._spa_crawler.crawl_page(ctx, url)
        except Exception as e:
            logger.debug('SPA crawl failed for %s: %s', url, e)
            return None
        finally:
            self._browser_pool.release(ctx)

    def _init_playwright(self):
        """Initialize Playwright browser."""
        try:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox',
                      '--disable-dev-shm-usage', '--disable-gpu'],
            )
            self._pw_context = self._browser.new_context(
                user_agent='SafeWeb AI Scanner/2.0 (Security Assessment Tool)',
                ignore_https_errors=True,
                viewport={'width': 1280, 'height': 720},
            )
            logger.info('Playwright browser initialized for JS rendering')
        except Exception as e:
            logger.warning(f'Failed to initialize Playwright: {e}')
            self.js_rendering = False
            self._cleanup_playwright()

    def _cleanup_playwright(self):
        """Clean up Playwright resources."""
        try:
            if self._pw_context:
                self._pw_context.close()
            if self._browser:
                self._browser.close()
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        finally:
            self._pw_context = None
            self._browser = None
            self._playwright = None

    def _should_skip(self, url: str) -> bool:
        """Check if URL points to a non-HTML resource."""
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return any(path_lower.endswith(ext) for ext in self.SKIP_EXTENSIONS)

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> list:
        """Extract all forms from the page."""
        forms = []
        for form_tag in soup.find_all('form'):
            action = form_tag.get('action', '')
            if action:
                action = urljoin(base_url, str(action))
            else:
                action = base_url

            method = str(form_tag.get('method', 'GET')).upper()

            inputs = []
            for input_tag in form_tag.find_all(['input', 'textarea', 'select']):
                name = input_tag.get('name', '')
                if name:
                    inputs.append(FormInput(
                        name=name,
                        input_type=input_tag.get('type', 'text'),
                        value=input_tag.get('value', ''),
                    ))

            forms.append(Form(action=action, method=method, inputs=inputs))

        return forms

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> list:
        """Extract all unique links from the page."""
        links = set()

        # Standard anchor tags
        for tag in soup.find_all('a', href=True):
            href = tag['href']
            if href.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:')):
                continue
            full_url = urljoin(base_url, href).split('#')[0]
            if self._is_in_scope(full_url):
                links.add(full_url)

        # Also check for links in other elements (forms, iframes, etc.)
        for tag in soup.find_all(['iframe', 'frame'], src=True):
            src = tag['src']
            if not src.startswith(('javascript:', 'about:', 'data:')):
                full_url = urljoin(base_url, src).split('#')[0]
                if self._is_in_scope(full_url):
                    links.add(full_url)

        # Meta refresh redirects
        for meta in soup.find_all('meta', attrs={'http-equiv': re.compile(r'refresh', re.I)}):
            content = meta.get('content', '')
            match = re.search(r'url\s*=\s*["\']?([^"\'\s;]+)', content, re.IGNORECASE)
            if match:
                full_url = urljoin(base_url, match.group(1)).split('#')[0]
                if self._is_in_scope(full_url):
                    links.add(full_url)

        # JS link extraction — find URLs in inline scripts and script src attributes
        for script in soup.find_all('script'):
            # External scripts
            src = script.get('src', '')
            if src and not src.startswith(('http://', 'https://', '//')):
                full_url = urljoin(base_url, src).split('#')[0]
                if self._is_in_scope(full_url):
                    links.add(full_url)

            # Inline script content
            script_text = script.string or ''
            if script_text:
                for pattern in JS_URL_PATTERNS:
                    for match in re.findall(pattern, script_text):
                        if match.startswith('/'):
                            full_url = urljoin(base_url, match).split('#')[0]
                            if self._is_in_scope(full_url):
                                links.add(full_url)

        # data- attribute links (common in SPAs)
        for tag in soup.find_all(attrs={'data-url': True}):
            data_url = tag['data-url']
            full_url = urljoin(base_url, data_url).split('#')[0]
            if self._is_in_scope(full_url):
                links.add(full_url)

        return list(links)

    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within the scanning scope."""
        try:
            parsed = urlparse(url)

            # Must be HTTP/HTTPS
            if parsed.scheme not in ('http', 'https'):
                return False

            # Check domain scope
            if self.include_subdomains:
                return parsed.netloc.endswith(self.parsed_base.netloc)
            else:
                return parsed.netloc == self.parsed_base.netloc

        except Exception:
            return False

    # ──────────────────────────────────────────────────
    # Pre-crawl discovery methods
    # ──────────────────────────────────────────────────

    def _parse_robots_txt(self):
        """Parse robots.txt for disallowed paths and sitemap references."""
        robots_url = f'{self.base_url}/robots.txt'
        try:
            response = self.session.get(robots_url, timeout=10)
            if response.status_code != 200:
                return

            self.robots_txt = response.text
            for line in response.text.splitlines():
                line = line.strip()
                if line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path and path != '/':
                        self.disallowed_paths.append(path)
                        # Disallowed paths are interesting for security testing
                        full_url = urljoin(self.base_url, path)
                        if full_url not in self.visited:
                            self.visited.add(full_url)
                            self.pages  # Don't auto-add — let them be queued
                elif line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    if sitemap_url.startswith('http'):
                        self._fetch_sitemap(sitemap_url)

            logger.info(f'robots.txt: {len(self.disallowed_paths)} disallowed paths found')

        except Exception as e:
            logger.debug(f'Could not fetch robots.txt: {e}')

    def _parse_sitemap(self):
        """Try common sitemap locations."""
        sitemap_urls = [
            f'{self.base_url}/sitemap.xml',
            f'{self.base_url}/sitemap_index.xml',
            f'{self.base_url}/sitemap/',
        ]

        for url in sitemap_urls:
            self._fetch_sitemap(url)
            if self.sitemap_urls:
                break

    def _fetch_sitemap(self, sitemap_url: str):
        """Parse a sitemap XML file for URLs."""
        try:
            response = self.session.get(sitemap_url, timeout=10)
            if response.status_code != 200:
                return

            content_type = response.headers.get('Content-Type', '')
            if 'xml' not in content_type and '<?xml' not in response.text[:100]:
                return

            root = ET.fromstring(response.text)
            ns = {'sm': 'http://www.sitemaps.org/schemas/sitemap/0.9'}

            # Check for sitemap index
            for sitemap in root.findall('.//sm:sitemap/sm:loc', ns):
                if sitemap.text:
                    self._fetch_sitemap(sitemap.text)  # Recursive for sitemap index

            # Standard sitemap URLs
            for url_elem in root.findall('.//sm:url/sm:loc', ns):
                if url_elem.text and self._is_in_scope(url_elem.text):
                    self.sitemap_urls.append(url_elem.text)

            # Also try without namespace (some sitemaps don't use it)
            if not self.sitemap_urls:
                for loc in root.iter('loc'):
                    if loc.text and self._is_in_scope(loc.text):
                        self.sitemap_urls.append(loc.text)

            if self.sitemap_urls:
                logger.info(f'Sitemap: {len(self.sitemap_urls)} URLs discovered from {sitemap_url}')

        except ET.ParseError:
            logger.debug(f'Invalid XML in sitemap: {sitemap_url}')
        except Exception as e:
            logger.debug(f'Could not fetch sitemap {sitemap_url}: {e}')

    def _probe_ai_endpoints(self):
        """Probe for common AI/ML and API endpoints."""
        for endpoint in AI_API_ENDPOINTS:
            url = f'{self.base_url}{endpoint}'
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in (200, 401, 403, 405):
                    self.ai_endpoints.append({
                        'url': url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', ''),
                    })
                    # Add to crawl queue
                    if url not in self.visited:
                        self.visited.add(url)

            except Exception:
                pass

        # Probe API versions
        for version in API_VERSIONS:
            url = f'{self.base_url}{version}'
            try:
                response = self.session.get(url, timeout=5, allow_redirects=False)
                if response.status_code in (200, 401, 403):
                    self.api_endpoints.append({
                        'url': url,
                        'status': response.status_code,
                    })
            except Exception:
                pass

        if self.ai_endpoints:
            logger.info(f'AI/API endpoints discovered: {len(self.ai_endpoints)}')

    def get_discovery_summary(self) -> dict:
        """Return a summary of all pre-crawl discovery results."""
        return {
            'pages_crawled': len(self.pages),
            'robots_txt_found': self.robots_txt is not None,
            'disallowed_paths': self.disallowed_paths,
            'sitemap_urls_count': len(self.sitemap_urls),
            'ai_endpoints': self.ai_endpoints,
            'api_endpoints': self.api_endpoints,
            'js_rendering_used': self.js_rendering,
        }

    # ═══════════════════════════════════════════════════════════════════
    # Phase 4 — Advanced discovery methods
    # ═══════════════════════════════════════════════════════════════════

    def _normalize_url(self, url: str) -> str:
        """Normalize URL for dedup: sort params, strip fragments, lowercase scheme."""
        parsed = urlparse(url)
        # Sort query parameters
        params = sorted(parse_qsl(parsed.query))
        normalized_query = urlencode(params)
        # Rebuild without fragment
        return f'{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}' + \
               (f'?{normalized_query}' if normalized_query else '')

    def _content_hash(self, body: str) -> str:
        """SHA-256 of whitespace-normalized body for exact-duplicate detection."""
        normalized = re.sub(r'\s+', ' ', body.strip())
        return hashlib.sha256(normalized.encode('utf-8', errors='replace')).hexdigest()

    def _intercept_api_calls(self, playwright_page) -> list:
        """Use CDP network interception to log all XHR/fetch during page load."""
        api_calls = []
        try:
            def _on_request(request):
                rtype = request.resource_type
                if rtype in ('xhr', 'fetch'):
                    api_calls.append({
                        'method': request.method,
                        'url': request.url,
                        'headers': dict(request.headers) if request.headers else {},
                        'post_data': request.post_data[:500] if request.post_data else None,
                    })

            playwright_page.on('request', _on_request)
        except Exception as e:
            logger.debug(f'API interception setup failed: {e}')
        return api_calls

    def _discover_websockets(self, playwright_page) -> list:
        """Intercept WebSocket connection attempts."""
        ws_endpoints = []
        try:
            def _on_ws(ws):
                ws_endpoints.append(ws.url)

            playwright_page.on('websocket', _on_ws)
        except Exception as e:
            logger.debug(f'WebSocket interception setup failed: {e}')
        return ws_endpoints

    def _discover_shadow_dom(self, playwright_page) -> list:
        """Traverse shadow roots and extract links/forms."""
        urls = []
        try:
            shadow_links = playwright_page.evaluate('''() => {
                const links = [];
                const walkShadow = (root) => {
                    const shadows = root.querySelectorAll('*');
                    shadows.forEach(el => {
                        if (el.shadowRoot) {
                            el.shadowRoot.querySelectorAll('a[href]').forEach(a => {
                                links.push(a.href);
                            });
                            walkShadow(el.shadowRoot);
                        }
                    });
                };
                walkShadow(document);
                return links;
            }''')
            urls = shadow_links or []
        except Exception as e:
            logger.debug(f'Shadow DOM traversal failed: {e}')
        return urls

    def _parse_openapi_spec(self, spec: dict) -> list:
        """Convert OpenAPI 3.x / Swagger 2.x spec into test URLs."""
        test_urls = []
        paths = spec.get('paths', {})
        # Determine base URL from spec
        servers = spec.get('servers', [])
        base = servers[0].get('url', self.base_url) if servers else self.base_url
        if base.startswith('/'):
            base = f'{self.parsed_base.scheme}://{self.parsed_base.netloc}{base}'

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, detail in methods.items():
                if method.lower() not in ('get', 'post', 'put', 'delete', 'patch'):
                    continue
                # Replace path params with example values
                resolved = re.sub(r'\{(\w+)\}', 'test', path)
                full_url = f'{base.rstrip("/")}{resolved}'
                test_urls.append(full_url)

        return test_urls[:100]  # cap
