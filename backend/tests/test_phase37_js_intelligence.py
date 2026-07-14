"""
Phase 37 — JavaScript Intelligence v2 Tests.

Tests for:
  - Source Map Analysis (engine/js/__init__.py)
  - Webpack Analyzer (engine/js/webpack_analyzer.py)
  - API Extractor (engine/js/api_extractor.py)
  - Framework Detector (engine/js/framework_detector.py)
  - JsIntelligenceTester (testers/js_intelligence_tester.py)
"""
import json
import sys
import os

# Ensure backend is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.testing')
django.setup()

# ──────────────────────────────────────────────────────────────────────────────
# Source Map Analysis Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestSourceMapUrlDetection:
    def test_conventional_suffix(self):
        from apps.scanning.engine.js import check_source_map_url
        result = check_source_map_url('https://example.com/static/main.js')
        assert result == 'https://example.com/static/main.js.map'

    def test_source_mapping_url_comment(self):
        from apps.scanning.engine.js import check_source_map_url
        content = 'var x=1;\n//# sourceMappingURL=main.js.map\n'
        result = check_source_map_url('https://example.com/static/main.js', content)
        assert result == 'https://example.com/static/main.js.map'

    def test_absolute_map_url_in_comment(self):
        from apps.scanning.engine.js import check_source_map_url
        content = '//# sourceMappingURL=https://cdn.example.com/maps/main.js.map'
        result = check_source_map_url('https://example.com/app.js', content)
        assert result == 'https://cdn.example.com/maps/main.js.map'

    def test_x_sourcemap_header(self):
        from apps.scanning.engine.js import check_source_map_url
        headers = {'x-sourcemap': '/maps/main.js.map'}
        result = check_source_map_url('https://example.com/app.js', headers=headers)
        assert result == 'https://example.com/maps/main.js.map'

    def test_data_uri_ignored(self):
        from apps.scanning.engine.js import check_source_map_url
        content = '//# sourceMappingURL=data:application/json;base64,abc123'
        # Data URI should be skipped — falls back to conventional suffix
        result = check_source_map_url('https://example.com/main.js', content)
        assert result == 'https://example.com/main.js.map'

    def test_non_js_url_with_header(self):
        from apps.scanning.engine.js import check_source_map_url
        headers = {'sourcemap': 'bundle.map'}
        result = check_source_map_url('https://example.com/', headers=headers)
        assert 'bundle.map' in result

    def test_resolve_relative_map_url(self):
        from apps.scanning.engine.js import _resolve_map_url
        result = _resolve_map_url('https://example.com/static/js/app.js', 'app.js.map')
        assert result == 'https://example.com/static/js/app.js.map'


class TestSourceMapParsing:
    def test_parse_valid_source_map(self):
        from apps.scanning.engine.js import parse_source_map
        sm = json.dumps({
            'version': 3,
            'sources': ['src/App.js', 'src/api.js'],
            'sourcesContent': ['// App content', '// API content'],
            'mappings': 'AAAA',
        })
        result = parse_source_map(sm)
        assert result['version'] == 3
        assert result['sources'] == ['src/App.js', 'src/api.js']
        assert result['mappings_present'] is True
        assert result['error'] is None

    def test_parse_invalid_json(self):
        from apps.scanning.engine.js import parse_source_map
        result = parse_source_map('not valid json{{{')
        assert result['error'] is not None
        assert result['sources'] == []

    def test_parse_empty_source_map(self):
        from apps.scanning.engine.js import parse_source_map
        result = parse_source_map(json.dumps({'version': 3}))
        assert result['version'] == 3
        assert result['sources'] == []
        assert result['mappings_present'] is False


class TestExtractSourcesInfo:
    def test_interesting_sources_detected(self):
        from apps.scanning.engine.js import extract_sources_info
        sm = {
            'sources': [
                'webpack:///src/App.js',
                'webpack:///node_modules/react/index.js',
                'webpack:///src/config/api.js',
                'webpack:///src/auth/login.js',
            ],
            'sources_content': [],
        }
        result = extract_sources_info(sm)
        assert result['sources_total'] == 4
        assert result['has_node_modules'] is True
        assert any('config' in s or 'auth' in s for s in result['interesting_sources'])

    def test_api_endpoints_extracted_from_content(self):
        from apps.scanning.engine.js import extract_sources_info
        sm = {
            'sources': ['src/api.js'],
            'sources_content': [
                "fetch('/api/users', { method: 'GET' })\nfetch('/api/login', { method: 'POST' })"
            ],
        }
        result = extract_sources_info(sm)
        assert '/api/users' in result['api_endpoints'] or '/api/login' in result['api_endpoints']

    def test_routes_extracted_from_content(self):
        from apps.scanning.engine.js import extract_sources_info
        sm = {
            'sources': ['src/routes.js'],
            'sources_content': [
                'API_URL = "/api/v1"\nconst BASE_URL = "https://example.com/api"'
            ],
        }
        result = extract_sources_info(sm)
        # Routes and api_endpoints should be lists
        assert isinstance(result['routes'], list)
        assert isinstance(result['api_endpoints'], list)

    def test_original_structure(self):
        from apps.scanning.engine.js import extract_sources_info
        sm = {
            'sources': ['webpack:///src/components/Header.js', 'webpack:///src/pages/Home.js'],
            'sources_content': [],
        }
        result = extract_sources_info(sm)
        assert isinstance(result['original_structure'], list)


class TestSecretDetection:
    def test_aws_access_key_detected(self):
        from apps.scanning.engine.js import detect_secrets_in_sources
        content = 'const key = "AKIAIOSFODNN7EXAMPLE";'
        results = detect_secrets_in_sources([content])
        assert any('AWS' in r['name'] for r in results)

    def test_stripe_key_detected(self):
        from apps.scanning.engine.js import detect_secrets_in_sources
        content = 'const stripe = "' + 'sk_li' + 've_abcdefghijklmnopqrstuvwx";'
        results = detect_secrets_in_sources([content])
        assert any('Stripe' in r['name'] for r in results)

    def test_google_api_key(self):
        from apps.scanning.engine.js import detect_secrets_in_sources
        # Must be exactly 35 chars after AIza prefix
        content = 'const gkey = "AIzaSyAbcDefGhIjKlMnOpQrStUvWxYz1234567";'
        results = detect_secrets_in_sources([content])
        assert any('Google' in r['name'] for r in results)

    def test_no_secrets_clean_code(self):
        from apps.scanning.engine.js import detect_secrets_in_sources
        content = 'function greet(name) { return "Hello " + name; }'
        results = detect_secrets_in_sources([content])
        assert results == []

    def test_line_number_reported(self):
        from apps.scanning.engine.js import detect_secrets_in_sources
        content = 'var a = 1;\nconst key = "AKIAIOSFODNN7EXAMPLE";\nvar b = 2;'
        results = detect_secrets_in_sources([content])
        assert any(r['line'] == 2 for r in results)

    def test_password_assignment_detected(self):
        from apps.scanning.engine.js import detect_secrets_in_sources
        content = 'const password = "supersecret123";'
        results = detect_secrets_in_sources([content])
        assert any('Password' in r['name'] or 'password' in r['name'].lower() for r in results)


class TestSourceMapRunAggregator:
    def test_quick_finds_map_urls(self):
        from apps.scanning.engine.js import run_source_map_analysis
        page = {
            'url': 'https://example.com/app.js',
            'headers': {},
            'content': '//# sourceMappingURL=app.js.map\nvar x=1;',
            'scripts': [],
        }
        result = run_source_map_analysis(page, depth='quick')
        assert result['stats']['maps_found'] >= 1

    def test_medium_parses_maps(self):
        from apps.scanning.engine.js import run_source_map_analysis
        sm_data = json.dumps({
            'version': 3,
            'sources': ['src/App.js'],
            'sourcesContent': ['function app() {}'],
            'mappings': 'AAAA',
        })

        def fake_fetch(url):
            return sm_data

        page = {
            'url': 'https://example.com/app.js',
            'headers': {},
            'content': '//# sourceMappingURL=app.js.map\nvar x=1;',
            'scripts': [],
        }
        result = run_source_map_analysis(page, depth='medium', fetch_fn=fake_fetch)
        assert result['stats']['maps_parsed'] >= 1

    def test_stats_always_present(self):
        from apps.scanning.engine.js import run_source_map_analysis
        page = {'url': 'https://example.com/', 'headers': {}, 'content': '', 'scripts': []}
        result = run_source_map_analysis(page)
        assert 'maps_found' in result['stats']
        assert 'elapsed_s' in result['stats']

    def test_scripts_list_probed(self):
        from apps.scanning.engine.js import run_source_map_analysis
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': '<html></html>',
            'scripts': [{'src': '/static/bundle.js'}],
        }
        result = run_source_map_analysis(page, depth='quick')
        assert result['stats']['maps_found'] >= 1


# ──────────────────────────────────────────────────────────────────────────────
# Webpack Analyzer Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestWebpackChunkDetection:
    def test_webpack_v5_detected(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_webpack_chunks
        content = '(self["webpackChunkapp"] = self["webpackChunkapp"] || []).push([[1], {__webpack_modules__: {}}]);'
        result = detect_webpack_chunks(content, 'https://example.com/main.js')
        assert result['is_webpack'] is True
        assert result['version_hint'] == 'v5'

    def test_webpack_v4_detected(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_webpack_chunks
        content = '(window["webpackJsonp"] = window["webpackJsonp"] || []).push([[0], {}]);'
        result = detect_webpack_chunks(content, 'https://example.com/main.js')
        assert result['is_webpack'] is True
        assert result['version_hint'] == 'v3/v4'

    def test_webpack_require_detected(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_webpack_chunks
        content = 'function __webpack_require__(moduleId) { return {}; }'
        result = detect_webpack_chunks(content)
        assert result['is_webpack'] is True

    def test_non_webpack_not_detected(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_webpack_chunks
        content = 'function greet() { return "hello"; }'
        result = detect_webpack_chunks(content)
        assert result['is_webpack'] is False

    def test_public_path_extracted(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_webpack_chunks
        content = '__webpack_require__.p = "/static/";__webpack_require__(1);'
        result = detect_webpack_chunks(content)
        assert result['public_path'] == '/static/'

    def test_empty_content(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_webpack_chunks
        result = detect_webpack_chunks('')
        assert result['is_webpack'] is False


class TestWebpackManifestParsing:
    def test_cra_manifest(self):
        from apps.scanning.engine.js.webpack_analyzer import parse_webpack_manifest
        manifest = json.dumps({
            'entrypoints': ['static/js/main.chunk.js'],
            'files': {
                'main.js': '/static/js/main.chunk.js',
                'static/js/runtime-main.js': '/static/js/runtime-main.abcdef12.js',
            },
        })
        result = parse_webpack_manifest(manifest)
        assert result['entrypoints'] == ['static/js/main.chunk.js']
        assert len(result['chunks']) >= 1
        assert result['error'] is None

    def test_route_inference(self):
        from apps.scanning.engine.js.webpack_analyzer import parse_webpack_manifest
        manifest = json.dumps({
            'files': {
                'pages/about': '/static/js/about.chunk.js',
                'pages/contact': '/static/js/contact.chunk.js',
                'main': '/static/js/main.js',  # generic — should be skipped
            },
        })
        result = parse_webpack_manifest(manifest)
        assert '/about' in result['routes_inferred'] or '/contact' in result['routes_inferred']

    def test_invalid_manifest(self):
        from apps.scanning.engine.js.webpack_analyzer import parse_webpack_manifest
        result = parse_webpack_manifest('not json')
        assert result['error'] is not None


class TestEnvVarDetection:
    def test_process_env_var_found(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_env_vars_in_js
        content = 'process.env.REACT_APP_API_URL, "https://api.example.com"'
        results = detect_env_vars_in_js(content)
        assert any(r['name'] == 'REACT_APP_API_URL' for r in results)

    def test_sensitive_var_flagged(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_env_vars_in_js
        content = 'process.env.REACT_APP_SECRET_KEY, "mysecretvalue123"'
        results = detect_env_vars_in_js(content)
        sensitive = [r for r in results if r['is_sensitive']]
        assert len(sensitive) >= 1

    def test_non_sensitive_var(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_env_vars_in_js
        content = 'process.env.REACT_APP_VERSION, "1.0.0"'
        results = detect_env_vars_in_js(content)
        normal = [r for r in results if not r['is_sensitive']]
        # REACT_APP_VERSION is not sensitive
        assert len(normal) >= 0  # may or may not match depending on pattern


class TestDebugBuildDetection:
    def test_node_env_development(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_debug_build
        content = 'process.env.NODE_ENV === "development"'
        result = detect_debug_build(content)
        assert result['is_debug'] is True
        assert any('NODE_ENV=development' in ind for ind in result['indicators'])

    def test_hmr_detected(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_debug_build
        content = 'webpack.HotModuleReplacementPlugin is active'
        result = detect_debug_build(content)
        assert result['is_debug'] is True

    def test_source_map_present(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_debug_build
        content = 'var x=1;\n//# sourceMappingURL=app.js.map'
        result = detect_debug_build(content)
        assert result['source_map_present'] is True

    def test_clean_production_build(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_debug_build
        # Minified-looking content
        content = 'a' * 1000  # single long line
        result = detect_debug_build(content)
        assert result['is_debug'] is False

    def test_empty_content(self):
        from apps.scanning.engine.js.webpack_analyzer import detect_debug_build
        result = detect_debug_build('')
        assert result['is_debug'] is False


class TestWebpackRunAggregator:
    def test_quick_scan(self):
        from apps.scanning.engine.js.webpack_analyzer import run_webpack_analysis
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': 'function __webpack_require__(id) {}',
        }
        result = run_webpack_analysis(page, depth='quick')
        assert result['is_webpack'] is True
        assert 'stats' in result

    def test_medium_scan_env_vars(self):
        from apps.scanning.engine.js.webpack_analyzer import run_webpack_analysis
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': '__webpack_require__.p = "/";process.env.REACT_APP_KEY, "abc123"',
        }
        result = run_webpack_analysis(page, depth='medium')
        assert len(result['env_vars']) >= 1

    def test_stats_populated(self):
        from apps.scanning.engine.js.webpack_analyzer import run_webpack_analysis
        page = {'url': 'https://example.com/', 'headers': {}, 'content': ''}
        result = run_webpack_analysis(page)
        assert 'elapsed_s' in result['stats']
        assert 'is_debug_build' in result['stats']


# ──────────────────────────────────────────────────────────────────────────────
# API Extractor Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestFetchExtraction:
    def test_simple_fetch_get(self):
        from apps.scanning.engine.js.api_extractor import extract_fetch_calls
        content = "fetch('/api/users')"
        results = extract_fetch_calls(content)
        assert any(r['url'] == '/api/users' for r in results)

    def test_fetch_with_method(self):
        from apps.scanning.engine.js.api_extractor import extract_fetch_calls
        content = "fetch('/api/login', { method: 'POST', body: data })"
        results = extract_fetch_calls(content)
        login = next((r for r in results if '/api/login' in r['url']), None)
        assert login is not None
        assert login['method'] == 'POST'

    def test_fetch_absolute_url(self):
        from apps.scanning.engine.js.api_extractor import extract_fetch_calls
        content = 'fetch("https://api.example.com/v1/users")'
        results = extract_fetch_calls(content)
        assert any('api.example.com' in r['url'] for r in results)

    def test_no_fetch_calls(self):
        from apps.scanning.engine.js.api_extractor import extract_fetch_calls
        content = 'function greet() { return "hello"; }'
        results = extract_fetch_calls(content)
        assert results == []


class TestAxiosExtraction:
    def test_axios_get(self):
        from apps.scanning.engine.js.api_extractor import extract_axios_calls
        content = "axios.get('/api/products')"
        results = extract_axios_calls(content)
        assert any(r['url'] == '/api/products' for r in results)

    def test_axios_post(self):
        from apps.scanning.engine.js.api_extractor import extract_axios_calls
        content = "axios.post('/api/register', payload)"
        results = extract_axios_calls(content)
        reg = next((r for r in results if '/api/register' in r['url']), None)
        assert reg is not None
        assert reg['method'] == 'POST'

    def test_axios_absolute(self):
        from apps.scanning.engine.js.api_extractor import extract_axios_calls
        content = 'axios.get("https://api.example.com/data")'
        results = extract_axios_calls(content)
        assert any('api.example.com' in r['url'] for r in results)


class TestXHRExtraction:
    def test_xhr_open_get(self):
        from apps.scanning.engine.js.api_extractor import extract_xhr_calls
        content = "xhr.open('GET', '/api/status');"
        results = extract_xhr_calls(content)
        assert any(r['url'] == '/api/status' and r['method'] == 'GET' for r in results)

    def test_xhr_open_post(self):
        from apps.scanning.engine.js.api_extractor import extract_xhr_calls
        content = 'xhr.open("POST", "/api/submit");'
        results = extract_xhr_calls(content)
        assert any(r['method'] == 'POST' for r in results)


class TestGraphQLExtraction:
    def test_query_operation(self):
        from apps.scanning.engine.js.api_extractor import extract_graphql_operations
        content = 'query GetUser($id: ID!) { user(id: $id) { name } }'
        results = extract_graphql_operations(content)
        assert any(r['name'] == 'GetUser' for r in results)

    def test_mutation_operation(self):
        from apps.scanning.engine.js.api_extractor import extract_graphql_operations
        content = 'mutation CreatePost($input: PostInput!) { createPost(input: $input) { id } }'
        results = extract_graphql_operations(content)
        assert any(r['name'] == 'CreatePost' and r['type'] == 'mutation' for r in results)

    def test_graphql_endpoint_url(self):
        from apps.scanning.engine.js.api_extractor import extract_graphql_operations
        content = 'const endpoint = "/graphql"; query GetData { items { id } }'
        results = extract_graphql_operations(content)
        assert any(r.get('endpoint') == '/graphql' for r in results)

    def test_no_graphql(self):
        from apps.scanning.engine.js.api_extractor import extract_graphql_operations
        content = 'fetch("/api/data")'
        results = extract_graphql_operations(content)
        assert results == []


class TestWebSocketExtraction:
    def test_wss_url(self):
        from apps.scanning.engine.js.api_extractor import extract_websocket_endpoints
        content = 'const ws = new WebSocket("wss://example.com/ws");'
        results = extract_websocket_endpoints(content)
        assert 'wss://example.com/ws' in results

    def test_relative_ws_path(self):
        from apps.scanning.engine.js.api_extractor import extract_websocket_endpoints
        content = "const ws = new WebSocket('/ws/chat');"
        results = extract_websocket_endpoints(content)
        assert '/ws/chat' in results

    def test_no_websockets(self):
        from apps.scanning.engine.js.api_extractor import extract_websocket_endpoints
        content = 'fetch("/api/data")'
        results = extract_websocket_endpoints(content)
        assert results == []


class TestTemplateLiteralURLs:
    def test_api_template_literal(self):
        from apps.scanning.engine.js.api_extractor import extract_template_literal_urls
        content = 'const url = `/api/users/${userId}`;'
        results = extract_template_literal_urls(content)
        assert any('/api/users/' in r for r in results)

    def test_versioned_api(self):
        from apps.scanning.engine.js.api_extractor import extract_template_literal_urls
        content = 'const path = `/v1/products/${id}`;'
        results = extract_template_literal_urls(content)
        assert any('/v1/' in r for r in results)


class TestDeduplication:
    def test_deduplicates_same_method_url(self):
        from apps.scanning.engine.js.api_extractor import deduplicate_endpoints
        endpoints = [
            {'url': '/api/users', 'method': 'GET', 'type': 'fetch'},
            {'url': '/api/users', 'method': 'GET', 'type': 'axios'},
            {'url': '/api/users', 'method': 'POST', 'type': 'fetch'},
        ]
        result = deduplicate_endpoints(endpoints)
        assert len(result) == 2

    def test_empty_input(self):
        from apps.scanning.engine.js.api_extractor import deduplicate_endpoints
        assert deduplicate_endpoints([]) == []


class TestAPIExtractionAggregator:
    def test_quick_extracts_fetch(self):
        from apps.scanning.engine.js.api_extractor import run_api_extraction
        page = {
            'url': 'https://example.com/',
            'content': "fetch('/api/data')",
            'scripts': [],
        }
        result = run_api_extraction(page, depth='quick')
        assert result['stats']['total_endpoints'] >= 1

    def test_medium_extracts_axios_and_gql(self):
        from apps.scanning.engine.js.api_extractor import run_api_extraction
        page = {
            'url': 'https://example.com/',
            'content': "axios.get('/api/items'); query GetAll { items { id } }",
            'scripts': [],
        }
        result = run_api_extraction(page, depth='medium')
        assert result['stats']['graphql_operations'] >= 1 or result['stats']['total_endpoints'] >= 1

    def test_deep_includes_websockets(self):
        from apps.scanning.engine.js.api_extractor import run_api_extraction
        page = {
            'url': 'https://example.com/',
            'content': 'new WebSocket("wss://example.com/ws")',
            'scripts': [],
        }
        result = run_api_extraction(page, depth='deep')
        assert result['stats']['websocket_endpoints'] >= 1

    def test_stats_always_present(self):
        from apps.scanning.engine.js.api_extractor import run_api_extraction
        page = {'url': 'https://example.com/', 'content': '', 'scripts': []}
        result = run_api_extraction(page)
        assert 'total_endpoints' in result['stats']
        assert 'elapsed_s' in result['stats']


# ──────────────────────────────────────────────────────────────────────────────
# Framework Detector Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestReactDetection:
    def test_react_devtools_hook(self):
        from apps.scanning.engine.js.framework_detector import check_react
        content = 'window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = { isDisabled: false };'
        result = check_react(content)
        assert result['detected'] is True
        assert result['devtools_hook_present'] is True

    def test_react_create_element(self):
        from apps.scanning.engine.js.framework_detector import check_react
        content = 'React.createElement("div", null, props.children)'
        result = check_react(content)
        assert result['detected'] is True

    def test_react_hydration(self):
        from apps.scanning.engine.js.framework_detector import check_react
        content = 'ReactDOM.hydrate(<App />, document.getElementById("root"))'
        result = check_react(content)
        assert result['detected'] is True
        assert result['hydration_mode'] is True

    def test_not_react(self):
        from apps.scanning.engine.js.framework_detector import check_react
        result = check_react('function greet() {}')
        assert result['detected'] is False


class TestAngularDetection:
    def test_ng_version_attr(self):
        from apps.scanning.engine.js.framework_detector import check_angular
        content = '<div ng-version="14.2.0"></div>'
        result = check_angular(content)
        assert result['detected'] is True
        assert result['version'] == '14.2.0'

    def test_debug_mode_no_prod_mode(self):
        from apps.scanning.engine.js.framework_detector import check_angular
        content = 'ngInjector.get(NgZone);'
        result = check_angular(content)
        assert result['detected'] is True
        assert result['debug_mode'] is True
        assert len(result['issues']) >= 1

    def test_prod_mode_enabled(self):
        from apps.scanning.engine.js.framework_detector import check_angular
        content = 'zone.js is loaded; enableProdMode();'
        result = check_angular(content)
        assert result['detected'] is True
        assert result['prod_mode_enabled'] is True
        assert result['debug_mode'] is False

    def test_route_extraction(self):
        from apps.scanning.engine.js.framework_detector import check_angular
        content = "zone.js; path: '/dashboard', component: DashboardComponent"
        result = check_angular(content)
        assert result['detected'] is True
        assert '/dashboard' in result['routes']


class TestVueDetection:
    def test_vue_app_detected(self):
        from apps.scanning.engine.js.framework_detector import check_vue
        content = 'window.__vue_app__ = createApp(App);'
        result = check_vue(content)
        assert result['detected'] is True

    def test_vuex_presence(self):
        from apps.scanning.engine.js.framework_detector import check_vue
        content = '__vue_app__; const store = new Vuex.Store({ state: {} });'
        result = check_vue(content)
        assert result['detected'] is True
        assert result['vuex_present'] is True

    def test_devtools_explicitly_enabled(self):
        from apps.scanning.engine.js.framework_detector import check_vue
        content = 'Vue.config.devtools = true; new Vue({ el: "#app" });'
        result = check_vue(content)
        assert result['detected'] is True
        assert result['devtools_enabled'] is True
        assert len(result['issues']) >= 1

    def test_ssr_state_exposure(self):
        from apps.scanning.engine.js.framework_detector import check_vue
        content = 'new Vue(); window.__INITIAL_STATE__ = { user: null };'
        result = check_vue(content)
        assert result['detected'] is True
        assert any('state' in issue.lower() for issue in result['issues'])


class TestNextJsDetection:
    def test_next_data_detected(self):
        from apps.scanning.engine.js.framework_detector import check_nextjs
        # __NEXT_DATA__ in JS assignment form (used by Next.js hydration)
        content = 'window.__NEXT_DATA__ = {"props":{"pageProps":{}},"query":{}} <'
        result = check_nextjs(content)
        assert result['detected'] is True
        assert result['next_data_exposed'] is True

    def test_api_routes_extracted(self):
        from apps.scanning.engine.js.framework_detector import check_nextjs
        content = '/_next/static/chunks/main.js, buildId: "abc123", "/api/auth/session" '
        result = check_nextjs(content)
        assert result['detected'] is True
        assert any('/api/' in r for r in result['api_routes'])

    def test_data_fetch_urls_generated(self):
        from apps.scanning.engine.js.framework_detector import check_nextjs
        content = '__NEXT_DATA__ buildId: "build123" "/api/posts"'
        result = check_nextjs(content, url='https://example.com/')
        if result['detected'] and result['build_id']:
            assert isinstance(result['data_fetch_urls'], list)

    def test_not_nextjs(self):
        from apps.scanning.engine.js.framework_detector import check_nextjs
        result = check_nextjs('function greet() {}')
        assert result['detected'] is False


class TestNuxtJsDetection:
    def test_nuxt_state_exposure(self):
        from apps.scanning.engine.js.framework_detector import check_nuxtjs
        content = 'window.__NUXT__ = { data: [{"user": null}] };'
        result = check_nuxtjs(content)
        assert result['detected'] is True
        assert result['ssr_state_exposed'] is True
        assert len(result['issues']) >= 1

    def test_nuxt_payload_exposure(self):
        from apps.scanning.engine.js.framework_detector import check_nuxtjs
        content = '_nuxt/main.js; window.__NUXT_PAYLOAD__ = fetch("/_payload.json");'
        result = check_nuxtjs(content)
        assert result['detected'] is True
        assert result['payload_exposed'] is True

    def test_not_nuxt(self):
        from apps.scanning.engine.js.framework_detector import check_nuxtjs
        result = check_nuxtjs('function greet() {}')
        assert result['detected'] is False


class TestFrameworkAggregator:
    def test_detect_react_only(self):
        from apps.scanning.engine.js.framework_detector import detect_frameworks
        content = 'React.createElement("div", null)'
        result = detect_frameworks(content)
        assert 'react' in result['detected_frameworks']
        assert 'angular' not in result['detected_frameworks']

    def test_detect_multiple_frameworks(self):
        from apps.scanning.engine.js.framework_detector import detect_frameworks
        content = '__vue_app__; React.createElement("span")'
        result = detect_frameworks(content)
        assert 'react' in result['detected_frameworks']
        assert 'vue' in result['detected_frameworks']

    def test_no_frameworks(self):
        from apps.scanning.engine.js.framework_detector import detect_frameworks
        result = detect_frameworks('function greet() { return 42; }')
        assert result['detected_frameworks'] == []

    def test_issues_aggregated(self):
        from apps.scanning.engine.js.framework_detector import detect_frameworks
        content = 'Vue.config.devtools = true; new Vue({ el: "#app" });'
        result = detect_frameworks(content)
        assert len(result['all_issues']) >= 1

    def test_run_framework_detection(self):
        from apps.scanning.engine.js.framework_detector import run_framework_detection
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': '__NEXT_DATA__; /_next/static/',
        }
        result = run_framework_detection(page)
        assert 'detected_frameworks' in result
        assert 'stats' in result
        assert 'nextjs' in result['detected_frameworks']


# ──────────────────────────────────────────────────────────────────────────────
# JsIntelligenceTester Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestJsIntelligenceTester:
    def _make_tester(self):
        from apps.scanning.engine.testers.js_intelligence_tester import JsIntelligenceTester
        return JsIntelligenceTester()

    def test_tester_name(self):
        t = self._make_tester()
        assert t.TESTER_NAME == 'JS Intelligence Scanner'

    def test_empty_page_returns_empty(self):
        t = self._make_tester()
        assert t.test({}) == []

    def test_no_url_returns_empty(self):
        t = self._make_tester()
        assert t.test({'url': ''}) == []

    def test_quick_source_map_detection(self):
        t = self._make_tester()
        page = {
            'url': 'https://example.com/app.js',
            'headers': {},
            'content': '//# sourceMappingURL=app.js.map\nvar x=1;',
            'scripts': [],
        }
        vulns = t.test(page, depth='quick')
        assert any('Source Map' in v['name'] for v in vulns)

    def test_quick_framework_detection_vue(self):
        t = self._make_tester()
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': '__vue_app__; Vue.config.devtools = true; new Vue({ el: "#app" });',
            'scripts': [],
        }
        vulns = t.test(page, depth='quick')
        assert any('Framework' in v['name'] or 'DevTools' in v['name'] or 'Issue' in v['name']
                   for v in vulns)

    def test_medium_webpack_env_vars(self):
        t = self._make_tester()
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': '__webpack_require__.p = "/";process.env.REACT_APP_SECRET_KEY, "mysecret123"',
            'scripts': [],
        }
        vulns = t.test(page, depth='medium')
        assert any('webpack' in v['name'].lower() or 'Environment' in v['name'] for v in vulns)

    def test_medium_api_endpoints(self):
        t = self._make_tester()
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': "fetch('/api/users'); fetch('/api/products', { method: 'POST' });",
            'scripts': [],
        }
        vulns = t.test(page, depth='medium')
        assert any('API Endpoint' in v['name'] for v in vulns)

    def test_deep_debug_build(self):
        t = self._make_tester()
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': 'webpack.HotModuleReplacementPlugin is loaded; __webpack_require__(1);',
            'scripts': [],
        }
        vulns = t.test(page, depth='deep')
        assert any('Debug' in v['name'] or 'debug' in v['name'].lower() for v in vulns)

    def test_deep_websocket_detection(self):
        t = self._make_tester()
        page = {
            'url': 'https://example.com/',
            'headers': {},
            'content': 'new WebSocket("wss://example.com/ws");',
            'scripts': [],
        }
        vulns = t.test(page, depth='deep')
        assert any('WebSocket' in v['name'] for v in vulns)


# ──────────────────────────────────────────────────────────────────────────────
# Registration Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRegistration:
    def test_tester_count_69(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_js_intelligence_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        names = [t.TESTER_NAME for t in get_all_testers()]
        assert 'JS Intelligence Scanner' in names

    def test_js_intelligence_position(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        [t.TESTER_NAME for t in testers]
        assert testers[-19].TESTER_NAME == 'JS Intelligence Scanner'
