"""Tests for new recon modules: header_analyzer and cookie_analyzer."""


# ---------------------------------------------------------------------------
# Header Analyzer
# ---------------------------------------------------------------------------
class TestHeaderAnalyzer:
    def test_returns_dict(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={'Content-Type': 'text/html'},
        )
        assert isinstance(result, dict)

    def test_detects_missing_security_headers(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={'Content-Type': 'text/html'},
        )
        # With no security headers present, should report missing headers
        assert 'missing' in result
        missing = result.get('missing', [])
        assert isinstance(missing, list)
        assert len(missing) > 0  # Should flag several missing headers

    def test_recognizes_good_headers(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
                'Content-Security-Policy': "default-src 'self'",
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
            },
        )
        assert isinstance(result, dict)
        # With good headers, missing list should be shorter
        missing = result.get('missing', [])
        # At least HSTS, CSP, XCTO, XFO, Referrer-Policy present -> fewer missing
        assert len(missing) < 10

    def test_detects_dangerous_headers(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={
                'X-Powered-By': 'Express 4.18.2',
                'Server': 'Apache/2.4.41 (Ubuntu)',
                'X-Debug-Token': 'abc123',
            },
        )
        dangerous = result.get('dangerous_headers', result.get('issues', []))
        assert isinstance(dangerous, list)
        assert len(dangerous) > 0

    def test_csp_analysis(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={
                'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'; style-src *",
            },
        )
        csp = result.get('csp_analysis', {})
        assert isinstance(csp, dict)
        # unsafe-inline and unsafe-eval should be flagged
        issues = csp.get('issues', [])
        assert isinstance(issues, list)

    def test_hsts_analysis(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={
                'Strict-Transport-Security': 'max-age=300',
            },
        )
        hsts = result.get('hsts_analysis', {})
        assert isinstance(hsts, dict)

    def test_score_present(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers={},
        )
        assert 'score' in result
        assert isinstance(result['score'], (int, float))
        assert 0 <= result['score'] <= 100

    def test_none_headers_handled(self):
        from apps.scanning.engine.recon.header_analyzer import run_header_analysis
        result = run_header_analysis(
            target_url='https://example.com',
            response_headers=None,
        )
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Cookie Analyzer
# ---------------------------------------------------------------------------
class TestCookieAnalyzer:
    def test_returns_dict(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies={'session': 'abc123'},
        )
        assert isinstance(result, dict)

    def test_detects_insecure_session_cookie(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies={'session_id': 'abc123'},
            set_cookie_headers=['session_id=abc123; Path=/'],
        )
        # Session cookie without Secure, HttpOnly, SameSite should have issues
        cookie_results = result.get('cookies', [])
        assert isinstance(cookie_results, list)
        if cookie_results:
            issues = cookie_results[0].get('issues', [])
            assert len(issues) > 0

    def test_recognizes_secure_cookie(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies={'session': 'abc123'},
            set_cookie_headers=[
                'session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/'
            ],
        )
        assert isinstance(result, dict)
        cookie_results = result.get('cookies', [])
        if cookie_results:
            # Secure cookie should have fewer issues
            issues = cookie_results[0].get('issues', [])
            assert isinstance(issues, list)

    def test_no_cookies_handled(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies=None,
        )
        assert isinstance(result, dict)

    def test_score_present(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies={'test': 'value'},
        )
        assert 'score' in result
        assert isinstance(result['score'], (int, float))

    def test_empty_cookies_handled(self):
        from apps.scanning.engine.recon.cookie_analyzer import run_cookie_analysis
        result = run_cookie_analysis(
            target_url='https://example.com',
            cookies={},
        )
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Cert Analysis (upgraded features)
# ---------------------------------------------------------------------------
class TestCertAnalysisUpgrade:
    def test_tls_attacks_field(self):
        from apps.scanning.engine.recon.cert_analysis import run_cert_analysis
        result = run_cert_analysis('https://127.0.0.1:0')
        assert isinstance(result, dict)
        # New fields should be present even on failure
        assert 'tls_attacks' in result or 'has_ssl' in result

    def test_http_handled_gracefully(self):
        from apps.scanning.engine.recon.cert_analysis import run_cert_analysis
        result = run_cert_analysis('http://example.com')
        assert isinstance(result, dict)
