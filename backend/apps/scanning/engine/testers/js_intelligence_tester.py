"""
JS Intelligence Tester — BaseTester wrapper for Phase 37.

Performs JavaScript Intelligence v2 analysis:
  - Source map exposure detection
  - Webpack/build tool fingerprinting
  - Environment variable leakage in bundles
  - Debug/development build detection
  - API endpoint extraction (fetch/axios/XHR/GraphQL/WebSocket)
  - Frontend framework detection (React/Angular/Vue/Next.js/Nuxt.js)
  - Framework-specific security issues (DevTools, debug mode, SSR state)

Depth behaviour:
  - quick : Source map URL detection + framework detection
  - medium: + webpack analysis + API extraction + env var scanning
  - deep  : + source map parsing + GraphQL + WebSocket + debug build checks
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class JsIntelligenceTester(BaseTester):
    TESTER_NAME = 'JS Intelligence Scanner'

    def test(self, page: dict, depth: str = 'quick',
             recon_data: dict | None = None) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        vulns: list[dict] = []

        # ── Source Map Detection (always) ─────────────────────────────────
        vulns.extend(self._check_source_maps(url, page, depth))

        # ── Framework Detection (always) ──────────────────────────────────
        vulns.extend(self._check_frameworks(url, page))

        if depth in ('medium', 'deep'):
            # ── Webpack Analysis ──────────────────────────────────────────
            vulns.extend(self._check_webpack(url, page))

            # ── API Endpoint Extraction ───────────────────────────────────
            vulns.extend(self._check_api_endpoints(url, page, depth))

        if depth == 'deep':
            # ── Debug Build Detection ─────────────────────────────────────
            vulns.extend(self._check_debug_build(url, page))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Source Map Checks
    # ─────────────────────────────────────────────────────────────────────
    def _check_source_maps(self, url: str, page: dict, depth: str) -> list[dict]:
        """Detect source map exposure."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.js import run_source_map_analysis
            result = run_source_map_analysis(page, depth=depth)

            maps_found = result['stats']['maps_found']
            if maps_found > 0:
                vulns.append(self._build_vuln(
                    'JavaScript Source Map Exposure',
                    'medium', 'information-disclosure',
                    f'Detected {maps_found} potential source map file(s) for {url}. '
                    f'Source maps reveal original source code, file structure, '
                    f'and may expose sensitive logic.',
                    'Original application source code is accessible to attackers, '
                    'revealing internal logic, API endpoints, and potential secrets',
                    'Remove source map files from production deployment or restrict '
                    'access to .map files via web server configuration',
                    'CWE-540', 5.3, url,
                    f'Source map URLs found: {result["map_urls_found"][:3]}',
                ))

            # Secrets found in source maps
            secrets = result.get('secrets', [])
            if secrets:
                secret_names = list({s['name'] for s in secrets})
                vulns.append(self._build_vuln(
                    'Secrets Exposed via Source Map',
                    'high', 'information-disclosure',
                    f'Hard-coded secret(s) detected in source map content: '
                    f'{", ".join(secret_names)}',
                    'Exposed secrets (API keys, tokens, passwords) can be used by '
                    'attackers to compromise integrations and accounts',
                    'Rotate all exposed credentials immediately. Never hard-code '
                    'secrets in source code; use environment variables at runtime',
                    'CWE-312', 7.5, url,
                    f'Secret types found: {secret_names}',
                ))

            # Rich source info for deep scans
            for info in result.get('sources_info', []):
                if info.get('api_endpoints'):
                    vulns.append(self._build_vuln(
                        'API Endpoints Extracted from Source Map',
                        'info', 'information-disclosure',
                        f'Source map reveals {len(info["api_endpoints"])} API endpoint(s)',
                        'Internal API surface is exposed to attackers',
                        'Remove source maps from production',
                        'CWE-540', 0.0, url,
                        f'Endpoints: {info["api_endpoints"][:5]}',
                    ))

        except Exception as exc:
            logger.debug('Source map check failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Framework Checks
    # ─────────────────────────────────────────────────────────────────────
    def _check_frameworks(self, url: str, page: dict) -> list[dict]:
        """Detect frontend frameworks and their security issues."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.js.framework_detector import run_framework_detection
            result = run_framework_detection(page)

            frameworks = result.get('detected_frameworks', [])
            issues = result.get('all_issues', [])
            details = result.get('details', {})

            if frameworks:
                vulns.append(self._build_vuln(
                    'Frontend Framework Detected',
                    'info', 'information-disclosure',
                    f'Detected frontend framework(s): {", ".join(frameworks)}. '
                    'This information helps attackers target framework-specific vulnerabilities.',
                    'Framework fingerprinting enables targeted exploit selection',
                    'Consider obfuscating framework indicators in production builds',
                    'CWE-200', 0.0, url,
                    f'Frameworks: {frameworks}',
                ))

            # Framework-specific security issues
            for issue in issues:
                severity = 'medium'
                cwe = 'CWE-16'
                cvss = 4.3
                if 'DevTools' in issue or 'devtools' in issue.lower():
                    severity = 'medium'
                    cwe = 'CWE-489'
                    cvss = 4.3
                elif 'debug mode' in issue.lower():
                    severity = 'medium'
                    cwe = 'CWE-489'
                    cvss = 5.3
                elif 'SSR state' in issue or 'serialized' in issue:
                    severity = 'medium'
                    cwe = 'CWE-200'
                    cvss = 5.3

                vulns.append(self._build_vuln(
                    'Framework Security Configuration Issue',
                    severity, 'misconfiguration',
                    issue,
                    'Framework security misconfiguration may expose internal data or enable attack vectors',
                    'Review and harden framework security settings for production deployment',
                    cwe, cvss, url, issue,
                ))

            # Next.js: _next/data exposure
            nextjs = details.get('nextjs', {})
            if nextjs.get('detected') and nextjs.get('data_fetch_urls'):
                vulns.append(self._build_vuln(
                    'Next.js _next/data API Endpoints Exposed',
                    'info', 'information-disclosure',
                    f'Next.js build ID {nextjs.get("build_id", "unknown")!r} reveals '
                    f'{len(nextjs["data_fetch_urls"])} page data API endpoint(s)',
                    'Data fetch endpoints expose server-side rendered page props as JSON',
                    'Implement authorization on _next/data endpoints for sensitive pages',
                    'CWE-200', 0.0, url,
                    f'Data URLs: {nextjs["data_fetch_urls"][:3]}',
                ))

        except Exception as exc:
            logger.debug('Framework detection failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Webpack Analysis
    # ─────────────────────────────────────────────────────────────────────
    def _check_webpack(self, url: str, page: dict) -> list[dict]:
        """Detect webpack and embedded environment variables."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.js.webpack_analyzer import run_webpack_analysis
            result = run_webpack_analysis(page, depth='medium')

            if result['is_webpack']:
                vulns.append(self._build_vuln(
                    'Webpack Bundle Detected',
                    'info', 'information-disclosure',
                    f'Application uses webpack ({result.get("version_hint", "unknown")} style). '
                    f'Found {result["stats"]["chunks_found"]} chunk URL(s).',
                    'Webpack bundle structure may leak implementation details',
                    'Enable webpack output obfuscation and remove source maps in production',
                    'CWE-200', 0.0, url,
                    f'Version hint: {result.get("version_hint")}',
                ))

            env_vars = result.get('env_vars', [])
            sensitive = [e for e in env_vars if e.get('is_sensitive')]
            if sensitive:
                names = [e['name'] for e in sensitive]
                vulns.append(self._build_vuln(
                    'Sensitive Environment Variables in JS Bundle',
                    'high', 'information-disclosure',
                    f'Sensitive environment variable(s) embedded in JavaScript bundle: '
                    f'{", ".join(names)}',
                    'Exposed environment variables (API keys, secrets, tokens) can be '
                    'read by any user who can access the JavaScript bundle',
                    'Do not embed sensitive values via DefinePlugin. '
                    'Use server-side APIs to pass necessary configuration at runtime',
                    'CWE-312', 7.5, url,
                    f'Sensitive vars: {names}',
                ))
            elif env_vars:
                vulns.append(self._build_vuln(
                    'Environment Variables Exposed in JS Bundle',
                    'low', 'information-disclosure',
                    f'{len(env_vars)} environment variable(s) embedded in JavaScript bundle',
                    'Application configuration is visible in publicly accessible bundles',
                    'Review which configuration values are embedded in client-side bundles',
                    'CWE-200', 3.1, url,
                    f'Variables: {[e["name"] for e in env_vars[:5]]}',
                ))

        except Exception as exc:
            logger.debug('Webpack analysis failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # API Endpoint Extraction
    # ─────────────────────────────────────────────────────────────────────
    def _check_api_endpoints(self, url: str, page: dict, depth: str) -> list[dict]:
        """Extract and report API endpoints from JS."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.js.api_extractor import run_api_extraction
            result = run_api_extraction(page, depth=depth)

            total = result['stats']['total_endpoints']
            if total > 0:
                endpoints_sample = [
                    f'{e["method"]} {e["url"]}'
                    for e in result['all_endpoints'][:10]
                ]
                vulns.append(self._build_vuln(
                    'API Endpoints Identified in JavaScript',
                    'info', 'information-disclosure',
                    f'Extracted {total} API endpoint(s) from JavaScript source code',
                    'API surface enumeration aids attackers in targeting specific endpoints',
                    'This is informational; ensure all extracted endpoints implement '
                    'proper authentication and authorization',
                    'CWE-200', 0.0, url,
                    f'Sample endpoints: {endpoints_sample}',
                ))

            gql = result.get('graphql', [])
            if gql:
                op_names = [g['name'] for g in gql if g.get('name')]
                vulns.append(self._build_vuln(
                    'GraphQL Operations Identified',
                    'info', 'information-disclosure',
                    f'Found {len(gql)} GraphQL operation(s) in JavaScript',
                    'GraphQL schema and operation details are exposed',
                    'Implement query depth limiting, complexity analysis, and '
                    'field-level authorization on GraphQL endpoints',
                    'CWE-200', 0.0, url,
                    f'Operations: {op_names[:5]}',
                ))

            ws_endpoints = result.get('websockets', [])
            if ws_endpoints:
                vulns.append(self._build_vuln(
                    'WebSocket Endpoints Identified',
                    'info', 'information-disclosure',
                    f'Found {len(ws_endpoints)} WebSocket endpoint(s) in JavaScript',
                    'WebSocket endpoints may lack authentication or authorization',
                    'Ensure WebSocket connections require authentication and '
                    'validate Origin header',
                    'CWE-319', 0.0, url,
                    f'WebSocket URLs: {ws_endpoints[:3]}',
                ))

        except Exception as exc:
            logger.debug('API extraction failed: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Debug Build Detection
    # ─────────────────────────────────────────────────────────────────────
    def _check_debug_build(self, url: str, page: dict) -> list[dict]:
        """Detect development/debug builds shipped to production."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.js.webpack_analyzer import detect_debug_build
            content = page.get('content', '')
            headers = page.get('headers', {})
            result = detect_debug_build(content, headers, url)

            if result['is_debug']:
                indicators = result.get('indicators', [])
                vulns.append(self._build_vuln(
                    'Development/Debug Build Deployed to Production',
                    'medium', 'misconfiguration',
                    f'JavaScript bundle shows signs of being a development build: '
                    f'{", ".join(indicators[:3])}',
                    'Development builds contain additional debug information, '
                    'unminified code, and may have security checks disabled',
                    'Build and deploy production-optimized bundles. '
                    'Set NODE_ENV=production and enable webpack optimization',
                    'CWE-489', 5.3, url,
                    f'Debug indicators: {indicators}',
                ))
            elif result.get('source_map_present') and result.get('minified') is False:
                vulns.append(self._build_vuln(
                    'Unminified JavaScript with Source Map',
                    'low', 'information-disclosure',
                    'JavaScript appears unminified and contains a sourceMappingURL comment',
                    'Unminified code exposes internal logic and is larger than necessary',
                    'Minify JavaScript bundles and remove source maps in production',
                    'CWE-540', 3.1, url,
                    'Source map present, code appears unminified',
                ))

        except Exception as exc:
            logger.debug('Debug build check failed: %s', exc)
        return vulns
