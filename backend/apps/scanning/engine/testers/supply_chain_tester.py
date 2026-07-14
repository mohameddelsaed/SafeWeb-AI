"""
Supply Chain Tester — BaseTester wrapper for Phase 33.

Integrates the SupplyChainScanner (JS library scanning, backend dependency
checking, dependency-confusion detection) into the standard tester pipeline.

Depth behaviour:
  - quick : JS library scan only
  - medium: JS library + backend dependency scan
  - deep  : JS library + backend dependency + dependency confusion check
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class SupplyChainTester(BaseTester):
    TESTER_NAME = 'Supply Chain Scanner'

    # Probe payloads — not needed; we analyse response content & headers.

    def test(self, page: dict, depth: str = 'quick', recon_data: dict | None = None) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        vulns: list[dict] = []

        # Lazy import to keep module loading light
        from apps.scanning.engine.supply_chain import SupplyChainScanner
        scanner = SupplyChainScanner()

        # ── Fetch page to get HTML + headers ─────────────────────────────
        resp = self._make_request('GET', url)
        if resp is None:
            return []

        html = resp.text or ''
        headers = dict(resp.headers)

        # ── JS library scan (all depths) ─────────────────────────────────
        js_results = scanner.scan_js_libraries(html, headers)
        for lib in js_results:
            for v in lib.get('vulnerabilities', []):
                vulns.append(self._lib_vuln(url, lib, v))

        # ── Backend dependency scan (medium + deep) ──────────────────────
        if depth in ('medium', 'deep'):
            dep_results = scanner.scan_backend_dependencies(headers)
            for comp in dep_results:
                for cve in comp.get('cves', []):
                    vulns.append(self._dep_vuln(url, comp, cve))

        # ── Dependency confusion (deep only) ─────────────────────────────
        if depth == 'deep':
            confusion = scanner.check_dependency_confusion(html)
            for item in confusion:
                vulns.append(self._confusion_vuln(url, item))

        return vulns

    # ── Helpers ───────────────────────────────────────────────────────────

    def _lib_vuln(self, url: str, lib: dict, vuln: dict) -> dict:
        sev = vuln.get('severity', 'medium')
        cve = vuln.get('cve', 'N/A')
        return self._build_vuln(
            name=f"Vulnerable JS Library: {lib['name']} {lib['version']}",
            severity=sev,
            category='supply_chain_js',
            description=(
                f"The page includes {lib['name']} version {lib['version']} "
                f"which is affected by {cve}: {vuln.get('info', '')}."
            ),
            impact=(
                'An attacker can exploit known vulnerabilities in outdated '
                'client-side libraries to perform XSS, prototype pollution, '
                'or other attacks against users.'
            ),
            remediation=(
                f"Upgrade {lib['name']} to the latest stable version. "
                'Use automated dependency management (e.g. Dependabot, Renovate) '
                'to stay current.'
            ),
            cwe='CWE-1104',  # Use of Unmaintained Third-Party Components
            cvss=0,
            affected_url=url,
            evidence=f"Detected {lib['name']}@{lib['version']} via {lib.get('source', 'unknown')}. {cve}: {vuln.get('info', '')}",
        )

    def _dep_vuln(self, url: str, comp: dict, cve_entry: dict) -> dict:
        sev = cve_entry.get('severity', 'medium')
        cve_id = cve_entry.get('cve', 'N/A')
        confirmed = cve_entry.get('confirmed', False)
        epss = cve_entry.get('epss', 0.0)
        return self._build_vuln(
            name=f"Vulnerable Server Component: {comp['name']} {comp['version']}".strip(),
            severity=sev,
            category='supply_chain_backend',
            description=(
                f"The server exposes {comp['name']}"
                f"{' version ' + comp['version'] if comp['version'] else ''} "
                f"via the {comp['header']} header. "
                f"{'Confirmed' if confirmed else 'Potential'} vulnerability: "
                f"{cve_id} — {cve_entry.get('info', '')}. "
                f"EPSS score: {epss:.2f}."
            ),
            impact=(
                'Known server-side vulnerabilities can lead to remote code '
                'execution, information disclosure, or denial of service.'
            ),
            remediation=(
                f"Upgrade {comp['name']} to the latest stable version and "
                'suppress version disclosure headers (Server, X-Powered-By).'
            ),
            cwe='CWE-1104',
            cvss=0,
            affected_url=url,
            evidence=f"{comp['header']}: {comp['raw_value']}. {cve_id}: {cve_entry.get('info', '')}",
        )

    def _confusion_vuln(self, url: str, item: dict) -> dict:
        return self._build_vuln(
            name=f"Dependency Confusion Risk: {item['package']}",
            severity='high',
            category='supply_chain_confusion',
            description=(
                f"The page references a package '{item['package']}' that "
                f"appears to be a private/internal dependency "
                f"(scoped={item['is_scoped']}, internal-name={item['is_internal_name']}). "
                'If this package name is not claimed on the public npm registry, '
                'an attacker could publish a malicious package with the same name.'
            ),
            impact=(
                'Supply-chain attack via dependency confusion can lead to '
                'arbitrary code execution during the build process or at runtime.'
            ),
            remediation=(
                'Claim the package name on the public registry as a placeholder, '
                'use scoped packages with a private registry, or configure .npmrc '
                'to restrict install sources.'
            ),
            cwe='CWE-427',  # Uncontrolled Search Path Element
            cvss=0,
            affected_url=url,
            evidence=f"Package: {item['package']}, scoped: {item['is_scoped']}, "
                      f"internal: {item['is_internal_name']}, risk: {item['risk']}",
        )
