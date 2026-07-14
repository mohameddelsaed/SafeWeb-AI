"""
Supply Chain & Dependency Scanner — Phase 33.

Sub-modules:
  - js_library_scanner: Detect JS libraries and known vulnerable versions
  - dependency_checker: Backend dependency detection and CVE lookup
"""

from .js_library_scanner import JSLibraryScanner
from .dependency_checker import DependencyChecker


class SupplyChainScanner:
    """Unified supply-chain analysis combining JS library + backend dep checks."""

    def __init__(self):
        self.js_scanner = JSLibraryScanner()
        self.dep_checker = DependencyChecker()

    # ── JS Library Analysis ──────────────────────────────────────────────

    def scan_js_libraries(self, html: str, headers: dict = None) -> list[dict]:
        """Detect JS libraries from page HTML and check for known vulns."""
        detected = self.js_scanner.detect_libraries(html)
        results = []
        for lib in detected:
            vulns = self.js_scanner.check_vulnerabilities(
                lib['name'], lib['version'],
            )
            results.append({**lib, 'vulnerabilities': vulns})
        return results

    # ── Backend Dependency Analysis ──────────────────────────────────────

    def scan_backend_dependencies(self, headers: dict) -> list[dict]:
        """Extract backend tech from HTTP headers and check for known CVEs."""
        components = self.dep_checker.detect_from_headers(headers)
        results = []
        for comp in components:
            cves = self.dep_checker.check_cves(
                comp['name'], comp['version'],
            )
            results.append({**comp, 'cves': cves})
        return results

    # ── Dependency Confusion ─────────────────────────────────────────────

    def check_dependency_confusion(self, html: str) -> list[dict]:
        """Extract package names and check for dependency confusion vectors."""
        return self.js_scanner.detect_dependency_confusion(html)

    # ── Combined ─────────────────────────────────────────────────────────

    def full_scan(self, html: str, headers: dict) -> dict:
        """Run all supply-chain checks and return combined results."""
        return {
            'js_libraries': self.scan_js_libraries(html, headers),
            'backend_dependencies': self.scan_backend_dependencies(headers),
            'dependency_confusion': self.check_dependency_confusion(html),
        }
