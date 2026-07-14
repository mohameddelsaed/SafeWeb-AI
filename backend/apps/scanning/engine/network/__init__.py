"""
Advanced Port & Service Scanning — Phase 34.

Sub-modules:
  - port_scanner: TCP connect scan, banner grabbing, service fingerprinting
  - service_detector: Service-specific security tests (FTP anon, Redis unauth, …)
  - ssl_tester: SSL/TLS protocol, cipher, certificate, and vulnerability checks
"""

from .port_scanner import PortScanner
from .service_detector import ServiceDetector
from .ssl_tester import SSLTester


class NetworkScanner:
    """Unified network-layer scanner combining port, service, and SSL analysis."""

    def __init__(self, timeout: float = 3.0):
        self.port_scanner = PortScanner(timeout=timeout)
        self.service_detector = ServiceDetector(timeout=timeout)
        self.ssl_tester = SSLTester(timeout=timeout)

    # ── Port scan ────────────────────────────────────────────────────────

    def scan_ports(self, host: str, ports: list[int] | None = None) -> list[dict]:
        """Scan *host* for open ports with banner grabbing.

        Returns list of ``{port, state, service, banner, version}`` dicts.
        """
        return self.port_scanner.scan(host, ports)

    # ── Service-specific tests ───────────────────────────────────────────

    def test_services(self, host: str, open_ports: list[dict]) -> list[dict]:
        """Run security tests against detected services.

        Returns list of finding dicts.
        """
        return self.service_detector.test_all(host, open_ports)

    # ── SSL/TLS analysis ────────────────────────────────────────────────

    def test_ssl(self, host: str, port: int = 443) -> dict:
        """Run comprehensive SSL/TLS checks.

        Returns dict with protocol_versions, ciphers, certificate,
        vulnerabilities, hsts, ocsp sections.
        """
        return self.ssl_tester.full_test(host, port)

    # ── Combined ─────────────────────────────────────────────────────────

    def full_scan(self, host: str, ports: list[int] | None = None) -> dict:
        """Port scan → service tests → SSL analysis in one call."""
        open_ports = self.scan_ports(host, ports)
        service_findings = self.test_services(host, open_ports)
        ssl_result = self.test_ssl(host)
        return {
            'open_ports': open_ports,
            'service_findings': service_findings,
            'ssl': ssl_result,
        }
