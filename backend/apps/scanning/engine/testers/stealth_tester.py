"""
Stealth Mode Tester — BaseTester wrapper for Phase 40.

Inspects the active scan's stealth configuration and raises findings when
the stealth setup is absent, misconfigured, or internally contradictory.

Depth behaviour:
  quick  — Rate-limit presence + User-Agent rotation check
  medium — + TLS / HTTP-version consistency analysis
  deep   — + Proxy / Tor configuration for high-risk scans
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class StealthTester(BaseTester):
    TESTER_NAME = 'Stealth Mode Engine'

    def test(
        self,
        page: dict,
        depth: str = 'quick',
        recon_data: dict | None = None,
    ) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        rd = recon_data or {}
        vulns: list[dict] = []

        # ── Always: rate-limit presence + UA rotation ─────────────────────
        vulns.extend(self._check_rate_limit_config(url, rd))
        vulns.extend(self._check_ua_rotation(url, rd))

        if depth in ('medium', 'deep'):
            # ── TLS / HTTP version consistency ────────────────────────────
            vulns.extend(self._check_tls_http_version(url, rd))

        if depth == 'deep':
            # ── Proxy / Tor for high-risk scans ───────────────────────────
            vulns.extend(self._check_proxy_configuration(url, rd))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Rate-limit check
    # ─────────────────────────────────────────────────────────────────────

    def _check_rate_limit_config(self, url: str, recon_data: dict) -> list[dict]:
        """Flag scans running at high RPS with no jitter (easily detectable)."""
        vulns: list[dict] = []
        try:
            from apps.scanning.engine.stealth.traffic_shaper import DEFAULT_RPS

            stealth_cfg = recon_data.get('stealth', {})
            rps = stealth_cfg.get('rps', DEFAULT_RPS)
            jitter_pct = stealth_cfg.get('jitter_pct', 0.0)

            if rps > 50 and jitter_pct == 0.0:
                vulns.append(self._build_vuln(
                    'Stealth: No Rate Limiting or Jitter Configured',
                    'medium', 'stealth-configuration',
                    f'Scan is running at {rps} RPS with no delay jitter. '
                    'High-speed, uniform requests are trivially detectable by '
                    'WAFs and IDS/IPS systems.',
                    'Predictable request cadence at high RPS allows WAFs to '
                    'accurately fingerprint and block automated scanners. '
                    'This reduces scan effectiveness and may trigger target '
                    'security alerts.',
                    'Reduce RPS to ≤20 for stealthy scans and enable '
                    'jitter_pct ≥ 0.20 via the TrafficShaper configuration.',
                    'CWE-400', 4.3, url,
                    f'rps={rps}, jitter_pct={jitter_pct}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_rate_limit_config error: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # UA rotation check
    # ─────────────────────────────────────────────────────────────────────

    def _check_ua_rotation(self, url: str, recon_data: dict) -> list[dict]:
        """Flag scans that transmit a fixed User-Agent string."""
        vulns: list[dict] = []
        try:
            stealth_cfg = recon_data.get('stealth', {})
            ua_rotation = stealth_cfg.get('ua_rotation', True)

            if not ua_rotation:
                vulns.append(self._build_vuln(
                    'Stealth: User-Agent Not Rotating',
                    'low', 'stealth-configuration',
                    'User-Agent rotation is disabled. All outgoing requests '
                    'carry the same static User-Agent, making it trivial for '
                    'the target to fingerprint and block the scanner.',
                    'A fixed User-Agent string allows WAFs and security '
                    'monitoring tools to recognise and filter every scan '
                    'request by its distinctive fingerprint.',
                    'Enable ua_rotation=True in the FingerprintEvasion '
                    'configuration to rotate User-Agents per request.',
                    'CWE-693', 2.0, url,
                    'ua_rotation=False',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_ua_rotation error: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # TLS / HTTP version consistency
    # ─────────────────────────────────────────────────────────────────────

    def _check_tls_http_version(self, url: str, recon_data: dict) -> list[dict]:
        """Flag contradictory TLS variation without HTTP version variation."""
        vulns: list[dict] = []
        try:
            stealth_cfg = recon_data.get('stealth', {})
            tls_variation = stealth_cfg.get('tls_variation', False)
            http_version_variation = stealth_cfg.get('http_version_variation', False)

            if tls_variation and not http_version_variation:
                vulns.append(self._build_vuln(
                    'Stealth: TLS Variation Enabled Without HTTP Version Variation',
                    'info', 'stealth-configuration',
                    'TLS fingerprint variation is active, but HTTP version is '
                    'fixed. Advanced deep-packet inspection correlates TLS '
                    'profiles with expected HTTP versions — inconsistent '
                    'pairing can itself become a detectable anomaly.',
                    'Advanced network monitoring correlates TLS fingerprints '
                    'with expected HTTP versions for known client types. '
                    'Mismatched combinations may flag traffic as anomalous '
                    'automated activity.',
                    'Enable http_version_variation=True in the '
                    'FingerprintEvasion configuration to coherently match '
                    'the HTTP version to the selected TLS profile.',
                    'CWE-693', 0.0, url,
                    f'tls_variation={tls_variation}, '
                    f'http_version_variation={http_version_variation}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_tls_http_version error: %s', exc)
        return vulns

    # ─────────────────────────────────────────────────────────────────────
    # Proxy / Tor for high-risk scans
    # ─────────────────────────────────────────────────────────────────────

    def _check_proxy_configuration(self, url: str, recon_data: dict) -> list[dict]:
        """Flag high-risk scans that expose the scanner's real IP."""
        vulns: list[dict] = []
        try:
            stealth_cfg = recon_data.get('stealth', {})
            scan_risk = recon_data.get('scan_risk', 'normal')
            proxy = stealth_cfg.get('proxy')
            tor_enabled = stealth_cfg.get('tor_enabled', False)

            if scan_risk == 'high' and not proxy and not tor_enabled:
                vulns.append(self._build_vuln(
                    'Stealth: No Proxy Configured for High-Risk Scan',
                    'medium', 'stealth-configuration',
                    'This scan is classified as high-risk but neither a proxy '
                    'nor Tor integration is configured. The scanner\'s real '
                    'IP address is exposed to the target on every request.',
                    'In adversarial or sensitive testing scenarios, exposing '
                    'the scanner IP can result in attribution, IP blacklisting, '
                    'or legal exposure if the target is out of scope.',
                    'Configure at least one HTTP/SOCKS5 proxy via '
                    'TrafficShaper.set_proxies() or enable Tor integration '
                    'with TrafficShaper.enable_tor() before running '
                    'high-risk scans.',
                    'CWE-200', 4.3, url,
                    f'scan_risk={scan_risk}, proxy={proxy}, '
                    f'tor_enabled={tor_enabled}',
                ))
        except Exception as exc:  # pragma: no cover
            logger.debug('_check_proxy_configuration error: %s', exc)
        return vulns
