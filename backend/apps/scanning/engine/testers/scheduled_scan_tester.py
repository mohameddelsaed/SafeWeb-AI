"""
Scheduled & Continuous Scanning Tester — Phase 43.

Monitors the target for changes across successive scans:
  - SSL certificate expiry
  - New subdomains / closed subdomains
  - New open ports / closed ports
  - Technology stack changes
  - New / fixed / regressed findings (differential scanning)

Depth behaviour:
  quick  — SSL certificate expiry monitoring only
  medium — + Asset change detection (subdomains, ports, technologies)
  deep   — + Full differential scan (new / fixed / regressed findings)
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester
from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine

logger = logging.getLogger(__name__)

TESTER_NAME = 'Scheduled & Continuous Scanning'


class ScheduledScanTester(BaseTester):
    TESTER_NAME = TESTER_NAME

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
        engine = ScheduledScanEngine()
        vulns: list[dict] = []

        # ── quick — SSL expiry monitoring ──────────────────────────────
        ssl_changes = engine.check_ssl_expiry_from_recon(rd)
        vulns.extend(engine.changes_to_findings(ssl_changes, url))

        if depth in ('medium', 'deep'):
            # ── medium — Asset change detection ──────────────────────
            prev_recon: dict = rd.get('prev_recon', {}) or {}
            asset_changes = engine.detect_all_changes(prev_recon, rd)
            # SSL changes are already handled above — skip duplicates
            non_ssl = [c for c in asset_changes
                       if not c.change_type.startswith('ssl')]
            vulns.extend(engine.changes_to_findings(non_ssl, url))

        if depth == 'deep':
            # ── deep — Differential scan ──────────────────────────────
            prev_findings: list[dict] = rd.get('prev_findings', []) or []
            curr_findings: list[dict] = rd.get('findings', []) or []
            if prev_findings or curr_findings:
                try:
                    from apps.scanning.engine.scan_comparison import ScanComparison
                    diff = ScanComparison(prev_findings, curr_findings).compare()
                    vulns.extend(engine.diff_to_findings(diff, url))
                except Exception as exc:  # pragma: no cover
                    logger.warning('Scan diff failed: %s', exc)

        return vulns
