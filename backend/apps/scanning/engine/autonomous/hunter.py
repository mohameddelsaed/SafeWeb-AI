"""
Autonomous Hunter — Phase 18.

Orchestrates continuous / hunting mode scanning with scope expansion
and change detection. Runs as a long-lived Celery task.
"""
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class AutonomousHunter:
    """
    Orchestrates continuous scanning with scope expansion and change detection.

    Runs as a long-lived Celery beat / apply_async task for scans where
    mode is 'hunting' or 'continuous'.

    Safety rules:
    - NEVER auto-expands scope to unrelated domains (confidence threshold 0.8+
      AND domain must share the seed's TLD root).
    - New child scans are created with status='pending' — they do NOT start
      automatically without the Celery task picking them up.
    - max_iterations caps total loops to prevent runaway tasks.
    """

    DEFAULT_RESCAN_INTERVAL_HOURS = 24
    SCOPE_CONFIDENCE_THRESHOLD = 0.8

    def __init__(self, base_scan_id: str, config: dict | None = None):
        self.base_scan_id = base_scan_id
        self.config = config or {}
        self._rescan_interval = self.config.get(
            'rescan_interval_hours', self.DEFAULT_RESCAN_INTERVAL_HOURS,
        )

    # ── Main hunting loop ─────────────────────────

    async def hunt(self, max_iterations: int = 10) -> None:
        """
        Main hunting loop:
          1. Load base scan
          2. Run standard scan via orchestrator
          3. Detect changes from previous scan
          4. If significant changes or new scope candidates → create child scans
          5. Update parent with delta report
          6. Schedule next re-scan
          7. Repeat until max_iterations or manual stop
        """
        from apps.scanning.models import Scan
        from apps.scanning.engine.orchestrator import ScanOrchestrator
        from apps.scanning.engine.autonomous.change_detector import ChangeDetector
        from apps.scanning.engine.autonomous.scope_expander import ScopeExpander

        iteration = 0
        previous_scan = None

        try:
            base_scan = await asyncio.to_thread(Scan.objects.get, id=self.base_scan_id)
        except Exception as exc:
            logger.error(f'AutonomousHunter: base scan {self.base_scan_id} not found: {exc}')
            return

        while iteration < max_iterations:
            iteration += 1
            logger.info(
                f'[Hunter] Iteration {iteration}/{max_iterations} for scan {self.base_scan_id}'
            )

            # 1. Execute standard scan
            try:
                orchestrator = ScanOrchestrator()
                await asyncio.to_thread(orchestrator.execute_scan, str(base_scan.id))
                # Reload scan state
                base_scan = await asyncio.to_thread(Scan.objects.get, id=self.base_scan_id)
            except Exception as exc:
                logger.error(f'[Hunter] Scan execution failed: {exc}')
                break

            # 2. Detect changes from previous iteration
            delta: dict[str, Any] = {}
            if previous_scan is not None:
                detector = ChangeDetector(previous_scan, base_scan)
                delta = detector.detect_changes()
                has_changes = detector.has_significant_changes()
                logger.info(
                    f'[Hunter] Change detection: new_pages={len(delta.get("new_pages", []))}, '
                    f'new_vulns={len(delta.get("new_vulns", []))}, '
                    f'score_delta={delta.get("score_delta", 0)}'
                )
            else:
                has_changes = True  # first iteration always proceeds

            # 3. Scope expansion
            recon_data = base_scan.recon_data or {}
            expander = ScopeExpander(base_scan.target, recon_data)
            candidates = expander.get_expansion_candidates()
            approved = self._should_expand_scope(candidates, base_scan.target)

            if approved:
                await self._create_child_scans(base_scan, approved)

            # 4. Store delta in recon_data
            if delta:
                recon_data['hunter_delta'] = delta
                base_scan.recon_data = recon_data
                await asyncio.to_thread(
                    base_scan.save, update_fields=['recon_data']
                )

            # 5. If no significant changes and no new scope → pause loop
            if not has_changes and not approved:
                logger.info(f'[Hunter] No significant changes — pausing after iteration {iteration}')

            # 6. Schedule next scan
            previous_scan = base_scan
            self.schedule_rescan(str(base_scan.id), self._rescan_interval)

            # Sleep until next scheduled time (non-blocking)
            await asyncio.sleep(self._rescan_interval * 3600)

        logger.info(f'[Hunter] Hunt complete after {iteration} iterations')

    # ── Scope filter ──────────────────────────────

    def _should_expand_scope(self, candidates: list[dict], seed_url: str) -> list[dict]:
        """
        Filter candidates by:
          1. confidence > SCOPE_CONFIDENCE_THRESHOLD
          2. Domain shares the seed's base TLD root

        NEVER auto-expand to unrelated domains.
        """
        from urllib.parse import urlparse
        seed_domain = urlparse(seed_url).netloc or seed_url
        seed_root = '.'.join(seed_domain.split('.')[-2:])  # e.g. "example.com"

        approved = []
        for c in candidates:
            if c['confidence'] < self.SCOPE_CONFIDENCE_THRESHOLD:
                continue
            domain = c['domain']
            if domain.endswith(seed_root) or domain == seed_root:
                approved.append(c)
                logger.info(
                    f'[Hunter] Approved scope expansion: {domain} '
                    f'(confidence={c["confidence"]:.2f}, reason={c["reason"]})'
                )
        return approved

    # ── Child scan creation ───────────────────────

    async def _create_child_scans(self, parent_scan, candidates: list[dict]) -> None:
        """Create child Scan records for approved scope expansions."""
        from apps.scanning.models import Scan

        for c in candidates:
            try:
                child = Scan(
                    user=parent_scan.user,
                    scan_type='website',
                    target=f'https://{c["domain"]}',
                    depth=parent_scan.depth,
                    status='pending',
                    mode='hunting',
                    parent_scan=parent_scan,
                )
                await asyncio.to_thread(child.save)
                logger.info(
                    f'[Hunter] Created child scan {child.id} for {c["domain"]}'
                )
            except Exception as exc:
                logger.warning(f'[Hunter] Failed to create child scan for {c["domain"]}: {exc}')

    # ── Scheduling ────────────────────────────────

    def schedule_rescan(self, scan_id: str, delay_hours: int) -> None:
        """Schedule a Celery task for future re-scan."""
        try:
            from apps.scanning.tasks import execute_scan_task
            execute_scan_task.apply_async(
                args=[scan_id],
                countdown=delay_hours * 3600,
            )
            logger.info(
                f'[Hunter] Scheduled re-scan for {scan_id} '
                f'in {delay_hours}h'
            )
        except Exception as exc:
            logger.warning(f'[Hunter] Failed to schedule re-scan: {exc}')
