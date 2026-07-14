"""
Change Detector — Phase 18 Autonomous Hunting.

Detects meaningful differences between two scans of the same target,
so the autonomous hunter can decide whether a re-scan is warranted.
"""
import logging
from typing import Any

logger = logging.getLogger(__name__)


class ChangeDetector:
    """
    Detect meaningful changes in a target between two scans.
    Uses content hashes and recon_data stored in Scan.recon_data to compare.
    """

    # Minimum number of changed pages to consider changes "significant"
    MIN_NEW_PAGES = 3
    MIN_NEW_PARAMS = 5
    SCORE_DELTA_THRESHOLD = 10  # point drop that triggers re-scan

    def __init__(self, previous_scan, current_scan):
        """
        previous_scan / current_scan: Scan model instances (or dicts with
        the same keys for testing).
        """
        self.previous = previous_scan
        self.current = current_scan

    # ── Public API ────────────────────────────────

    def detect_changes(self) -> dict[str, Any]:
        """
        Compare two scans and return:
        {
            'new_pages': [...],
            'removed_pages': [...],
            'new_parameters': [...],
            'new_technologies': [...],
            'new_subdomains': [...],
            'score_delta': int,
            'new_vulns': [...],
            'fixed_vulns': [...],
        }
        """
        prev_recon = self._recon(self.previous)
        curr_recon = self._recon(self.current)

        prev_pages = set(prev_recon.get('pages', []))
        curr_pages = set(curr_recon.get('pages', []))

        prev_params = set(prev_recon.get('parameters', []))
        curr_params = set(curr_recon.get('parameters', []))

        prev_tech = set(prev_recon.get('technologies', []))
        curr_tech = set(curr_recon.get('technologies', []))

        prev_subs = set(prev_recon.get('subdomains', []))
        curr_subs = set(curr_recon.get('subdomains', []))

        prev_score = self._score(self.previous)
        curr_score = self._score(self.current)

        prev_vulns = self._vuln_names(self.previous)
        curr_vulns = self._vuln_names(self.current)

        return {
            'new_pages': sorted(curr_pages - prev_pages),
            'removed_pages': sorted(prev_pages - curr_pages),
            'new_parameters': sorted(curr_params - prev_params),
            'new_technologies': sorted(curr_tech - prev_tech),
            'new_subdomains': sorted(curr_subs - prev_subs),
            'score_delta': curr_score - prev_score,
            'new_vulns': sorted(curr_vulns - prev_vulns),
            'fixed_vulns': sorted(prev_vulns - curr_vulns),
        }

    def has_significant_changes(self) -> bool:
        """Return True if changes warrant a new scan iteration."""
        changes = self.detect_changes()

        if len(changes['new_pages']) >= self.MIN_NEW_PAGES:
            return True
        if len(changes['new_parameters']) >= self.MIN_NEW_PARAMS:
            return True
        if changes['new_subdomains']:
            return True
        if changes['score_delta'] <= -self.SCORE_DELTA_THRESHOLD:
            return True
        if changes['new_vulns']:
            return True
        return False

    # ── Helpers ───────────────────────────────────

    @staticmethod
    def _recon(scan) -> dict:
        if hasattr(scan, 'recon_data'):
            return scan.recon_data or {}
        if isinstance(scan, dict):
            return scan.get('recon_data', {})
        return {}

    @staticmethod
    def _score(scan) -> int:
        if hasattr(scan, 'score'):
            return scan.score or 0
        if isinstance(scan, dict):
            return scan.get('score', 0)
        return 0

    @staticmethod
    def _vuln_names(scan) -> set:
        try:
            if hasattr(scan, 'vulnerabilities'):
                return {v.name for v in scan.vulnerabilities.all()}
        except Exception:
            pass
        if isinstance(scan, dict):
            return {v.get('name', '') for v in scan.get('vulnerabilities', [])}
        return set()
