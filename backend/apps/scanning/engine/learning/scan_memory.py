"""
Scan Memory — Persistent memory of scan outcomes across targets.

Stores:
  - Per-tech-stack success rates for each vuln type
  - Per-WAF bypass effectiveness
  - Payload success history
  - FP/TP confirmation records
  - Target fingerprints and prior scan summaries

Used by the ML models and LLM reasoning engine to make smarter decisions
on future scans based on accumulated experience.
"""
from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ScanOutcome:
    """Summary of a completed scan."""
    target: str
    timestamp: float = 0.0
    tech_stack: list[str] = field(default_factory=list)
    waf: str = ''
    total_findings: int = 0
    confirmed_tp: int = 0
    confirmed_fp: int = 0
    vuln_types_found: list[str] = field(default_factory=list)
    best_payloads: dict[str, list[str]] = field(default_factory=dict)
    duration_seconds: float = 0.0
    vuln_category: str = ''
    was_vulnerable: bool = False
    payload_used: str = ''
    waf_present: bool = False
    waf_bypassed: bool = False


class ScanMemory:
    """Persistent cross-scan memory for learning."""

    DEFAULT_PATH = Path(__file__).parent.parent / 'data' / 'scan_memory.json'

    def __init__(self, path: Path | str | None = None):
        self._path = Path(path) if path else self.DEFAULT_PATH
        self._outcomes: list[ScanOutcome] = []
        self._tech_vuln_rates: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self._waf_bypass_rates: dict[str, float] = defaultdict(float)
        self._payload_success: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._load()

    def record_outcome(self, outcome: ScanOutcome) -> None:
        """Record a completed scan outcome."""
        if not outcome.timestamp:
            outcome.timestamp = time.time()
        self._outcomes.append(outcome)

        # Update aggregates
        for tech in outcome.tech_stack:
            tech_lower = tech.lower()
            for vt in outcome.vuln_types_found:
                self._tech_vuln_rates[tech_lower][vt] += 1

        if outcome.waf:
            total_bypass = outcome.confirmed_tp
            total_blocked = len([p for payloads in outcome.blocked_payloads.values()
                                  for p in payloads])
            if total_bypass + total_blocked > 0:
                self._waf_bypass_rates[outcome.waf.lower()] = (
                    total_bypass / (total_bypass + total_blocked)
                )

        # Track payload success
        for vt, payloads in outcome.best_payloads.items():
            for p in payloads[:5]:
                self._payload_success[vt][p[:100]] += 1

        self._save()

    def get_vuln_likelihood(self, tech_stack: list[str], vuln_type: str) -> float:
        """Get historical likelihood of a vuln type for a tech stack (0-1)."""
        if not tech_stack:
            return 0.5
        scores = []
        for tech in tech_stack:
            tech_lower = tech.lower()
            if tech_lower in self._tech_vuln_rates:
                rates = self._tech_vuln_rates[tech_lower]
                total = sum(rates.values())
                if total > 0:
                    scores.append(rates.get(vuln_type, 0) / total)
        return sum(scores) / len(scores) if scores else 0.5

    def get_waf_bypass_rate(self, waf: str) -> float:
        """Get historical bypass rate for a specific WAF."""
        return self._waf_bypass_rates.get(waf.lower(), 0.5)

    def get_best_payloads(self, vuln_type: str, top_k: int = 10) -> list[str]:
        """Get historically most successful payloads for a vuln type."""
        if vuln_type not in self._payload_success:
            return []
        ranked = sorted(
            self._payload_success[vuln_type].items(),
            key=lambda x: x[1], reverse=True,
        )
        return [p for p, _ in ranked[:top_k]]

    def get_scan_count(self) -> int:
        return len(self._outcomes)

    def summary(self) -> dict:
        return {
            'total_scans': len(self._outcomes),
            'tech_stacks_seen': len(self._tech_vuln_rates),
            'wafs_seen': len(self._waf_bypass_rates),
            'payload_types_tracked': len(self._payload_success),
        }

    # ── Persistence ───────────────────────────────────────────────────────

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                'outcomes': [
                    {
                        'target': o.target,
                        'timestamp': o.timestamp,
                        'tech_stack': o.tech_stack,
                        'waf': o.waf,
                        'total_findings': o.total_findings,
                        'confirmed_tp': o.confirmed_tp,
                        'confirmed_fp': o.confirmed_fp,
                        'vuln_types_found': o.vuln_types_found,
                        'duration_seconds': o.duration_seconds,
                    }
                    for o in self._outcomes[-100:]  # Keep last 100
                ],
                'tech_vuln_rates': dict(self._tech_vuln_rates),
                'waf_bypass_rates': dict(self._waf_bypass_rates),
                'payload_success': {
                    vt: dict(list(payloads.items())[:50])
                    for vt, payloads in self._payload_success.items()
                },
            }
            self._path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        except Exception as e:
            logger.debug('ScanMemory save error: %s', e)

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding='utf-8'))
            for o in data.get('outcomes', []):
                self._outcomes.append(ScanOutcome(
                    target=o.get('target', ''),
                    timestamp=o.get('timestamp', 0),
                    tech_stack=o.get('tech_stack', []),
                    waf=o.get('waf', ''),
                    total_findings=o.get('total_findings', 0),
                    confirmed_tp=o.get('confirmed_tp', 0),
                    confirmed_fp=o.get('confirmed_fp', 0),
                    vuln_types_found=o.get('vuln_types_found', []),
                    duration_seconds=o.get('duration_seconds', 0),
                ))
            for tech, rates in data.get('tech_vuln_rates', {}).items():
                self._tech_vuln_rates[tech] = defaultdict(float, rates)
            self._waf_bypass_rates = defaultdict(float, data.get('waf_bypass_rates', {}))
            for vt, payloads in data.get('payload_success', {}).items():
                self._payload_success[vt] = defaultdict(int, payloads)
            logger.debug('ScanMemory loaded: %d outcomes', len(self._outcomes))
        except Exception as e:
            logger.debug('ScanMemory load error: %s', e)
