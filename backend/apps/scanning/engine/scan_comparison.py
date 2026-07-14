"""
Scan Comparison Engine — Diff two scan results to detect new, fixed,
changed-severity, and regressed vulnerabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field


def _finding_key(f: dict) -> str:
    """Deterministic identity key for a finding (name + category + url)."""
    return '|'.join([
        f.get('name', ''),
        f.get('category', ''),
        f.get('affected_url', ''),
    ]).lower()


@dataclass
class ComparisonResult:
    """Result of comparing two scans."""
    new_findings: list[dict] = field(default_factory=list)
    fixed_findings: list[dict] = field(default_factory=list)
    recurring_findings: list[dict] = field(default_factory=list)
    severity_changes: list[dict] = field(default_factory=list)
    regression_findings: list[dict] = field(default_factory=list)
    baseline_total: int = 0
    current_total: int = 0

    def to_dict(self) -> dict:
        return {
            'new': len(self.new_findings),
            'fixed': len(self.fixed_findings),
            'recurring': len(self.recurring_findings),
            'severity_changes': len(self.severity_changes),
            'regressions': len(self.regression_findings),
            'baseline_total': self.baseline_total,
            'current_total': self.current_total,
            'delta': self.current_total - self.baseline_total,
            'new_findings': self.new_findings,
            'fixed_findings': self.fixed_findings,
            'severity_changes': self.severity_changes,
            'regression_findings': self.regression_findings,
        }

    @property
    def improved(self) -> bool:
        return len(self.fixed_findings) > len(self.new_findings) and len(self.regression_findings) == 0

    @property
    def degraded(self) -> bool:
        return len(self.new_findings) > len(self.fixed_findings) or len(self.regression_findings) > 0


SEV_ORDER = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}


class ScanComparison:
    """Compare baseline scan results to current scan results."""

    def __init__(self, baseline_findings: list[dict],
                 current_findings: list[dict]):
        self.baseline = baseline_findings
        self.current = current_findings

    def compare(self) -> ComparisonResult:
        result = ComparisonResult(
            baseline_total=len(self.baseline),
            current_total=len(self.current),
        )

        baseline_map: dict[str, dict] = {}
        for f in self.baseline:
            key = _finding_key(f)
            baseline_map[key] = f

        current_map: dict[str, dict] = {}
        for f in self.current:
            key = _finding_key(f)
            current_map[key] = f

        # New findings: in current but not in baseline
        for key, finding in current_map.items():
            if key not in baseline_map:
                result.new_findings.append(finding)

        # Fixed findings: in baseline but not in current
        for key, finding in baseline_map.items():
            if key not in current_map:
                result.fixed_findings.append(finding)

        # Recurring & severity changes
        for key in set(baseline_map) & set(current_map):
            old = baseline_map[key]
            cur = current_map[key]
            result.recurring_findings.append(cur)

            old_sev = old.get('severity', 'info').lower()
            cur_sev = cur.get('severity', 'info').lower()
            if old_sev != cur_sev:
                change = {
                    'finding': cur,
                    'old_severity': old_sev,
                    'new_severity': cur_sev,
                    'direction': 'escalated' if SEV_ORDER.get(cur_sev, 0) > SEV_ORDER.get(old_sev, 0) else 'reduced',
                }
                result.severity_changes.append(change)

        # Regressions: findings that were fixed before but re-appeared
        # (new findings with severity >= high)
        for f in result.new_findings:
            sev = f.get('severity', 'info').lower()
            if SEV_ORDER.get(sev, 0) >= SEV_ORDER.get('high', 3):
                result.regression_findings.append(f)

        return result


def compute_security_posture(findings: list[dict]) -> dict:
    """Compute a security posture score (0-100) from findings."""
    if not findings:
        return {'score': 100, 'grade': 'A+', 'breakdown': {}}

    penalties = {'critical': 20, 'high': 10, 'medium': 3, 'low': 1, 'info': 0}
    total_penalty = 0
    breakdown: dict[str, int] = {}
    for f in findings:
        sev = f.get('severity', 'info').lower()
        breakdown[sev] = breakdown.get(sev, 0) + 1
        total_penalty += penalties.get(sev, 0)

    score = max(0, 100 - total_penalty)
    if score >= 95:
        grade = 'A+'
    elif score >= 90:
        grade = 'A'
    elif score >= 80:
        grade = 'B'
    elif score >= 70:
        grade = 'C'
    elif score >= 60:
        grade = 'D'
    else:
        grade = 'F'

    return {'score': score, 'grade': grade, 'breakdown': breakdown}


def generate_trend(scan_history: list[dict]) -> list[dict]:
    """Generate trend data from a list of scan summaries.

    Each summary should contain ``{scan_id, timestamp, findings}``
    where findings is a list of finding dicts.
    """
    trend = []
    for entry in scan_history:
        findings = entry.get('findings', [])
        posture = compute_security_posture(findings)
        trend.append({
            'scan_id': entry.get('scan_id', ''),
            'timestamp': entry.get('timestamp', ''),
            'total_findings': len(findings),
            'score': posture['score'],
            'grade': posture['grade'],
            'breakdown': posture['breakdown'],
        })
    return trend
