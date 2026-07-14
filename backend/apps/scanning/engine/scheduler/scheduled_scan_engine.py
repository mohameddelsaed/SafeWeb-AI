"""
Scheduled & Continuous Scanning Engine — Phase 43.

Provides:
  - Cron-based schedule evaluation (`compute_next_run`)
  - SSL certificate expiry monitoring
  - Asset change detection (subdomains, ports, technologies)
  - Differential scan analysis (new / fixed / regressed findings)
  - Monitoring report builder
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRON_PRESETS: dict[str, dict] = {
    'hourly':  {'cron': '0 * * * *',  'interval_hours': 1},
    'daily':   {'cron': '0 2 * * *',  'interval_hours': 24},
    'weekly':  {'cron': '0 2 * * 1',  'interval_hours': 168},
    'monthly': {'cron': '0 2 1 * *',  'interval_hours': 720},
}

# Days remaining before expiry triggers a finding
SSL_EXPIRY_WARNING_DAYS: int = 30
SSL_EXPIRY_CRITICAL_DAYS: int = 7

# Severity per asset change type
ASSET_CHANGE_SEVERITY: dict[str, str] = {
    'new_subdomain':    'medium',
    'removed_subdomain': 'info',
    'new_port':         'medium',
    'closed_port':      'info',
    'tech_added':       'low',
    'tech_removed':     'info',
    'ssl_expiring':     'high',
    'ssl_expired':      'critical',
    'new_finding':      'high',
    'fixed_finding':    'info',
    'regressed_finding': 'high',
}

# How often (in hours) each monitoring dimension should be checked
MONITORING_INTERVALS: dict[str, int] = {
    'ssl':        24,
    'subdomains': 168,
    'ports':      336,
    'tech':       168,
    'findings':   24,
}

# CVSS scores used when emitting findings from monitoring alerts
_CHANGE_CVSS: dict[str, float] = {
    'ssl_expired':       9.0,
    'ssl_expiring':      7.5,
    'new_subdomain':     5.0,
    'new_port':          5.0,
    'tech_added':        3.0,
    'regressed_finding': 7.5,
    'new_finding':       7.5,
    'fixed_finding':     0.0,
    'removed_subdomain': 0.0,
    'closed_port':       0.0,
    'tech_removed':      0.0,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class ScheduleConfig:
    """Parsed scheduling configuration."""
    name: str
    preset: str               # hourly | daily | weekly | monthly | custom
    cron_expr: str
    interval_hours: int
    next_run: datetime
    is_active: bool = True


@dataclass
class AssetChange:
    """A single detected asset change."""
    change_type: str          # key from ASSET_CHANGE_SEVERITY
    asset: str                # the asset identifier (domain, IP, tech name …)
    detail: str               # human-readable description
    severity: str             # from ASSET_CHANGE_SEVERITY
    detected_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )


@dataclass
class MonitoringReport:
    """Full monitoring report for a target."""
    url: str
    ssl_changes: list[AssetChange]
    asset_changes: list[AssetChange]
    new_findings: list[dict]
    fixed_findings: list[dict]
    regressed_findings: list[dict]
    severity_changes: list[dict]
    risk_delta: float                  # positive = worse, negative = improved
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(tz=timezone.utc)
    )

    def to_dict(self) -> dict:
        return {
            'url': self.url,
            'ssl_changes': [
                {'change_type': c.change_type, 'asset': c.asset,
                 'detail': c.detail, 'severity': c.severity}
                for c in self.ssl_changes
            ],
            'asset_changes': [
                {'change_type': c.change_type, 'asset': c.asset,
                 'detail': c.detail, 'severity': c.severity}
                for c in self.asset_changes
            ],
            'new_findings': len(self.new_findings),
            'fixed_findings': len(self.fixed_findings),
            'regressed_findings': len(self.regressed_findings),
            'severity_changes': len(self.severity_changes),
            'risk_delta': self.risk_delta,
            'generated_at': self.generated_at.isoformat(),
        }


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class ScheduledScanEngine:
    """
    Core engine for scheduled and continuous scanning operations.

    This is a *pure* utility class — it has no Django ORM calls, making it
    fully testable without a running database.
    """

    # ── Schedule helpers ─────────────────────────────────────────────────

    def compute_next_run(
        self,
        schedule: str,
        from_dt: Optional[datetime] = None,
    ) -> datetime:
        """
        Compute the next scheduled run datetime.

        *schedule* can be a named preset (``'daily'``, ``'weekly'``, etc.) or
        a custom cron expression string like ``'0 3 * * *'``.  For custom
        expressions the interval is derived from the cron field values.

        Returns a UTC-aware datetime.
        """
        base = from_dt or datetime.now(tz=timezone.utc)

        preset = CRON_PRESETS.get(schedule)
        if preset:
            return base + timedelta(hours=preset['interval_hours'])

        # Custom cron expression — derive interval from simple parse
        hours = self._parse_cron_interval_hours(schedule)
        return base + timedelta(hours=hours)

    def _parse_cron_interval_hours(self, cron_expr: str) -> int:
        """
        Very lightweight cron interval estimator.

        Supports only the 5-field POSIX cron syntax.  Returns the approximate
        interval in hours based on the least-frequently-varying field:
          - */n in minutes  → n/60 hours (rounded up to 1 h)
          - */n in hours    → n hours
          - specific day-of-month → 720 h (monthly)
          - specific day-of-week  → 168 h (weekly)
          - wildcard hour         → 24 h (daily fallback)
        """
        parts = cron_expr.strip().split()
        if len(parts) != 5:
            return 24  # safe fallback

        _minute, hour, dom, _month, dow = parts

        if dom not in ('*', '?') and dom.isdigit():
            return 720  # monthly

        if dow not in ('*', '?') and re.match(r'^\d+$', dow):
            return 168  # weekly

        if hour.startswith('*/'):
            try:
                return int(hour[2:])
            except ValueError:
                pass

        if hour == '*':
            minute = _minute
            if minute.startswith('*/'):
                try:
                    interval_min = int(minute[2:])
                    return max(1, interval_min // 60)
                except ValueError:
                    pass
            return 1  # every hour

        return 24

    def get_preset_cron(self, preset: str) -> str:
        """Return the cron expression for a named preset."""
        return CRON_PRESETS.get(preset, CRON_PRESETS['daily'])['cron']

    def get_preset_interval_hours(self, preset: str) -> int:
        """Return interval hours for a named preset."""
        return CRON_PRESETS.get(preset, CRON_PRESETS['daily'])['interval_hours']

    # ── SSL monitoring ───────────────────────────────────────────────────

    def check_ssl_expiry_from_recon(self, recon_data: dict) -> list[AssetChange]:
        """
        Extract SSL expiry information from recon_data and return any
        AssetChange alerts.

        Expected recon_data keys (all optional):
          - ``ssl_info``      : dict with ``days_remaining`` / ``expiry_date``
          - ``ssl_valid``     : bool
          - ``ssl_expiry``    : ISO-8601 string or days-remaining int
        """
        changes: list[AssetChange] = []
        ssl_info = recon_data.get('ssl_info') or {}
        target = recon_data.get('url', recon_data.get('target', 'unknown'))

        # Normalise days_remaining from various sources
        days_remaining: Optional[int] = None

        if 'days_remaining' in ssl_info:
            try:
                days_remaining = int(ssl_info['days_remaining'])
            except (TypeError, ValueError):
                pass

        if days_remaining is None and 'ssl_expiry' in recon_data:
            raw = recon_data['ssl_expiry']
            if isinstance(raw, (int, float)):
                days_remaining = int(raw)
            elif isinstance(raw, str):
                try:
                    expiry_dt = datetime.fromisoformat(raw.replace('Z', '+00:00'))
                    days_remaining = (expiry_dt - datetime.now(tz=timezone.utc)).days
                except ValueError:
                    pass

        if days_remaining is None:
            return changes  # no SSL info available

        if days_remaining <= 0:
            changes.append(AssetChange(
                change_type='ssl_expired',
                asset=target,
                detail=f'SSL certificate for {target} has expired '
                       f'({abs(days_remaining)} days ago).',
                severity='critical',
            ))
        elif days_remaining <= SSL_EXPIRY_CRITICAL_DAYS:
            changes.append(AssetChange(
                change_type='ssl_expiring',
                asset=target,
                detail=f'SSL certificate for {target} expires in '
                       f'{days_remaining} day(s) — CRITICAL.',
                severity='critical',
            ))
        elif days_remaining <= SSL_EXPIRY_WARNING_DAYS:
            changes.append(AssetChange(
                change_type='ssl_expiring',
                asset=target,
                detail=f'SSL certificate for {target} expires in '
                       f'{days_remaining} day(s) — renew soon.',
                severity='high',
            ))

        return changes

    def detect_ssl_changes(
        self, prev_ssl: dict, curr_ssl: dict
    ) -> list[AssetChange]:
        """
        Compare two SSL info snapshots and return any changes as AssetChange
        instances.
        """
        changes: list[AssetChange] = []

        prev_days = prev_ssl.get('days_remaining')
        curr_days = curr_ssl.get('days_remaining')

        if prev_days is not None and curr_days is not None:
            try:
                prev_d = int(prev_days)
                curr_d = int(curr_days)
                if prev_d > SSL_EXPIRY_WARNING_DAYS >= curr_d:
                    changes.append(AssetChange(
                        change_type='ssl_expiring',
                        asset=curr_ssl.get('domain', 'unknown'),
                        detail=f'Certificate entered warning window: '
                               f'{curr_d} days remaining.',
                        severity='high',
                    ))
            except (TypeError, ValueError):
                pass

        return changes

    # ── Asset change detection ───────────────────────────────────────────

    def detect_subdomain_changes(
        self,
        prev_subs: list[str],
        curr_subs: list[str],
    ) -> list[AssetChange]:
        prev_set = {s.lower().strip() for s in prev_subs}
        curr_set = {s.lower().strip() for s in curr_subs}

        changes: list[AssetChange] = []
        for sub in curr_set - prev_set:
            changes.append(AssetChange(
                change_type='new_subdomain',
                asset=sub,
                detail=f'New subdomain discovered: {sub}',
                severity=ASSET_CHANGE_SEVERITY['new_subdomain'],
            ))
        for sub in prev_set - curr_set:
            changes.append(AssetChange(
                change_type='removed_subdomain',
                asset=sub,
                detail=f'Subdomain no longer resolving: {sub}',
                severity=ASSET_CHANGE_SEVERITY['removed_subdomain'],
            ))
        return changes

    def detect_tech_changes(
        self,
        prev_tech: list[str],
        curr_tech: list[str],
    ) -> list[AssetChange]:
        prev_set = {t.lower().strip() for t in prev_tech}
        curr_set = {t.lower().strip() for t in curr_tech}

        changes: list[AssetChange] = []
        for tech in curr_set - prev_set:
            changes.append(AssetChange(
                change_type='tech_added',
                asset=tech,
                detail=f'New technology detected: {tech}',
                severity=ASSET_CHANGE_SEVERITY['tech_added'],
            ))
        for tech in prev_set - curr_set:
            changes.append(AssetChange(
                change_type='tech_removed',
                asset=tech,
                detail=f'Technology no longer detected: {tech}',
                severity=ASSET_CHANGE_SEVERITY['tech_removed'],
            ))
        return changes

    def detect_port_changes(
        self,
        prev_ports: list[int],
        curr_ports: list[int],
    ) -> list[AssetChange]:
        prev_set = set(prev_ports)
        curr_set = set(curr_ports)

        changes: list[AssetChange] = []
        for port in curr_set - prev_set:
            changes.append(AssetChange(
                change_type='new_port',
                asset=str(port),
                detail=f'New open port detected: {port}',
                severity=ASSET_CHANGE_SEVERITY['new_port'],
            ))
        for port in prev_set - curr_set:
            changes.append(AssetChange(
                change_type='closed_port',
                asset=str(port),
                detail=f'Port closed since last scan: {port}',
                severity=ASSET_CHANGE_SEVERITY['closed_port'],
            ))
        return changes

    def detect_all_changes(
        self,
        prev_recon: dict,
        curr_recon: dict,
    ) -> list[AssetChange]:
        """
        Detect all asset-level changes between two recon snapshots.

        Both arguments should be recon_data dicts with optional keys:
        ``subdomains``, ``technologies``, ``open_ports``, ``ssl_info``.
        """
        changes: list[AssetChange] = []

        # Subdomains
        changes.extend(self.detect_subdomain_changes(
            prev_recon.get('subdomains', []),
            curr_recon.get('subdomains', []),
        ))

        # Technologies
        changes.extend(self.detect_tech_changes(
            prev_recon.get('technologies', []),
            curr_recon.get('technologies', []),
        ))

        # Open ports
        changes.extend(self.detect_port_changes(
            prev_recon.get('open_ports', []),
            curr_recon.get('open_ports', []),
        ))

        # SSL snapshot comparison
        prev_ssl = prev_recon.get('ssl_info', {}) or {}
        curr_ssl = curr_recon.get('ssl_info', {}) or {}
        if prev_ssl or curr_ssl:
            changes.extend(self.detect_ssl_changes(prev_ssl, curr_ssl))

        return changes

    # ── Differential scanning ─────────────────────────────────────────────

    def diff_to_findings(
        self,
        comparison_result,  # apps.scanning.engine.scan_comparison.ComparisonResult
        url: str,
    ) -> list[dict]:
        """
        Convert a ScanComparison result to BaseTester-style finding dicts.

        Returns one finding per new/fixed/regressed item.
        """

        dummy = _DummyTester()
        vulns: list[dict] = []

        for f in comparison_result.new_findings:
            name = f.get('name', 'Unknown')
            sev = f.get('severity', 'medium').lower()
            cvss = float(f.get('cvss', 0))
            vulns.append(dummy._build_vuln(
                f'[New] {name}',
                sev,
                'scan-diff-new',
                f'A new "{name}" finding appeared since the last scan. '
                'Investigation is recommended.',
                'New vulnerabilities may indicate recent code changes or '
                'newly introduced dependencies.',
                'Investigate and remediate the new finding promptly.',
                f.get('cwe', 'CWE-693'),
                cvss,
                url,
                f'Differential scan: new finding | '
                f'Original URL: {f.get("affected_url", "")} | '
                f'Category: {f.get("category", "")}',
            ))

        for f in comparison_result.fixed_findings:
            name = f.get('name', 'Unknown')
            vulns.append(dummy._build_vuln(
                f'[Fixed] {name}',
                'info',
                'scan-diff-fixed',
                f'The "{name}" finding from the previous scan is no longer '
                'detected in this scan.',
                'Tracking fixed vulnerabilities confirms effective remediation.',
                'No action required — verify that the fix is permanent.',
                'CWE-693',
                0.0,
                url,
                f'Differential scan: fixed finding | '
                f'Original URL: {f.get("affected_url", "")}',
            ))

        for f in comparison_result.regression_findings:
            name = f.get('name', 'Unknown')
            sev = f.get('severity', 'high').lower()
            cvss = float(f.get('cvss', 7.5))
            vulns.append(dummy._build_vuln(
                f'[Regressed] {name}',
                sev,
                'scan-diff-regression',
                f'The "{name}" finding re-appeared after being absent in a '
                'previous scan.  This may indicate an incomplete fix.',
                'Regressions indicate the remediation was not properly '
                'applied or was reverted.',
                'Re-investigate the remediation and apply a permanent fix.',
                f.get('cwe', 'CWE-693'),
                cvss,
                url,
                f'Differential scan: regression | '
                f'Severity: {sev} | URL: {f.get("affected_url", "")}',
            ))

        return vulns

    def changes_to_findings(
        self,
        changes: list[AssetChange],
        url: str,
    ) -> list[dict]:
        """Convert a list of AssetChange instances to finding dicts."""
        dummy = _DummyTester()
        vulns: list[dict] = []
        for change in changes:
            cvss = _CHANGE_CVSS.get(change.change_type, 3.0)
            vulns.append(dummy._build_vuln(
                f'Asset Change: {change.change_type.replace("_", " ").title()} '
                f'— {change.asset}',
                change.severity,
                'asset-monitoring',
                change.detail,
                _change_impact(change.change_type),
                _change_remediation(change.change_type),
                'CWE-693',
                cvss,
                url,
                f'Change type: {change.change_type} | '
                f'Asset: {change.asset} | '
                f'Detected: {change.detected_at.isoformat()}',
            ))
        return vulns

    # ── Monitoring report ─────────────────────────────────────────────────

    def build_monitoring_report(
        self,
        url: str,
        prev_recon: dict,
        curr_recon: dict,
        prev_findings: Optional[list[dict]] = None,
        curr_findings: Optional[list[dict]] = None,
    ) -> MonitoringReport:
        """Build a full monitoring report from two recon/findings snapshots."""
        from apps.scanning.engine.scan_comparison import ScanComparison

        ssl_changes = self.check_ssl_expiry_from_recon(curr_recon)
        asset_changes = [
            c for c in self.detect_all_changes(prev_recon, curr_recon)
            if not c.change_type.startswith('ssl')
        ]

        prev_f = prev_findings or []
        curr_f = curr_findings or []
        diff = ScanComparison(prev_f, curr_f).compare()

        # Risk delta: positive means more/higher-severity findings
        cvss_sum = lambda lst: sum(f.get('cvss', 0) for f in lst)  # noqa: E731
        risk_delta = round(cvss_sum(diff.new_findings) - cvss_sum(diff.fixed_findings), 2)

        return MonitoringReport(
            url=url,
            ssl_changes=ssl_changes,
            asset_changes=asset_changes,
            new_findings=diff.new_findings,
            fixed_findings=diff.fixed_findings,
            regressed_findings=diff.regression_findings,
            severity_changes=diff.severity_changes,
            risk_delta=risk_delta,
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _change_impact(change_type: str) -> str:
    impacts = {
        'ssl_expired':       ('Expired certificates make HTTPS connections untrusted, '
                              'exposing users to MITM attacks.'),
        'ssl_expiring':      ('Certificate expiry will disrupt HTTPS and trigger browser '
                              'warnings, impacting availability and user trust.'),
        'new_subdomain':     ('New subdomains may expose additional attack surface, '
                              'especially if misconfigured or unmonitored.'),
        'new_port':          ('Newly open ports may indicate a misconfiguration or '
                              'unauthorised service that expands the attack surface.'),
        'tech_added':        ('New technologies may introduce unknown vulnerabilities '
                              'or dependencies.'),
        'regressed_finding': ('A previously remediated vulnerability has re-appeared, '
                              'indicating an incomplete or reverted fix.'),
        'new_finding':       ('A new security vulnerability was detected.',),
    }
    return impacts.get(change_type, 'Asset change detected during continuous monitoring.')


def _change_remediation(change_type: str) -> str:
    remediations = {
        'ssl_expired':       'Renew the SSL certificate immediately.',
        'ssl_expiring':      'Renew the SSL certificate before it expires.',
        'new_subdomain':     'Review and secure the new subdomain.',
        'new_port':          'Close the port if not required or ensure it is properly secured.',
        'tech_added':        'Verify the new technology is intentional and scan for known CVEs.',
        'regressed_finding': 'Re-apply the remediation and verify with a re-test.',
        'new_finding':       'Investigate and remediate the new finding.',
    }
    return remediations.get(change_type, 'Review the detected asset change.')


class _DummyTester:
    """Lightweight stand-in to call BaseTester._build_vuln without BaseTester setup."""

    def _build_vuln(self, name, severity, category, description, impact,
                    remediation, cwe, cvss, affected_url, evidence):
        # Inline the severity ↔ CVSS alignment from base_tester
        SEVERITY_CVSS_MAP = {
            'critical': 9.5, 'high': 7.5, 'medium': 5.0, 'low': 2.5, 'info': 0.0,
        }
        CVSS_SEV = [(9.0, 'critical'), (7.0, 'high'), (4.0, 'medium'), (0.1, 'low')]

        if cvss == 0 and severity in SEVERITY_CVSS_MAP:
            cvss = SEVERITY_CVSS_MAP[severity]

        if cvss > 0:
            for threshold, derived in CVSS_SEV:
                if cvss >= threshold:
                    severity = derived
                    break
            else:
                severity = 'info'

        return {
            'name': name,
            'severity': severity,
            'category': category,
            'description': description,
            'impact': impact,
            'remediation': remediation,
            'cwe': cwe,
            'cvss': cvss,
            'affected_url': affected_url,
            'evidence': evidence,
        }


# Deferred import to avoid circular deps at module load time
import re  # noqa: E402 (used in _parse_cron_interval_hours)
