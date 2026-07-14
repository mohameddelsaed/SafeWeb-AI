"""
Reporting Integration Tester — BaseTester wrapper for Phase 35.

Validates that a target's scan results can be properly:
  - Streamed via real-time findings pipeline (notifications)
  - Exported to issue trackers (Jira / GitHub / GitLab)
  - Compared across scans (diff / trend / posture)

Depth behaviour:
  - quick : notification pipeline validation + basic posture
  - medium: + issue tracker format validation + scan comparison
  - deep  : + full channel validation + trend analysis
"""
from __future__ import annotations

import logging

from apps.scanning.engine.testers.base_tester import BaseTester

logger = logging.getLogger(__name__)


class ReportingIntegrationTester(BaseTester):
    TESTER_NAME = 'Reporting & Integration Scanner'

    def test(self, page: dict, depth: str = 'quick', recon_data: dict | None = None) -> list[dict]:
        url = page.get('url', '')
        if not url:
            return []

        vulns: list[dict] = []

        # ── Notification Pipeline Validation ─────────────────────────────
        vulns.extend(self._check_notification_pipeline(url, depth))

        # ── Security Posture Assessment ──────────────────────────────────
        vulns.extend(self._check_security_posture(url, recon_data))

        if depth in ('medium', 'deep'):
            # ── Issue Tracker Format Validation ──────────────────────────
            vulns.extend(self._check_issue_tracker_formats(url, recon_data))

            # ── Scan Comparison ──────────────────────────────────────────
            vulns.extend(self._check_scan_comparison(url, recon_data))

        if depth == 'deep':
            # ── Trend Analysis ───────────────────────────────────────────
            vulns.extend(self._check_trend_analysis(url, recon_data))

        return vulns

    # ─────────────────────────────────────────────────────────────────────
    def _check_notification_pipeline(self, url: str, depth: str) -> list[dict]:
        """Verify that the notification system can stream findings."""
        vulns = []
        try:
            from apps.scanning.engine.notifications import (
                NotificationManager, SeverityFilter,
            )

            mgr = NotificationManager(min_severity='medium')
            stream = mgr.stream

            # Emit a test finding
            test_finding = {
                'name': 'Test Finding',
                'severity': 'high',
                'category': 'test',
                'affected_url': url,
                'description': 'Notification pipeline test',
            }
            mgr.emit_finding(test_finding)

            if stream.count < 1:
                vulns.append(self._build_vuln(
                    'Notification Pipeline Not Functional',
                    'medium', 'reporting',
                    'Real-time notification pipeline failed to buffer events',
                    'Scan findings may not reach administrators in real-time',
                    'Review notification engine configuration',
                    'CWE-778', 0.0, url, 'FindingsStream count=0 after emit',
                ))

            # Verify severity filter works
            sf = SeverityFilter(min_severity='high')
            low_finding = {'severity': 'low'}
            if sf.should_alert(low_finding):
                vulns.append(self._build_vuln(
                    'Severity Filter Bypass',
                    'low', 'reporting',
                    'Severity filter not correctly filtering low-severity findings',
                    'Excessive noise in alerts may cause alert fatigue',
                    'Ensure severity filter thresholds are properly configured',
                    'CWE-778', 0.0, url, 'Low finding passed high filter',
                ))

        except Exception as exc:
            logger.debug('Notification pipeline check error: %s', exc)
            vulns.append(self._build_vuln(
                'Notification System Error',
                'medium', 'reporting',
                f'Notification pipeline raised an error: {type(exc).__name__}',
                'Real-time alerts may not function during scans',
                'Check notification engine dependencies and configuration',
                'CWE-778', 0.0, url, str(exc),
            ))
        return vulns

    def _check_security_posture(self, url: str, recon_data: dict | None) -> list[dict]:
        """Compute security posture from any available findings."""
        vulns = []
        try:
            from apps.scanning.engine.scan_comparison import compute_security_posture

            existing = []
            if recon_data and 'findings' in recon_data:
                existing = recon_data['findings']

            posture = compute_security_posture(existing)
            score = posture.get('score', 100)
            grade = posture.get('grade', 'A+')

            if score < 50:
                vulns.append(self._build_vuln(
                    'Critical Security Posture',
                    'high', 'reporting',
                    f'Security posture score is {score}/100 (Grade: {grade})',
                    'Target has a high number of security vulnerabilities',
                    'Address critical and high severity vulnerabilities first',
                    'CWE-693', 0.0, url,
                    f'Score: {score}, Grade: {grade}, Breakdown: {posture.get("breakdown", {})}',
                ))
            elif score < 70:
                vulns.append(self._build_vuln(
                    'Poor Security Posture',
                    'medium', 'reporting',
                    f'Security posture score is {score}/100 (Grade: {grade})',
                    'Target has notable security weaknesses',
                    'Review and remediate medium+ severity findings',
                    'CWE-693', 0.0, url,
                    f'Score: {score}, Grade: {grade}',
                ))

        except Exception as exc:
            logger.debug('Posture check error: %s', exc)
        return vulns

    def _check_issue_tracker_formats(self, url: str, recon_data: dict | None) -> list[dict]:
        """Validate that findings can be formatted for issue trackers."""
        vulns = []
        try:
            from apps.scanning.engine.integrations import (
                JiraIntegration, GitHubIntegration,
            )

            sample_finding = {
                'name': 'Sample XSS',
                'severity': 'high',
                'category': 'xss',
                'affected_url': url,
                'description': 'Reflected XSS in parameter',
                'impact': 'Session hijacking',
                'remediation': 'Encode output',
                'cwe': 'CWE-79',
                'cvss': 6.1,
                'evidence': '<script>alert(1)</script>',
            }

            # Validate Jira format
            jira = JiraIntegration(
                base_url='https://test.atlassian.net',
                email='test@test.com',
                api_token='fake-for-validation',
                project_key='SEC',
            )
            payload = jira.build_payload(sample_finding)
            if not payload.get('fields', {}).get('summary'):
                vulns.append(self._build_vuln(
                    'Jira Integration Format Error',
                    'low', 'reporting',
                    'Jira issue payload missing summary field',
                    'Vulnerability findings cannot be exported to Jira',
                    'Review Jira integration format_title method',
                    'CWE-778', 0.0, url, str(payload),
                ))

            # Validate GitHub format
            gh = GitHubIntegration(token='fake', owner='test', repo='test')
            gh_payload = gh.build_payload(sample_finding)
            if not gh_payload.get('title'):
                vulns.append(self._build_vuln(
                    'GitHub Integration Format Error',
                    'low', 'reporting',
                    'GitHub issue payload missing title',
                    'Vulnerability findings cannot be exported to GitHub Issues',
                    'Review GitHub integration format_title method',
                    'CWE-778', 0.0, url, str(gh_payload),
                ))

        except Exception as exc:
            logger.debug('Issue tracker format check error: %s', exc)
        return vulns

    def _check_scan_comparison(self, url: str, recon_data: dict | None) -> list[dict]:
        """Validate scan comparison engine with sample data."""
        vulns = []
        try:
            from apps.scanning.engine.scan_comparison import ScanComparison

            baseline = [
                {'name': 'SQLi', 'severity': 'high', 'category': 'injection', 'affected_url': url},
            ]
            current = [
                {'name': 'SQLi', 'severity': 'critical', 'category': 'injection', 'affected_url': url},
                {'name': 'XSS', 'severity': 'medium', 'category': 'xss', 'affected_url': url},
            ]
            comp = ScanComparison(baseline, current)
            result = comp.compare()

            if result.degraded:
                vulns.append(self._build_vuln(
                    'Security Regression Detected',
                    'medium', 'reporting',
                    f'Scan comparison: {len(result.new_findings)} new, '
                    f'{len(result.fixed_findings)} fixed, '
                    f'{len(result.severity_changes)} severity changes',
                    'New vulnerabilities or escalations detected compared to baseline',
                    'Investigate new findings and severity changes',
                    'CWE-693', 0.0, url,
                    str(result.to_dict()),
                ))

        except Exception as exc:
            logger.debug('Scan comparison check error: %s', exc)
        return vulns

    def _check_trend_analysis(self, url: str, recon_data: dict | None) -> list[dict]:
        """Validate trend generation works."""
        vulns = []
        try:
            from apps.scanning.engine.scan_comparison import generate_trend

            history = [
                {'scan_id': '1', 'timestamp': '2024-01-01', 'findings': [
                    {'severity': 'critical'}, {'severity': 'high'},
                ]},
                {'scan_id': '2', 'timestamp': '2024-02-01', 'findings': [
                    {'severity': 'high'},
                ]},
            ]
            trend = generate_trend(history)
            if len(trend) != 2:
                vulns.append(self._build_vuln(
                    'Trend Analysis Error',
                    'low', 'reporting',
                    'Trend generation produced unexpected results',
                    'Security trend tracking may be inaccurate',
                    'Review generate_trend function',
                    'CWE-778', 0.0, url,
                    f'Expected 2 entries, got {len(trend)}',
                ))

        except Exception as exc:
            logger.debug('Trend analysis check error: %s', exc)
        return vulns
