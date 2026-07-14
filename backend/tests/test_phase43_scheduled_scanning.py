"""
Phase 43 — Scheduled & Continuous Scanning
Tests for ScheduledScanEngine, ScheduledScanTester, models, and tasks.
"""
import pytest
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now():
    return datetime.now(tz=timezone.utc)


def _recon_with_ssl(days_remaining):
    return {
        'url': 'https://example.com',
        'ssl_info': {'days_remaining': days_remaining, 'domain': 'example.com'},
    }


def _page(url='https://example.com'):
    return {'url': url, 'content': '<html></html>', 'headers': {}, 'status_code': 200}


# ---------------------------------------------------------------------------
# 1. Constants
# ---------------------------------------------------------------------------

class TestConstants:
    def test_cron_presets_keys(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import CRON_PRESETS
        for key in ('hourly', 'daily', 'weekly', 'monthly'):
            assert key in CRON_PRESETS

    def test_cron_presets_have_cron_and_interval(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import CRON_PRESETS
        for name, cfg in CRON_PRESETS.items():
            assert 'cron' in cfg, f'{name} missing cron'
            assert 'interval_hours' in cfg, f'{name} missing interval_hours'

    def test_ssl_expiry_warning_days(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import SSL_EXPIRY_WARNING_DAYS
        assert SSL_EXPIRY_WARNING_DAYS >= 14

    def test_ssl_expiry_critical_days(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import SSL_EXPIRY_CRITICAL_DAYS
        assert 1 <= SSL_EXPIRY_CRITICAL_DAYS <= 14

    def test_ssl_expiry_critical_less_than_warning(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            SSL_EXPIRY_CRITICAL_DAYS, SSL_EXPIRY_WARNING_DAYS,
        )
        assert SSL_EXPIRY_CRITICAL_DAYS < SSL_EXPIRY_WARNING_DAYS

    def test_asset_change_severity_keys(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ASSET_CHANGE_SEVERITY
        for key in ('new_subdomain', 'new_port', 'ssl_expiring', 'ssl_expired', 'tech_added'):
            assert key in ASSET_CHANGE_SEVERITY

    def test_monitoring_intervals_keys(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import MONITORING_INTERVALS
        for key in ('ssl', 'subdomains', 'ports', 'tech'):
            assert key in MONITORING_INTERVALS


# ---------------------------------------------------------------------------
# 2. Dataclasses
# ---------------------------------------------------------------------------

class TestDataclasses:
    def test_schedule_config_instantiation(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduleConfig
        now = _now()
        sc = ScheduleConfig(
            name='Weekly Scan',
            preset='weekly',
            cron_expr='0 2 * * 1',
            interval_hours=168,
            next_run=now,
            is_active=True,
        )
        assert sc.name == 'Weekly Scan'
        assert sc.interval_hours == 168

    def test_asset_change_instantiation(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import AssetChange
        ac = AssetChange(
            change_type='new_subdomain',
            asset='sub.example.com',
            detail='New subdomain discovered',
            severity='medium',
        )
        assert ac.change_type == 'new_subdomain'
        assert ac.severity == 'medium'

    def test_asset_change_has_detected_at(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import AssetChange
        ac = AssetChange('new_port', '8080', 'New port', 'medium')
        assert ac.detected_at is not None

    def test_monitoring_report_to_dict(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import MonitoringReport
        report = MonitoringReport(
            url='https://example.com',
            ssl_changes=[],
            asset_changes=[],
            new_findings=[],
            fixed_findings=[],
            regressed_findings=[],
            severity_changes=[],
            risk_delta=0.0,
        )
        d = report.to_dict()
        assert d['url'] == 'https://example.com'
        assert 'risk_delta' in d
        assert 'generated_at' in d


# ---------------------------------------------------------------------------
# 3. compute_next_run
# ---------------------------------------------------------------------------

class TestComputeNextRun:
    def test_daily_preset(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        base = _now()
        next_run = engine.compute_next_run('daily', from_dt=base)
        delta = next_run - base
        assert 23 <= delta.total_seconds() / 3600 <= 25

    def test_weekly_preset(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        base = _now()
        next_run = engine.compute_next_run('weekly', from_dt=base)
        delta = next_run - base
        assert 167 <= delta.total_seconds() / 3600 <= 169

    def test_hourly_preset(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        base = _now()
        next_run = engine.compute_next_run('hourly', from_dt=base)
        delta = next_run - base
        assert 0.9 <= delta.total_seconds() / 3600 <= 1.1

    def test_monthly_preset(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        base = _now()
        next_run = engine.compute_next_run('monthly', from_dt=base)
        delta = next_run - base
        assert delta.total_seconds() / 3600 > 700

    def test_custom_cron_daily_fallback(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        base = _now()
        next_run = engine.compute_next_run('0 3 * * *', from_dt=base)
        delta = next_run - base
        # daily fallback for hour-specified daily cron
        assert delta.total_seconds() > 0

    def test_returns_aware_datetime(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        next_run = engine.compute_next_run('daily')
        assert next_run.tzinfo is not None

    def test_get_preset_cron(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        cron = engine.get_preset_cron('daily')
        assert isinstance(cron, str)
        assert len(cron.split()) == 5

    def test_get_preset_interval_hours(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        assert engine.get_preset_interval_hours('daily') == 24
        assert engine.get_preset_interval_hours('weekly') == 168


# ---------------------------------------------------------------------------
# 4. SSL monitoring
# ---------------------------------------------------------------------------

class TestSSLMonitoring:
    def test_expired_ssl_returns_critical(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.check_ssl_expiry_from_recon(_recon_with_ssl(-5))
        assert len(changes) == 1
        assert changes[0].change_type == 'ssl_expired'
        assert changes[0].severity == 'critical'

    def test_ssl_expiring_critical_window(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            ScheduledScanEngine, SSL_EXPIRY_CRITICAL_DAYS,
        )
        engine = ScheduledScanEngine()
        changes = engine.check_ssl_expiry_from_recon(
            _recon_with_ssl(SSL_EXPIRY_CRITICAL_DAYS - 1)
        )
        assert len(changes) == 1
        assert changes[0].severity == 'critical'

    def test_ssl_expiring_warning_window(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            ScheduledScanEngine, SSL_EXPIRY_WARNING_DAYS, SSL_EXPIRY_CRITICAL_DAYS,
        )
        engine = ScheduledScanEngine()
        days = (SSL_EXPIRY_WARNING_DAYS + SSL_EXPIRY_CRITICAL_DAYS) // 2
        changes = engine.check_ssl_expiry_from_recon(_recon_with_ssl(days))
        assert len(changes) == 1
        assert changes[0].change_type == 'ssl_expiring'

    def test_ssl_healthy_no_changes(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.check_ssl_expiry_from_recon(_recon_with_ssl(90))
        assert changes == []

    def test_no_ssl_info_no_changes(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.check_ssl_expiry_from_recon({'url': 'https://example.com'})
        assert changes == []

    def test_ssl_expiry_from_ssl_expiry_key_integer(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        recon = {'ssl_expiry': 5}
        changes = engine.check_ssl_expiry_from_recon(recon)
        assert len(changes) == 1

    def test_detect_ssl_changes_entering_warning(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            ScheduledScanEngine, SSL_EXPIRY_WARNING_DAYS,
        )
        engine = ScheduledScanEngine()
        prev = {'days_remaining': SSL_EXPIRY_WARNING_DAYS + 10, 'domain': 'example.com'}
        curr = {'days_remaining': SSL_EXPIRY_WARNING_DAYS - 1, 'domain': 'example.com'}
        changes = engine.detect_ssl_changes(prev, curr)
        assert len(changes) == 1
        assert changes[0].change_type == 'ssl_expiring'

    def test_detect_ssl_changes_still_healthy(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        prev = {'days_remaining': 90, 'domain': 'example.com'}
        curr = {'days_remaining': 89, 'domain': 'example.com'}
        changes = engine.detect_ssl_changes(prev, curr)
        assert changes == []


# ---------------------------------------------------------------------------
# 5. Asset change detection
# ---------------------------------------------------------------------------

class TestAssetChangeDetection:
    def test_new_subdomain_detected(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.detect_subdomain_changes([], ['api.example.com'])
        assert any(c.change_type == 'new_subdomain' for c in changes)

    def test_removed_subdomain_detected(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.detect_subdomain_changes(['old.example.com'], [])
        assert any(c.change_type == 'removed_subdomain' for c in changes)

    def test_no_subdomain_change(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        subs = ['api.example.com', 'www.example.com']
        assert engine.detect_subdomain_changes(subs, subs) == []

    def test_new_tech_detected(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.detect_tech_changes(['nginx'], ['nginx', 'react'])
        assert any(c.change_type == 'tech_added' for c in changes)

    def test_tech_removed_detected(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.detect_tech_changes(['nginx', 'jquery'], ['nginx'])
        assert any(c.change_type == 'tech_removed' for c in changes)

    def test_new_port_detected(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.detect_port_changes([80, 443], [80, 443, 8080])
        assert any(c.change_type == 'new_port' for c in changes)

    def test_closed_port_detected(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        changes = engine.detect_port_changes([80, 443, 8080], [80, 443])
        assert any(c.change_type == 'closed_port' for c in changes)

    def test_detect_all_changes_combines(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        prev = {'subdomains': [], 'technologies': ['nginx'], 'open_ports': [80]}
        curr = {'subdomains': ['api.example.com'], 'technologies': ['nginx', 'react'], 'open_ports': [80, 8080]}
        changes = engine.detect_all_changes(prev, curr)
        types = {c.change_type for c in changes}
        assert 'new_subdomain' in types
        assert 'tech_added' in types
        assert 'new_port' in types

    def test_detect_all_changes_empty_to_empty(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        assert engine.detect_all_changes({}, {}) == []


# ---------------------------------------------------------------------------
# 6. changes_to_findings / diff_to_findings
# ---------------------------------------------------------------------------

class TestFindingConversion:
    def test_changes_to_findings_returns_list(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            ScheduledScanEngine, AssetChange,
        )
        engine = ScheduledScanEngine()
        changes = [AssetChange('new_subdomain', 'api.example.com', 'New sub', 'medium')]
        findings = engine.changes_to_findings(changes, 'https://example.com')
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_changes_to_findings_has_required_keys(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            ScheduledScanEngine, AssetChange,
        )
        engine = ScheduledScanEngine()
        changes = [AssetChange('ssl_expiring', 'example.com', 'Expiring soon', 'high')]
        finding = engine.changes_to_findings(changes, 'https://example.com')[0]
        for key in ('name', 'severity', 'category', 'description', 'cvss'):
            assert key in finding

    def test_changes_to_findings_empty(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        assert engine.changes_to_findings([], 'https://example.com') == []

    def test_diff_to_findings_new_finding(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        from apps.scanning.engine.scan_comparison import ScanComparison
        engine = ScheduledScanEngine()
        prev = []
        curr = [{'name': 'XSS', 'category': 'xss', 'severity': 'high',
                 'cvss': 7.5, 'affected_url': 'https://example.com'}]
        diff = ScanComparison(prev, curr).compare()
        findings = engine.diff_to_findings(diff, 'https://example.com')
        assert any('[New]' in f['name'] for f in findings)

    def test_diff_to_findings_fixed_finding(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        from apps.scanning.engine.scan_comparison import ScanComparison
        engine = ScheduledScanEngine()
        prev = [{'name': 'XSS', 'category': 'xss', 'severity': 'high',
                 'cvss': 7.5, 'affected_url': 'https://example.com'}]
        curr = []
        diff = ScanComparison(prev, curr).compare()
        findings = engine.diff_to_findings(diff, 'https://example.com')
        assert any('[Fixed]' in f['name'] for f in findings)

    def test_diff_to_findings_no_changes_empty(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        from apps.scanning.engine.scan_comparison import ScanComparison
        engine = ScheduledScanEngine()
        same = [{'name': 'XSS', 'category': 'xss', 'severity': 'high',
                 'cvss': 7.5, 'affected_url': 'https://example.com'}]
        diff = ScanComparison(same, same).compare()
        findings = engine.diff_to_findings(diff, 'https://example.com')
        # no new / fixed / regression → empty
        assert findings == []

    def test_diff_to_findings_category_scan_diff(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        from apps.scanning.engine.scan_comparison import ScanComparison
        engine = ScheduledScanEngine()
        diff = ScanComparison(
            [],
            [{'name': 'SQLI', 'category': 'sqli', 'severity': 'high',
              'cvss': 7.5, 'affected_url': 'https://example.com'}],
        ).compare()
        findings = engine.diff_to_findings(diff, 'https://example.com')
        assert all('scan-diff' in f['category'] for f in findings)


# ---------------------------------------------------------------------------
# 7. build_monitoring_report
# ---------------------------------------------------------------------------

class TestMonitoringReport:
    def test_returns_monitoring_report(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import (
            ScheduledScanEngine, MonitoringReport,
        )
        engine = ScheduledScanEngine()
        report = engine.build_monitoring_report(
            'https://example.com', {}, {'ssl_info': {'days_remaining': 5}},
        )
        assert isinstance(report, MonitoringReport)

    def test_ssl_expiry_populated_in_report(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        report = engine.build_monitoring_report(
            'https://example.com', {},
            {'ssl_info': {'days_remaining': 3, 'domain': 'example.com'}},
        )
        assert len(report.ssl_changes) > 0

    def test_asset_changes_populated(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        prev = {'subdomains': []}
        curr = {'subdomains': ['new.example.com']}
        report = engine.build_monitoring_report('https://example.com', prev, curr)
        assert len(report.asset_changes) > 0

    def test_diff_populated_in_report(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        prev_f = []
        curr_f = [{'name': 'SQLi', 'category': 'sqli', 'severity': 'high',
                   'cvss': 7.5, 'affected_url': 'https://example.com'}]
        report = engine.build_monitoring_report(
            'https://example.com', {}, {}, prev_f, curr_f,
        )
        assert len(report.new_findings) > 0

    def test_to_dict_has_keys(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        report = engine.build_monitoring_report('https://example.com', {}, {})
        d = report.to_dict()
        for key in ('url', 'ssl_changes', 'asset_changes', 'new_findings',
                    'fixed_findings', 'risk_delta', 'generated_at'):
            assert key in d

    def test_risk_delta_positive_when_new_findings(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        curr_f = [{'name': 'SQLi', 'category': 'sqli', 'severity': 'high',
                   'cvss': 7.5, 'affected_url': 'https://example.com'}]
        report = engine.build_monitoring_report('https://example.com', {}, {}, [], curr_f)
        assert report.risk_delta > 0

    def test_risk_delta_negative_when_fixed(self):
        from apps.scanning.engine.scheduler.scheduled_scan_engine import ScheduledScanEngine
        engine = ScheduledScanEngine()
        prev_f = [{'name': 'SQLi', 'category': 'sqli', 'severity': 'high',
                   'cvss': 7.5, 'affected_url': 'https://example.com'}]
        report = engine.build_monitoring_report('https://example.com', {}, {}, prev_f, [])
        assert report.risk_delta < 0


# ---------------------------------------------------------------------------
# 8. ScheduledScanTester
# ---------------------------------------------------------------------------

class TestScheduledScanTester:
    def test_tester_name(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        assert ScheduledScanTester.TESTER_NAME == 'Scheduled & Continuous Scanning'

    def test_empty_url_returns_empty(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        assert t.test({'url': '', 'content': '', 'headers': {}}, 'quick', {}) == []

    def test_no_recon_returns_empty(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        result = t.test(_page(), 'quick', {})
        assert isinstance(result, list)

    def test_expiring_ssl_detected_at_quick(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        rd = _recon_with_ssl(5)
        result = t.test(_page(), 'quick', rd)
        assert len(result) > 0
        sev = {f['severity'] for f in result}
        assert sev & {'critical', 'high'}

    def test_healthy_ssl_no_findings_at_quick(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        rd = _recon_with_ssl(90)
        result = t.test(_page(), 'quick', rd)
        assert result == []

    def test_new_subdomain_at_medium(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        rd = {
            'subdomains': ['api.example.com'],
            'prev_recon': {'subdomains': []},
        }
        result = t.test(_page(), 'medium', rd)
        assert any('subdomain' in f['name'].lower() or 'asset' in f['name'].lower()
                   for f in result)

    def test_no_asset_changes_at_quick(self):
        """New subdomain should not appear at quick depth."""
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        rd = {
            'subdomains': ['api.example.com'],
            'prev_recon': {'subdomains': []},
        }
        result = t.test(_page(), 'quick', rd)
        # quick only checks SSL — no SSL info here so result should be empty
        assert result == []

    def test_diff_findings_at_deep(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        prev_f = []
        curr_f = [{'name': 'XSS', 'category': 'xss', 'severity': 'high',
                   'cvss': 7.5, 'affected_url': 'https://example.com'}]
        rd = {'prev_findings': prev_f, 'findings': curr_f}
        result = t.test(_page(), 'deep', rd)
        assert any('[New]' in f['name'] for f in result)

    def test_no_diff_at_medium(self):
        """Differential findings should only appear at deep depth."""
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        prev_f = []
        curr_f = [{'name': 'XSS', 'category': 'xss', 'severity': 'high',
                   'cvss': 7.5, 'affected_url': 'https://example.com'}]
        rd = {'prev_findings': prev_f, 'findings': curr_f}
        result = t.test(_page(), 'medium', rd)
        # medium doesn't compute diff
        assert not any('[New]' in f.get('name', '') for f in result)

    def test_finding_has_required_keys(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        rd = _recon_with_ssl(3)
        for f in t.test(_page(), 'quick', rd):
            for key in ('name', 'severity', 'category', 'description', 'cvss', 'cwe'):
                assert key in f

    def test_fixed_finding_at_deep(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        prev_f = [{'name': 'SQLi', 'category': 'sqli', 'severity': 'high',
                   'cvss': 7.5, 'affected_url': 'https://example.com'}]
        rd = {'prev_findings': prev_f, 'findings': []}
        result = t.test(_page(), 'deep', rd)
        assert any('[Fixed]' in f['name'] for f in result)

    def test_combined_ssl_and_diff_at_deep(self):
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        t = ScheduledScanTester()
        rd = {
            **_recon_with_ssl(5),
            'prev_findings': [],
            'findings': [{'name': 'XSS', 'category': 'xss', 'severity': 'high',
                          'cvss': 7.5, 'affected_url': 'https://example.com'}],
        }
        result = t.test(_page(), 'deep', rd)
        names = [f['name'] for f in result]
        assert any('ssl' in n.lower() or 'certificate' in n.lower() or 'expir' in n.lower()
                   for n in names)
        assert any('[New]' in n for n in names)


# ---------------------------------------------------------------------------
# 9. Django models (field verification)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScheduledScanModel:
    def test_model_importable(self):
        from apps.scanning.models import ScheduledScan
        assert ScheduledScan is not None

    def test_has_expected_fields(self):
        from apps.scanning.models import ScheduledScan
        field_names = {f.name for f in ScheduledScan._meta.get_fields()}
        for name in ('name', 'scan_config', 'cron_expr', 'schedule_preset',
                     'last_run', 'next_run', 'is_active', 'notify_on_new_findings'):
            assert name in field_names, f'Missing field: {name}'

    def test_str_representation(self, django_user_model):
        from django.utils import timezone
        from apps.scanning.models import ScheduledScan
        user = django_user_model.objects.create_user(
            username='sched_test_u', password='pass',
        )
        scheduled = ScheduledScan.objects.create(
            user=user,
            name='My Weekly Scan',
            scan_config={'target': 'https://example.com'},
            schedule_preset='weekly',
            next_run=timezone.now() + timezone.timedelta(days=7),
        )
        assert 'weekly' in str(scheduled).lower() or 'my weekly scan' in str(scheduled).lower()

    def test_default_is_active(self, django_user_model):
        from django.utils import timezone
        from apps.scanning.models import ScheduledScan
        user = django_user_model.objects.create_user(
            username='sched_test_u2', password='pass',
        )
        scheduled = ScheduledScan.objects.create(
            user=user,
            name='Test',
            scan_config={},
            next_run=timezone.now(),
        )
        assert scheduled.is_active is True


@pytest.mark.django_db
class TestAssetMonitorRecordModel:
    def test_model_importable(self):
        from apps.scanning.models import AssetMonitorRecord
        assert AssetMonitorRecord is not None

    def test_has_expected_fields(self):
        from apps.scanning.models import AssetMonitorRecord
        field_names = {f.name for f in AssetMonitorRecord._meta.get_fields()}
        for name in ('target', 'change_type', 'detail', 'severity', 'acknowledged'):
            assert name in field_names

    def test_create_record(self, django_user_model):
        from apps.scanning.models import AssetMonitorRecord
        record = AssetMonitorRecord.objects.create(
            target='https://example.com',
            change_type='new_subdomain',
            detail='api.example.com discovered',
            severity='medium',
        )
        assert record.pk is not None
        assert record.acknowledged is False

    def test_str_representation(self, django_user_model):
        from apps.scanning.models import AssetMonitorRecord
        record = AssetMonitorRecord.objects.create(
            target='https://example.com',
            change_type='ssl_expiring',
            detail='Expiring in 5 days',
            severity='high',
        )
        s = str(record)
        assert 'ssl_expiring' in s or 'example.com' in s


# ---------------------------------------------------------------------------
# 10. Celery tasks (unit — no real Celery worker)
# ---------------------------------------------------------------------------

class TestCeleryTasks:
    def test_run_scheduled_scans_importable(self):
        from apps.scanning.tasks import run_scheduled_scans
        assert callable(run_scheduled_scans)

    def test_execute_scheduled_scan_task_importable(self):
        from apps.scanning.tasks import execute_scheduled_scan_task
        assert callable(execute_scheduled_scan_task)

    def test_compute_scan_diff_task_importable(self):
        from apps.scanning.tasks import compute_scan_diff_task
        assert callable(compute_scan_diff_task)

    def test_execute_scan_task_still_exists(self):
        """Sanity-check that the original task was not removed."""
        from apps.scanning.tasks import execute_scan_task
        assert callable(execute_scan_task)


# ---------------------------------------------------------------------------
# 11. Registration
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_tester_count_75(self):
        from apps.scanning.engine.testers import get_all_testers
        assert len(get_all_testers()) == 87

    def test_scheduled_scan_tester_registered(self):
        from apps.scanning.engine.testers import get_all_testers
        from apps.scanning.engine.testers.scheduled_scan_tester import ScheduledScanTester
        assert any(isinstance(t, ScheduledScanTester) for t in get_all_testers())

    def test_scheduled_scan_tester_is_last(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert testers[-13].TESTER_NAME == 'Scheduled & Continuous Scanning'
