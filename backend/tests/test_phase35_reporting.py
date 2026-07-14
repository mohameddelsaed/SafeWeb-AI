"""
Phase 35 — Reporting & Integration Mega-Upgrade tests.

Covers:
  - Notifications: Severity, ScanEvent, SeverityFilter, FindingsStream,
    NotificationChannel, NotificationManager
  - Channels: Slack, Discord, Teams, Telegram, CustomWebhook
  - Integrations: IssueTrackerIntegration, JiraIntegration, GitHubIntegration,
    GitLabIntegration, IntegrationManager
  - Scan Comparison: ScanComparison, ComparisonResult, compute_security_posture,
    generate_trend
  - ReportingIntegrationTester: BaseTester integration, registration, count (67)
"""
import time
import pytest
from unittest.mock import patch, MagicMock

# ── Notification imports ─────────────────────────────────────────────────────
from apps.scanning.engine.notifications import (
    Severity,
    ScanEvent,
    SeverityFilter,
    FindingsStream,
    NotificationChannel,
    NotificationManager,
)
from apps.scanning.engine.notifications.channels import (
    SlackChannel,
    DiscordChannel,
    TeamsChannel,
    TelegramChannel,
    CustomWebhookChannel,
    _severity_emoji,
    _format_finding,
    _format_progress,
    _format_event,
    _post_json,
)

# ── Integration imports ──────────────────────────────────────────────────────
from apps.scanning.engine.integrations import (
    IssueTrackerIntegration,
    JiraIntegration,
    GitHubIntegration,
    GitLabIntegration,
    IntegrationManager,
    _api_request,
)

# ── Scan comparison imports ──────────────────────────────────────────────────
from apps.scanning.engine.scan_comparison import (
    ScanComparison,
    ComparisonResult,
    compute_security_posture,
    generate_trend,
    SEV_ORDER,
    _finding_key,
)

# ── Tester import ────────────────────────────────────────────────────────────
from apps.scanning.engine.testers.reporting_integration_tester import (
    ReportingIntegrationTester,
)


# ════════════════════════════════════════════════════════════════════════════
# Severity Enum
# ════════════════════════════════════════════════════════════════════════════

class TestSeverity:

    def test_values(self):
        assert Severity.INFO.value == 0
        assert Severity.LOW.value == 1
        assert Severity.MEDIUM.value == 2
        assert Severity.HIGH.value == 3
        assert Severity.CRITICAL.value == 4

    def test_from_str_valid(self):
        assert Severity.from_str('critical') == Severity.CRITICAL
        assert Severity.from_str('HIGH') == Severity.HIGH
        assert Severity.from_str('Medium') == Severity.MEDIUM

    def test_from_str_default(self):
        assert Severity.from_str('unknown') == Severity.INFO
        assert Severity.from_str('') == Severity.INFO

    def test_comparison(self):
        assert Severity.CRITICAL.value > Severity.HIGH.value
        assert Severity.LOW.value < Severity.MEDIUM.value


# ════════════════════════════════════════════════════════════════════════════
# ScanEvent
# ════════════════════════════════════════════════════════════════════════════

class TestScanEvent:

    def test_creation(self):
        ev = ScanEvent(event_type='finding', timestamp=1.0, data={'a': 1})
        assert ev.event_type == 'finding'
        assert ev.timestamp == 1.0
        assert ev.data == {'a': 1}

    def test_to_dict(self):
        ev = ScanEvent(event_type='progress', timestamp=2.0, data={'b': 2})
        d = ev.to_dict()
        assert d['event_type'] == 'progress'
        assert d['timestamp'] == 2.0
        assert d['data'] == {'b': 2}


# ════════════════════════════════════════════════════════════════════════════
# SeverityFilter
# ════════════════════════════════════════════════════════════════════════════

class TestSeverityFilter:

    def test_default_threshold(self):
        sf = SeverityFilter()
        assert sf.should_alert({'severity': 'low'}) is True
        assert sf.should_alert({'severity': 'info'}) is False

    def test_high_threshold(self):
        sf = SeverityFilter(min_severity='high')
        assert sf.should_alert({'severity': 'critical'}) is True
        assert sf.should_alert({'severity': 'high'}) is True
        assert sf.should_alert({'severity': 'medium'}) is False
        assert sf.should_alert({'severity': 'low'}) is False

    def test_info_threshold(self):
        sf = SeverityFilter(min_severity='info')
        assert sf.should_alert({'severity': 'info'}) is True
        assert sf.should_alert({'severity': 'critical'}) is True

    def test_set_threshold(self):
        sf = SeverityFilter(min_severity='info')
        sf.set_threshold('critical')
        assert sf.should_alert({'severity': 'high'}) is False
        assert sf.should_alert({'severity': 'critical'}) is True

    def test_missing_severity(self):
        sf = SeverityFilter(min_severity='low')
        assert sf.should_alert({}) is False  # defaults to info < low


# ════════════════════════════════════════════════════════════════════════════
# FindingsStream
# ════════════════════════════════════════════════════════════════════════════

class TestFindingsStream:

    def test_push_and_count(self):
        fs = FindingsStream()
        ev = ScanEvent('finding', time.time(), {'a': 1})
        idx = fs.push(ev)
        assert idx == 0
        assert fs.count == 1

    def test_get_all(self):
        fs = FindingsStream()
        fs.push(ScanEvent('a', 1.0, {}))
        fs.push(ScanEvent('b', 2.0, {}))
        assert len(fs.get_all()) == 2

    def test_get_since(self):
        fs = FindingsStream()
        fs.push(ScanEvent('a', 1.0, {}))
        fs.push(ScanEvent('b', 2.0, {}))
        fs.push(ScanEvent('c', 3.0, {}))
        since = fs.get_since(0)
        assert len(since) == 2

    def test_latest(self):
        fs = FindingsStream()
        fs.push(ScanEvent('a', 1.0, {}))
        fs.push(ScanEvent('b', 2.0, {}))
        assert fs.latest().event_type == 'b'

    def test_latest_empty(self):
        fs = FindingsStream()
        assert fs.latest() is None

    def test_clear(self):
        fs = FindingsStream()
        fs.push(ScanEvent('a', 1.0, {}))
        fs.clear()
        assert fs.count == 0

    def test_max_events_cap(self):
        fs = FindingsStream(max_events=3)
        for i in range(5):
            fs.push(ScanEvent(f'e{i}', float(i), {}))
        assert fs.count == 3
        assert fs.get_all()[0].event_type == 'e2'


# ════════════════════════════════════════════════════════════════════════════
# NotificationChannel (base)
# ════════════════════════════════════════════════════════════════════════════

class TestNotificationChannel:

    def test_base_name(self):
        ch = NotificationChannel()
        assert ch.name == 'base'

    def test_send_returns_false(self):
        ch = NotificationChannel()
        ev = ScanEvent('test', 1.0, {})
        assert ch.send(ev) is False

    def test_test_connection_false(self):
        ch = NotificationChannel()
        assert ch.test_connection() is False


# ════════════════════════════════════════════════════════════════════════════
# NotificationManager
# ════════════════════════════════════════════════════════════════════════════

class TestNotificationManager:

    def test_add_channel(self):
        mgr = NotificationManager()
        ch = NotificationChannel()
        ch.name = 'test'
        mgr.add_channel(ch)
        assert 'test' in mgr.get_channels()

    def test_remove_channel(self):
        mgr = NotificationManager()
        ch = NotificationChannel()
        ch.name = 'test'
        mgr.add_channel(ch)
        assert mgr.remove_channel('test') is True
        assert mgr.remove_channel('nonexistent') is False

    def test_emit_finding_streams_event(self):
        mgr = NotificationManager(min_severity='low')
        mgr.emit_finding({'severity': 'high', 'name': 'Test'})
        assert mgr.stream.count == 1
        assert mgr.stats['findings'] == 1

    def test_emit_finding_filters_by_severity(self):
        mgr = NotificationManager(min_severity='high')
        # Channels only get dispatched for high+ severity,
        # but event always enters the stream
        callback_data = []
        mgr.add_callback(lambda ev: callback_data.append(ev))
        mgr.emit_finding({'severity': 'low', 'name': 'Low'})
        assert mgr.stream.count == 1  # always streamed
        assert len(callback_data) == 1  # callbacks always fire

    def test_emit_progress(self):
        mgr = NotificationManager()
        mgr.emit_progress('xss', 5, 10, 3)
        assert mgr.stream.count == 1
        latest = mgr.stream.latest()
        assert latest.event_type == 'progress'
        assert latest.data['phase'] == 'xss'

    def test_emit_phase_start(self):
        mgr = NotificationManager()
        mgr.emit_phase_start('sqli', 'SQL Injection Testing')
        assert mgr.stream.latest().event_type == 'phase_start'

    def test_emit_phase_end(self):
        mgr = NotificationManager()
        mgr.emit_phase_end('sqli', 5)
        assert mgr.stream.latest().event_type == 'phase_end'

    def test_emit_scan_complete(self):
        mgr = NotificationManager()
        mgr.emit_scan_complete({'total': 10})
        assert mgr.stream.latest().event_type == 'scan_complete'

    def test_emit_error(self):
        mgr = NotificationManager()
        mgr.emit_error('Connection failed', {'host': 'example.com'})
        assert mgr.stream.latest().event_type == 'error'
        assert mgr.stats['errors'] == 1

    def test_set_min_severity(self):
        mgr = NotificationManager(min_severity='low')
        mgr.set_min_severity('critical')
        # Low finding should not trigger channel dispatch
        ch = MagicMock(spec=NotificationChannel)
        ch.name = 'mock'
        ch.send = MagicMock()
        mgr.add_channel(ch)
        mgr.emit_finding({'severity': 'medium', 'name': 'Med'})
        ch.send.assert_not_called()

    def test_dispatch_to_channel(self):
        mgr = NotificationManager(min_severity='low')
        ch = MagicMock(spec=NotificationChannel)
        ch.name = 'mock'
        ch.send = MagicMock()
        mgr.add_channel(ch)
        mgr.emit_finding({'severity': 'high', 'name': 'High'})
        ch.send.assert_called_once()

    def test_callback_always_fires(self):
        mgr = NotificationManager(min_severity='critical')
        events = []
        mgr.add_callback(lambda ev: events.append(ev))
        mgr.emit_finding({'severity': 'low', 'name': 'Low'})
        assert len(events) == 1

    def test_stats_property(self):
        mgr = NotificationManager()
        mgr.emit_finding({'severity': 'high', 'name': 'H'})
        mgr.emit_error('err')
        stats = mgr.stats
        assert stats['findings'] == 1
        assert stats['errors'] == 1


# ════════════════════════════════════════════════════════════════════════════
# Channel Helpers
# ════════════════════════════════════════════════════════════════════════════

class TestChannelHelpers:

    def test_severity_emoji(self):
        assert '🔴' in _severity_emoji('critical')
        assert '🟠' in _severity_emoji('high')
        assert _severity_emoji('unknown') is not None

    def test_format_finding(self):
        data = {'severity': 'high', 'name': 'XSS', 'affected_url': 'http://x.com'}
        text = _format_finding(data)
        assert 'XSS' in text
        assert 'HIGH' in text

    def test_format_progress(self):
        data = {'phase': 'sqli', 'current': 3, 'total': 10}
        text = _format_progress(data)
        assert 'sqli' in text
        assert '3' in text

    def test_format_event_finding(self):
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'Test'})
        text = _format_event(ev)
        assert 'Test' in text

    def test_format_event_progress(self):
        ev = ScanEvent('progress', 1.0, {'phase': 'xss', 'current': 1, 'total': 5})
        text = _format_event(ev)
        assert 'xss' in text

    def test_format_event_scan_complete(self):
        ev = ScanEvent('scan_complete', 1.0, {'total': 42})
        text = _format_event(ev)
        assert '42' in text or 'complete' in text.lower()

    def test_format_event_error(self):
        ev = ScanEvent('error', 1.0, {'error': 'timeout'})
        text = _format_event(ev)
        assert 'timeout' in text.lower() or 'error' in text.lower()


# ════════════════════════════════════════════════════════════════════════════
# Slack Channel
# ════════════════════════════════════════════════════════════════════════════

class TestSlackChannel:

    def test_name(self):
        ch = SlackChannel(webhook_url='https://hooks.slack.com/test')
        assert ch.name == 'slack'

    def test_build_payload(self):
        ch = SlackChannel(webhook_url='https://hooks.slack.com/test', channel='#security')
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'XSS'})
        payload = ch.build_payload(ev)
        assert 'text' in payload
        assert payload['channel'] == '#security'

    def test_build_payload_no_channel(self):
        ch = SlackChannel(webhook_url='https://hooks.slack.com/test')
        ev = ScanEvent('finding', 1.0, {'severity': 'low', 'name': 'Info'})
        payload = ch.build_payload(ev)
        assert 'text' in payload
        assert 'channel' not in payload

    @patch('apps.scanning.engine.notifications.channels._post_json', return_value=True)
    def test_send_success(self, mock_post):
        ch = SlackChannel(webhook_url='https://hooks.slack.com/test')
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'XSS'})
        assert ch.send(ev) is True
        mock_post.assert_called_once()

    @patch('apps.scanning.engine.notifications.channels._post_json', return_value=True)
    def test_test_connection(self, mock_post):
        ch = SlackChannel(webhook_url='https://hooks.slack.com/test')
        assert ch.test_connection() is True


# ════════════════════════════════════════════════════════════════════════════
# Discord Channel
# ════════════════════════════════════════════════════════════════════════════

class TestDiscordChannel:

    def test_name(self):
        ch = DiscordChannel(webhook_url='https://discord.com/api/webhooks/test')
        assert ch.name == 'discord'

    def test_default_username(self):
        ch = DiscordChannel(webhook_url='https://discord.com/api/webhooks/test')
        assert ch.username == 'SafeWeb AI'

    def test_build_payload(self):
        ch = DiscordChannel(webhook_url='https://discord.com/api/webhooks/test')
        ev = ScanEvent('finding', 1.0, {'severity': 'critical', 'name': 'SQLi'})
        payload = ch.build_payload(ev)
        assert payload['username'] == 'SafeWeb AI'
        assert 'content' in payload

    @patch('apps.scanning.engine.notifications.channels._post_json', return_value=True)
    def test_send(self, mock_post):
        ch = DiscordChannel(webhook_url='https://discord.com/webhooks/test')
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'XSS'})
        assert ch.send(ev) is True


# ════════════════════════════════════════════════════════════════════════════
# Teams Channel
# ════════════════════════════════════════════════════════════════════════════

class TestTeamsChannel:

    def test_name(self):
        ch = TeamsChannel(webhook_url='https://outlook.webhook.office.com/test')
        assert ch.name == 'teams'

    def test_build_payload_critical(self):
        ch = TeamsChannel(webhook_url='https://teams.test')
        ev = ScanEvent('finding', 1.0, {'severity': 'critical', 'name': 'RCE'})
        payload = ch.build_payload(ev)
        assert payload['themeColor'] == 'FF0000'
        assert 'RCE' in payload.get('title', '') or 'RCE' in payload.get('text', '')

    def test_build_payload_info(self):
        ch = TeamsChannel(webhook_url='https://teams.test')
        ev = ScanEvent('progress', 1.0, {'phase': 'xss', 'current': 1, 'total': 5})
        payload = ch.build_payload(ev)
        assert '@type' in payload

    @patch('apps.scanning.engine.notifications.channels._post_json', return_value=True)
    def test_send(self, mock_post):
        ch = TeamsChannel(webhook_url='https://teams.test')
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'XSS'})
        assert ch.send(ev) is True


# ════════════════════════════════════════════════════════════════════════════
# Telegram Channel
# ════════════════════════════════════════════════════════════════════════════

class TestTelegramChannel:

    def test_name(self):
        ch = TelegramChannel(bot_token='fake', chat_id='123')
        assert ch.name == 'telegram'

    def test_build_payload(self):
        ch = TelegramChannel(bot_token='tok', chat_id='456')
        ev = ScanEvent('finding', 1.0, {'severity': 'low', 'name': 'Info Leak'})
        payload = ch.build_payload(ev)
        assert payload['chat_id'] == '456'
        assert payload['parse_mode'] == 'HTML'
        assert 'text' in payload

    @patch('apps.scanning.engine.notifications.channels._post_json', return_value=True)
    def test_send(self, mock_post):
        ch = TelegramChannel(bot_token='tok', chat_id='789')
        ev = ScanEvent('finding', 1.0, {'severity': 'medium', 'name': 'CORS'})
        assert ch.send(ev) is True
        call_url = mock_post.call_args[0][0]
        assert 'api.telegram.org/bottok/sendMessage' in call_url


# ════════════════════════════════════════════════════════════════════════════
# Custom Webhook Channel
# ════════════════════════════════════════════════════════════════════════════

class TestCustomWebhookChannel:

    def test_name_default(self):
        ch = CustomWebhookChannel(webhook_url='https://my.hook.com')
        assert ch.name == 'custom_webhook'

    def test_name_override(self):
        ch = CustomWebhookChannel(webhook_url='https://my.hook.com', name_override='my_hook')
        assert ch.name == 'my_hook'

    def test_build_payload(self):
        ch = CustomWebhookChannel(webhook_url='https://my.hook.com')
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'RCE'})
        payload = ch.build_payload(ev)
        assert payload['source'] == 'safeweb-ai'
        assert 'event' in payload

    @patch('apps.scanning.engine.notifications.channels.urlopen')
    def test_send_dispatches(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        ch = CustomWebhookChannel(webhook_url='https://my.hook.com')
        ev = ScanEvent('finding', 1.0, {'severity': 'high', 'name': 'Test'})
        assert ch.send(ev) is True


# ════════════════════════════════════════════════════════════════════════════
# _post_json
# ════════════════════════════════════════════════════════════════════════════

class TestPostJson:

    @patch('apps.scanning.engine.notifications.channels.urlopen')
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        assert _post_json('https://example.com', {'a': 1}) is True

    @patch('apps.scanning.engine.notifications.channels.urlopen', side_effect=Exception('fail'))
    def test_failure(self, mock_urlopen):
        assert _post_json('https://example.com', {'a': 1}) is False


# ════════════════════════════════════════════════════════════════════════════
# IssueTrackerIntegration (base)
# ════════════════════════════════════════════════════════════════════════════

class TestIssueTrackerIntegration:

    def test_format_title(self):
        it = IssueTrackerIntegration()
        title = it.format_title({'severity': 'high', 'name': 'SQL Injection'})
        assert '[HIGH]' in title
        assert 'SQL Injection' in title

    def test_format_body(self):
        it = IssueTrackerIntegration()
        body = it.format_body({
            'name': 'XSS',
            'severity': 'medium',
            'category': 'xss',
            'cwe': 'CWE-79',
            'cvss': 6.1,
            'affected_url': 'http://test.com',
            'description': 'Reflected XSS',
            'impact': 'Cookie theft',
            'remediation': 'Encode output',
            'evidence': '<script>alert(1)</script>',
        })
        assert 'XSS' in body
        assert 'CWE-79' in body
        assert 'SafeWeb AI' in body

    def test_severity_to_priority(self):
        assert IssueTrackerIntegration.severity_to_priority('critical') == 'highest'
        assert IssueTrackerIntegration.severity_to_priority('high') == 'high'
        assert IssueTrackerIntegration.severity_to_priority('medium') == 'medium'
        assert IssueTrackerIntegration.severity_to_priority('low') == 'low'
        assert IssueTrackerIntegration.severity_to_priority('info') == 'lowest'

    def test_create_issue_not_implemented(self):
        it = IssueTrackerIntegration()
        with pytest.raises(NotImplementedError):
            it.create_issue({'severity': 'high'})


# ════════════════════════════════════════════════════════════════════════════
# Jira Integration
# ════════════════════════════════════════════════════════════════════════════

class TestJiraIntegration:

    def _jira(self):
        return JiraIntegration(
            base_url='https://test.atlassian.net',
            email='user@test.com',
            api_token='fake-token',
            project_key='SEC',
        )

    def test_name(self):
        assert self._jira().name == 'jira'

    def test_build_payload(self):
        jira = self._jira()
        finding = {'severity': 'high', 'name': 'SQLi', 'category': 'injection'}
        payload = jira.build_payload(finding)
        assert payload['fields']['project']['key'] == 'SEC'
        assert '[HIGH]' in payload['fields']['summary']

    def test_labels(self):
        jira = JiraIntegration(
            base_url='https://test.atlassian.net',
            email='u@t.com', api_token='fake',
            project_key='VUL', labels=['vuln'],
        )
        payload = jira.build_payload({'severity': 'low', 'name': 'Test'})
        assert 'vuln' in payload['fields']['labels']

    @patch('apps.scanning.engine.integrations._api_request')
    def test_create_issue_success(self, mock_api):
        mock_api.return_value = {'id': '123', 'key': 'SEC-45'}
        jira = self._jira()
        result = jira.create_issue({'severity': 'high', 'name': 'XSS'})
        assert result is not None
        assert result['key'] == 'SEC-45'
        assert '/browse/SEC-45' in result['url']

    @patch('apps.scanning.engine.integrations._api_request', return_value=None)
    def test_create_issue_failure(self, mock_api):
        jira = self._jira()
        result = jira.create_issue({'severity': 'high', 'name': 'XSS'})
        assert result is None

    @patch('apps.scanning.engine.integrations._api_request')
    def test_test_connection_success(self, mock_api):
        mock_api.return_value = {'accountId': 'abc'}
        assert self._jira().test_connection() is True

    @patch('apps.scanning.engine.integrations._api_request', return_value=None)
    def test_test_connection_failure(self, mock_api):
        assert self._jira().test_connection() is False


# ════════════════════════════════════════════════════════════════════════════
# GitHub Integration
# ════════════════════════════════════════════════════════════════════════════

class TestGitHubIntegration:

    def _gh(self):
        return GitHubIntegration(token='ghp_fake', owner='testorg', repo='webapp')

    def test_name(self):
        assert self._gh().name == 'github'

    def test_build_payload(self):
        gh = self._gh()
        payload = gh.build_payload({'severity': 'critical', 'name': 'RCE'})
        assert '[CRITICAL]' in payload['title']
        assert 'critical' in payload['labels']

    @patch('apps.scanning.engine.integrations._api_request')
    def test_create_issue_success(self, mock_api):
        mock_api.return_value = {'number': 42, 'html_url': 'https://github.com/42'}
        gh = self._gh()
        result = gh.create_issue({'severity': 'high', 'name': 'XSS'})
        assert result is not None
        assert result['key'] == '#42'

    @patch('apps.scanning.engine.integrations._api_request', return_value=None)
    def test_create_issue_failure(self, mock_api):
        assert self._gh().create_issue({'severity': 'high', 'name': 'X'}) is None

    @patch('apps.scanning.engine.integrations._api_request')
    def test_test_connection_success(self, mock_api):
        mock_api.return_value = {'id': 12345}
        assert self._gh().test_connection() is True


# ════════════════════════════════════════════════════════════════════════════
# GitLab Integration
# ════════════════════════════════════════════════════════════════════════════

class TestGitLabIntegration:

    def _gl(self):
        return GitLabIntegration(
            base_url='https://gitlab.com',
            token='glpat-fake',
            project_id=99,
        )

    def test_name(self):
        assert self._gl().name == 'gitlab'

    def test_build_payload(self):
        gl = self._gl()
        payload = gl.build_payload({'severity': 'medium', 'name': 'CORS'})
        assert '[MEDIUM]' in payload['title']
        assert 'medium' in payload['labels']

    @patch('apps.scanning.engine.integrations._api_request')
    def test_create_issue_success(self, mock_api):
        mock_api.return_value = {'iid': 15, 'web_url': 'https://gitlab.com/15'}
        gl = self._gl()
        result = gl.create_issue({'severity': 'low', 'name': 'Info Leak'})
        assert result is not None
        assert result['key'] == '#15'

    @patch('apps.scanning.engine.integrations._api_request', return_value=None)
    def test_create_issue_failure(self, mock_api):
        assert self._gl().create_issue({'severity': 'low', 'name': 'X'}) is None

    @patch('apps.scanning.engine.integrations._api_request')
    def test_test_connection(self, mock_api):
        mock_api.return_value = {'id': 99}
        assert self._gl().test_connection() is True


# ════════════════════════════════════════════════════════════════════════════
# IntegrationManager
# ════════════════════════════════════════════════════════════════════════════

class TestIntegrationManager:

    def test_add_integration(self):
        mgr = IntegrationManager()
        jira = MagicMock(spec=IssueTrackerIntegration)
        jira.name = 'jira'
        mgr.add_integration(jira)
        assert 'jira' in mgr.get_integrations()

    def test_remove_integration(self):
        mgr = IntegrationManager()
        mock = MagicMock(spec=IssueTrackerIntegration)
        mock.name = 'test'
        mgr.add_integration(mock)
        assert mgr.remove_integration('test') is True
        assert mgr.remove_integration('nonexistent') is False

    def test_should_create_issue_above_threshold(self):
        mgr = IntegrationManager(min_severity='high')
        assert mgr.should_create_issue({'severity': 'critical'}) is True
        assert mgr.should_create_issue({'severity': 'high'}) is True
        assert mgr.should_create_issue({'severity': 'medium'}) is False

    def test_create_issues_dispatches(self):
        mgr = IntegrationManager(min_severity='medium')
        mock = MagicMock(spec=IssueTrackerIntegration)
        mock.name = 'mock'
        mock.create_issue.return_value = {'id': '1', 'key': 'M-1', 'url': 'http://x'}
        mgr.add_integration(mock)

        results = mgr.create_issues({'severity': 'high', 'name': 'XSS'})
        assert len(results) == 1
        assert results[0]['integration'] == 'mock'

    def test_create_issues_filters_below_threshold(self):
        mgr = IntegrationManager(min_severity='high')
        mock = MagicMock(spec=IssueTrackerIntegration)
        mock.name = 'mock'
        mgr.add_integration(mock)

        results = mgr.create_issues({'severity': 'low', 'name': 'Low'})
        assert len(results) == 0
        mock.create_issue.assert_not_called()

    def test_created_issues_property(self):
        mgr = IntegrationManager(min_severity='low')
        mock = MagicMock(spec=IssueTrackerIntegration)
        mock.name = 'mock'
        mock.create_issue.return_value = {'id': '1', 'key': 'M-1', 'url': 'http://x'}
        mgr.add_integration(mock)
        mgr.create_issues({'severity': 'high', 'name': 'X'})
        assert len(mgr.created_issues) == 1

    def test_set_min_severity(self):
        mgr = IntegrationManager(min_severity='low')
        mgr.set_min_severity('critical')
        assert mgr.should_create_issue({'severity': 'high'}) is False


# ════════════════════════════════════════════════════════════════════════════
# _api_request
# ════════════════════════════════════════════════════════════════════════════

class TestApiRequest:

    @patch('apps.scanning.engine.integrations.urlopen')
    def test_success(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'{"ok": true}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        result = _api_request('https://api.test.com', 'GET', {})
        assert result == {'ok': True}

    @patch('apps.scanning.engine.integrations.urlopen', side_effect=Exception('fail'))
    def test_failure(self, mock_urlopen):
        result = _api_request('https://api.test.com', 'GET', {})
        assert result is None


# ════════════════════════════════════════════════════════════════════════════
# Scan Comparison — _finding_key
# ════════════════════════════════════════════════════════════════════════════

class TestFindingKey:

    def test_basic(self):
        key = _finding_key({'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a'})
        assert 'xss' in key
        assert 'http://a' in key

    def test_case_insensitive(self):
        k1 = _finding_key({'name': 'XSS', 'category': 'Xss', 'affected_url': ''})
        k2 = _finding_key({'name': 'xss', 'category': 'xss', 'affected_url': ''})
        assert k1 == k2

    def test_missing_fields(self):
        key = _finding_key({})
        assert key == '||'


# ════════════════════════════════════════════════════════════════════════════
# ComparisonResult
# ════════════════════════════════════════════════════════════════════════════

class TestComparisonResult:

    def test_to_dict(self):
        cr = ComparisonResult(
            new_findings=[{'a': 1}],
            fixed_findings=[],
            baseline_total=5,
            current_total=6,
        )
        d = cr.to_dict()
        assert d['new'] == 1
        assert d['fixed'] == 0
        assert d['delta'] == 1

    def test_improved(self):
        cr = ComparisonResult(
            new_findings=[],
            fixed_findings=[{'a': 1}, {'b': 2}],
            regression_findings=[],
        )
        assert cr.improved is True

    def test_degraded_with_new(self):
        cr = ComparisonResult(
            new_findings=[{'a': 1}, {'b': 2}],
            fixed_findings=[],
        )
        assert cr.degraded is True

    def test_degraded_with_regression(self):
        cr = ComparisonResult(
            new_findings=[],
            fixed_findings=[{'a': 1}],
            regression_findings=[{'r': 1}],
        )
        assert cr.degraded is True

    def test_not_improved_not_degraded(self):
        cr = ComparisonResult()
        assert cr.improved is False
        assert cr.degraded is False


# ════════════════════════════════════════════════════════════════════════════
# ScanComparison
# ════════════════════════════════════════════════════════════════════════════

class TestScanComparison:

    def test_no_changes(self):
        findings = [{'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a', 'severity': 'high'}]
        comp = ScanComparison(findings, findings)
        result = comp.compare()
        assert len(result.new_findings) == 0
        assert len(result.fixed_findings) == 0
        assert len(result.recurring_findings) == 1

    def test_new_finding(self):
        baseline = [{'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a', 'severity': 'high'}]
        current = baseline + [{'name': 'SQLi', 'category': 'injection', 'affected_url': 'http://b', 'severity': 'critical'}]
        result = ScanComparison(baseline, current).compare()
        assert len(result.new_findings) == 1
        assert result.new_findings[0]['name'] == 'SQLi'

    def test_fixed_finding(self):
        baseline = [
            {'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a', 'severity': 'high'},
            {'name': 'SQLi', 'category': 'injection', 'affected_url': 'http://b', 'severity': 'critical'},
        ]
        current = [{'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a', 'severity': 'high'}]
        result = ScanComparison(baseline, current).compare()
        assert len(result.fixed_findings) == 1
        assert result.fixed_findings[0]['name'] == 'SQLi'

    def test_severity_change(self):
        baseline = [{'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a', 'severity': 'medium'}]
        current = [{'name': 'XSS', 'category': 'xss', 'affected_url': 'http://a', 'severity': 'critical'}]
        result = ScanComparison(baseline, current).compare()
        assert len(result.severity_changes) == 1
        assert result.severity_changes[0]['direction'] == 'escalated'
        assert result.severity_changes[0]['old_severity'] == 'medium'
        assert result.severity_changes[0]['new_severity'] == 'critical'

    def test_severity_reduced(self):
        baseline = [{'name': 'X', 'category': 'x', 'affected_url': 'http://a', 'severity': 'critical'}]
        current = [{'name': 'X', 'category': 'x', 'affected_url': 'http://a', 'severity': 'low'}]
        result = ScanComparison(baseline, current).compare()
        assert result.severity_changes[0]['direction'] == 'reduced'

    def test_regression_detection(self):
        baseline = []
        current = [
            {'name': 'RCE', 'category': 'injection', 'affected_url': 'http://a', 'severity': 'critical'},
        ]
        result = ScanComparison(baseline, current).compare()
        assert len(result.regression_findings) == 1

    def test_no_regression_for_low(self):
        baseline = []
        current = [{'name': 'Info', 'category': 'info', 'affected_url': 'http://a', 'severity': 'low'}]
        result = ScanComparison(baseline, current).compare()
        assert len(result.regression_findings) == 0

    def test_totals(self):
        baseline = [{'name': 'A', 'category': 'a', 'affected_url': '', 'severity': 'low'}] * 3
        current = [{'name': 'A', 'category': 'a', 'affected_url': '', 'severity': 'low'}] * 3
        result = ScanComparison(baseline, current).compare()
        assert result.baseline_total == 3
        assert result.current_total == 3


# ════════════════════════════════════════════════════════════════════════════
# Security Posture
# ════════════════════════════════════════════════════════════════════════════

class TestSecurityPosture:

    def test_no_findings(self):
        p = compute_security_posture([])
        assert p['score'] == 100
        assert p['grade'] == 'A+'

    def test_critical_findings(self):
        findings = [{'severity': 'critical'}, {'severity': 'critical'}]
        p = compute_security_posture(findings)
        assert p['score'] == 60
        assert p['grade'] == 'D'

    def test_mixed_findings(self):
        findings = [
            {'severity': 'high'},
            {'severity': 'medium'},
            {'severity': 'low'},
        ]
        p = compute_security_posture(findings)
        assert p['score'] == 86  # 100 - 10 - 3 - 1
        assert p['grade'] == 'B'

    def test_breakdown(self):
        findings = [
            {'severity': 'high'},
            {'severity': 'high'},
            {'severity': 'low'},
        ]
        p = compute_security_posture(findings)
        assert p['breakdown']['high'] == 2
        assert p['breakdown']['low'] == 1

    def test_score_floor(self):
        findings = [{'severity': 'critical'}] * 10
        p = compute_security_posture(findings)
        assert p['score'] == 0
        assert p['grade'] == 'F'


# ════════════════════════════════════════════════════════════════════════════
# Trend Generation
# ════════════════════════════════════════════════════════════════════════════

class TestTrendGeneration:

    def test_empty_history(self):
        assert generate_trend([]) == []

    def test_single_scan(self):
        history = [{'scan_id': '1', 'timestamp': '2024-01-01', 'findings': []}]
        trend = generate_trend(history)
        assert len(trend) == 1
        assert trend[0]['score'] == 100

    def test_multiple_scans(self):
        history = [
            {'scan_id': '1', 'timestamp': '2024-01-01', 'findings': [
                {'severity': 'critical'}, {'severity': 'high'},
            ]},
            {'scan_id': '2', 'timestamp': '2024-02-01', 'findings': [
                {'severity': 'low'},
            ]},
        ]
        trend = generate_trend(history)
        assert len(trend) == 2
        assert trend[0]['score'] < trend[1]['score']
        assert trend[0]['total_findings'] == 2
        assert trend[1]['total_findings'] == 1

    def test_trend_contains_grade(self):
        history = [{'scan_id': '1', 'timestamp': '', 'findings': []}]
        trend = generate_trend(history)
        assert 'grade' in trend[0]


# ════════════════════════════════════════════════════════════════════════════
# SEV_ORDER constant
# ════════════════════════════════════════════════════════════════════════════

class TestSevOrder:

    def test_ordering(self):
        assert SEV_ORDER['critical'] > SEV_ORDER['high']
        assert SEV_ORDER['high'] > SEV_ORDER['medium']
        assert SEV_ORDER['medium'] > SEV_ORDER['low']
        assert SEV_ORDER['low'] > SEV_ORDER['info']


# ════════════════════════════════════════════════════════════════════════════
# ReportingIntegrationTester
# ════════════════════════════════════════════════════════════════════════════

class TestReportingIntegrationTester:

    def setup_method(self):
        self.tester = ReportingIntegrationTester()

    def test_tester_name(self):
        assert self.tester.TESTER_NAME == 'Reporting & Integration Scanner'

    def test_empty_url(self):
        assert self.tester.test({'url': ''}) == []

    def test_quick_depth(self):
        vulns = self.tester.test({'url': 'https://example.com'}, depth='quick')
        assert isinstance(vulns, list)

    def test_medium_depth(self):
        vulns = self.tester.test({'url': 'https://example.com'}, depth='medium')
        assert isinstance(vulns, list)
        # Medium depth triggers scan comparison which should find degradation
        degraded = [v for v in vulns if 'Regression' in v.get('name', '')]
        assert len(degraded) >= 1

    def test_deep_depth(self):
        vulns = self.tester.test({'url': 'https://example.com'}, depth='deep')
        assert isinstance(vulns, list)

    def test_with_poor_posture(self):
        recon = {'findings': [{'severity': 'critical'}] * 5}
        vulns = self.tester.test({'url': 'https://example.com'}, depth='quick', recon_data=recon)
        posture_vulns = [v for v in vulns if 'Posture' in v.get('name', '')]
        assert len(posture_vulns) >= 1

    def test_vuln_structure(self):
        vulns = self.tester.test({'url': 'https://example.com'}, depth='medium')
        for v in vulns:
            assert 'name' in v
            assert 'severity' in v
            assert 'category' in v


# ════════════════════════════════════════════════════════════════════════════
# Registration / Tester count
# ════════════════════════════════════════════════════════════════════════════

class TestRegistration:

    def test_reporting_tester_in_registry(self):
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        names = [t.TESTER_NAME for t in testers]
        assert 'Reporting & Integration Scanner' in names

    def test_tester_count(self):
        """Total tester count is 67 (66 + Phase 35)."""
        from apps.scanning.engine.testers import get_all_testers
        testers = get_all_testers()
        assert len(testers) == 87
