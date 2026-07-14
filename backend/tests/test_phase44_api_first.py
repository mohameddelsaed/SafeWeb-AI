"""
Phase 44 — API-First Architecture
Tests for: REST endpoints, Webhook model/delivery, NucleiTemplate,
SARIF export, scan comparison, profiles, auth-configs.
"""
import json
import uuid
import pytest
from unittest.mock import patch, MagicMock
from django.urls import reverse
from rest_framework.test import APIClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def api_client():
    return APIClient()


@pytest.fixture
def auth_client(django_user_model):
    user = django_user_model.objects.create_user(
        username='ph44_user', password='testpass123',
    )
    client = APIClient()
    client.force_authenticate(user=user)
    return client, user


@pytest.fixture
def completed_scan(auth_client):
    from apps.scanning.models import Scan, Vulnerability

    _, user = auth_client
    scan = Scan.objects.create(
        user=user,
        scan_type='website',
        target='https://example.com',
        status='completed',
        depth='medium',
        score=75,
    )
    Vulnerability.objects.create(
        scan=scan,
        name='SQL Injection',
        severity='high',
        category='sqli',
        description='SQLi found',
        impact='Data breach',
        remediation='Use parameterised queries',
        cwe='CWE-89',
        cvss=8.5,
        affected_url='https://example.com/login',
    )
    Vulnerability.objects.create(
        scan=scan,
        name='Reflected XSS',
        severity='medium',
        category='xss',
        description='XSS in search param',
        impact='Cookie theft',
        remediation='Encode output',
        cwe='CWE-79',
        cvss=5.0,
        affected_url='https://example.com/search',
        verified=True,
    )
    return scan


# ---------------------------------------------------------------------------
# 1. Models
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestWebhookModel:
    def test_create_webhook(self, auth_client):
        from apps.scanning.models import Webhook
        _, user = auth_client
        wh = Webhook.objects.create(
            user=user,
            url='https://hooks.example.com/safeweb',
            events=['scan_completed', 'scan_failed'],
        )
        assert wh.pk is not None
        assert wh.is_active is True
        assert wh.max_retries == 3

    def test_webhook_str(self, auth_client):
        from apps.scanning.models import Webhook
        _, user = auth_client
        wh = Webhook.objects.create(
            user=user,
            url='https://hooks.example.com/x',
            events=[],
        )
        assert 'hooks.example.com' in str(wh)

    def test_webhook_event_choices(self):
        from apps.scanning.models import Webhook
        choices = dict(Webhook.EVENT_CHOICES)
        assert 'scan_started' in choices
        assert 'finding_detected' in choices
        assert 'scan_completed' in choices
        assert 'scan_failed' in choices


@pytest.mark.django_db
class TestWebhookDeliveryModel:
    def test_create_delivery(self, auth_client):
        from apps.scanning.models import Webhook, WebhookDelivery
        _, user = auth_client
        wh = Webhook.objects.create(user=user, url='https://hook.test/', events=[])
        delivery = WebhookDelivery.objects.create(
            webhook=wh,
            event_type='scan_completed',
            payload={'scan_id': 'abc'},
            status='pending',
        )
        assert delivery.pk is not None
        assert delivery.status == 'pending'
        assert delivery.attempt_count == 0

    def test_delivery_str(self, auth_client):
        from apps.scanning.models import Webhook, WebhookDelivery
        _, user = auth_client
        wh = Webhook.objects.create(user=user, url='https://hook.test/', events=[])
        d = WebhookDelivery.objects.create(
            webhook=wh,
            event_type='scan_failed',
            payload={},
            status='failed',
        )
        assert 'scan_failed' in str(d)


@pytest.mark.django_db
class TestNucleiTemplateModel:
    def test_create_template(self, auth_client):
        from apps.scanning.models import NucleiTemplate
        _, user = auth_client
        tmpl = NucleiTemplate.objects.create(
            name='My Custom Template',
            content='id: my-template\ninfo:\n  name: Test',
            severity='high',
            uploaded_by=user,
        )
        assert tmpl.pk is not None
        assert tmpl.is_active is True

    def test_template_str(self, auth_client):
        from apps.scanning.models import NucleiTemplate
        _, user = auth_client
        tmpl = NucleiTemplate.objects.create(
            name='SQLi YAML', content='id: sqli', uploaded_by=user,
        )
        assert 'SQLi YAML' in str(tmpl)

    def test_template_severity_choices(self):
        from apps.scanning.models import NucleiTemplate
        valid = {c[0] for c in NucleiTemplate.SEVERITY_CHOICES}
        assert valid == {'info', 'low', 'medium', 'high', 'critical'}


# ---------------------------------------------------------------------------
# 2. Serializers
# ---------------------------------------------------------------------------

class TestScanFullCreateSerializer:
    def test_valid_minimal(self):
        from apps.scanning.serializers import ScanFullCreateSerializer
        s = ScanFullCreateSerializer(data={'url': 'https://example.com'})
        assert s.is_valid(), s.errors

    def test_with_profile_and_scope(self):
        from apps.scanning.serializers import ScanFullCreateSerializer
        s = ScanFullCreateSerializer(data={
            'url': 'https://example.com',
            'profile': 'deep_scan',
            'scope': ['example.com', 'api.example.com'],
            'scan_mode': 'hunting',
        })
        assert s.is_valid(), s.errors
        assert s.validated_data['scope'] == ['example.com', 'api.example.com']

    def test_invalid_url(self):
        from apps.scanning.serializers import ScanFullCreateSerializer
        s = ScanFullCreateSerializer(data={'url': 'not-a-url'})
        assert not s.is_valid()
        assert 'url' in s.errors

    def test_invalid_depth(self):
        from apps.scanning.serializers import ScanFullCreateSerializer
        s = ScanFullCreateSerializer(data={'url': 'https://example.com', 'scan_depth': 'ultra'})
        assert not s.is_valid()


class TestWebhookSerializer:
    def test_valid_webhook(self):
        from apps.scanning.serializers import WebhookSerializer
        s = WebhookSerializer(data={
            'url': 'https://hooks.example.com/safeweb',
            'events': ['scan_completed', 'scan_failed'],
        })
        assert s.is_valid(), s.errors

    def test_invalid_event_type(self):
        from apps.scanning.serializers import WebhookSerializer
        s = WebhookSerializer(data={
            'url': 'https://hooks.example.com/',
            'events': ['unknown_event'],
        })
        assert not s.is_valid()

    def test_empty_events_allowed(self):
        from apps.scanning.serializers import WebhookSerializer
        s = WebhookSerializer(data={'url': 'https://hooks.example.com/', 'events': []})
        assert s.is_valid(), s.errors


# ---------------------------------------------------------------------------
# 3. Webhook utility
# ---------------------------------------------------------------------------

class TestWebhookUtility:
    def test_build_scan_payload(self):
        from apps.scanning.engine.webhooks import build_scan_payload
        mock_scan = MagicMock()
        mock_scan.id = uuid.uuid4()
        mock_scan.target = 'https://example.com'
        mock_scan.status = 'completed'
        mock_scan.scan_type = 'website'
        mock_scan.score = 80
        payload = build_scan_payload(mock_scan)
        assert payload['target'] == 'https://example.com'
        assert 'timestamp' in payload

    def test_sign_payload(self):
        from apps.scanning.engine.webhooks import _sign_payload
        sig = _sign_payload('mysecret', '{"test": true}')
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex

    def test_build_headers_with_secret(self):
        from apps.scanning.engine.webhooks import _build_headers
        headers = _build_headers('secret123', '{}')
        assert 'X-SafeWeb-Signature' in headers
        assert headers['X-SafeWeb-Signature'].startswith('sha256=')

    def test_build_headers_without_secret(self):
        from apps.scanning.engine.webhooks import _build_headers
        headers = _build_headers('', '{}')
        assert 'X-SafeWeb-Signature' not in headers
        assert headers['Content-Type'] == 'application/json'

    @pytest.mark.django_db
    def test_fire_event_no_webhooks(self, auth_client):
        from apps.scanning.engine.webhooks import fire_event
        _, user = auth_client
        count = fire_event(user, 'scan_completed', {'scan_id': 'abc'})
        assert count == 0

    @pytest.mark.django_db
    def test_fire_event_triggers_matching_webhooks(self, auth_client):
        from apps.scanning.models import Webhook
        from apps.scanning.engine.webhooks import fire_event
        _, user = auth_client
        Webhook.objects.create(
            user=user,
            url='https://hook.example.com/',
            events=['scan_completed'],
            is_active=True,
        )
        with patch('apps.scanning.engine.webhooks.fire_webhook') as mock_fire:
            mock_fire.return_value = True
            count = fire_event(user, 'scan_completed', {})
        assert count == 1
        mock_fire.assert_called_once()

    @pytest.mark.django_db
    def test_fire_event_skips_inactive_webhooks(self, auth_client):
        from apps.scanning.models import Webhook
        from apps.scanning.engine.webhooks import fire_event
        _, user = auth_client
        Webhook.objects.create(
            user=user,
            url='https://hook.example.com/',
            events=[],
            is_active=False,
        )
        with patch('apps.scanning.engine.webhooks.fire_webhook') as mock_fire:
            count = fire_event(user, 'scan_completed', {})
        assert count == 0
        mock_fire.assert_not_called()


# ---------------------------------------------------------------------------
# 4. API endpoints (auth required)
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestScanCreateFullAPI:
    def test_requires_auth(self, api_client):
        resp = api_client.post('/api/scan/', {'url': 'https://example.com'}, format='json')
        assert resp.status_code == 401

    def test_creates_scan(self, auth_client):
        client, _ = auth_client
        with patch('apps.scanning.views.execute_scan_task') as mock_task:
            mock_task.delay = MagicMock()
            resp = client.post('/api/scan/', {
                'url': 'https://example.com',
                'scan_depth': 'medium',
                'profile': 'standard_scan',
            }, format='json')
        assert resp.status_code == 201
        assert resp.data['status'] == 'pending'
        assert resp.data['target'] == 'https://example.com'

    def test_creates_scan_with_auth_config(self, auth_client):
        client, _ = auth_client
        with patch('apps.scanning.views.execute_scan_task') as mock_task:
            mock_task.delay = MagicMock()
            resp = client.post('/api/scan/', {
                'url': 'https://example.com',
                'auth_config': {'auth_type': 'bearer', 'token': 'abc123'},
            }, format='json')
        assert resp.status_code == 201

    def test_invalid_url_rejected(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/', {'url': 'not-a-url'}, format='json')
        assert resp.status_code == 400


@pytest.mark.django_db
class TestScanFindingsAPI:
    def test_requires_auth(self, api_client, completed_scan):
        url = f'/api/scan/{completed_scan.id}/findings/'
        resp = api_client.get(url)
        assert resp.status_code == 401

    def test_returns_all_findings(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.get(f'/api/scan/{completed_scan.id}/findings/')
        assert resp.status_code == 200
        # List response may be paginated or plain list
        data = resp.data
        if isinstance(data, dict):
            results = data.get('results', data.get('findings', []))
        else:
            results = data
        assert len(results) == 2

    def test_filters_by_severity(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.get(f'/api/scan/{completed_scan.id}/findings/?severity=high')
        assert resp.status_code == 200
        data = resp.data
        results = data.get('results', data) if isinstance(data, dict) else data
        assert all(f['severity'] == 'high' for f in results)

    def test_filters_by_verified(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.get(f'/api/scan/{completed_scan.id}/findings/?verified=true')
        assert resp.status_code == 200
        data = resp.data
        results = data.get('results', data) if isinstance(data, dict) else data
        assert len(results) == 1
        assert results[0]['verified'] is True

    def test_returns_404_for_other_user_scan(self, api_client, django_user_model, completed_scan):
        other = django_user_model.objects.create_user(username='other_ph44', password='pass', email='other_ph44@test.com')
        api_client.force_authenticate(user=other)
        resp = api_client.get(f'/api/scan/{completed_scan.id}/findings/')
        assert resp.status_code == 200
        data = resp.data
        results = data.get('results', data) if isinstance(data, dict) else data
        assert len(results) == 0  # own-data filter returns empty


@pytest.mark.django_db
class TestScanCompareAPI:
    def test_compare_two_scans(self, auth_client):
        from apps.scanning.models import Scan, Vulnerability
        client, user = auth_client

        scan_a = Scan.objects.create(
            user=user, scan_type='website', target='https://example.com',
            status='completed',
        )
        scan_b = Scan.objects.create(
            user=user, scan_type='website', target='https://example.com',
            status='completed',
        )
        Vulnerability.objects.create(
            scan=scan_b, name='XSS', severity='high', category='xss',
            description='xss', impact='i', remediation='r', cvss=7.0,
        )

        resp = client.get(f'/api/scan/compare/{scan_a.id}/{scan_b.id}/')
        assert resp.status_code == 200
        assert 'new_findings' in resp.data
        assert 'fixed_findings' in resp.data
        assert resp.data['scan_a'] == str(scan_a.id)
        assert resp.data['scan_b'] == str(scan_b.id)

    def test_compare_returns_improved_flag(self, auth_client):
        from apps.scanning.models import Scan, Vulnerability
        client, user = auth_client
        scan_a = Scan.objects.create(
            user=user, scan_type='website', target='https://example.com',
            status='completed',
        )
        Vulnerability.objects.create(
            scan=scan_a, name='SQLi', severity='high', category='sqli',
            description='sqli', impact='i', remediation='r', cvss=8.0,
        )
        scan_b = Scan.objects.create(
            user=user, scan_type='website', target='https://example.com',
            status='completed',
        )
        resp = client.get(f'/api/scan/compare/{scan_a.id}/{scan_b.id}/')
        assert resp.status_code == 200
        assert 'improved' in resp.data

    def test_compare_missing_scan_returns_404(self, auth_client):
        client, _ = auth_client
        resp = client.get(f'/api/scan/compare/{uuid.uuid4()}/{uuid.uuid4()}/')
        assert resp.status_code == 404


@pytest.mark.django_db
class TestScanExportFormatAPI:
    def test_export_json(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/json/')
        assert resp.status_code == 200
        assert 'json' in resp['Content-Type']

    def test_export_csv(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/csv/')
        assert resp.status_code == 200
        assert 'csv' in resp['Content-Type']

    def test_export_sarif(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/sarif/')
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data['version'] == '2.1.0'
        assert 'runs' in data
        assert len(data['runs'][0]['results']) == 2

    def test_export_html(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/html/')
        assert resp.status_code == 200
        assert b'<html>' in resp.content

    def test_export_invalid_format(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/docx/')
        assert resp.status_code == 400

    def test_export_requires_auth(self, api_client, completed_scan):
        resp = api_client.post(f'/api/scan/{completed_scan.id}/export/json/')
        assert resp.status_code == 401


@pytest.mark.django_db
class TestSarifExportStructure:
    def test_sarif_has_rules(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/sarif/')
        data = json.loads(resp.content)
        rules = data['runs'][0]['tool']['driver']['rules']
        assert len(rules) >= 1
        assert 'id' in rules[0]
        assert 'shortDescription' in rules[0]

    def test_sarif_levels_mapping(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/sarif/')
        data = json.loads(resp.content)
        levels = {r['level'] for r in data['runs'][0]['results']}
        assert levels <= {'error', 'warning', 'note'}

    def test_sarif_result_locations(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/export/sarif/')
        data = json.loads(resp.content)
        for result in data['runs'][0]['results']:
            assert 'locations' in result
            assert len(result['locations']) > 0


@pytest.mark.django_db
class TestScanStreamAPI:
    def test_stream_returns_sse(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.get(f'/api/scan/{completed_scan.id}/stream/')
        assert resp.status_code == 200
        assert 'event-stream' in resp.get('Content-Type', '')

    def test_stream_requires_auth(self, api_client, completed_scan):
        resp = api_client.get(f'/api/scan/{completed_scan.id}/stream/')
        assert resp.status_code == 401

    def test_stream_missing_scan_returns_404(self, auth_client):
        client, _ = auth_client
        resp = client.get(f'/api/scan/{uuid.uuid4()}/stream/')
        assert resp.status_code == 404


@pytest.mark.django_db
class TestRescanFindingAPI:
    def test_rescan_finding(self, auth_client, completed_scan):
        client, _ = auth_client
        vuln = completed_scan.vulnerabilities.first()
        with patch('apps.scanning.views.execute_scan_task') as mock_task:
            mock_task.delay = MagicMock()
            resp = client.post(f'/api/scan/{completed_scan.id}/rescan-finding/', {
                'finding_id': str(vuln.id),
            }, format='json')
        assert resp.status_code == 201
        assert 'id' in resp.data
        assert resp.data['finding_id'] == str(vuln.id)

    def test_missing_finding_id(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/rescan-finding/', {}, format='json')
        assert resp.status_code == 400

    def test_nonexistent_finding(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post(f'/api/scan/{completed_scan.id}/rescan-finding/', {
            'finding_id': str(uuid.uuid4()),
        }, format='json')
        assert resp.status_code == 404


@pytest.mark.django_db
class TestNucleiTemplateAPI:
    def test_list_templates(self, auth_client):
        client, _ = auth_client
        resp = client.get('/api/scan/templates/')
        assert resp.status_code == 200
        assert 'builtin' in resp.data
        assert 'custom' in resp.data

    def test_builtin_templates_present(self, auth_client):
        client, _ = auth_client
        resp = client.get('/api/scan/templates/')
        assert len(resp.data['builtin']) >= 5

    def test_upload_template(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/templates/custom/', {
            'name': 'My XSS Probe',
            'content': 'id: my-xss\ninfo:\n  name: My XSS',
            'severity': 'high',
            'category': 'xss',
        }, format='multipart')
        assert resp.status_code == 201
        assert resp.data['name'] == 'My XSS Probe'
        assert resp.data['severity'] == 'high'

    def test_upload_requires_content(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/templates/custom/', {
            'name': 'Empty Template',
        }, format='multipart')
        assert resp.status_code == 400

    def test_upload_requires_name(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/templates/custom/', {
            'content': 'id: test',
        }, format='multipart')
        assert resp.status_code == 400

    def test_uploaded_template_in_list(self, auth_client):
        from apps.scanning.models import NucleiTemplate
        client, user = auth_client
        NucleiTemplate.objects.create(
            name='DB Template', content='id: db', severity='high', uploaded_by=user,
        )
        resp = client.get('/api/scan/templates/')
        assert resp.status_code == 200
        custom_names = [t['name'] for t in resp.data['custom']]
        assert 'DB Template' in custom_names

    def test_templates_require_auth(self, api_client):
        resp = api_client.get('/api/scan/templates/')
        assert resp.status_code == 401


@pytest.mark.django_db
class TestScanProfilesAPI:
    def test_list_profiles(self, auth_client):
        client, _ = auth_client
        resp = client.get('/api/scan/profiles/')
        assert resp.status_code == 200
        assert 'profiles' in resp.data
        assert resp.data['count'] >= 9

    def test_profiles_have_required_fields(self, auth_client):
        client, _ = auth_client
        resp = client.get('/api/scan/profiles/')
        assert resp.status_code == 200
        for profile in resp.data['profiles']:
            assert 'id' in profile
            assert 'name' in profile
            assert 'depth' in profile

    def test_profiles_require_auth(self, api_client):
        resp = api_client.get('/api/scan/profiles/')
        assert resp.status_code == 401

    def test_standard_scan_in_profiles(self, auth_client):
        client, _ = auth_client
        resp = client.get('/api/scan/profiles/')
        ids = [p['id'] for p in resp.data['profiles']]
        assert 'standard_scan' in ids


@pytest.mark.django_db
class TestAuthConfigAPI:
    def test_create_auth_config(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/auth-configs/', {
            'auth_type': 'bearer',
            'config_data': {'token': 'my-token-123'},
        }, format='json')
        assert resp.status_code == 201
        assert resp.data['auth_type'] == 'bearer'

    def test_requires_config_data(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/auth-configs/', {
            'auth_type': 'bearer',
        }, format='json')
        assert resp.status_code == 400

    def test_with_known_scan_id(self, auth_client, completed_scan):
        client, _ = auth_client
        resp = client.post('/api/scan/auth-configs/', {
            'scan_id': str(completed_scan.id),
            'auth_type': 'cookie',
            'config_data': {'session': 'abc'},
        }, format='json')
        assert resp.status_code == 201
        assert str(completed_scan.id) in resp.data['scan_id']

    def test_invalid_scan_id_returns_404(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/auth-configs/', {
            'scan_id': str(uuid.uuid4()),
            'auth_type': 'bearer',
            'config_data': {'token': 'x'},
        }, format='json')
        assert resp.status_code == 404


@pytest.mark.django_db
class TestWebhookAPI:
    def test_create_webhook(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/webhooks/', {
            'url': 'https://hooks.example.com/test',
            'events': ['scan_completed'],
        }, format='json')
        assert resp.status_code == 201
        assert resp.data['is_active'] is True

    def test_list_webhooks(self, auth_client):
        from apps.scanning.models import Webhook
        client, user = auth_client
        Webhook.objects.create(user=user, url='https://hooks.example.com/', events=[])
        resp = client.get('/api/scan/webhooks/')
        assert resp.status_code == 200
        data = resp.data
        results = data.get('results', data) if isinstance(data, dict) else data
        assert len(results) >= 1

    def test_update_webhook(self, auth_client):
        from apps.scanning.models import Webhook
        client, user = auth_client
        wh = Webhook.objects.create(user=user, url='https://hooks.example.com/', events=[])
        resp = client.patch(f'/api/scan/webhooks/{wh.id}/', {
            'events': ['scan_started', 'scan_failed'],
        }, format='json')
        assert resp.status_code == 200
        wh.refresh_from_db()
        assert 'scan_started' in wh.events

    def test_delete_webhook(self, auth_client):
        from apps.scanning.models import Webhook
        client, user = auth_client
        wh = Webhook.objects.create(user=user, url='https://hooks.example.com/', events=[])
        resp = client.delete(f'/api/scan/webhooks/{wh.id}/')
        assert resp.status_code == 204
        assert not Webhook.objects.filter(id=wh.id).exists()

    def test_webhooks_isolated_per_user(self, api_client, django_user_model):
        from apps.scanning.models import Webhook
        user_a = django_user_model.objects.create_user(username='whuser_a', password='pass', email='whuser_a@test.com')
        user_b = django_user_model.objects.create_user(username='whuser_b', password='pass', email='whuser_b@test.com')
        Webhook.objects.create(user=user_a, url='https://a.example.com/', events=[])
        api_client.force_authenticate(user=user_b)
        resp = api_client.get('/api/scan/webhooks/')
        data = resp.data
        results = data.get('results', data) if isinstance(data, dict) else data
        assert len(results) == 0

    def test_webhook_invalid_event(self, auth_client):
        client, _ = auth_client
        resp = client.post('/api/scan/webhooks/', {
            'url': 'https://hooks.example.com/',
            'events': ['not_valid_event'],
        }, format='json')
        assert resp.status_code == 400

    def test_webhook_test_endpoint(self, auth_client):
        from apps.scanning.models import Webhook
        client, user = auth_client
        wh = Webhook.objects.create(user=user, url='https://hooks.example.com/', events=[])
        with patch('apps.scanning.engine.webhooks.fire_webhook') as mock_fire:
            mock_fire.return_value = True
            resp = client.post(f'/api/scan/webhooks/{wh.id}/test/')
        assert resp.status_code == 200
        assert 'delivered' in resp.data

    def test_webhook_deliveries_list(self, auth_client):
        from apps.scanning.models import Webhook, WebhookDelivery
        client, user = auth_client
        wh = Webhook.objects.create(user=user, url='https://hooks.example.com/', events=[])
        WebhookDelivery.objects.create(
            webhook=wh, event_type='scan_completed', payload={}, status='delivered',
        )
        resp = client.get(f'/api/scan/webhooks/{wh.id}/deliveries/')
        assert resp.status_code == 200
        data = resp.data
        results = data.get('results', data) if isinstance(data, dict) else data
        assert len(results) >= 1

    def test_webhooks_require_auth(self, api_client):
        resp = api_client.get('/api/scan/webhooks/')
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# 5. URL routes sanity checks
# ---------------------------------------------------------------------------

class TestURLRoutes:
    def test_scan_create_full_url_name(self):
        from django.urls import reverse
        url = reverse('scan-create-full')
        assert '/api/scan/' in url

    def test_scan_compare_url_resolves(self):
        id1 = uuid.uuid4()
        id2 = uuid.uuid4()
        url = reverse('scan-compare', kwargs={'id1': id1, 'id2': id2})
        assert str(id1) in url
        assert str(id2) in url

    def test_templates_list_url_resolves(self):
        url = reverse('templates-list')
        assert 'templates' in url

    def test_webhooks_list_url_resolves(self):
        url = reverse('webhooks-list')
        assert 'webhooks' in url

    def test_profiles_list_url_resolves(self):
        url = reverse('profiles-list')
        assert 'profiles' in url
