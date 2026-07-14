"""
Phase 45 Tests — Multi-Target & Scope Management
=================================================
Tests for:
  - ScopeManager (engine logic)
  - TargetImporter (engine logic)
  - ScopeDefinition / MultiTargetScan / DiscoveredAsset models
  - REST API: /api/scan/scopes/*, /api/scan/multi/*, /api/scan/assets/*
"""
import pytest
from unittest.mock import patch
from rest_framework.test import APIClient

from apps.scanning.engine.scope.scope_manager import ScopeManager
from apps.scanning.engine.scope.target_importer import TargetImporter


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_user(django_user_model, username='scopeuser', email='scope@test.com'):
    return django_user_model.objects.create_user(
        username=username, email=email, password='pass'
    )


def _auth_client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


# ─────────────────────────────────────────────────────────────────────────────
# ScopeManager — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestScopeManagerExactMatch:
    def test_exact_domain_in_scope(self):
        sm = ScopeManager(in_scope=['example.com'])
        assert sm.is_in_scope('https://example.com/login') is True

    def test_exact_domain_not_in_scope(self):
        sm = ScopeManager(in_scope=['example.com'])
        assert sm.is_in_scope('https://other.com/') is False

    def test_no_in_scope_rules_allows_all(self):
        sm = ScopeManager(in_scope=[])
        assert sm.is_in_scope('https://anything.com/') is True

    def test_subdomain_matches_parent_pattern(self):
        sm = ScopeManager(in_scope=['example.com'])
        assert sm.is_in_scope('https://sub.example.com/') is True

    def test_bare_host_passed_as_target(self):
        sm = ScopeManager(in_scope=['example.com'])
        assert sm.is_in_scope('example.com') is True


class TestScopeManagerWildcard:
    def test_wildcard_subdomain_matches(self):
        sm = ScopeManager(in_scope=['*.example.com'])
        assert sm.is_in_scope('https://app.example.com/') is True

    def test_wildcard_does_not_match_other(self):
        sm = ScopeManager(in_scope=['*.example.com'])
        assert sm.is_in_scope('https://evil.com/') is False

    def test_wildcard_matches_deep_subdomain(self):
        sm = ScopeManager(in_scope=['*.example.com'])
        assert sm.is_in_scope('https://a.b.example.com/') is True


class TestScopeManagerCIDR:
    def test_cidr_match(self):
        sm = ScopeManager(in_scope=['192.168.1.0/24'])
        assert sm.is_in_scope('192.168.1.50') is True

    def test_cidr_no_match(self):
        sm = ScopeManager(in_scope=['192.168.1.0/24'])
        assert sm.is_in_scope('10.0.0.1') is False

    def test_single_ip_exact(self):
        sm = ScopeManager(in_scope=['10.0.0.1'])
        assert sm.is_in_scope('10.0.0.1') is True
        assert sm.is_in_scope('10.0.0.2') is False


class TestScopeManagerOutOfScope:
    def test_out_of_scope_excludes(self):
        sm = ScopeManager(in_scope=['*.example.com'], out_of_scope=['admin.example.com'])
        assert sm.is_in_scope('https://app.example.com/') is True
        assert sm.is_in_scope('https://admin.example.com/login') is False

    def test_empty_target_returns_false(self):
        sm = ScopeManager(in_scope=['example.com'])
        assert sm.is_in_scope('') is False

    def test_invalid_url_returns_false(self):
        sm = ScopeManager(in_scope=['example.com'])
        result = sm.is_in_scope('not-a-url')
        # 'not-a-url' treated as bare host — won't match example.com
        assert result is False


class TestScopeManagerValidateTargets:
    def test_partition(self):
        sm = ScopeManager(in_scope=['example.com'], out_of_scope=['admin.example.com'])
        targets = [
            'https://example.com/',
            'https://admin.example.com/',
            'https://evil.com/',
        ]
        in_s, out_s = sm.validate_targets(targets)
        assert 'https://example.com/' in in_s
        assert 'https://admin.example.com/' in out_s
        assert 'https://evil.com/' in out_s

    def test_filter_in_scope(self):
        sm = ScopeManager(in_scope=['*.example.com'])
        targets = ['https://a.example.com/', 'https://b.example.com/', 'https://x.com/']
        filtered = sm.filter_in_scope(targets)
        assert len(filtered) == 2
        assert 'https://x.com/' not in filtered


class TestScopeManagerCheckTarget:
    def test_check_target_in_scope(self):
        sm = ScopeManager(in_scope=['example.com'])
        res = sm.check_target('https://example.com/page')
        assert res['in_scope'] is True
        assert res['host'] == 'example.com'

    def test_check_target_out_of_scope(self):
        sm = ScopeManager(in_scope=['example.com'], out_of_scope=['admin.example.com'])
        res = sm.check_target('https://admin.example.com/')
        assert res['in_scope'] is False

    def test_check_target_not_in_in_scope(self):
        sm = ScopeManager(in_scope=['example.com'])
        res = sm.check_target('https://evil.com/')
        assert res['in_scope'] is False


class TestScopeManagerFromScopeDefinition:
    @pytest.mark.django_db
    def test_from_scope_definition(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'sdfuser1', 'sdf1@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Test',
            in_scope=['*.example.com'],
            out_of_scope=['admin.example.com'],
        )
        sm = ScopeManager.from_scope_definition(scope)
        assert sm.is_in_scope('https://app.example.com/')
        assert not sm.is_in_scope('https://admin.example.com/')

    @pytest.mark.django_db
    def test_from_scope_definition_dict_entries(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'sdfuser2', 'sdf2@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Test dict',
            in_scope=[{'type': 'domain', 'value': 'example.com'}],
            out_of_scope=[],
        )
        sm = ScopeManager.from_scope_definition(scope)
        assert sm.is_in_scope('https://example.com/')


# ─────────────────────────────────────────────────────────────────────────────
# TargetImporter — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestTargetImporterFromText:
    def test_simple_lines(self):
        text = "https://a.com\nhttps://b.com"
        result = TargetImporter.from_text(text)
        assert result == ['https://a.com', 'https://b.com']

    def test_bare_domains_get_https(self):
        result = TargetImporter.from_text('example.com\nother.org')
        assert all(t.startswith('https://') for t in result)

    def test_comments_stripped(self):
        text = "# ignore this\nexample.com"
        result = TargetImporter.from_text(text)
        assert len(result) == 1
        assert result[0] == 'https://example.com'

    def test_comma_separated(self):
        result = TargetImporter.from_text('a.com,b.com,c.com')
        assert len(result) == 3

    def test_semicolon_separated(self):
        result = TargetImporter.from_text('a.com;b.com')
        assert len(result) == 2

    def test_deduplication(self):
        result = TargetImporter.from_text('a.com\na.com\nhttps://a.com')
        # https://a.com appears once (bare a.com becomes https://a.com)
        assert len(result) == 1

    def test_empty_text(self):
        assert TargetImporter.from_text('') == []

    def test_none_text(self):
        assert TargetImporter.from_text(None) == []


class TestTargetImporterFromHackerOne:
    def _h1_payload(self, domains, eligible=True):
        return {
            'relationships': {
                'structured_scopes': {
                    'data': [
                        {
                            'attributes': {
                                'asset_identifier': d,
                                'asset_type': 'URL',
                                'eligible_for_submission': eligible,
                            }
                        }
                        for d in domains
                    ]
                }
            }
        }

    def test_eligible_targets_returned(self):
        targets, scope = TargetImporter.from_hackerone(
            self._h1_payload(['*.example.com', 'api.example.com'])
        )
        assert len(targets) == 2
        assert len(scope['in_scope']) == 2
        assert scope['out_of_scope'] == []

    def test_ineligible_goes_to_out_of_scope(self):
        payload = self._h1_payload(['admin.example.com'], eligible=False)
        targets, scope = TargetImporter.from_hackerone(payload)
        assert targets == []
        assert 'admin.example.com' in scope['out_of_scope']

    def test_empty_payload(self):
        targets, scope = TargetImporter.from_hackerone({})
        assert targets == []
        assert scope == {'in_scope': [], 'out_of_scope': []}

    def test_https_prefix_added(self):
        targets, _ = TargetImporter.from_hackerone(
            self._h1_payload(['example.com'])
        )
        assert any(t.startswith('https://') for t in targets)


class TestTargetImporterFromBugcrowd:
    def _bc_payload(self, uris, in_scope=True):
        return {
            'target_groups': [
                {
                    'targets': [
                        {'uri': u, 'category': 'website', 'in_scope': in_scope}
                        for u in uris
                    ]
                }
            ]
        }

    def test_in_scope_targets_returned(self):
        targets, scope = TargetImporter.from_bugcrowd(
            self._bc_payload(['https://a.com', 'https://b.com'])
        )
        assert len(targets) == 2
        assert len(scope['in_scope']) == 2

    def test_out_scope_targets(self):
        targets, scope = TargetImporter.from_bugcrowd(
            self._bc_payload(['https://a.com'], in_scope=False)
        )
        assert targets == []
        assert 'https://a.com' in scope['out_of_scope']

    def test_empty_payload(self):
        targets, scope = TargetImporter.from_bugcrowd({})
        assert targets == []


class TestTargetImporterClassifyAsset:
    def test_api_path(self):
        assert TargetImporter.classify_asset('https://example.com/api/v1/') == 'api'

    def test_api_host_prefix(self):
        assert TargetImporter.classify_asset('https://api.example.com/') == 'api'

    def test_graphql_path(self):
        assert TargetImporter.classify_asset('https://example.com/graphql') == 'api'

    def test_cdn_host(self):
        assert TargetImporter.classify_asset('https://cdn.example.com/image.png') == 'cdn'

    def test_web_app_default(self):
        assert TargetImporter.classify_asset('https://example.com/') == 'web_app'

    def test_ip_address(self):
        assert TargetImporter.classify_asset('http://192.168.1.1/') == 'ip'

    def test_mobile_host(self):
        assert TargetImporter.classify_asset('https://mobile.example.com/') == 'mobile_api'


# ─────────────────────────────────────────────────────────────────────────────
# Model smoke tests
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestScopeDefinitionModel:
    def test_create_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'scruser1', 'scr1@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Test Scope',
            organization='ACME Corp',
            in_scope=['*.acme.com'],
            out_of_scope=['admin.acme.com'],
        )
        assert scope.id is not None
        assert scope.is_active is True
        assert str(scope) == 'Test Scope (ACME Corp)'

    def test_str_without_org(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'scruser2', 'scr2@test.com')
        scope = ScopeDefinition.objects.create(user=user, name='Bare Scope')
        assert str(scope) == 'Bare Scope'

    def test_user_isolation(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        u1 = _make_user(django_user_model, 'iso1', 'iso1@test.com')
        u2 = _make_user(django_user_model, 'iso2', 'iso2@test.com')
        ScopeDefinition.objects.create(user=u1, name='Scope A')
        ScopeDefinition.objects.create(user=u2, name='Scope B')
        assert ScopeDefinition.objects.filter(user=u1).count() == 1
        assert ScopeDefinition.objects.filter(user=u2).count() == 1


@pytest.mark.django_db
class TestMultiTargetScanModel:
    def test_create_multi_scan(self, django_user_model):
        from apps.scanning.models import MultiTargetScan
        user = _make_user(django_user_model, 'msuser1', 'ms1@test.com')
        ms = MultiTargetScan.objects.create(
            user=user,
            name='Multi-scan A',
            targets=['https://a.com', 'https://b.com'],
            total_targets=2,
        )
        assert str(ms) == 'Multi-scan A (2 targets)'
        assert ms.status == 'pending'
        assert ms.parallel_limit == 3

    def test_scope_fk_nullable(self, django_user_model):
        from apps.scanning.models import MultiTargetScan
        user = _make_user(django_user_model, 'msuser2', 'ms2@test.com')
        ms = MultiTargetScan.objects.create(
            user=user, name='No Scope', targets=['https://x.com'], total_targets=1
        )
        assert ms.scope is None


@pytest.mark.django_db
class TestDiscoveredAssetModel:
    def test_create_asset(self, django_user_model):
        from apps.scanning.models import DiscoveredAsset
        user = _make_user(django_user_model, 'dauser1', 'da1@test.com')
        asset = DiscoveredAsset.objects.create(
            user=user,
            url='https://example.com/',
            asset_type='web_app',
        )
        assert asset.is_new is True
        assert asset.is_active is True
        assert str(asset) == 'web_app: https://example.com/'

    def test_unique_together_user_url(self, django_user_model):
        from apps.scanning.models import DiscoveredAsset
        from django.db import IntegrityError
        user = _make_user(django_user_model, 'dauser2', 'da2@test.com')
        DiscoveredAsset.objects.create(user=user, url='https://dup.com/')
        with pytest.raises(IntegrityError):
            DiscoveredAsset.objects.create(user=user, url='https://dup.com/')

    def test_different_users_same_url_ok(self, django_user_model):
        from apps.scanning.models import DiscoveredAsset
        u1 = _make_user(django_user_model, 'dauser3', 'da3@test.com')
        u2 = _make_user(django_user_model, 'dauser4', 'da4@test.com')
        DiscoveredAsset.objects.create(user=u1, url='https://shared.com/')
        DiscoveredAsset.objects.create(user=u2, url='https://shared.com/')
        assert DiscoveredAsset.objects.count() == 2


# ─────────────────────────────────────────────────────────────────────────────
# Scope Definition API
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestScopeDefinitionAPI:
    def test_create_scope(self, django_user_model):
        user = _make_user(django_user_model, 'sapiuser1', 'sapi1@test.com')
        client = _auth_client(user)
        resp = client.post('/api/scan/scopes/', {
            'name': 'API Scope',
            'in_scope': ['*.example.com'],
            'out_of_scope': ['admin.example.com'],
        }, format='json')
        assert resp.status_code == 201
        assert resp.data['name'] == 'API Scope'
        assert resp.data['in_scope'] == ['*.example.com']

    def test_list_scopes_returns_only_own(self, django_user_model):
        u1 = _make_user(django_user_model, 'sapiuser2', 'sapi2@test.com')
        u2 = _make_user(django_user_model, 'sapiuser3', 'sapi3@test.com')
        from apps.scanning.models import ScopeDefinition
        ScopeDefinition.objects.create(user=u1, name='S1', in_scope=[])
        ScopeDefinition.objects.create(user=u2, name='S2', in_scope=[])

        client = _auth_client(u1)
        resp = client.get('/api/scan/scopes/')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 1
        assert results[0]['name'] == 'S1'

    def test_retrieve_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'sapiuser4', 'sapi4@test.com')
        scope = ScopeDefinition.objects.create(user=user, name='Ret', in_scope=['x.com'])
        client = _auth_client(user)
        resp = client.get(f'/api/scan/scopes/{scope.id}/')
        assert resp.status_code == 200
        assert resp.data['name'] == 'Ret'

    def test_update_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'sapiuser5', 'sapi5@test.com')
        scope = ScopeDefinition.objects.create(user=user, name='Old name', in_scope=[])
        client = _auth_client(user)
        resp = client.patch(f'/api/scan/scopes/{scope.id}/', {'name': 'New name'}, format='json')
        assert resp.status_code == 200
        assert resp.data['name'] == 'New name'

    def test_delete_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'sapiuser6', 'sapi6@test.com')
        scope = ScopeDefinition.objects.create(user=user, name='Del', in_scope=[])
        client = _auth_client(user)
        resp = client.delete(f'/api/scan/scopes/{scope.id}/')
        assert resp.status_code == 204
        assert not ScopeDefinition.objects.filter(id=scope.id).exists()

    def test_unauthenticated_returns_401(self):
        client = APIClient()
        resp = client.get('/api/scan/scopes/')
        assert resp.status_code == 401

    def test_cannot_access_other_user_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        owner = _make_user(django_user_model, 'sapiuser7', 'sapi7@test.com')
        attacker = _make_user(django_user_model, 'sapiuser8', 'sapi8@test.com')
        scope = ScopeDefinition.objects.create(user=owner, name='Private', in_scope=[])
        client = _auth_client(attacker)
        resp = client.get(f'/api/scan/scopes/{scope.id}/')
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Scope Validate endpoint
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestScopeValidateAPI:
    def test_validate_in_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'svuser1', 'sv1@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Validate',
            in_scope=['*.example.com'],
            out_of_scope=['admin.example.com'],
        )
        client = _auth_client(user)
        resp = client.post(
            f'/api/scan/scopes/{scope.id}/validate/',
            {'url': 'https://app.example.com/'},
            format='json',
        )
        assert resp.status_code == 200
        assert resp.data['in_scope'] is True

    def test_validate_out_of_scope(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'svuser2', 'sv2@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Validate2',
            in_scope=['*.example.com'],
            out_of_scope=['admin.example.com'],
        )
        client = _auth_client(user)
        resp = client.post(
            f'/api/scan/scopes/{scope.id}/validate/',
            {'url': 'https://admin.example.com/'},
            format='json',
        )
        assert resp.status_code == 200
        assert resp.data['in_scope'] is False

    def test_validate_not_in_scope_list(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'svuser3', 'sv3@test.com')
        scope = ScopeDefinition.objects.create(
            user=user, name='Validate3', in_scope=['example.com']
        )
        client = _auth_client(user)
        resp = client.post(
            f'/api/scan/scopes/{scope.id}/validate/',
            {'url': 'https://evil.com/'},
            format='json',
        )
        assert resp.status_code == 200
        assert resp.data['in_scope'] is False

    def test_validate_wrong_user_404(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        owner = _make_user(django_user_model, 'svuser4', 'sv4@test.com')
        other = _make_user(django_user_model, 'svuser5', 'sv5@test.com')
        scope = ScopeDefinition.objects.create(user=owner, name='V4', in_scope=[])
        client = _auth_client(other)
        resp = client.post(
            f'/api/scan/scopes/{scope.id}/validate/',
            {'url': 'https://x.com/'},
            format='json',
        )
        assert resp.status_code == 404

    def test_validate_missing_url_400(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'svuser6', 'sv6@test.com')
        scope = ScopeDefinition.objects.create(user=user, name='V5', in_scope=[])
        client = _auth_client(user)
        resp = client.post(f'/api/scan/scopes/{scope.id}/validate/', {}, format='json')
        assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────────────────
# Scope Import endpoint
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestScopeImportAPI:
    def test_import_text(self, django_user_model):
        user = _make_user(django_user_model, 'siuser1', 'si1@test.com')
        client = _auth_client(user)
        resp = client.post('/api/scan/scopes/import/', {
            'name': 'Text Import',
            'platform': 'text',
            'raw_text': 'example.com\nother.org',
        }, format='json')
        assert resp.status_code == 201
        assert resp.data['total'] == 2
        assert 'scope' in resp.data

    def test_import_hackerone(self, django_user_model):
        user = _make_user(django_user_model, 'siuser2', 'si2@test.com')
        client = _auth_client(user)
        h1_data = {
            'relationships': {
                'structured_scopes': {
                    'data': [
                        {
                            'attributes': {
                                'asset_identifier': '*.example.com',
                                'asset_type': 'URL',
                                'eligible_for_submission': True,
                            }
                        }
                    ]
                }
            }
        }
        resp = client.post('/api/scan/scopes/import/', {
            'name': 'H1 Import',
            'platform': 'hackerone',
            'raw_data': h1_data,
        }, format='json')
        assert resp.status_code == 201
        assert resp.data['total'] >= 1

    def test_import_invalid_platform_400(self, django_user_model):
        user = _make_user(django_user_model, 'siuser3', 'si3@test.com')
        client = _auth_client(user)
        resp = client.post('/api/scan/scopes/import/', {
            'name': 'Bad Platform',
            'platform': 'unknown',
        }, format='json')
        assert resp.status_code == 400

    def test_import_creates_scope_definition(self, django_user_model):
        from apps.scanning.models import ScopeDefinition
        user = _make_user(django_user_model, 'siuser4', 'si4@test.com')
        client = _auth_client(user)
        resp = client.post('/api/scan/scopes/import/', {
            'name': 'DB Check',
            'platform': 'text',
            'raw_text': 'test.com',
        }, format='json')
        assert resp.status_code == 201
        assert ScopeDefinition.objects.filter(user=user, name='DB Check').exists()


# ─────────────────────────────────────────────────────────────────────────────
# MultiTargetScan API
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestMultiTargetScanAPI:
    @patch('apps.scanning.views.execute_scan_task')
    def test_create_multi_scan(self, mock_task, django_user_model):
        mock_task.delay = lambda *a, **kw: None
        user = _make_user(django_user_model, 'mtsuser1', 'mts1@test.com')
        client = _auth_client(user)
        resp = client.post('/api/scan/multi/create/', {
            'name': 'MT Scan 1',
            'targets': ['https://a.com/', 'https://b.com/'],
        }, format='json')
        assert resp.status_code == 201
        assert resp.data['name'] == 'MT Scan 1'
        assert resp.data['total_targets'] == 2

    @patch('apps.scanning.views.execute_scan_task')
    def test_create_requires_targets(self, mock_task, django_user_model):
        mock_task.delay = lambda *a, **kw: None
        user = _make_user(django_user_model, 'mtsuser2', 'mts2@test.com')
        client = _auth_client(user)
        resp = client.post('/api/scan/multi/create/', {
            'name': 'Empty Targets',
            'targets': [],
        }, format='json')
        assert resp.status_code == 400

    @patch('apps.scanning.views.execute_scan_task')
    def test_list_multi_scans(self, mock_task, django_user_model):
        mock_task.delay = lambda *a, **kw: None
        user = _make_user(django_user_model, 'mtsuser3', 'mts3@test.com')
        client = _auth_client(user)
        # Create one
        client.post('/api/scan/multi/create/', {
            'name': 'List Test',
            'targets': ['https://x.com/'],
        }, format='json')
        resp = client.get('/api/scan/multi/')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 1

    @patch('apps.scanning.views.execute_scan_task')
    def test_retrieve_multi_scan(self, mock_task, django_user_model):
        mock_task.delay = lambda *a, **kw: None
        user = _make_user(django_user_model, 'mtsuser4', 'mts4@test.com')
        client = _auth_client(user)
        create_resp = client.post('/api/scan/multi/create/', {
            'name': 'Retrieve Test',
            'targets': ['https://t.com/'],
        }, format='json')
        scan_id = create_resp.data['id']
        resp = client.get(f'/api/scan/multi/{scan_id}/')
        assert resp.status_code == 200
        assert 'sub_scans' in resp.data

    @patch('apps.scanning.views.execute_scan_task')
    def test_create_with_scope_filters(self, mock_task, django_user_model):
        from apps.scanning.models import ScopeDefinition
        mock_task.delay = lambda *a, **kw: None
        user = _make_user(django_user_model, 'mtsuser5', 'mts5@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Filter scope',
            in_scope=['allowed.com'],
            out_of_scope=[],
        )
        client = _auth_client(user)
        resp = client.post('/api/scan/multi/create/', {
            'name': 'Scoped MT',
            'targets': ['https://allowed.com/', 'https://blocked.com/'],
            'scope': str(scope.id),
        }, format='json')
        assert resp.status_code == 201
        # Only allowed.com passes through scope filter
        assert resp.data['total_targets'] == 1

    @patch('apps.scanning.views.execute_scan_task')
    def test_all_targets_filtered_returns_400(self, mock_task, django_user_model):
        from apps.scanning.models import ScopeDefinition
        mock_task.delay = lambda *a, **kw: None
        user = _make_user(django_user_model, 'mtsuser6', 'mts6@test.com')
        scope = ScopeDefinition.objects.create(
            user=user,
            name='Strict scope',
            in_scope=['only.com'],
            out_of_scope=[],
        )
        client = _auth_client(user)
        resp = client.post('/api/scan/multi/create/', {
            'name': 'All blocked',
            'targets': ['https://blocked.com/'],
            'scope': str(scope.id),
        }, format='json')
        assert resp.status_code == 400

    def test_unauthenticated_returns_401(self):
        client = APIClient()
        resp = client.get('/api/scan/multi/')
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Asset Inventory API
# ─────────────────────────────────────────────────────────────────────────────

@pytest.mark.django_db
class TestAssetInventoryAPI:
    def _create_asset(self, user, url='https://asset.com/', org='', asset_type='web_app', is_new=True):
        from apps.scanning.models import DiscoveredAsset
        return DiscoveredAsset.objects.create(
            user=user, url=url, organization=org, asset_type=asset_type, is_new=is_new
        )

    def test_list_assets(self, django_user_model):
        user = _make_user(django_user_model, 'aiuser1', 'ai1@test.com')
        self._create_asset(user, 'https://a1.com/')
        self._create_asset(user, 'https://a2.com/')
        client = _auth_client(user)
        resp = client.get('/api/scan/assets/')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 2

    def test_filter_by_organization(self, django_user_model):
        user = _make_user(django_user_model, 'aiuser2', 'ai2@test.com')
        self._create_asset(user, 'https://a1.com/', org='ACME')
        self._create_asset(user, 'https://a2.com/', org='BigCo')
        client = _auth_client(user)
        resp = client.get('/api/scan/assets/?organization=ACME')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 1
        assert results[0]['organization'] == 'ACME'

    def test_filter_by_asset_type(self, django_user_model):
        user = _make_user(django_user_model, 'aiuser3', 'ai3@test.com')
        self._create_asset(user, 'https://a1.com/', asset_type='api')
        self._create_asset(user, 'https://a2.com/', asset_type='web_app')
        client = _auth_client(user)
        resp = client.get('/api/scan/assets/?asset_type=api')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 1
        assert results[0]['asset_type'] == 'api'

    def test_filter_by_is_new(self, django_user_model):
        user = _make_user(django_user_model, 'aiuser4', 'ai4@test.com')
        self._create_asset(user, 'https://new.com/', is_new=True)
        self._create_asset(user, 'https://old.com/', is_new=False)
        client = _auth_client(user)
        resp = client.get('/api/scan/assets/?is_new=true')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 1
        assert results[0]['is_new'] is True

    def test_retrieve_asset(self, django_user_model):
        user = _make_user(django_user_model, 'aiuser5', 'ai5@test.com')
        asset = self._create_asset(user, 'https://detail.com/')
        client = _auth_client(user)
        resp = client.get(f'/api/scan/assets/{asset.id}/')
        assert resp.status_code == 200
        assert resp.data['url'] == 'https://detail.com/'

    def test_update_asset_notes(self, django_user_model):
        user = _make_user(django_user_model, 'aiuser6', 'ai6@test.com')
        asset = self._create_asset(user, 'https://notes.com/')
        client = _auth_client(user)
        resp = client.patch(
            f'/api/scan/assets/{asset.id}/',
            {'notes': 'This is a critical asset', 'is_new': False},
            format='json',
        )
        assert resp.status_code == 200
        assert resp.data['notes'] == 'This is a critical asset'
        assert resp.data['is_new'] is False

    def test_user_isolation(self, django_user_model):
        u1 = _make_user(django_user_model, 'aiuser7', 'ai7@test.com')
        u2 = _make_user(django_user_model, 'aiuser8', 'ai8@test.com')
        self._create_asset(u1, 'https://u1asset.com/')
        client = _auth_client(u2)
        resp = client.get('/api/scan/assets/')
        assert resp.status_code == 200
        results = resp.data.get('results', resp.data)
        assert len(results) == 0

    def test_cannot_access_other_user_asset(self, django_user_model):
        owner = _make_user(django_user_model, 'aiuser9', 'ai9@test.com')
        attacker = _make_user(django_user_model, 'aiuser10', 'ai10@test.com')
        asset = self._create_asset(owner, 'https://private.com/')
        client = _auth_client(attacker)
        resp = client.get(f'/api/scan/assets/{asset.id}/')
        assert resp.status_code == 404

    def test_unauthenticated_returns_401(self):
        client = APIClient()
        resp = client.get('/api/scan/assets/')
        assert resp.status_code == 401
