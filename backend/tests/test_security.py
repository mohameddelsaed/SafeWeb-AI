import pytest
from rest_framework.test import APIClient
from apps.accounts.models import User, Organization, OrganizationMembership
from apps.scanning.models import Target

pytestmark = pytest.mark.django_db

@pytest.fixture
def other_user():
    return User.objects.create_user(
        email='otheruser@example.com',
        username='otheruser@example.com',
        password='Password123!',
        name='Other User'
    )

@pytest.fixture
def other_organization(other_user):
    org = Organization.objects.create(name='Other Org')
    OrganizationMembership.objects.create(
        user=other_user,
        organization=org,
        role='admin'
    )
    return org

@pytest.fixture
def other_auth_client(other_user, other_organization):
    client = APIClient()
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(other_user)
    client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
        HTTP_X_ORGANIZATION_ID=str(other_organization.id)
    )
    client.force_authenticate(user=other_user)
    return client

class TestSecuritySuite:
    def test_ssrf_prevention(self, auth_client):
        """Test that SSRF payloads like cloud metadata IP are blocked."""
        data = {
            'target': 'http://169.254.169.254/latest/meta-data/',
            'scope_type': 'single_domain'
        }
        # Assuming the endpoint is /api/v1/scan/website/
        response = auth_client.post('/api/v1/scan/website/', data)
        assert response.status_code == 400
        assert 'target' in response.data.get('details', {}) or 'domain' in response.data.get('details', {})

    def test_stored_xss_in_target(self, auth_client):
        """Test if XSS payload in target creation is properly handled (either sanitized or accepted but safely escaped).
        We assert it doesn't break the API."""
        import json
        xss_payload = '<script>alert(1)</script>'
        data = {
            'domain': 'example.com',
            'display_name': xss_payload,
            'tags': json.dumps([xss_payload])
        }
        response = auth_client.post('/api/v1/scan/targets/', data)
        # Should either be 400 if strictly sanitized, or 201 if accepted
        assert response.status_code in [201, 400]
        if response.status_code == 201:
            # Check the created target
            created_target = Target.objects.get(id=response.data['id'])
            # Since React handles escaping, backend might just store it. We just verify the API behavior.
            assert created_target.display_name == xss_payload

    def test_idor_organizations(self, auth_client, organization, other_auth_client, other_organization):
        """Test IDOR: Other user should not be able to read/modify Target or Scan belonging to Organization."""
        import json
        # Create a Target in first org
        target_data = {
            'domain': 'victim.com',
            'display_name': 'Victim Target',
            'tags': json.dumps(['prod'])
        }
        resp = auth_client.post('/api/v1/scan/targets/', target_data)
        assert resp.status_code == 201
        target_id = resp.data['id']

        # Attempt to read from other org
        resp_read = other_auth_client.get(f'/api/v1/scan/targets/{target_id}/')
        assert resp_read.status_code in [403, 404]

        # Attempt to delete from other org
        resp_delete = other_auth_client.delete(f'/api/v1/scan/targets/{target_id}/')
        assert resp_delete.status_code in [403, 404]

    def test_security_headers(self, auth_client):
        """Test that security headers are present in responses."""
        from django.test import override_settings
        with override_settings(SECURE_HSTS_SECONDS=31536000):
            response = auth_client.get('/api/v1/health/', secure=True)
            
            # Check standard security headers
            assert response.has_header('Content-Security-Policy')
            assert response['X-Frame-Options'] == 'DENY'
            assert response.has_header('Strict-Transport-Security')
