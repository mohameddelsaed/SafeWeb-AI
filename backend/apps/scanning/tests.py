import pytest
from unittest.mock import patch
from rest_framework.exceptions import ValidationError
from apps.scanning.serializers import TargetSerializer
from apps.scanning.models import Target, Scan
from apps.accounts.models import Organization

pytestmark = pytest.mark.django_db

@pytest.mark.unit
class TestScanningUnit:
    def test_scope_validator_rejects_private_ips(self):
        """Assert that validate_domain blocks 169.254.169.254 and 127.0.0.1"""
        serializer = TargetSerializer()
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_domain('169.254.169.254')
        assert 'Local or private network targets' in str(exc_info.value)
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_domain('http://localhost:8080')
        assert 'Local or private network targets' in str(exc_info.value)
        
        # Valid domain
        assert serializer.validate_domain('example.com') == 'example.com'

    def test_severity_calculation(self):
        """Assert that a CVSS score of 9.5 maps to CRITICAL severity enum."""
        from apps.scanning.engine.tools.result import ToolSeverity
        assert ToolSeverity.from_cvss(9.5) == ToolSeverity.CRITICAL

@pytest.mark.integration
class TestScanningIntegration:
    @patch('apps.scanning.views._dispatch_scan_task')
    def test_create_scan_flow(self, mock_dispatch, auth_client, organization):
        """Post to /api/v1/scan/website/. Assert HTTP 201. Assert Scan pending and task delayed."""
        data = {
            'target': 'https://example.com',
            'scope_type': 'single_domain'
        }
        response = auth_client.post('/api/v1/scan/website/', data)
        assert response.status_code == 201
        assert response.data['status'] == 'pending'
        
        scan_id = response.data['id']
        scan = Scan.objects.filter(id=scan_id).first()
        assert scan is not None
        assert scan.status == 'pending'
        assert scan.organization == organization
        mock_dispatch.assert_called_once_with(str(scan_id))

    def test_scan_crud_operations(self, auth_client, organization):
        """Assert GET /api/v1/scan/<id>/ and DELETE /api/v1/scan/<id>/delete/ work."""
        from apps.accounts.models import User
        target = Target.objects.create(organization=organization, domain='crud.com', display_name='CRUD')
        user = User.objects.first()
        scan = Scan.objects.create(organization=organization, target=target, user=user, scan_type='website', status='pending')
        
        # Read
        response = auth_client.get(f'/api/v1/scan/{scan.id}/')
        assert response.status_code == 200
        assert response.data['id'] == str(scan.id)
        
        # Delete
        response_delete = auth_client.delete(f'/api/v1/scan/{scan.id}/delete/')
        assert response_delete.status_code in [200, 204]
        assert not Scan.objects.filter(id=scan.id).exists()

    def test_target_management_flow(self, auth_client, organization):
        """Assert POST /api/v1/scan/targets/ and GET /api/v1/scan/targets/<id>/ work."""
        data = {
            'domain': 'new-target.com',
            'display_name': 'New Target'
        }
        response = auth_client.post('/api/v1/scan/targets/', data)
        assert response.status_code == 201
        target_id = response.data['id']
        
        # Read
        response_get = auth_client.get(f'/api/v1/scan/targets/{target_id}/')
        assert response_get.status_code == 200
        assert response_get.data['domain'] == 'new-target.com'

@pytest.mark.isolation
class TestTenantIsolation:
    def test_cross_tenant_scan_access(self, api_client, user):
        """Assert that User from Org B gets 404 for Scan in Org A."""
        from rest_framework_simplejwt.tokens import RefreshToken
        
        org_a = Organization.objects.create(name='Org A')
        org_b = Organization.objects.create(name='Org B')
        
        # Give user membership to Org B
        from apps.accounts.models import OrganizationMembership
        OrganizationMembership.objects.create(user=user, organization=org_b, role='admin')
        
        # Create scan in Org A
        target_a = Target.objects.create(organization=org_a, domain='orga.com', display_name='OrgA')
        scan_a = Scan.objects.create(organization=org_a, target=target_a, user=user)
        
        # Auth client as Org B
        refresh = RefreshToken.for_user(user)
        api_client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
            HTTP_X_ORGANIZATION_ID=str(org_b.id)
        )
        api_client.force_authenticate(user=user)
        api_client.force_login(user)
        
        # Attempt to access Org A's scan
        response = api_client.get(f'/api/v1/scan/{scan_a.id}/')
        assert response.status_code == 404  # Not 403, prevents ID enumeration
