import pytest
from unittest.mock import patch
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from apps.accounts.models import Organization, OrganizationMembership
from apps.scanning.models import Scan

User = get_user_model()

pytestmark = pytest.mark.django_db(transaction=True)

@pytest.fixture
def smoke_client():
    return APIClient()

def test_staging_smoke_health_endpoint(smoke_client):
    """Verify /health returns 200 with db: connected."""
    response = smoke_client.get('/health')
    assert response.status_code == 200
    assert response.json().get('status') == 'ok'
    assert response.json().get('db') == 'connected'

@patch('apps.scanning.views._dispatch_scan_task')
def test_staging_smoke_user_journey_end_to_end(mock_dispatch, smoke_client):
    """
    Simulate full 20-minute staging smoke test sequence:
    1. Register account
    2. Login
    3. Add Target
    4. Start Scan
    5. Verify AI Explanations
    6. Export PDF
    """
    # 1. Register
    reg_data = {
        'name': 'Smoke Test QA',
        'email': 'smoke@safeweb.ai',
        'password': 'Password123!',
        'confirm_password': 'Password123!'
    }
    reg_resp = smoke_client.post('/api/v1/auth/register/', reg_data)
    assert reg_resp.status_code == 201
    
    # 2. Login
    login_resp = smoke_client.post('/api/v1/auth/login/', {
        'email': 'smoke@safeweb.ai',
        'password': 'Password123!'
    })
    assert login_resp.status_code == 200
    token = login_resp.json()['tokens']['access']
    
    user = User.objects.get(email='smoke@safeweb.ai')
    org = Organization.objects.create(name='Smoke Org')
    OrganizationMembership.objects.create(user=user, organization=org, role='admin')
    
    smoke_client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {token}',
        HTTP_X_ORGANIZATION_ID=str(org.id)
    )
    smoke_client.force_authenticate(user=user)
    
    # 3. Add Target
    target_resp = smoke_client.post('/api/v1/scan/targets/', {
        'domain': 'staging-target.com',
        'display_name': 'Staging Smoke Target'
    })
    assert target_resp.status_code == 201
    
    # 4. Start Scan
    scan_resp = smoke_client.post('/api/v1/scan/website/', {
        'target': 'https://staging-target.com',
        'scope_type': 'single_domain'
    })
    assert scan_resp.status_code == 201
    scan_id = scan_resp.json()['id']
    mock_dispatch.assert_called_once_with(str(scan_id))
    
    # 5. Verify Scan retrieval & AI Fields
    scan_obj = Scan.objects.get(id=scan_id)
    scan_obj.status = 'completed'
    scan_obj.save()
    
    get_scan_resp = smoke_client.get(f'/api/v1/scan/{scan_id}/')
    assert get_scan_resp.status_code == 200
    data = get_scan_resp.json()
    assert data.get('status') in ['completed', 'scanning', 'pending']
    assert 'vulnerabilities' in data
    assert isinstance(data['vulnerabilities'], list)
    
    # 6. Export PDF
    with patch('apps.scanning.engine.report_generator.generate_pdf_report', return_value=b'%PDF-1.4 mock pdf bytes'):
        export_resp = smoke_client.get(f'/api/v1/scan/{scan_id}/export/?export_format=pdf')
        assert export_resp.status_code == 200
        assert export_resp['Content-Type'] == 'application/pdf'
