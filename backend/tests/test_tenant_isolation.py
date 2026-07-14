import pytest
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from apps.accounts.models import Organization, OrganizationMembership
from apps.scanning.models import Scan, Target

User = get_user_model()

pytestmark = pytest.mark.django_db(transaction=True)

@pytest.fixture
def org_a():
    return Organization.objects.create(name='Org A')

@pytest.fixture
def org_b():
    return Organization.objects.create(name='Org B')

@pytest.fixture
def user_a(org_a):
    user = User.objects.create_user(
        email='usera@example.com',
        username='usera@example.com',
        password='password123!',
        name='User A'
    )
    OrganizationMembership.objects.create(
        user=user,
        organization=org_a,
        role='admin'
    )
    return user

@pytest.fixture
def user_b(org_b):
    user = User.objects.create_user(
        email='userb@example.com',
        username='userb@example.com',
        password='password123!',
        name='User B'
    )
    OrganizationMembership.objects.create(
        user=user,
        organization=org_b,
        role='admin'
    )
    return user

@pytest.fixture
def client_b(user_b, org_b):
    client = APIClient()
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user_b)
    client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
        HTTP_X_ORGANIZATION_ID=str(org_b.id)
    )
    client.force_authenticate(user=user_b)
    return client

@pytest.fixture
def scan_a(user_a, org_a):
    return Scan.objects.create(
        user=user_a,
        organization=org_a,
        scan_type='website',
        target='https://target-a.com',
        depth='medium',
        status='pending'
    )

def test_tenant_isolation_data_segregation(client_b, scan_a, org_b):
    """
    Test Data Segregation:
    User B (Org B) requests Scan A (Org A) passing their own Org B ID.
    Assert HTTP 404 Not Found.
    """
    response = client_b.get(f'/api/v1/scan/{scan_a.id}/')
    
    # Verify it's 404 Not Found to prevent ID enumeration
    assert response.status_code == 404

def test_tenant_isolation_middleware_tampering(client_b, user_b, scan_a, org_a):
    """
    Test Middleware Tampering:
    User B (from Org B) tries to bypass isolation by passing Org A's ID
    in the X-Organization-ID header.
    Assert the middleware detects user B is not a member of Org A.
    """
    # Overwrite the credentials to pass Org A's ID
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user_b)
    client_b.credentials(
        HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
        HTTP_X_ORGANIZATION_ID=str(org_a.id)
    )
    
    response = client_b.get(f'/api/v1/scan/{scan_a.id}/')
    
    # Depending on how the middleware/view responds:
    # It might return 404 or 403. Let's assert it's strictly denied.
    assert response.status_code in [403, 404]

@pytest.fixture
def target_a(user_a, org_a):
    return Target.objects.create(
        organization=org_a,
        domain='target-a.com',
        display_name='Target A'
    )

def test_tenant_isolation_delete_tampering(client_b, target_a):
    """
    Test Delete Tampering:
    User B attempts to delete a Target belonging to Org A.
    """
    response = client_b.delete(f'/api/v1/scan/targets/{target_a.id}/')
    assert response.status_code in [403, 404]
