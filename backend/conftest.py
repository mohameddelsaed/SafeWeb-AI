import pytest
from rest_framework.test import APIClient
from apps.accounts.models import User, Organization, OrganizationMembership

@pytest.fixture
def api_client():
    return APIClient()

@pytest.fixture
def user():
    return User.objects.create_user(
        email='testuser@example.com',
        username='testuser@example.com',
        password='Password123!',
        name='Test User'
    )

@pytest.fixture
def organization(user):
    org = Organization.objects.create(name='Test Org')
    OrganizationMembership.objects.create(
        user=user,
        organization=org,
        role='admin'
    )
    return org

@pytest.fixture
def auth_client(api_client, user, organization):
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user)
    api_client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
        HTTP_X_ORGANIZATION_ID=str(organization.id)
    )
    api_client.force_authenticate(user=user)
    api_client.force_login(user)
    return api_client
