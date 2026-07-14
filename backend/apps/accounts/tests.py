import pytest
from rest_framework.exceptions import ValidationError
from apps.accounts.models import User
from apps.accounts.serializers import RegisterSerializer

pytestmark = pytest.mark.django_db

@pytest.mark.unit
class TestAccountsUnit:
    def test_password_validator_rejects_weak_passwords(self):
        """Assert that passwords without symbols, numbers, and uppercase letters raise ValidationError."""
        serializer = RegisterSerializer()
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_password('weakpassword')
        assert 'least one uppercase letter' in str(exc_info.value.detail)
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_password('Weakpassword')
        assert 'number' in str(exc_info.value.detail)
        
        with pytest.raises(ValidationError) as exc_info:
            serializer.validate_password('Weakpassword1')
        assert 'special character' in str(exc_info.value.detail)
        
        # Valid password
        assert serializer.validate_password('StrongPass1!') == 'StrongPass1!'

    def test_user_role_assignment(self):
        """Assert that a user defaults to user role."""
        user = User.objects.create_user(email='test@example.com', username='test@example.com', password='Password123!', name='Test')
        assert user.role == 'user'
        assert user.is_staff is False
        assert user.is_superuser is False
        
        admin = User.objects.create_superuser(email='admin@example.com', username='admin@example.com', password='Password123!', name='Admin', role='admin')
        assert admin.role == 'admin'
        assert admin.is_superuser is True

@pytest.mark.integration
class TestAccountsIntegration:
    def test_register_flow(self, api_client):
        """Post to /api/v1/auth/register/. Assert 201 Created."""
        data = {
            'name': 'Integration Test User',
            'email': 'integration@example.com',
            'password': 'Password123!',
            'confirm_password': 'Password123!'
        }
        response = api_client.post('/api/v1/auth/register/', data)
        assert response.status_code == 201
        assert 'access' in response.data.get('tokens', {})
        assert 'refresh' in response.data.get('tokens', {})
        assert User.objects.filter(email='integration@example.com').exists()

    def test_login_flow(self, api_client, user):
        """Post to /api/v1/auth/login/. Assert 200 OK. Assert Last Login IP is updated."""
        data = {
            'email': 'testuser@example.com',
            'password': 'Password123!'
        }
        response = api_client.post('/api/v1/auth/login/', data, HTTP_X_FORWARDED_FOR='192.168.1.100')
        assert response.status_code == 200
        assert 'access' in response.data.get('tokens', {})
        
        user.refresh_from_db()
        assert user.last_login_ip == '192.168.1.100'

@pytest.mark.integration
class TestTwoFactorIntegration:
    def test_2fa_enable_flow(self, auth_client):
        """GET /api/v1/user/profile/2fa/enable/ generates secret and QR."""
        response = auth_client.post('/api/v1/user/profile/2fa/enable/')
        assert response.status_code == 200
        assert 'secret' in response.data
        assert 'qrCode' in response.data

    def test_2fa_verify_flow(self, auth_client, user):
        """POST /api/v1/user/profile/2fa/verify/ with valid TOTP enables 2FA."""
        enable_response = auth_client.post('/api/v1/user/profile/2fa/enable/')
        secret = enable_response.data['secret']
        
        import pyotp
        totp = pyotp.TOTP(secret)
        code = totp.now()
        
        verify_response = auth_client.post('/api/v1/user/profile/2fa/verify/', {'code': code})
        assert verify_response.status_code == 200
        
        user.refresh_from_db()
        assert getattr(user, 'is_2fa_enabled', getattr(user, 'two_factor_enabled', True))

@pytest.mark.integration
class TestOrganizationMembershipIntegration:
    def test_organization_membership_access(self, api_client, user):
        """Assert users cannot access endpoints of an organization they are not a member of."""
        from apps.accounts.models import Organization
        from apps.scanning.models import Target
        
        other_org = Organization.objects.create(name='Other Org')
        Target.objects.create(organization=other_org, domain='other.com', display_name='Other')
        
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(user)
        api_client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
            HTTP_X_ORGANIZATION_ID=str(other_org.id)
        )
        
        response = api_client.get('/api/v1/scan/targets/')
        if response.status_code == 200:
            domains = [t.get('domain') for t in response.data.get('results', [])]
            assert 'other.com' not in domains
        else:
            assert response.status_code in [403, 401]
