import pytest
from django.test import TestCase
from apps.accounts.models import Organization, User

@pytest.mark.django_db
class TestSecuritySuite(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='security_test@example.com', username='security_test@example.com', password='Password123!')
        self.org = Organization.objects.create(name='Security Org')
        # Add membership so user can start scans
        from apps.accounts.models import OrganizationMembership
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role='admin')
        self.client.force_login(self.user)

    def test_ssrf_prevention(self):
        """Test SSRF Prevention via Scanner Engine"""
        # Attempt to scan AWS metadata IP
        payload = {
            "target": "http://169.254.169.254/latest/meta-data/",
            "scan_depth": "medium",
            "scope_type": "single_domain"
        }
        
        # Mocking the organization headers
        {
            "HTTP_X_ORGANIZATION_ID": str(self.org.id),
            "HTTP_AUTHORIZATION": "Bearer fake_token"
        }
        
        # We need to authenticate fully
        from rest_framework_simplejwt.tokens import RefreshToken
        refresh = RefreshToken.for_user(self.user)
        
        from rest_framework.test import APIClient
        api_client = APIClient()
        api_client.credentials(
            HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}',
            HTTP_X_ORGANIZATION_ID=str(self.org.id)
        )
        api_client.force_authenticate(user=self.user)
        api_client.force_login(self.user)

        response = api_client.post('/api/v1/scan/website/', payload)
        
        # Assert the API rejects the private IP/AWS Metadata URL
        self.assertIn('details', response.data)
        self.assertIn('target', response.data['details'])

    def test_security_headers(self):
        """Test API Security Headers"""
        response = self.client.get('/api/v1/health/')
        
        # Django's default security middleware covers some of these.
        # We check for standard headers that should be configured.
        # X-Frame-Options is usually handled by XFrameOptionsMiddleware
        self.assertIn('X-Frame-Options', response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertIn('X-Content-Type-Options', response.headers)
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
