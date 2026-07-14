from django.test import TestCase
from rest_framework.test import APIClient
from apps.accounts.models import User


class AdminDashboardTest(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(
            email='admin@test.com', username='admin@test.com', password='Admin123!@#', role='admin'
        )
        self.client = APIClient()
        self.client.force_authenticate(self.admin)

    def test_dashboard(self):
        response = self.client.get('/api/v1/admin/dashboard/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('stats', response.data)
        self.assertIn('recentUsers', response.data)

    def test_users_list(self):
        response = self.client.get('/api/v1/admin/users/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('users', response.data)

    def test_settings(self):
        response = self.client.get('/api/v1/admin/settings/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('settings', response.data)

    def test_non_admin_denied(self):
        user = User.objects.create_user(email='user@test.com', username='user@test.com', password='User123!@#')
        self.client.force_authenticate(user)
        response = self.client.get('/api/v1/admin/dashboard/')
        self.assertEqual(response.status_code, 403)
