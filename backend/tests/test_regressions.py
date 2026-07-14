import pytest
from django.urls import reverse
from rest_framework import status
from unittest.mock import patch

@pytest.fixture
def scan(organization, user):
    from apps.scanning.models import Scan
    return Scan.objects.create(
        organization=organization,
        user=user,
        target='https://example.com',
        scan_type='website',
        status='scanning'
    )

@pytest.mark.django_db
def test_sse_jwt_token(api_client, user, scan):
    """
    Prevents Bugfix #45: JWT Signature missing from SSE connections.
    Ensure that passing the JWT token in the query string (?token=...) 
    is accepted by the SSE streaming endpoint.
    """
    from rest_framework_simplejwt.tokens import RefreshToken
    refresh = RefreshToken.for_user(user)
    token = str(refresh.access_token)
    
    url = reverse('scan-stream', kwargs={'id': scan.id})
    # Attach token in query string
    url_with_token = f"{url}?token={token}"
    
    response = api_client.get(url_with_token)
    
    assert response.status_code == status.HTTP_200_OK
    assert response['Content-Type'] == 'text/event-stream'

@pytest.mark.django_db
def test_export_report(auth_client, scan):
    """
    Prevents Bugfix #22: 404 on Scan Report Export.
    Ensure that GET /api/v1/scan/{id}/export/?export_format=pdf 
    returns 200 OK and application/pdf.
    """
    url = reverse('scan-export', kwargs={'id': scan.id})
    url_with_format = f"{url}?export_format=pdf"
    
    scan.status = 'completed'
    scan.save()
    
    with patch('apps.scanning.engine.report_generator.generate_pdf_report') as mock_gen:
        mock_gen.return_value = b'fake pdf content'
        response = auth_client.get(url_with_format)
        
        assert response.status_code == status.HTTP_200_OK
        assert response['Content-Type'] == 'application/pdf'

@pytest.mark.django_db
def test_contact_form_csrf(api_client):
    """
    Prevents Bugfix #89: Missing CSRF tokens on Contact Form.
    Ensure that the Contact Form requires a CSRF token.
    """
    url = reverse('contact')
    
    data = {
        'name': 'Test User',
        'email': 'test@example.com',
        'message': 'This is a test message.'
    }
    
    from django.test import Client
    csrf_client = Client(enforce_csrf_checks=True)
    
    response = csrf_client.post(url, data)
    
    assert response.status_code == status.HTTP_403_FORBIDDEN
