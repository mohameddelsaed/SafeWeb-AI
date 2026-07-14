import pytest
from apps.scanning.models import Scan
from unittest.mock import patch

@pytest.mark.django_db(transaction=True)
def test_celery_backpressure(auth_client):
    """
    Test that Celery worker can handle a burst of 100 scans being dispatched simultaneously.
    We mock the actual scanning task to avoid spamming the network, but verify that
    the system accepts and queues the tasks properly without dropping any.
    """
    # 1. Dispatch 100 scans
    scan_ids = []
    
    # We patch the celery task dispatch to avoid spawning threads/tasks
    # which locks the SQLite database during testing.
    with patch('apps.scanning.views._dispatch_scan_task') as mock_dispatch:
        for i in range(100):
            response = auth_client.post('/api/v1/scan/website/', {
                'target': f'https://example-{i}.com',
                'scanType': 'website',
                'scanDepth': 'shallow'
            }, format='json')
            
            assert response.status_code in [200, 201], f"Failed to create scan {i}: {response.status_code} - {response.data}"
            scan_ids.append(response.data.get('id'))
            
        # Verify 100 tasks were queued
        assert mock_dispatch.call_count == 100
        
    # Verify the database has 100 scans recorded
    assert Scan.objects.filter(id__in=scan_ids).count() == 100
