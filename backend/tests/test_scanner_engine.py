import pytest
import json
from unittest.mock import patch, MagicMock
from apps.scanning.models import Scan, Vulnerability
from apps.scanning.tasks import execute_scan_task
from django.contrib.auth import get_user_model
from apps.accounts.models import Organization, OrganizationMembership

User = get_user_model()
pytestmark = pytest.mark.django_db(transaction=True)

@pytest.fixture
def test_env():
    user = User.objects.create_user(
        email='scanner@example.com',
        username='scanner@example.com',
        password='password123!'
    )
    org = Organization.objects.create(name='Scanner Org')
    OrganizationMembership.objects.create(user=user, organization=org, role='admin')
    
    scan = Scan.objects.create(
        user=user,
        organization=org,
        target='https://example.com',
        scan_type='website',
        depth='shallow'
    )
    return {'user': user, 'org': org, 'scan': scan}


@pytest.fixture
def comprehensive_mock():
    """Mock out all network and blocking calls."""
    # Create empty mock page
    class MockPage:
        def __init__(self):
            self.url = 'https://example.com'
            self.status_code = 200
            self.headers = {}
            self.body = ''
            self.forms = []
            self.inputs = []
            self.links = []

    with patch('requests.get') as m_req, \
         patch('httpx.AsyncClient.get') as m_httpx, \
         patch('httpx.AsyncClient.post') as m_httpx_post, \
         patch('apps.scanning.engine.crawler.WebCrawler.crawl', return_value=[MockPage()]), \
         patch('apps.scanning.engine.analyzers.ssl_analyzer.SSLAnalyzer.analyze', return_value=None), \
         patch('apps.scanning.engine.analyzers.header_analyzer.HeaderAnalyzer.analyze', return_value=None), \
         patch('apps.scanning.engine.analyzers.cookie_analyzer.CookieAnalyzer.analyze', return_value=None), \
         patch('apps.scanning.engine.oob.oob_manager.OOBManager.start', return_value=False), \
         patch('asyncio.sleep', return_value=None):
         
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "mock html"
        mock_resp.json.return_value = {}
        m_req.return_value = mock_resp
        
        async def mock_async_get(*args, **kwargs):
            return mock_resp
            
        m_httpx.side_effect = mock_async_get
        m_httpx_post.side_effect = mock_async_get
        
        yield


@patch('subprocess.run')
def test_mock_execution_and_phases(mock_subprocess, test_env, comprehensive_mock):
    """
    Test Mock Execution:
    Mock subprocess.run to return a predefined Nuclei JSON output.
    Dispatch execute_scan_task.
    Assert Vulnerability objects are created from the mocked stdout.
    """
    scan = test_env['scan']
    
    # Mock Nuclei output
    nuclei_output = {
        "info": {"name": "Test Nuclei Vuln", "severity": "high", "description": "Test"},
        "type": "http",
        "host": "https://example.com",
        "matched-at": "https://example.com/admin"
    }
    
    def side_effect(*args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        if 'nuclei' in args[0]:
            res.stdout = json.dumps(nuclei_output)
        else:
            res.stdout = "mocked stdout"
        return res
        
    mock_subprocess.side_effect = side_effect
    
    with patch('apps.scanning.tasks.populate_ai_explanations_task.delay'), \
         patch('apps.scanning.tasks.check_parent_scan_completion.delay'), \
         patch('apps.scanning.engine.testers.get_all_testers', return_value=[]), \
         patch('apps.scanning.engine.tools.wrappers.nuclei_cli_wrapper.NucleiCLITool.is_available', return_value=True), \
         patch('apps.scanning.engine.nuclei.template_manager.TemplateManager.setup', return_value=True):
        
        execute_scan_task(scan.id)
    
    scan.refresh_from_db()
    
    # Ensure it traversed phases and completed
    assert scan.status == 'completed'
    assert scan.progress == 100
    
    # Ensure vulnerability was created
    vulns = Vulnerability.objects.filter(scan=scan)
    assert vulns.count() > 0
    assert any("Test Nuclei Vuln" in v.name for v in vulns)


@patch('subprocess.run')
def test_vulnerability_deduplication(mock_subprocess, test_env, comprehensive_mock):
    """
    Test Deduplication:
    Mock subprocess.run to return two identical vulnerabilities.
    Assert the second one is ignored rather than creating a duplicate row.
    """
    scan = test_env['scan']
    
    # Mock Nuclei output with two identical vulnerabilities
    nuclei_output_line1 = json.dumps({
        "info": {"name": "Duplicate Vuln", "severity": "high", "description": "Test"},
        "type": "http",
        "host": "https://example.com",
        "matched-at": "https://example.com/admin"
    })
    
    nuclei_output = nuclei_output_line1 + "\n" + nuclei_output_line1
    
    def side_effect(*args, **kwargs):
        res = MagicMock()
        res.returncode = 0
        if 'nuclei' in args[0]:
            res.stdout = nuclei_output
        else:
            res.stdout = "mocked stdout"
        return res
        
    mock_subprocess.side_effect = side_effect
    
    with patch('apps.scanning.tasks.populate_ai_explanations_task.delay'), \
         patch('apps.scanning.tasks.check_parent_scan_completion.delay'), \
         patch('apps.scanning.engine.testers.get_all_testers', return_value=[]), \
         patch('apps.scanning.engine.tools.wrappers.nuclei_cli_wrapper.NucleiCLITool.is_available', return_value=True), \
         patch('apps.scanning.engine.nuclei.template_manager.TemplateManager.setup', return_value=True):
        
        execute_scan_task(scan.id)
    
    # Verify only one was created
    vulns = Vulnerability.objects.filter(scan=scan, name__contains='Duplicate Vuln')
    assert vulns.count() == 1
