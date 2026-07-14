"""Targeted scan test — validates key pipeline components without full scan."""
import os
import sys
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
os.environ['DJANGO_ALLOW_ASYNC_UNSAFE'] = 'true'
sys.path.insert(0, os.path.dirname(__file__))

import django
django.setup()

from apps.scanning.engine.crawler import Page, Form, FormInput


def test_page_compatibility():
    """Verify Page dataclass supports both attribute and dict-style access."""
    page = Page(
        url='http://testphp.vulnweb.com/listproducts.php?cat=1',
        status_code=200,
        headers={'Content-Type': 'text/html'},
        body='<html><form action="/search.php"><input name="q" type="text"/></form></html>',
        forms=[Form(action='/search.php', method='GET', inputs=[FormInput(name='q', input_type='text')])],
        parameters={'cat': ['1']},
    )
    # Attribute access (used by XSS, SQLi, CMDi testers)
    assert page.url == 'http://testphp.vulnweb.com/listproducts.php?cat=1'
    assert page.status_code == 200
    assert page.body.startswith('<html>')
    assert len(page.forms) == 1
    assert page.forms[0].inputs[0].name == 'q'
    assert 'cat' in page.parameters

    # Dict-style access (used by attack_graph, network, ml_enhancement, etc.)
    assert page.get('url') == page.url
    assert page.get('body') == page.body
    assert page.get('nonexistent', 'default') == 'default'
    assert page['url'] == page.url
    assert 'url' in page
    assert 'nonexistent' not in page

    print('[PASS] Page dataclass - attribute and dict-style access both work')


def test_individual_testers():
    """Run XSS and SQLi testers on a single known-vulnerable page."""
    import requests
    # Fetch a real page from testphp.vulnweb.com
    resp = requests.get(
        'http://testphp.vulnweb.com/listproducts.php?cat=1',
        timeout=10,
        verify=False,
    )
    page = Page(
        url='http://testphp.vulnweb.com/listproducts.php?cat=1',
        status_code=resp.status_code,
        headers=dict(resp.headers),
        body=resp.text,
        forms=[],
        parameters={'cat': ['1']},
    )

    results = {}

    # Test SQLi tester
    try:
        from apps.scanning.engine.testers.sqli_tester import SQLInjectionTester
        tester = SQLInjectionTester()
        vulns = tester.test(page, depth='shallow')
        results['SQLi'] = len(vulns)
        for v in vulns[:2]:
            print(f'  SQLi finding: {v.get("name", "?")} | {v.get("severity", "?")}')
    except Exception as e:
        results['SQLi'] = f'ERROR: {e}'

    # Test XSS tester
    try:
        from apps.scanning.engine.testers.xss_tester import XSSTester
        tester = XSSTester()
        # Use a page with a search parameter
        resp2 = requests.get(
            'http://testphp.vulnweb.com/search.php?test=foo',
            timeout=10,
            verify=False,
        )
        search_page = Page(
            url='http://testphp.vulnweb.com/search.php?test=foo',
            status_code=resp2.status_code,
            headers=dict(resp2.headers),
            body=resp2.text,
            forms=[],
            parameters={'test': ['foo']},
        )
        vulns = tester.test(search_page, depth='shallow')
        results['XSS'] = len(vulns)
        for v in vulns[:2]:
            print(f'  XSS finding: {v.get("name", "?")} | {v.get("severity", "?")}')
    except Exception as e:
        results['XSS'] = f'ERROR: {e}'

    # Test misconfiguration tester (uses page.get())
    try:
        from apps.scanning.engine.testers.misconfig_tester import MisconfigTester
        tester = MisconfigTester()
        vulns = tester.test(page, depth='shallow')
        results['Misconfig'] = len(vulns)
    except Exception as e:
        results['Misconfig'] = f'ERROR: {e}'

    print(f'\n[RESULTS] Tester findings: {json.dumps(results, default=str)}')
    return results


def test_exploit_generation():
    """Test exploit generator with a mock verified vulnerability."""
    try:
        from apps.scanning.engine.exploit.exploit_generator import ExploitGenerator
        gen = ExploitGenerator()

        # Simulate a verified SQLi vulnerability
        mock_vuln = {
            'category': 'SQL Injection',
            'severity': 'critical',
            'affected_url': 'http://testphp.vulnweb.com/listproducts.php?cat=1',
            'evidence': "Error: You have an error in your SQL syntax",
            'name': 'SQL Injection in cat parameter',
            'description': 'SQL injection via cat parameter allows UNION-based extraction',
        }
        result = gen.generate(mock_vuln)
        print(f'\n  Exploit success: {result.get("success")}')
        print(f'  Exploit type: {result.get("exploit_type")}')
        if result.get('poc'):
            print(f'  PoC: {result["poc"][:150]}')
        if result.get('impact_proof'):
            print(f'  Impact proof: {result["impact_proof"][:150]}')

        print(f'[{"PASS" if result.get("success") else "PARTIAL"}] Exploit generator')
        return result
    except Exception as e:
        print(f'[FAIL] Exploit generator: {e}')
        import traceback; traceback.print_exc()
        return None


def test_bb_report():
    """Test bug bounty report generator."""
    try:
        from apps.scanning.engine.exploit.report_generator import BBReportGenerator
        gen = BBReportGenerator()

        mock_vuln = {
            'category': 'SQL Injection',
            'severity': 'critical',
            'affected_url': 'http://testphp.vulnweb.com/listproducts.php?cat=1',
            'evidence': "Error: You have an error in your SQL syntax",
            'name': 'SQL Injection in cat parameter',
            'cvss': 9.8,
            'cwe': 'CWE-89',
        }
        mock_exploit = {
            'success': True,
            'exploit_type': 'sqli_union',
            'poc': "GET /listproducts.php?cat=1' UNION SELECT 1,2,3,4--",
            'impact_proof': 'Extracted 5 database tables',
            'extracted_data': {'tables': ['users', 'products', 'orders']},
        }
        report = gen.generate_report(mock_vuln, mock_exploit)
        md = report.get('markdown', '')
        print(f'\n  Report length: {len(md)} chars')
        print(f'  Has structured data: {bool(report.get("structured"))}')
        print(f'  LLM enhanced: {report.get("llm_enhanced", False)}')
        if md:
            # Show first few lines
            for line in md.split('\n')[:8]:
                print(f'  | {line}')

        print(f'[PASS] BB Report generator ({"LLM" if report.get("llm_enhanced") else "template"})')
        return report
    except Exception as e:
        print(f'[FAIL] BB Report generator: {e}')
        import traceback; traceback.print_exc()
        return None


def test_ml_prioritizer():
    """Test that ML prioritizer preserves Page objects."""
    try:
        from apps.scanning.engine.ml.attack_prioritizer import AttackPrioritizer
        prioritizer = AttackPrioritizer()
        pages = [
            Page(url='http://example.com/admin', status_code=200, body='<form>', parameters={'id': ['1']}),
            Page(url='http://example.com/', status_code=200, body='hello', parameters={}),
            Page(url='http://example.com/api/v1/users?id=5', status_code=200, body='{}', parameters={'id': ['5']}),
        ]
        result = prioritizer.prioritize(pages, {})
        # Verify URLs are correctly extracted (not str(Page(...)))
        urls = [r['url'] for r in result]
        assert all(u.startswith('http://') for u in urls), f'URLs mangled: {urls}'
        assert 'http://example.com/admin' in urls
        assert 'http://example.com/api/v1/users?id=5' in urls
        print(f'[PASS] ML prioritizer preserves correct URLs: {urls}')
    except Exception as e:
        print(f'[FAIL] ML prioritizer: {e}')
        import traceback; traceback.print_exc()


if __name__ == '__main__':
    print('=' * 60)
    print('  SafeWeb AI — Targeted Pipeline Test')
    print('=' * 60)

    test_page_compatibility()
    print()
    test_ml_prioritizer()
    print()
    tester_results = test_individual_testers()
    print()
    exploit_result = test_exploit_generation()
    print()
    report_result = test_bb_report()

    print('\n' + '=' * 60)
    any_findings = any(
        isinstance(v, int) and v > 0
        for v in (tester_results or {}).values()
    )
    print(f'  Active testers found vulns: {any_findings}')
    print(f'  Exploit generator works: {bool(exploit_result)}')
    print(f'  BB report generator works: {bool(report_result)}')
    print('=' * 60)
