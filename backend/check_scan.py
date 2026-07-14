"""Quick DB status check — run from backend/ directory."""
import os
import sys
import json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')
os.environ['DJANGO_ALLOW_ASYNC_UNSAFE'] = 'true'
sys.path.insert(0, os.path.dirname(__file__))
import django
django.setup()

from apps.scanning.models import Scan, Vulnerability

scan = Scan.objects.order_by('-created_at').first()
if not scan:
    print("NO_SCANS_IN_DB")
    sys.exit(0)

vulns = Vulnerability.objects.filter(scan=scan)
exploited = [v for v in vulns if v.exploit_data]
verified = list(vulns.filter(verified=True))

sev = {}
for v in vulns:
    sev[v.severity] = sev.get(v.severity, 0) + 1

print(f"SCAN_ID:{scan.id}")
print(f"STATUS:{scan.status}")
print(f"SCORE:{scan.score}")
print(f"PAGES:{scan.pages_crawled}")
print(f"DURATION:{scan.duration}s")
print(f"TOTAL_VULNS:{vulns.count()}")
print(f"VERIFIED:{len(verified)}")
print(f"WITH_EXPLOIT_DATA:{len(exploited)}")
print(f"SEVERITY:{json.dumps(sev)}")
print()
print("TOP_12_VULNS:")
for v in vulns.order_by('-cvss', '-severity')[:12]:
    tag = '[E]' if v.exploit_data else '[ ]'
    v2 = '[V]' if v.verified else '[ ]'
    url = (v.affected_url or '-')[:50]
    print(f"  {tag}{v2} [{v.severity.upper():8s}] {v.name[:55]:55s} | {url}")

if exploited:
    print()
    print("EXPLOIT_SAMPLE:")
    v = exploited[0]
    ed = v.exploit_data
    expl = ed.get('exploit', {})
    rpt = ed.get('report', {})
    print(f"  NAME:{v.name}")
    print(f"  SUCCESS:{expl.get('success')}")
    print(f"  TYPE:{expl.get('exploit_type')}")
    print(f"  PoC_chars:{len(expl.get('poc', ''))}")
    print(f"  STEPS:{len(expl.get('steps', []))}")
    print(f"  REPORT_chars:{len(rpt.get('markdown', ''))}")
    print(f"  LLM_ENHANCED:{rpt.get('llm_enhanced')}")
    # Also test the API serializer
    from apps.scanning.serializers import VulnerabilitySerializer
    s = VulnerabilitySerializer(v)
    data = s.data
    print(f"  API_exploit_data_present:{'exploit_data' in data and bool(data['exploit_data'])}")
else:
    print()
    print("NO_EXPLOIT_DATA_YET")
    # Show tester results to understand how scanning went
    trs = scan.tester_results or []
    passed = [t for t in trs if isinstance(t, dict) and t.get('status') == 'passed']
    failed = [t for t in trs if isinstance(t, dict) and t.get('status') == 'failed']
    print(f"  TESTERS_total:{len(trs)} passed:{len(passed)} failed:{len(failed)}")
    if passed[:5]:
        print(f"  PASSED_SAMPLE:{[t.get('tester_name','?') for t in passed[:5]]}")

print()
print("-- API SERIALIZER TEST --")
from apps.scanning.serializers import ScanDetailSerializer
s2 = ScanDetailSerializer(scan)
d2 = s2.data
print(f"  vulns_in_api:{len(d2['vulnerabilities'])}")
if d2['vulnerabilities']:
    first = d2['vulnerabilities'][0]
    print(f"  first_vuln_keys:{list(first.keys())}")
    print(f"  exploit_data_in_first:{first.get('exploit_data') is not None}")
