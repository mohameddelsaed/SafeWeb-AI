"""Debug: compare DB vuln IDs vs API vuln IDs to identify discrepancy."""
import sys
sys.path.insert(0, r'd:\My Files\Graduation Project\safeweb-ai\backend\venv\Lib\site-packages')
sys.path.insert(1, r'd:\My Files\Graduation Project\safeweb-ai\backend')
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
import django
django.setup()

from apps.scanning.models import Vulnerability, Scan
import requests

SCAN_ID = 'a3269bde-82ae-42ca-a8e2-aafd31feacaa'
scan = Scan.objects.get(id=SCAN_ID)

# DB query
vulns_db = list(Vulnerability.objects.filter(scan=scan).order_by('id'))
print(f"DB: {len(vulns_db)} vulns")
for v in vulns_db:
    ed = bool(v.exploit_data)
    print(f"  [{str(v.id)[:8]}] ed={ed} verified={v.verified} url={v.affected_url[:30] if v.affected_url else 'EMPTY'} | {v.name[:45]}")

print()

# HTTP API
login_resp = requests.post("http://localhost:8000/api/auth/login/",
    json={"email": "test@safeweb.ai", "password": "testpass123"}, timeout=10)
data = login_resp.json()
token = data.get("tokens", data).get("access", "")
headers = {"Authorization": f"Bearer {token}"}

resp = requests.get(f"http://localhost:8000/api/scan/{SCAN_ID}/", headers=headers, timeout=15)
vulns_api = resp.json().get("vulnerabilities", [])
print(f"API: {len(vulns_api)} vulns")
for v in vulns_api:
    ed = bool(v.get('exploit_data'))
    url = (v.get('affected_url') or 'EMPTY')[:30]
    print(f"  [{str(v.get('id',''))[:8]}] ed={ed} verified={v.get('verified')} url={url} | {v.get('name','')[:45]}")

# Compare
print("\n--- ID comparison ---")
db_ids = {str(v.id) for v in vulns_db}
api_ids = {str(v.get('id','')) for v in vulns_api}
print(f"  DB IDs: {sorted(db_ids)}")
print(f"  API IDs: {sorted(api_ids)}")
print(f"  Same set: {db_ids == api_ids}")

# Direct serializer check on the exploited vuln
exploited_db = next((v for v in vulns_db if v.exploit_data), None)
if exploited_db:
    print(f"\n--- Direct serializer on DB vuln {str(exploited_db.id)[:8]} ---")
    from apps.scanning.serializers import VulnerabilitySerializer
    data = dict(VulnerabilitySerializer(exploited_db).data)
    print(f"  exploit_data: {bool(data.get('exploit_data'))}")
    print(f"  exploit keys: {list(data.get('exploit_data', {}).keys())}")
    print(f"  affected_url: {repr(data.get('affected_url'))}")
