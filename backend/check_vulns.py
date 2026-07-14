"""Check all vulns in the test scan to verify exploit_data injection."""
import sys
sys.path.insert(0, r'd:\My Files\Graduation Project\safeweb-ai\backend\venv\Lib\site-packages')
sys.path.insert(1, r'd:\My Files\Graduation Project\safeweb-ai\backend')
import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
import django
django.setup()

from apps.scanning.models import Vulnerability, Scan
import requests

scan = Scan.objects.get(id='a3269bde-82ae-42ca-a8e2-aafd31feacaa')
vulns = list(Vulnerability.objects.filter(scan=scan))
print(f"Scan {scan.id} [{scan.status}]: {len(vulns)} vulns")
print()
for v in vulns:
    ed = v.exploit_data
    has_ed = bool(ed)
    url = v.affected_url[:40] if v.affected_url else "EMPTY"
    print(f"  ed={str(has_ed):5} verified={v.verified} | {v.name[:50]} | url={url}")

print()
print("--- Testing HTTP API ---")
# Login
login_resp = requests.post("http://localhost:8000/api/auth/login/", json={"email": "test@safeweb.ai", "password": "testpass123"}, timeout=10)
data = login_resp.json()
token = data.get("tokens", data).get("access", "")
headers = {"Authorization": f"Bearer {token}"}

# Get scan
resp = requests.get(f"http://localhost:8000/api/scan/{scan.id}/", headers=headers, timeout=15)
vulns_api = resp.json().get("vulnerabilities", [])
print(f"API: {len(vulns_api)} vulns returned")
print()
for v in vulns_api:
    ed = v.get('exploit_data')
    has_ed = bool(ed)
    url = (v.get('affected_url') or 'EMPTY')[:40]
    print(f"  ed={str(has_ed):5} verified={v.get('verified')} | {v.get('name','')[:50]} | url={url}")
