"""Raw HTTP response dump for the first vulnerability."""
import sys
sys.path.insert(0, r'd:\My Files\Graduation Project\safeweb-ai\backend\venv\Lib\site-packages')
import requests
import json

login = requests.post("http://localhost:8000/api/auth/login/",
    json={"email": "test@safeweb.ai", "password": "testpass123"}, timeout=10)
data = login.json()
token = data.get("tokens", data).get("access", "")
headers = {"Authorization": f"Bearer {token}"}

resp = requests.get("http://localhost:8000/api/scan/a3269bde-82ae-42ca-a8e2-aafd31feacaa/",
    headers=headers, timeout=15)

full = resp.json()
vulns = full.get("vulnerabilities", [])

print(f"HTTP status: {resp.status_code}")
print(f"Vuln count: {len(vulns)}")
if vulns:
    v = vulns[0]
    print("\nFirst vuln raw JSON:")
    print(json.dumps(v, indent=2, default=str))
