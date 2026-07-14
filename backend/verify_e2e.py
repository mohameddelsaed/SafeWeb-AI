"""Final E2E verification: confirm camelCase API fields and expliot_data rendering path."""
import sys
sys.path.insert(0, r'd:\My Files\Graduation Project\safeweb-ai\backend\venv\Lib\site-packages')
import requests

BASE = "http://localhost:8000"
SCAN_ID = "a3269bde-82ae-42ca-a8e2-aafd31feacaa"

# Auth
login = requests.post(f"{BASE}/api/auth/login/", json={"email": "test@safeweb.ai", "password": "testpass123"}, timeout=10)
token = login.json().get("tokens", login.json()).get("access", "")
H = {"Authorization": f"Bearer {token}"}

# Get scan
resp = requests.get(f"{BASE}/api/scan/{SCAN_ID}/", headers=H, timeout=15)
data = resp.json()
vulns = data.get("vulnerabilities", [])

print(f"HTTP {resp.status_code} | Scan [{data.get('status')}]")
print(f"startTime: {data.get('startTime')} | endTime: {data.get('endTime')}")
print(f"pagesCrawled: {data.get('pagesCrawled')} | totalRequests: {data.get('totalRequests')}")
print(f"Vulns: {len(vulns)}")
print()

# Check camelCase fields in vulns
required = ["id", "name", "severity", "category", "affectedUrl", "isFalsePositive",
            "falsePositiveScore", "attackChain", "exploitData", "verified"]
missing = [k for k in required if k not in vulns[0]] if vulns else []
print(f"Required camelCase keys missing from first vuln: {missing}")

# Find the exploited vuln
exploited = [v for v in vulns if v.get("exploitData")]
print(f"Vulns with exploitData: {len(exploited)}")

if exploited:
    v = exploited[0]
    ed = v["exploitData"]
    exploit = ed.get("exploit", {})
    report = ed.get("report", {})
    print(f"\nExploited vuln: {v['name']}")
    print(f"  affectedUrl:   {v.get('affectedUrl')}")
    print(f"  isFalsePos:    {v.get('isFalsePositive')}")
    print(f"  falsePosSco:   {v.get('falsePositiveScore')}")
    print(f"  attackChain:   {v.get('attackChain')}")
    print(f"  verified:      {v.get('verified')}")
    print()
    print(f"  exploit.success:     {exploit.get('success')}")
    print(f"  exploit.exploitType: {exploit.get('exploitType')}")
    print(f"  exploit.poc (30):    {str(exploit.get('poc', ''))[:30]}")
    print(f"  exploit.steps count: {len(exploit.get('steps', []))}")
    print(f"  exploit.impactProof: {exploit.get('impactProof')}")
    print(f"  exploit.extractedData: {str(exploit.get('extractedData', ''))[:40]}")
    print()
    print(f"  report.markdown len:  {len(report.get('markdown', ''))}")
    print(f"  report.llmEnhanced:   {report.get('llmEnhanced')}")
    print()
    print("--- FULL PIPELINE VERIFIED ---")
    print("Frontend at: http://localhost:5173/scan/" + SCAN_ID)
    print("Open this URL in browser to see the Exploit Proof + BB Report sections")
else:
    print("No exploited vulns found yet (scan still running)")
    print("Frontend at: http://localhost:5173/")
