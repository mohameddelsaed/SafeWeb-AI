"""Diagnose API serializer output for vulnerability fields."""
import sys
sys.path.insert(0, r'd:\My Files\Graduation Project\safeweb-ai\backend\venv\Lib\site-packages')
sys.path.insert(1, r'd:\My Files\Graduation Project\safeweb-ai\backend')

import os
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'

import django
django.setup()

from apps.scanning.models import Scan, Vulnerability
from apps.scanning.serializers import VulnerabilitySerializer, ScanDetailSerializer
import json

# Get first scan with vulns
scans = list(Scan.objects.order_by('-started_at')[:10])
target_scan = None
for s in scans:
    vc = Vulnerability.objects.filter(scan=s).count()
    if vc > 0:
        target_scan = s
        break

if not target_scan:
    print("No scans with vulnerabilities found!")
    sys.exit(1)

print(f"Using scan: {target_scan.id} [{target_scan.status}] vulns={Vulnerability.objects.filter(scan=target_scan).count()}")

# Get first vuln and inspect its model fields
v = Vulnerability.objects.filter(scan=target_scan).first()
print("\n--- Model fields ---")
print(f"  name           = {v.name}")
print(f"  affected_url   = {repr(v.affected_url)}")
print(f"  is_false_pos   = {v.is_false_positive}")
print(f"  fp_score       = {v.false_positive_score}")
print(f"  attack_chain   = {repr(v.attack_chain)}")
print(f"  exploit_data   = {v.exploit_data!r}")
print(f"  oob_callback   = {repr(v.oob_callback)}")
print(f"  evidence       = {repr(v.evidence)[:60]}")

# Serialize it
data = dict(VulnerabilitySerializer(v).data)
print("\n--- Serializer output ---")
print(f"  Keys: {list(data.keys())}")
print(f"\n  affected_url   -> {repr(data.get('affected_url'))}")
print(f"  is_false_pos   -> {repr(data.get('is_false_positive'))}")
print(f"  fp_score       -> {repr(data.get('false_positive_score'))}")
print(f"  attack_chain   -> {repr(data.get('attack_chain'))}")
print(f"  exploit_data   -> {repr(data.get('exploit_data'))}")

REQUIRED_KEYS = ['id', 'name', 'severity', 'category', 'description',
                 'impact', 'remediation', 'cwe', 'cvss', 'affected_url',
                 'evidence', 'is_false_positive', 'verified',
                 'false_positive_score', 'attack_chain', 'exploit_data']

missing = [k for k in REQUIRED_KEYS if k not in data]
extra = [k for k in data.keys() if k not in REQUIRED_KEYS]
print(f"\n  MISSING KEYS: {missing}")
print(f"  EXTRA KEYS:   {extra}")

# Test full scan serializer
print("\n--- ScanDetailSerializer ---")
sd = ScanDetailSerializer(target_scan)
sdata = sd.data
vulns_in_response = sdata.get('vulnerabilities', [])
print(f"  Vulnerabilities in response: {len(vulns_in_response)}")
if vulns_in_response:
    first = dict(vulns_in_response[0])
    missing2 = [k for k in REQUIRED_KEYS if k not in first]
    print(f"  First vuln keys: {list(first.keys())}")
    print(f"  MISSING in scan response: {missing2}")
    print("\n  Full first vuln JSON:")
    print(json.dumps(first, default=str, indent=4))
