import os
import django
import json
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
django.setup()
from apps.scanning.models import Scan
s = Scan.objects.get(pk='ae815d02-78cd-4314-8816-84b6da75940b')
rd = s.recon_data

# Check specific fields the frontend needs
print("=== technologies ===")
print(json.dumps(rd.get('technologies', {}).get('technologies', [])[:3], indent=2))

print("\n=== waf ===")
w = rd.get('waf', {})
print(f"detected={w.get('detected')}, findings={len(w.get('findings', []))}")

print("\n=== passive_subdomains ===")
subs = rd.get('passive_subdomains', {}).get('subdomains', [])
print(f"count={len(subs)}, sample={subs[:3]}")

print("\n=== certificate ===")
cert = rd.get('certificate', {})
print(f"hostname={cert.get('hostname')}")
# look for cert details
for k in cert.keys():
    if k not in ('findings', 'metadata', 'errors', 'stats', 'issues'):
        print(f"  {k} = {json.dumps(cert[k])[:200]}")

print("\n=== headers ===")
h = rd.get('headers', {})
present = h.get('present', {})
print(f"present type={type(present).__name__}")
if isinstance(present, dict):
    for hk in list(present.keys())[:5]:
        print(f"  {hk}: {present[hk]}")
elif isinstance(present, list):
    print(f"  count={len(present)}, sample={present[:3]}")

print("\n=== cookies ===")
c = rd.get('cookies', {}).get('cookies', [])
print(f"count={len(c)}, sample={json.dumps(c[:2], indent=2)}")

print("\n=== emails ===")
em = rd.get('emails', {}).get('emails', [])
print(f"count={len(em)}, sample={em[:5]}")

print("\n=== social ===")
soc = rd.get('social', {}).get('social_profiles', [])
print(f"type={type(soc).__name__}")
if isinstance(soc, list):
    print(f"count={len(soc)}, sample={soc[:3]}")
elif isinstance(soc, dict):
    print(f"keys={list(soc.keys())[:5]}")
