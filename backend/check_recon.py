import os
import django
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
django.setup()
from apps.scanning.models import Scan
s = Scan.objects.get(pk='ae815d02-78cd-4314-8816-84b6da75940b')
rd = s.recon_data
for k, v in rd.items():
    t = type(v).__name__
    if isinstance(v, list):
        sample = v[:2] if v else []
        print(f"{k}: list[{len(v)}] sample={sample}")
    elif isinstance(v, dict):
        keys = list(v.keys())[:6]
        print(f"{k}: dict keys={keys}")
    else:
        print(f"{k}: {t} = {str(v)[:100]}")
