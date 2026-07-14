import os
import django
os.environ['DJANGO_SETTINGS_MODULE'] = 'config.settings.development'
django.setup()
from apps.scanning.models import Scan
for s in Scan.objects.all().order_by('-created_at')[:5]:
    vc = s.vulnerabilities.count()
    print(f'{s.id} | status={s.status} | progress={s.progress} | phase={s.current_phase} | vulns={vc} | pages={s.pages_crawled}')
