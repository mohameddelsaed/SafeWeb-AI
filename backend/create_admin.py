import os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.base')

import django
django.setup()

from apps.accounts.models import User

if not User.objects.filter(username='admin').exists():
    u = User.objects.create_superuser(
        username='admin',
        email='admin@safeweb.ai',
        password='SafeWeb@2026!'
    )
    print(f'Created superuser: {u.username}')
else:
    print('Superuser admin already exists')
