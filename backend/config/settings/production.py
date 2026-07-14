import os

import dj_database_url

from .base import *  # noqa: F401, F403

DEBUG = False

# Require a real SECRET_KEY in production
SECRET_KEY = os.environ['SECRET_KEY']

# Allow Railway and custom domains
ALLOWED_HOSTS = os.getenv(
    'ALLOWED_HOSTS',
    '.railway.app,safeweb.ai,www.safeweb.ai',
).split(',')

# Security settings for production
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Database — PostgreSQL enforced
_database_url = os.getenv('DATABASE_URL')
if _database_url:
    DATABASES = {
        'default': dj_database_url.parse(_database_url, conn_max_age=600, ssl_require=True)
    }

# CORS — load production origins from env
CORS_ALLOWED_ORIGINS = os.getenv(
    'CORS_ALLOWED_ORIGINS',
    'https://safeweb.ai,https://www.safeweb.ai',
).split(',')

# Use real email backend in production
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'

# Celery with real Redis in production
CELERY_TASK_ALWAYS_EAGER = False
