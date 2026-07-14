import os
from pathlib import Path
from datetime import timedelta
from dotenv import load_dotenv
import dj_database_url
from django.core.exceptions import ImproperlyConfigured

load_dotenv(Path(__file__).resolve().parent.parent.parent / '.env')

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-safeweb-dev-key')

DEBUG = os.getenv('DEBUG', 'True').lower() in ('true', '1', 'yes')

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Auto-allow Railway's public domain
_RAILWAY_PUBLIC = os.getenv('RAILWAY_PUBLIC_DOMAIN', '')
if _RAILWAY_PUBLIC and _RAILWAY_PUBLIC not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(_RAILWAY_PUBLIC)

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    # Third party
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',
    'django_filters',
    # Local apps
    'apps.accounts',
    'apps.scanning',
    'apps.ml',
    'apps.chatbot',
    'apps.admin_panel',
    'apps.learn',
]

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'apps.core.middleware.RequestIDMiddleware',
    'apps.accounts.middleware.OrganizationMiddleware',
    'apps.core.middleware.SecurityHeadersMiddleware',
]

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
SECURE_REFERRER_POLICY = 'same-origin'
if not DEBUG:
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

# Database — PostgreSQL mandate in production, allow SQLite in local development
_db_url = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite3')
if not DEBUG and (not _db_url or _db_url.startswith('sqlite://')):
    raise ImproperlyConfigured("DATABASE_URL must be set and must point to PostgreSQL in production.")

DATABASES = {
    'default': dj_database_url.parse(_db_url, conn_max_age=600, conn_health_checks=True)
}

# Custom user model
AUTH_USER_MODEL = 'accounts.User'

# Authentication backends
AUTHENTICATION_BACKENDS = [
    'apps.accounts.backends.EmailBackend',
    'django.contrib.auth.backends.ModelBackend',
]

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 8}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Media files
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# CORS Configuration — local dev + production Vercel domain
_FRONTEND_URL = os.getenv('FRONTEND_URL', '')  # e.g. https://safeweb-ai.vercel.app
CORS_ALLOWED_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:3000',
]
if _FRONTEND_URL:
    CORS_ALLOWED_ORIGINS.append(_FRONTEND_URL)
CORS_ALLOW_CREDENTIALS = True

# CSRF Configuration — trust Vercel and Railway origins
CSRF_TRUSTED_ORIGINS = [
    'http://localhost:5173',
    'http://localhost:3000',
]
if _FRONTEND_URL:
    CSRF_TRUSTED_ORIGINS.append(_FRONTEND_URL)
if _RAILWAY_PUBLIC:
    CSRF_TRUSTED_ORIGINS.append(f'https://{_RAILWAY_PUBLIC}')

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20,
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '30/minute',
        'user': '120/minute',
    },
    'DEFAULT_RENDERER_CLASSES': [
        'djangorestframework_camel_case.render.CamelCaseJSONRenderer',
        'djangorestframework_camel_case.render.CamelCaseBrowsableAPIRenderer',
    ],
    'DEFAULT_PARSER_CLASSES': [
        'djangorestframework_camel_case.parser.CamelCaseFormParser',
        'djangorestframework_camel_case.parser.CamelCaseMultiPartParser',
        'djangorestframework_camel_case.parser.CamelCaseJSONParser',
    ],
    'EXCEPTION_HANDLER': 'apps.accounts.exceptions.custom_exception_handler',
}

# JWT Configuration
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=int(os.getenv('JWT_ACCESS_LIFETIME_MINUTES', 60))),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=int(os.getenv('JWT_REFRESH_LIFETIME_DAYS', 7))),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
    'AUTH_HEADER_TYPES': ('Bearer',),
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
}

# Celery Configuration
CELERY_BROKER_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
CELERY_RESULT_BACKEND = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
CELERY_TASK_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_TIME_LIMIT = 3600

# File upload limits
FILE_UPLOAD_MAX_MEMORY_SIZE = int(os.getenv('MAX_FILE_SIZE_MB', 50)) * 1024 * 1024
DATA_UPLOAD_MAX_MEMORY_SIZE = int(os.getenv('MAX_FILE_SIZE_MB', 50)) * 1024 * 1024

# Security
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'
if not DEBUG:
    # Railway/Render/etc handle HTTPS termination at the load balancer;
    # do NOT enable SECURE_SSL_REDIRECT — it breaks internal healthchecks.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# AI API
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', '')
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', '')
OPENROUTER_MODEL = os.getenv('OPENROUTER_MODEL', 'google/gemini-2.0-flash-001')
GEMINI_API_KEY = os.getenv('GEMINI_API_KEY', '')
GOOGLE_API_KEY = os.getenv('GOOGLE_API_KEY', '')

# Phase 23: OSINT API Keys
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', '')
CENSYS_API_ID = os.getenv('CENSYS_API_ID', '')
CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET', '')
VT_API_KEY = os.getenv('VT_API_KEY', '')
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')

# Scan Configuration
MAX_CONCURRENT_SCANS = int(os.getenv('MAX_CONCURRENT_SCANS', 10))
SCAN_TIMEOUT_SECONDS = int(os.getenv('SCAN_TIMEOUT_SECONDS', 3600))
MAX_CRAWL_PAGES = int(os.getenv('MAX_CRAWL_PAGES', 200))

# Phase 14: Scanner Performance Tuning
SCANNER_PERFORMANCE = {
    'MAX_CONCURRENT_REQUESTS': int(os.getenv('SCANNER_MAX_CONCURRENT', 50)),
    'MAX_CRAWL_CONCURRENCY': int(os.getenv('SCANNER_CRAWL_CONCURRENCY', 5)),
    'RESPONSE_SIZE_LIMIT_BYTES': int(os.getenv('SCANNER_RESPONSE_SIZE_LIMIT', 5 * 1024 * 1024)),
    'DNS_CACHE_TTL': int(os.getenv('SCANNER_DNS_CACHE_TTL', 300)),
    'MEMORY_GUARD_MB': int(os.getenv('SCANNER_MEMORY_GUARD_MB', 500)),
}

# Email Configuration
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # Override in production
EMAIL_HOST = os.getenv('EMAIL_HOST', 'smtp.gmail.com')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 587))
EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER', '')
EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD', '')
EMAIL_USE_TLS = os.getenv('EMAIL_USE_TLS', 'True').lower() in ('true', '1')
DEFAULT_FROM_EMAIL = 'SafeWeb AI <noreply@safeweb.ai>'

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'request_id': {
            '()': 'apps.core.middleware.RequestIDLogFilter',
        },
    },
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} [{request_id}] {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
            'filters': ['request_id'],
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'apps': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
