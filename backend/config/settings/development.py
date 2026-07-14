from .base import *  # noqa: F401, F403

DEBUG = True

# Use console email backend in development
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'

# Disable throttling in development for easier testing
REST_FRAMEWORK['DEFAULT_THROTTLE_CLASSES'] = []

# Celery eager mode (runs tasks synchronously when Redis is unavailable)
CELERY_TASK_ALWAYS_EAGER = os.getenv('CELERY_TASK_ALWAYS_EAGER', 'True').lower() in ('true', '1')
CELERY_TASK_EAGER_PROPAGATES = os.getenv('CELERY_TASK_EAGER_PROPAGATES', 'True').lower() in ('true', '1')
