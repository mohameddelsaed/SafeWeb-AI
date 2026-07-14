import os
from celery import Celery
from celery.signals import worker_ready

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings.development')

app = Celery('safeweb')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()


@worker_ready.connect
def on_worker_ready(**kwargs):
    """Register all external tool wrappers when a Celery worker starts."""
    try:
        import django
        django.setup()
        from apps.scanning.engine.tools.registry import ToolRegistry
        registry = ToolRegistry()
        registry.register_all_tools()
    except Exception:
        pass


@app.task(bind=True, ignore_result=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
