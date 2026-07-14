from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.http import JsonResponse


def health_check(request):
    try:
        from django.db import connection
        connection.ensure_connection()
        db_status = 'connected'
    except Exception:
        db_status = 'disconnected'
    return JsonResponse({'status': 'ok', 'db': db_status})



def celery_health_check(request):
    try:
        from celery_app import app
        inspector = app.control.inspect(timeout=1.0)
        pings = inspector.ping()
        if not pings:
            return JsonResponse({'status': 'unavailable', 'detail': 'No Celery workers available'}, status=503)
        return JsonResponse({'status': 'ok', 'workers': len(pings)})
    except Exception as e:
        return JsonResponse({'status': 'error', 'detail': str(e)}, status=503)


urlpatterns = [
    path('health', health_check, name='root-health-check'),
    path('api/v1/health/', health_check, name='health-check'),
    path('api/v1/health/celery/', celery_health_check, name='celery-health-check'),
    path('admin/', admin.site.urls),
    path('api/v1/auth/', include('apps.accounts.urls')),
    path('api/v1/contact/', include('apps.accounts.contact_urls')),
    path('api/v1/careers/', include('apps.accounts.careers_urls')),
    path('api/v1/user/', include('apps.accounts.profile_urls')),
    path('api/v1/scan/', include('apps.scanning.urls')),
    path('api/v1/scans/', include('apps.scanning.list_urls')),
    path('api/v1/dashboard/', include('apps.scanning.dashboard_urls')),
    path('api/v1/chat/', include('apps.chatbot.urls')),
    path('api/v1/admin/', include('apps.admin_panel.urls')),
    path('api/v1/learn/', include('apps.learn.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
