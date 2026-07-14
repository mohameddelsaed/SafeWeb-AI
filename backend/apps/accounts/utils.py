from django.utils import timezone


def time_ago(dt):
    """Convert a datetime to a human-readable 'time ago' string."""
    if not dt:
        return 'Never'

    now = timezone.now()
    diff = now - dt

    seconds = diff.total_seconds()
    if seconds < 60:
        return 'Just now'
    minutes = seconds / 60
    if minutes < 60:
        n = int(minutes)
        return f'{n} minute{"s" if n != 1 else ""} ago'
    hours = minutes / 60
    if hours < 24:
        n = int(hours)
        return f'{n} hour{"s" if n != 1 else ""} ago'
    days = hours / 24
    if days < 30:
        n = int(days)
        return f'{n} day{"s" if n != 1 else ""} ago'
    months = days / 30
    if months < 12:
        n = int(months)
        return f'{n} month{"s" if n != 1 else ""} ago'
    years = days / 365
    n = int(years)
    return f'{n} year{"s" if n != 1 else ""} ago'


def get_client_ip(request):
    """Extract client IP address from request."""
    x_forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded:
        return x_forwarded.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '127.0.0.1')
