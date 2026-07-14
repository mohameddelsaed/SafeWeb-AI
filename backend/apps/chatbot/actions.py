"""
Chatbot Action System — execute real actions on behalf of the user.
Actions are invoked by the LLM via function calling or keyword-based intent detection.
"""
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)


def execute_action(action_name, params, user):
    """Dispatch an action by name. Returns {data, action} dict."""
    handler = ACTION_REGISTRY.get(action_name)
    if not handler:
        return {'data': {'error': f'Unknown action: {action_name}'}, 'action': None}
    try:
        return handler(params, user)
    except Exception as e:
        logger.error(f'Action {action_name} failed: {e}')
        return {'data': {'error': str(e)}, 'action': None}


# ── Individual Action Handlers ───────────────────────────────────────

def _start_scan(params, user):
    """Start a new scan for the user."""
    from apps.scanning.models import Scan

    target = params.get('target', '').strip()
    if not target:
        return {'data': {'error': 'No target URL provided'}, 'action': None}

    # Basic URL normalization
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'

    # Check scan quota for free users
    if getattr(user, 'plan', 'free') == 'free':
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        scan_count = Scan.objects.filter(user=user, created_at__gte=month_start).count()
        if scan_count >= 5:
            return {
                'data': {'error': 'Monthly scan limit reached (5/5). Upgrade to Pro for unlimited scans.'},
                'action': {'type': 'navigate', 'path': '/subscription'},
            }

    scan_type = params.get('scan_type', 'quick')
    depth = params.get('depth', 'moderate')

    scan = Scan.objects.create(
        user=user,
        target=target,
        scan_type=scan_type,
        depth=depth,
        status='pending',
    )

    # Dispatch scan task
    try:
        from apps.scanning.views import _dispatch_scan_task
        _dispatch_scan_task(str(scan.id))
    except Exception as e:
        logger.warning(f'Failed to dispatch scan task: {e}')

    return {
        'data': {
            'scan_id': str(scan.id),
            'target': target,
            'scan_type': scan_type,
            'depth': depth,
            'status': 'pending',
        },
        'action': {
            'type': 'navigate',
            'path': f'/scans/{scan.id}',
        },
    }


def _get_recent_scans(params, user):
    """Get user's recent scans."""
    from apps.scanning.models import Scan

    limit = min(params.get('limit', 5), 10)
    scans = Scan.objects.filter(user=user).order_by('-created_at')[:limit]

    scan_list = []
    for s in scans:
        scan_list.append({
            'id': str(s.id),
            'target': s.target,
            'status': s.status,
            'score': s.score,
            'scan_type': s.scan_type,
            'created_at': s.created_at.isoformat() if s.created_at else None,
            'vuln_count': s.vulnerabilities.count() if hasattr(s, 'vulnerabilities') else 0,
        })

    return {'data': {'scans': scan_list, 'total': len(scan_list)}, 'action': None}


def _get_scan_status(params, user):
    """Get status of a specific scan."""
    from apps.scanning.models import Scan

    scan_id = params.get('scan_id', '')
    if not scan_id:
        return {'data': {'error': 'No scan_id provided'}, 'action': None}

    try:
        scan = Scan.objects.get(id=scan_id, user=user)
    except Scan.DoesNotExist:
        return {'data': {'error': 'Scan not found'}, 'action': None}

    return {
        'data': {
            'id': str(scan.id),
            'target': scan.target,
            'status': scan.status,
            'score': scan.score,
            'progress': getattr(scan, 'progress', None),
            'current_phase': getattr(scan, 'current_phase', None),
            'current_tool': getattr(scan, 'current_tool', None),
            'scan_type': scan.scan_type,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'vuln_count': scan.vulnerabilities.count() if hasattr(scan, 'vulnerabilities') else 0,
        },
        'action': None,
    }


def _export_scan(params, user):
    """Generate an export URL for a scan."""
    from apps.scanning.models import Scan

    scan_id = params.get('scan_id', '')
    fmt = params.get('format', 'pdf')
    if not scan_id:
        return {'data': {'error': 'No scan_id provided'}, 'action': None}

    try:
        scan = Scan.objects.get(id=scan_id, user=user)
    except Scan.DoesNotExist:
        return {'data': {'error': 'Scan not found'}, 'action': None}

    if scan.status != 'completed':
        return {'data': {'error': 'Scan must be completed before exporting'}, 'action': None}

    export_url = f'/api/scans/{scan.id}/export/?format={fmt}'
    return {
        'data': {
            'export_url': export_url,
            'format': fmt,
            'scan_id': str(scan.id),
        },
        'action': {
            'type': 'download',
            'url': export_url,
        },
    }


def _get_subscription_info(params, user):
    """Get user's subscription details."""
    from apps.scanning.models import Scan

    plan = getattr(user, 'plan', 'free')
    month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_scans = Scan.objects.filter(user=user, created_at__gte=month_start).count()
    total_scans = Scan.objects.filter(user=user).count()

    plan_limits = {
        'free': {'scans_per_month': 5, 'price': '$0'},
        'pro': {'scans_per_month': 'Unlimited', 'price': '$49/mo'},
        'enterprise': {'scans_per_month': 'Unlimited', 'price': 'Custom'},
    }
    limits = plan_limits.get(plan, plan_limits['free'])

    return {
        'data': {
            'plan': plan,
            'price': limits['price'],
            'scans_this_month': monthly_scans,
            'scans_limit': limits['scans_per_month'],
            'total_scans': total_scans,
            'features': {
                'scheduled_scans': plan != 'free',
                'api_access': plan != 'free',
                'webhooks': plan != 'free',
                'all_scan_types': plan != 'free',
            },
        },
        'action': None,
    }


def _get_vulnerability_details(params, user):
    """Get detailed info about a specific vulnerability."""
    vuln_id = params.get('vulnerability_id', '')
    if not vuln_id:
        return {'data': {'error': 'No vulnerability_id provided'}, 'action': None}

    try:
        from apps.scanning.models import Vulnerability
        vuln = Vulnerability.objects.select_related('scan').get(id=vuln_id, scan__user=user)
    except Exception:
        return {'data': {'error': 'Vulnerability not found'}, 'action': None}

    return {
        'data': {
            'id': str(vuln.id),
            'name': vuln.name,
            'severity': vuln.severity,
            'category': getattr(vuln, 'category', ''),
            'description': vuln.description,
            'impact': getattr(vuln, 'impact', ''),
            'remediation': getattr(vuln, 'remediation', ''),
            'cwe': getattr(vuln, 'cwe', ''),
            'cvss': getattr(vuln, 'cvss', None),
            'affected_url': getattr(vuln, 'affected_url', ''),
            'evidence': getattr(vuln, 'evidence', ''),
        },
        'action': None,
    }


def _navigate_to(params, user):
    """Return navigation instruction for the frontend."""
    page = params.get('page', '/dashboard')
    valid_pages = [
        '/dashboard', '/scans', '/assets', '/reports', '/settings',
        '/subscription', '/profile', '/scheduled-scans', '/scope-manager',
    ]
    # Also allow scan-specific pages
    if not any(page.startswith(p) for p in valid_pages + ['/scans/']):
        page = '/dashboard'

    return {
        'data': {'page': page},
        'action': {'type': 'navigate', 'path': page},
    }


def _search_learning_center(params, user):
    """Search the 557 PostgreSQL security articles and return matching documentation."""
    from django.db.models import Q
    query = params.get('query', '').strip()
    if not query:
        return {'data': {'error': 'No search query provided'}, 'action': None}
    
    try:
        from apps.learn.models import Article
        articles = Article.objects.filter(
            Q(title__icontains=query) | Q(excerpt__icontains=query) | Q(content__icontains=query) | Q(category__icontains=query)
        ).filter(is_published=True)[:3]
        
        results = []
        for a in articles:
            results.append({
                'id': str(a.id),
                'title': a.title,
                'slug': a.slug,
                'category': a.category,
                'summary': a.excerpt,
                'snippet': (a.content[:400] + '...') if a.content else '',
            })
        return {'data': {'articles': results, 'total': len(results)}, 'action': {'type': 'navigate', 'path': f'/learn'}}
    except Exception as e:
        logger.error(f'Search articles failed: {e}')
        return {'data': {'error': 'Search failed'}, 'action': None}


# ── Action Registry ──────────────────────────────────────────────────
ACTION_REGISTRY = {
    'start_scan': _start_scan,
    'get_recent_scans': _get_recent_scans,
    'get_scan_status': _get_scan_status,
    'export_scan': _export_scan,
    'get_subscription_info': _get_subscription_info,
    'get_vulnerability_details': _get_vulnerability_details,
    'navigate_to': _navigate_to,
    'search_learning_center': _search_learning_center,
}

