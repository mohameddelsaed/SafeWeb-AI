import json
import logging
import threading
from django.conf import settings as django_settings
from django.utils import timezone
from django.db.models import Count, Avg, Q
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

from .models import Scan, Vulnerability, Webhook, WebhookDelivery, NucleiTemplate, ScopeDefinition, MultiTargetScan, DiscoveredAsset, ScheduledScan, AssetMonitorRecord, AuthConfig, SharedReport
from .serializers import (
    ScanCreateSerializer,
    ScanURLCreateSerializer,
    ScanDetailSerializer, ScanListSerializer,
    ScanFullCreateSerializer, WebhookSerializer,
    WebhookDeliverySerializer, NucleiTemplateSerializer,
    VulnerabilitySerializer,
    ScopeDefinitionSerializer, MultiTargetScanSerializer,
    DiscoveredAssetSerializer, ScopeImportSerializer, ScopeValidateSerializer,
    ScheduledScanSerializer, AssetMonitorRecordSerializer,
)
from .tasks import execute_scan_task
from apps.accounts.utils import time_ago

logger = logging.getLogger(__name__)


from rest_framework.exceptions import APIException

class ServiceUnavailable(APIException):
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    default_detail = 'Service temporarily unavailable, try again later.'
    default_code = 'service_unavailable'

def _dispatch_scan_task(scan_id: str):
    """Dispatch scan task via Celery. If the broker is unavailable, raise 503."""
    if getattr(django_settings, 'CELERY_TASK_ALWAYS_EAGER', False):
        def _run_scan_in_thread(sid):
            import os
            os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"
            try:
                execute_scan_task(sid)
            except Exception as e:
                logger.error(f'Thread scan failed for {sid}: {e}')
        t = threading.Thread(target=_run_scan_in_thread, args=(scan_id,), daemon=True)
        t.start()
    else:
        try:
            execute_scan_task.delay(scan_id)
        except Exception as e:
            logger.error(f'Failed to dispatch Celery task for scan {scan_id}: {e}')
            from apps.scanning.models import Scan
            try:
                scan = Scan.objects.get(id=scan_id)
                scan.status = 'failed'
                scan.error_message = 'Service temporarily unavailable. Background workers could not be reached.'
                scan.save(update_fields=['status', 'error_message'])
            except Exception:
                pass
            raise ServiceUnavailable(detail="The scanning queue is currently unavailable. Please try again later.")


class WebsiteScanCreateView(views.APIView):
    """POST /api/scan/website — Create a new website scan."""
    from apps.accounts.permissions import CanStartScan
    permission_classes = [IsAuthenticated, CanStartScan]

    def post(self, request):
        serializer = ScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        assert serializer.validated_data is not None
        data = serializer.validated_data

        scope_type = data.get('scope_type', 'single_domain')
        seed_domains = data.get('seed_domains', [])

        # Wide scope starts in pending_confirmation so user can review discovered domains
        initial_status = 'pending_confirmation' if scope_type == 'wide_scope' else 'pending'

        org = request.organization
        if not org and hasattr(request, 'user') and request.user.is_authenticated:
            org_id = request.headers.get('X-Organization-ID') or request.META.get('HTTP_X_ORGANIZATION_ID')
            if org_id:
                from apps.accounts.models import Organization
                org = Organization.objects.filter(id=org_id, memberships__user=request.user).first()
            if not org:
                from apps.accounts.models import OrganizationMembership
                first_mem = OrganizationMembership.objects.filter(user=request.user).first()
                if first_mem:
                    org = first_mem.organization

        scan = Scan.objects.create(
            user=request.user,
            organization=org,
            scan_type='website',
            target=data['target'],
            depth=data.get('scan_depth', 'medium'),
            selected_categories=data.get('selected_categories', []),
            include_subdomains=True,  # Always true for all scope types
            check_ssl=data.get('check_ssl', True),
            follow_redirects=data.get('follow_redirects', True),
            control_external_tools=data.get('control_external_tools', True),
            scope_type=scope_type,
            seed_domains=seed_domains,
            status=initial_status,
        )

        # For single_domain and wildcard: dispatch immediately
        if scope_type != 'wide_scope':
            _dispatch_scan_task(str(scan.id))

        logger.info(f'Website scan created: {scan.id} (scope={scope_type}) for {scan.target} by {request.user.email}')

        return Response({
            'id': str(scan.id),
            'target': scan.target,
            'type': 'website',
            'scopeType': scope_type,
            'controlExternalTools': scan.control_external_tools,
            'status': initial_status,
            'startTime': timezone.now().isoformat(),
            'message': 'Scan initiated. Use GET /api/scan/{id} to check progress.' if scope_type != 'wide_scope' else 'Wide scope scan created. Confirm discovered domains to start scanning.',
        }, status=status.HTTP_201_CREATED)


class ResolveScopeView(views.APIView):
    """POST /api/scan/{id}/resolve — Trigger scope resolution for wide_scope scans.

    Runs OSINT sources to discover domains associated with the target company.
    Updates scan.discovered_domains and returns the list for user confirmation.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        import asyncio
        try:
            scan = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found.'}, status=status.HTTP_404_NOT_FOUND)

        if scan.status != 'pending_confirmation':
            return Response(
                {'detail': f'Scope resolution only available for pending_confirmation scans (current: {scan.status}).'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from .engine.scope import ScopeResolver
        resolver = ScopeResolver()

        try:
            domains = asyncio.run(resolver.resolve(
                scan.scope_type, scan.target, scan.seed_domains,
            ))
        except Exception as exc:
            logger.error(f'Scope resolution failed for scan {id}: {exc}')
            return Response(
                {'detail': f'Scope resolution failed: {str(exc)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        scan.discovered_domains = domains
        scan.save(update_fields=['discovered_domains'])

        logger.info(f'Scope resolved for scan {id}: {len(domains)} domains discovered')
        return Response({
            'id': str(scan.id),
            'discoveredDomains': domains,
            'count': len(domains),
        })


class ConfirmWideScopeView(views.APIView):
    """POST /api/scan/{id}/confirm — Confirm and start a wide_scope scan.

    Accepts a list of selected domains. Creates child scans and dispatches them.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found.'}, status=status.HTTP_404_NOT_FOUND)

        if scan.status != 'pending_confirmation':
            return Response(
                {'detail': f'Confirmation only available for pending_confirmation scans (current: {scan.status}).'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        selected_domains = request.data.get('selectedDomains', scan.discovered_domains)
        if not selected_domains:
            return Response(
                {'detail': 'No domains selected.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Update discovered_domains to reflect user's selection
        scan.discovered_domains = selected_domains
        scan.status = 'scanning'
        scan.started_at = timezone.now()
        scan.save(update_fields=['discovered_domains', 'status', 'started_at'])

        # Create child scans for each selected domain
        child_ids = []
        for domain in selected_domains:
            child = Scan.objects.create(
                user=request.user,
                scan_type='website',
                target=domain,
                depth=scan.depth,
                include_subdomains=True,
                check_ssl=scan.check_ssl,
                follow_redirects=scan.follow_redirects,
                control_external_tools=scan.control_external_tools,
                scope_type='single_domain',
                parent_scan=scan,
                status='pending',
            )
            _dispatch_scan_task(str(child.id))
            child_ids.append(str(child.id))

        logger.info(f'Wide scope confirmed for scan {id}: {len(child_ids)} child scans created')
        return Response({
            'id': str(scan.id),
            'status': 'scanning',
            'childScans': child_ids,
            'count': len(child_ids),
        })


class FileScanCreateView(views.APIView):
    """POST /api/scan/file — Upload and scan a file for malware."""
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        uploaded_file = request.FILES.get('file')
        if not uploaded_file:
            return Response(
                {'detail': 'No file provided.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate file size (50MB)
        if uploaded_file.size > 50 * 1024 * 1024:
            return Response(
                {'detail': 'File size exceeds 50MB limit.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan = Scan.objects.create(
            user=request.user,
            scan_type='file',
            target=uploaded_file.name,
            uploaded_file=uploaded_file,
            status='pending',
        )

        _dispatch_scan_task(str(scan.id))
        logger.info(f'File scan created: {scan.id} for {uploaded_file.name}')

        return Response({
            'id': str(scan.id),
            'target': uploaded_file.name,
            'type': 'file',
            'status': 'pending',
            'startTime': timezone.now().isoformat(),
        }, status=status.HTTP_201_CREATED)


class URLScanCreateView(views.APIView):
    """POST /api/scan/url — Scan a URL for phishing."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanURLCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        scan = Scan.objects.create(
            user=request.user,
            scan_type='url',
            target=serializer.validated_data['url'],  # type: ignore[index]
            status='pending',
        )

        _dispatch_scan_task(str(scan.id))
        logger.info(f'URL scan created: {scan.id} for {scan.target}')

        return Response({
            'id': str(scan.id),
            'target': scan.target,
            'type': 'url',
            'status': 'pending',
            'startTime': timezone.now().isoformat(),
        }, status=status.HTTP_201_CREATED)


class ScanDetailView(generics.RetrieveAPIView):
    """GET /api/scan/{id} — Get scan results."""
    serializer_class = ScanDetailSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):  # type: ignore[override]
        return Scan.objects.filter(user=self.request.user).prefetch_related('vulnerabilities')


class ScanDeleteView(views.APIView):
    """DELETE /api/scan/{id} — Delete a scan."""
    permission_classes = [IsAuthenticated]

    def delete(self, request, id):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
            scan.delete()
            return Response({'detail': 'Scan deleted successfully.'})
        except Scan.DoesNotExist:
            return Response(
                {'detail': 'Scan not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )


class RescanView(views.APIView):
    """POST /api/scan/{id}/rescan — Re-run a scan with same config."""
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            original = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response(
                {'detail': 'Scan not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        new_scan = Scan.objects.create(
            user=request.user,
            scan_type=original.scan_type,
            target=original.target,
            depth=original.depth,
            include_subdomains=original.include_subdomains,
            check_ssl=original.check_ssl,
            follow_redirects=original.follow_redirects,
            control_external_tools=original.control_external_tools,
            status='pending',
        )

        try:
            _dispatch_scan_task(str(new_scan.id))
        except Exception as e:
            logger.error(f'Rescan task failed for {new_scan.id}: {e}')
            # The task/orchestrator already sets status to 'failed' on error,
            # but refresh from DB just in case
            new_scan.refresh_from_db()
            if new_scan.status != 'failed':
                new_scan.status = 'failed'
                new_scan.error_message = str(e)
                new_scan.save(update_fields=['status', 'error_message'])

        # Always return the new scan — frontend will poll for status
        new_scan.refresh_from_db()
        return Response({
            'id': str(new_scan.id),
            'status': new_scan.status,
            'target': new_scan.target,
            'type': new_scan.scan_type,
            'message': 'Re-scan initiated.' if new_scan.status != 'failed' else 'Re-scan completed with errors.',
        }, status=status.HTTP_201_CREATED)


class ScanExportView(views.APIView):
    """GET /api/scan/{id}/export?format=pdf|json|csv"""
    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response(
                {'detail': 'Scan not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        export_format = request.query_params.get('export_format', 'json')

        if export_format == 'json':
            return self._export_json(scan)
        elif export_format == 'csv':
            return self._export_csv(scan)
        elif export_format == 'pdf':
            return self._export_pdf(scan)
        else:
            return Response(
                {'detail': f'Unsupported format: {export_format}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

    def _export_json(self, scan):
        from django.http import JsonResponse
        serializer = ScanDetailSerializer(scan)
        response = JsonResponse(serializer.data, json_dumps_params={'indent': 2})
        response['Content-Disposition'] = f'attachment; filename="safeweb-scan-{scan.id}.json"'
        return response

    def _export_csv(self, scan):
        import csv
        from django.http import HttpResponse
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="safeweb-scan-{scan.id}.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Name', 'Severity', 'Category', 'CWE', 'CVSS',
            'Affected URL', 'Description', 'Impact', 'Remediation',
        ])

        for vuln in scan.vulnerabilities.all():
            writer.writerow([
                vuln.name, vuln.severity, vuln.category, vuln.cwe, vuln.cvss,
                vuln.affected_url, vuln.description, vuln.impact, vuln.remediation,
            ])

        return response

    def _export_pdf(self, scan):
        from django.http import HttpResponse
        try:
            from apps.scanning.engine.report_generator import generate_pdf_report
            pdf_buffer = generate_pdf_report(scan)
        except ImportError:
            logger.error('reportlab is not installed — cannot generate PDF')
            return Response(
                {'detail': 'PDF export is not available. The reportlab package is not installed.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as e:
            logger.error(f'PDF generation failed for scan {scan.id}: {e}')
            return Response(
                {'detail': f'Failed to generate PDF report: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        response = HttpResponse(pdf_buffer, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="safeweb-scan-report-{scan.id}.pdf"'
        return response


# ── Scan List / History ──────────────────────────────

class ScanListView(generics.ListAPIView):
    """GET /api/scans — List user's scan history."""
    serializer_class = ScanListSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):  # type: ignore[override]
        queryset = Scan.objects.filter(user=self.request.user)

        # Search filter
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(target__icontains=search)

        # Status filter
        scan_status = self.request.query_params.get('status')
        if scan_status and scan_status != 'all':
            queryset = queryset.filter(status=scan_status)

        # Type filter
        scan_type = self.request.query_params.get('type')
        if scan_type and scan_type != 'all':
            queryset = queryset.filter(scan_type=scan_type.lower())

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)

        if page is not None:
            serializer = self.get_serializer(page, many=True)
            paginated = self.get_paginated_response(serializer.data)
            # Add stats
            all_scans = Scan.objects.filter(user=request.user)
            paginated.data['stats'] = {
                'total': all_scans.count(),
                'completed': all_scans.filter(status='completed').count(),
                'failed': all_scans.filter(status='failed').count(),
                'avgScore': all_scans.filter(status='completed').aggregate(
                    avg=Avg('score')
                )['avg'] or 0,
            }
            return paginated

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# ── Dashboard ──────────────────────────────

class DashboardView(views.APIView):
    """GET /api/dashboard — Dashboard stats for current user."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        scans = Scan.objects.filter(user=user)
        total_scans = scans.count()
        completed_scans = scans.filter(status='completed')

        # Critical issues count
        critical_count = Vulnerability.objects.filter(
            scan__user=user, severity='critical'
        ).count()

        # Average security score
        avg_score = completed_scans.aggregate(avg=Avg('score'))['avg'] or 0

        # Last scan time
        last_scan = scans.order_by('-created_at').first()
        last_scan_time = time_ago(last_scan.created_at) if last_scan else 'Never'

        # Compute 7-day change percentages
        from django.utils import timezone as tz
        from datetime import timedelta
        week_ago = tz.now() - timedelta(days=7)
        two_weeks_ago = tz.now() - timedelta(days=14)
        scans_this_week = scans.filter(created_at__gte=week_ago).count()
        scans_last_week = scans.filter(created_at__gte=two_weeks_ago, created_at__lt=week_ago).count()
        scans_change = ''
        if scans_last_week > 0:
            pct = ((scans_this_week - scans_last_week) / scans_last_week) * 100
            scans_change = f'+{pct:.1f}%' if pct >= 0 else f'{pct:.1f}%'
        elif scans_this_week > 0:
            scans_change = '+100%'

        critical_this_week = Vulnerability.objects.filter(
            scan__user=user, severity='critical', scan__created_at__gte=week_ago
        ).count()
        critical_last_week = Vulnerability.objects.filter(
            scan__user=user, severity='critical',
            scan__created_at__gte=two_weeks_ago, scan__created_at__lt=week_ago
        ).count()
        critical_change = ''
        if critical_last_week > 0:
            pct = ((critical_this_week - critical_last_week) / critical_last_week) * 100
            critical_change = f'+{pct:.1f}%' if pct >= 0 else f'{pct:.1f}%'
        elif critical_this_week > 0:
            critical_change = '+100%'

        completed_this_week = completed_scans.filter(created_at__gte=week_ago)
        completed_last_week = completed_scans.filter(
            created_at__gte=two_weeks_ago, created_at__lt=week_ago
        )
        score_this = completed_this_week.aggregate(avg=Avg('score'))['avg'] or 0
        score_last = completed_last_week.aggregate(avg=Avg('score'))['avg'] or 0
        score_change = ''
        if score_last > 0:
            pct = ((score_this - score_last) / score_last) * 100
            score_change = f'+{pct:.1f}%' if pct >= 0 else f'{pct:.1f}%'
        elif score_this > 0:
            score_change = 'New'

        # Recent scans (top 5)
        recent = ScanListSerializer(
            scans.order_by('-created_at')[:5], many=True
        ).data

        # Vulnerability overview
        vuln_counts = Vulnerability.objects.filter(scan__user=user).values(
            'severity'
        ).annotate(count=Count('id'))
        vuln_overview = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for item in vuln_counts:
            vuln_overview[item['severity']] = item['count']

        return Response({
            'stats': {
                'totalScans': total_scans,
                'criticalIssues': critical_count,
                'securityScore': round(avg_score),
                'lastScan': last_scan_time,
                'scansChange': scans_change,
                'criticalChange': critical_change,
                'scoreChange': score_change,
            },
            'recentScans': recent,
            'vulnerabilityOverview': vuln_overview,
        })


# ─────────────────────────── Phase 44: API-First Architecture ───────────────


class ScanCreateFullView(views.APIView):
    """
    POST /api/scans/
    Create a scan with full configuration: profile, auth config, scope,
    and scan mode.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ScanFullCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        assert serializer.validated_data is not None
        data = serializer.validated_data

        scan = Scan.objects.create(
            user=request.user,
            scan_type='website',
            target=data['url'],
            depth=data['scan_depth'],
            include_subdomains=data['include_subdomains'],
            check_ssl=data['check_ssl'],
            follow_redirects=data['follow_redirects'],
            control_external_tools=data.get('control_external_tools', True),
            mode=data.get('scan_mode', 'standard'),
            status='pending',
            recon_data={
                'profile': data.get('profile', ''),
                'scope': data.get('scope', []),
            },
        )

        # Store auth config if provided
        auth_cfg = data.get('auth_config')
        if auth_cfg:
            from .models import AuthConfig
            AuthConfig.objects.create(
                scan=scan,
                auth_type=auth_cfg.get('auth_type', 'custom'),
                role=auth_cfg.get('role', 'attacker'),
                config_data=auth_cfg,
            )

        _dispatch_scan_task(str(scan.id))
        logger.info(f'Full-config scan created: {scan.id} by {request.user}')

        return Response({
            'id': str(scan.id),
            'target': scan.target,
            'type': 'website',
            'status': 'pending',
            'controlExternalTools': scan.control_external_tools,
            'mode': scan.mode,
            'profile': data.get('profile', ''),
            'startTime': timezone.now().isoformat(),
        }, status=status.HTTP_201_CREATED)


class ScanFindingsListView(generics.ListAPIView):
    """
    GET /api/scans/<id>/findings/
    Paginated findings list with severity/category/verified filters.
    """
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):  # type: ignore[override]
        scan_id = self.kwargs['id']
        try:
            scan = Scan.objects.get(id=scan_id, user=self.request.user)
        except Scan.DoesNotExist:
            return Vulnerability.objects.none()

        qs = scan.vulnerabilities.all()

        severity = self.request.query_params.get('severity')
        if severity:
            qs = qs.filter(severity__in=severity.split(','))

        category = self.request.query_params.get('category')
        if category:
            qs = qs.filter(category__icontains=category)

        verified = self.request.query_params.get('verified')
        if verified is not None:
            qs = qs.filter(verified=(verified.lower() == 'true'))

        search = self.request.query_params.get('search')
        if search:
            qs = qs.filter(
                Q(name__icontains=search) | Q(description__icontains=search)
            )

        return qs


class RescanFindingView(views.APIView):
    """
    POST /api/scans/<id>/rescan-finding/
    Re-test a specific finding by id.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found.'}, status=status.HTTP_404_NOT_FOUND)

        finding_id = request.data.get('finding_id')
        if not finding_id:
            return Response({'detail': 'finding_id is required.'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            finding = scan.vulnerabilities.get(id=finding_id)
        except Vulnerability.DoesNotExist:
            return Response({'detail': 'Finding not found.'}, status=status.HTTP_404_NOT_FOUND)

        # Create a targeted rescan for this single finding
        new_scan = Scan.objects.create(
            user=request.user,
            scan_type=scan.scan_type,
            target=finding.affected_url or scan.target,
            depth=scan.depth,
            include_subdomains=False,
            check_ssl=scan.check_ssl,
            follow_redirects=scan.follow_redirects,
            control_external_tools=scan.control_external_tools,
            mode='standard',
            status='pending',
            recon_data={'rescan_finding': str(finding.id), 'parent_scan': str(scan.id)},
            parent_scan=scan,
        )
        _dispatch_scan_task(str(new_scan.id))

        return Response({
            'id': str(new_scan.id),
            'finding_id': str(finding.id),
            'finding_name': finding.name,
            'status': 'pending',
            'message': f'Re-scan initiated for finding "{finding.name}".',
        }, status=status.HTTP_201_CREATED)


class ScanCompareView(views.APIView):
    """
    GET /api/scans/compare/<id1>/<id2>/
    Diff two scans and return new / fixed / regressed findings.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, id1, id2):
        try:
            scan_a = Scan.objects.get(id=id1, user=request.user)
            scan_b = Scan.objects.get(id=id2, user=request.user)
        except Scan.DoesNotExist:
            return Response({'detail': 'One or both scans not found.'}, status=status.HTTP_404_NOT_FOUND)

        from .engine.scan_comparison import ScanComparison

        findings_a = list(scan_a.vulnerabilities.values(
            'name', 'category', 'severity', 'cvss', 'affected_url',
        ))
        findings_b = list(scan_b.vulnerabilities.values(
            'name', 'category', 'severity', 'cvss', 'affected_url',
        ))

        result = ScanComparison(findings_a, findings_b).compare()
        d = result.to_dict()
        d['scan_a'] = str(scan_a.id)
        d['scan_b'] = str(scan_b.id)
        d['improved'] = result.improved
        return Response(d)


class ScanExportFormatView(views.APIView):
    """
    POST /api/scans/<id>/export/<format>/
    Export scan to pdf | json | sarif | csv | html.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id, fmt):
        try:
            scan = Scan.objects.get(id=id, user=request.user)
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found.'}, status=status.HTTP_404_NOT_FOUND)

        fmt = fmt.lower()
        handlers = {
            'json': self._export_json,
            'csv': self._export_csv,
            'pdf': self._export_pdf,
            'sarif': self._export_sarif,
            'html': self._export_html,
        }
        handler = handlers.get(fmt)
        if not handler:
            return Response(
                {'detail': f'Unsupported format: {fmt!r}. Use: json, csv, pdf, sarif, html'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return handler(scan)

    def _export_json(self, scan):
        from django.http import JsonResponse
        serializer = ScanDetailSerializer(scan)
        resp = JsonResponse(serializer.data, json_dumps_params={'indent': 2})
        resp['Content-Disposition'] = f'attachment; filename="safeweb-{scan.id}.json"'
        return resp

    def _export_csv(self, scan):
        import csv
        from django.http import HttpResponse
        resp = HttpResponse(content_type='text/csv')
        resp['Content-Disposition'] = f'attachment; filename="safeweb-{scan.id}.csv"'
        writer = csv.writer(resp)
        writer.writerow(['Name', 'Severity', 'Category', 'CWE', 'CVSS', 'URL', 'Description'])
        for v in scan.vulnerabilities.all():
            writer.writerow([v.name, v.severity, v.category, v.cwe, v.cvss, v.affected_url, v.description])
        return resp

    def _export_pdf(self, scan):
        from django.http import HttpResponse
        try:
            from apps.scanning.engine.report_generator import generate_pdf_report
            pdf_buffer = generate_pdf_report(scan)
        except ImportError:
            return Response(
                {'detail': 'PDF export unavailable: reportlab not installed.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        except Exception as exc:
            return Response(
                {'detail': f'PDF generation failed: {exc}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        resp = HttpResponse(pdf_buffer, content_type='application/pdf')
        resp['Content-Disposition'] = f'attachment; filename="safeweb-{scan.id}.pdf"'
        return resp

    def _export_sarif(self, scan):
        """Export as SARIF 2.1.0 (Static Analysis Results Interchange Format)."""
        from django.http import JsonResponse

        rules = []
        results = []
        rule_ids_seen = set()

        for vuln in scan.vulnerabilities.all():
            rule_id = f'{vuln.category}-{vuln.cwe}' if vuln.cwe else vuln.category
            if rule_id not in rule_ids_seen:
                rules.append({
                    'id': rule_id,
                    'name': vuln.name,
                    'shortDescription': {'text': vuln.name},
                    'fullDescription': {'text': vuln.description},
                    'helpUri': f'https://cwe.mitre.org/data/definitions/{vuln.cwe.replace("CWE-", "")}.html' if vuln.cwe else '',
                    'properties': {'severity': vuln.severity, 'cvss': vuln.cvss},
                })
                rule_ids_seen.add(rule_id)

            _SARIF_LEVELS = {
                'critical': 'error', 'high': 'error',
                'medium': 'warning', 'low': 'note', 'info': 'note',
            }
            results.append({
                'ruleId': rule_id,
                'level': _SARIF_LEVELS.get(vuln.severity, 'warning'),
                'message': {'text': vuln.description},
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {'uri': vuln.affected_url or scan.target},
                    },
                }],
                'properties': {'severity': vuln.severity, 'cvss': vuln.cvss, 'cwe': vuln.cwe},
            })

        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'SafeWeb AI',
                        'version': '1.0',
                        'informationUri': 'https://safeweb.ai',
                        'rules': rules,
                    },
                },
                'results': results,
            }],
        }
        resp = JsonResponse(sarif, json_dumps_params={'indent': 2})
        resp['Content-Disposition'] = f'attachment; filename="safeweb-{scan.id}.sarif"'
        return resp

    def _export_html(self, scan):
        from django.http import HttpResponse
        vulns = scan.vulnerabilities.all()
        rows = ''.join(
            f'<tr><td>{v.name}</td><td>{v.severity}</td><td>{v.category}</td>'
            f'<td>{v.cvss}</td><td>{v.affected_url or "-"}</td></tr>'
            for v in vulns
        )
        html = (
            f'<!DOCTYPE html><html><head><meta charset="utf-8">'
            f'<title>SafeWeb Scan Report</title></head><body>'
            f'<h1>Scan Report: {scan.target}</h1>'
            f'<p>Status: {scan.status} | Score: {scan.score}</p>'
            f'<table border="1"><tr><th>Name</th><th>Severity</th>'
            f'<th>Category</th><th>CVSS</th><th>URL</th></tr>'
            f'{rows}</table></body></html>'
        )
        resp = HttpResponse(html, content_type='text/html')
        resp['Content-Disposition'] = f'attachment; filename="safeweb-{scan.id}.html"'
        return resp


def _get_historical_phase_averages(depth: str = 'medium', control_external_tools: bool = True) -> dict:
    """Return average seconds per phase from the last 10 completed scans.

    Used by ScanStreamView to compute estimated remaining time.
    Falls back to depth-based preset defaults if no history is available.
    """
    defaults_with_tools = {
        'shallow':  {'recon': 90,  'crawling': 120, 'analysis': 35, 'testing': 240,  'testing_verification': 60,  'nuclei_templates': 120, 'secret_scanning': 45,  'integrated_scanners': 180, 'verification': 90,  'correlation': 20},
        'medium':   {'recon': 240, 'crawling': 360, 'analysis': 60, 'testing': 900,  'testing_verification': 180, 'nuclei_templates': 360, 'secret_scanning': 90,  'integrated_scanners': 420, 'verification': 180, 'correlation': 30},
        'deep':     {'recon': 600, 'crawling': 960, 'analysis': 90, 'testing': 2100, 'testing_verification': 360, 'nuclei_templates': 900, 'secret_scanning': 150, 'integrated_scanners': 900, 'verification': 300, 'correlation': 45},
    }
    defaults_without_tools = {
        'shallow':  {'recon': 35,  'crawling': 70,  'analysis': 20, 'testing': 120, 'testing_verification': 30,  'nuclei_templates': 0, 'secret_scanning': 30,  'integrated_scanners': 0, 'verification': 45,  'correlation': 10},
        'medium':   {'recon': 80,  'crawling': 180, 'analysis': 35, 'testing': 420, 'testing_verification': 90,  'nuclei_templates': 0, 'secret_scanning': 60,  'integrated_scanners': 0, 'verification': 90,  'correlation': 15},
        'deep':     {'recon': 180, 'crawling': 420, 'analysis': 50, 'testing': 900, 'testing_verification': 180, 'nuclei_templates': 0, 'secret_scanning': 120, 'integrated_scanners': 0, 'verification': 180, 'correlation': 20},
    }
    defaults = defaults_with_tools if control_external_tools else defaults_without_tools
    fallback = defaults.get(depth, defaults['medium'])
    try:
        recent = Scan.objects.filter(
            status='completed', depth=depth, control_external_tools=control_external_tools,
        ).exclude(phase_timings={}).order_by('-created_at')[:10]
        if not recent:
            return fallback
        aggregated: dict[str, list] = {}
        for s in recent:
            for phase, dur in (s.phase_timings or {}).items():
                aggregated.setdefault(phase, []).append(float(dur))
        return {phase: sum(vals) / len(vals) for phase, vals in aggregated.items()} or fallback
    except Exception:
        return fallback


# Phase ordering for ETA calculation (phases in execution order)
_PHASE_ORDER = [
    'pre_scan_checks', 'reconnaissance', 'crawling', 'analyzing',
    'testing', 'testing_verification', 'oob_polling',
    'nuclei_templates', 'secret_scanning', 'integrated_scanners',
    'verification', 'exploit_gen', 'correlation', 'chaining', 'fp_reduction',
    'saving',
]


class ScanStreamView(views.APIView):
    """
    GET /api/scans/<id>/stream/
    Server-Sent Events stream for real-time scan status and findings.
    Polls the DB every 2 s and emits named events until the scan finishes.

    Enhanced payload includes:
      progress — percent, currentPhase, currentTool, status,
                 startedAt, elapsedSeconds, estimatedRemainingSeconds, findingCount
      finding  — emitted when new vulnerabilities are saved (totalFindings, newCount, phase)
      completed — final status + score
    """
    authentication_classes = []  # Header auth is accepted via request.user; token fallback for EventSource.
    permission_classes = []

    def perform_content_negotiation(self, request, force=False):
        """SSE endpoint — bypass DRF content negotiation.
        The actual response is a StreamingHttpResponse; use JSON for errors."""
        from rest_framework.renderers import JSONRenderer
        return (JSONRenderer(), 'application/json')

    def get(self, request, id):
        import time as _time
        from django.http import StreamingHttpResponse
        from rest_framework_simplejwt.tokens import AccessToken
        from django.contrib.auth import get_user_model

        # Support both normal authenticated requests (tests/clients that send
        # Authorization header) and EventSource token query parameter fallback.
        user = getattr(request, 'user', None)
        if not user or not user.is_authenticated:
            token_str = request.GET.get('token', '')
            if not token_str:
                return Response({'detail': 'Authentication token required.'}, status=status.HTTP_401_UNAUTHORIZED)
            try:
                validated = AccessToken(token_str)
                User = get_user_model()
                user = User.objects.get(id=validated['user_id'])
            except Exception:
                return Response({'detail': 'Invalid or expired token.'}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            scan_obj = Scan.objects.get(id=id, user=user)
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found.'}, status=status.HTTP_404_NOT_FOUND)

        user_id = user.id
        scan_depth = scan_obj.depth

        # Pre-compute historical phase averages once per connection
        hist_avgs = _get_historical_phase_averages(scan_depth, scan_obj.control_external_tools)

        def event_stream():
            _TERMINAL = {'completed', 'failed', 'error', 'cancelled'}
            _MAX_SECONDS = 14400  # 4-hour cap for deep scans
            last_progress = -1
            last_phase: str | None = None
            last_tool: str | None = None
            last_vuln_count = -1
            last_data_version = -1
            last_flow_status: str | None = None
            last_log_len = -1
            deadline = _time.monotonic() + _MAX_SECONDS

            while _time.monotonic() < deadline:
                try:
                    snap = Scan.objects.get(id=id, user_id=user_id)
                except Exception:
                    yield f'event: error\ndata: {json.dumps({"message": "Scan not found"})}\n\n'
                    return

                progress_changed = snap.progress != last_progress
                phase_changed = snap.current_phase != last_phase
                tool_changed = snap.current_tool != last_tool
                data_version_changed = snap.data_version != last_data_version

                # ── Elapsed / ETA ──────────────────────────────────────────
                elapsed_seconds = 0
                estimated_remaining = 0
                started_at_iso = None
                if snap.started_at:
                    from django.utils import timezone as _tz
                    elapsed_seconds = int((_tz.now() - snap.started_at).total_seconds())
                    started_at_iso = snap.started_at.isoformat()

                    # Estimate remaining time from historical phase averages
                    current_phase_name = snap.current_phase or ''
                    try:
                        idx = _PHASE_ORDER.index(current_phase_name)
                        remaining_phases = _PHASE_ORDER[idx + 1:]
                        estimated_remaining = sum(
                            hist_avgs.get(p, 0) for p in remaining_phases
                        )
                        # Add remaining fraction of the current phase
                        current_phase_avg = hist_avgs.get(current_phase_name, 0)
                        phase_progress_estimate = (snap.progress - (snap.progress * 0.1)) / 100
                        estimated_remaining += current_phase_avg * max(0, 1 - phase_progress_estimate)
                        estimated_remaining = int(estimated_remaining)
                    except ValueError:
                        estimated_remaining = 0

                # ── Current finding count ──────────────────────────────────
                vuln_count = snap.vulnerabilities.count()

                if phase_changed and snap.current_phase:
                    yield (
                        f'event: phase_change\ndata: '
                        f'{json.dumps({"phase": snap.current_phase})}\n\n'
                    )

                if progress_changed or phase_changed or tool_changed:
                    payload = {
                        'id': str(snap.id),
                        'progress': snap.progress,
                        'currentPhase': snap.current_phase,
                        'currentTool': snap.current_tool,
                        'status': snap.status,
                        'startedAt': started_at_iso,
                        'elapsedSeconds': elapsed_seconds,
                        'estimatedRemainingSeconds': estimated_remaining,
                        'findingCount': vuln_count,
                        'pagesCrawled': snap.pages_crawled,
                        'totalRequests': snap.total_requests,
                        'dataVersion': snap.data_version,
                    }
                    yield f'event: progress\ndata: {json.dumps(payload)}\n\n'
                    last_progress = snap.progress
                    last_phase = snap.current_phase
                    last_tool = snap.current_tool

                # ── Finding notification (new vulns saved to DB) ───────────
                if vuln_count != last_vuln_count and vuln_count > 0:
                    new_count = vuln_count - max(last_vuln_count, 0)
                    summary = {
                        sev: snap.vulnerabilities.filter(severity=sev).count()
                        for sev in ('critical', 'high', 'medium', 'low', 'info')
                        if snap.vulnerabilities.filter(severity=sev).exists()
                    }
                    finding_payload = {
                        'totalFindings': vuln_count,
                        'newCount': new_count,
                        'phase': snap.current_phase,
                        'summary': summary,
                    }
                    yield f'event: finding\ndata: {json.dumps(finding_payload)}\n\n'
                    last_vuln_count = vuln_count

                # ── data_update: recon_data or tester_results changed ──────
                if data_version_changed and last_data_version != -1:
                    yield (
                        f'event: data_update\ndata: '
                        f'{json.dumps({"dataVersion": snap.data_version})}\n\n'
                    )
                last_data_version = snap.data_version

                # ── agent_activity: multi-agent LangGraph telemetry ────────
                current_log_len = len(snap.engagement_log or [])
                if snap.flow_status != last_flow_status or current_log_len != last_log_len:
                    agent_payload = {
                        "flowStatus": snap.flow_status,
                        "costMeterUsd": float(snap.cost_meter_usd or 0.0),
                        "engagementLog": snap.engagement_log or [],
                        "taskGraph": snap.task_graph or {}
                    }
                    yield f'event: agent_activity\ndata: {json.dumps(agent_payload)}\n\n'
                    last_flow_status = snap.flow_status
                    last_log_len = current_log_len

                if snap.status in _TERMINAL:
                    yield (
                        f'event: completed\ndata: '
                        f'{json.dumps({"id": str(snap.id), "status": snap.status, "score": snap.score})}\n\n'
                    )
                    return

                _time.sleep(2)

            yield f'event: error\ndata: {json.dumps({"message": "Stream timeout"})}\n\n'

        response = StreamingHttpResponse(
            event_stream(), content_type='text/event-stream',
        )
        response['Cache-Control'] = 'no-cache'
        response['X-Accel-Buffering'] = 'no'
        return response


class NucleiTemplateListView(generics.ListAPIView):
    """
    GET /api/templates/
    List all active Nuclei templates (custom uploaded ones).
    Also includes a set of built-in template category stubs.
    """
    serializer_class = NucleiTemplateSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):  # type: ignore[override]
        return NucleiTemplate.objects.filter(is_active=True).order_by('-created_at')

    def list(self, request, *args, **kwargs):
        custom_qs = self.get_queryset()
        custom_data = self.get_serializer(custom_qs, many=True).data

        # Built-in category stubs
        builtin = [
            {'id': 'builtin-sqli', 'name': 'SQL Injection Templates', 'category': 'sqli',
             'severity': 'high', 'content': '', 'description': 'Built-in SQL injection probes',
             'uploaded_by': None, 'is_active': True, 'created_at': None},
            {'id': 'builtin-xss', 'name': 'XSS Templates', 'category': 'xss',
             'severity': 'medium', 'content': '', 'description': 'Built-in XSS detection templates',
             'uploaded_by': None, 'is_active': True, 'created_at': None},
            {'id': 'builtin-ssrf', 'name': 'SSRF Templates', 'category': 'ssrf',
             'severity': 'high', 'content': '', 'description': 'Built-in SSRF detection',
             'uploaded_by': None, 'is_active': True, 'created_at': None},
            {'id': 'builtin-lfi', 'name': 'LFI Templates', 'category': 'lfi',
             'severity': 'high', 'content': '', 'description': 'Built-in path traversal/LFI probes',
             'uploaded_by': None, 'is_active': True, 'created_at': None},
            {'id': 'builtin-misconfig', 'name': 'Misconfiguration Templates', 'category': 'misconfig',
             'severity': 'medium', 'content': '', 'description': 'Built-in server misconfiguration checks',
             'uploaded_by': None, 'is_active': True, 'created_at': None},
        ]

        return Response({'builtin': builtin, 'custom': list(custom_data)})


class NucleiTemplateUploadView(views.APIView):
    """
    POST /api/templates/custom/
    Upload a custom Nuclei YAML template.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        name = request.data.get('name', '').strip()
        content = request.data.get('content', '')

        # Accept file upload or raw content field
        uploaded_file = request.FILES.get('file')
        if uploaded_file:
            content = uploaded_file.read().decode('utf-8', errors='replace')
            if not name:
                name = uploaded_file.name

        if not name:
            return Response({'detail': 'name is required.'}, status=status.HTTP_400_BAD_REQUEST)
        if not content:
            return Response({'detail': 'Template content is required.'}, status=status.HTTP_400_BAD_REQUEST)

        template = NucleiTemplate.objects.create(
            name=name,
            description=request.data.get('description', ''),
            category=request.data.get('category', 'custom'),
            severity=request.data.get('severity', 'medium'),
            content=content,
            uploaded_by=request.user,
        )
        logger.info(f'Custom Nuclei template uploaded: {template.id} by {request.user}')
        return Response(
            NucleiTemplateSerializer(template).data,
            status=status.HTTP_201_CREATED,
        )


class ScanProfileListView(views.APIView):
    """
    GET /api/profiles/
    List available scan profiles from the engine registry.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from .engine.profiles import list_profiles
        profiles = list_profiles()
        data = []
        for p in profiles:
            data.append({
                'id': p.id,
                'name': p.name,
                'description': getattr(p, 'description', ''),
                'depth': p.depth,
                'stealth_level': getattr(p, 'stealth_level', 0),
                'max_duration_minutes': getattr(p, 'max_duration_minutes', None),
                'enabled_testers': list(getattr(p, 'testers', None) or []),
                'nuclei_tags': list(getattr(p, 'nuclei_tags', None) or []),
            })
        return Response({'count': len(data), 'profiles': data})


class AuthConfigCreateView(views.APIView):
    """
    POST /api/auth-configs/
    Save an authentication configuration for use in future scans.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        auth_type = request.data.get('auth_type', 'custom')
        config_data = request.data.get('config_data', {})

        if not config_data:
            return Response(
                {'detail': 'config_data is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        kwargs = {
            'auth_type': auth_type,
            'role': request.data.get('role', 'attacker'),
            'config_data': config_data,
        }

        if scan_id:
            try:
                scan = Scan.objects.get(id=scan_id, user=request.user)
                kwargs['scan'] = scan
            except Scan.DoesNotExist:
                return Response(
                    {'detail': 'Scan not found.'},
                    status=status.HTTP_404_NOT_FOUND,
                )
        else:
            # Create a placeholder scan entry for storing the auth config
            placeholder = Scan.objects.create(
                user=request.user,
                scan_type='website',
                target='auth-config-placeholder',
                status='pending',
            )
            kwargs['scan'] = placeholder

        auth_config = AuthConfig.objects.create(**kwargs)
        return Response({
            'id': str(auth_config.id),
            'auth_type': auth_config.auth_type,
            'scan_id': str(auth_config.scan_id) if auth_config.scan_id else None,
            'created_at': auth_config.created_at.isoformat(),
        }, status=status.HTTP_201_CREATED)


class WebhookListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/webhooks/  — List user's webhooks.
    POST /api/webhooks/  — Create a new webhook.
    """
    serializer_class = WebhookSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):  # type: ignore[override]
        return Webhook.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class WebhookDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/webhooks/<id>/  — Get webhook detail.
    PATCH  /api/webhooks/<id>/  — Update webhook.
    DELETE /api/webhooks/<id>/  — Delete webhook.
    """
    serializer_class = WebhookSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):  # type: ignore[override]
        return Webhook.objects.filter(user=self.request.user)


class WebhookTestView(views.APIView):
    """
    POST /api/webhooks/<id>/test/
    Send a test event to the webhook endpoint.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            webhook = Webhook.objects.get(id=id, user=request.user)
        except Webhook.DoesNotExist:
            return Response({'detail': 'Webhook not found.'}, status=status.HTTP_404_NOT_FOUND)

        from .engine.webhooks import fire_webhook
        test_payload = {
            'event': 'test',
            'message': 'SafeWeb AI webhook test',
            'webhook_id': str(webhook.id),
        }
        success = fire_webhook(webhook, 'test', test_payload)
        return Response({
            'delivered': success,
            'webhook_url': webhook.url,
            'event': 'test',
        })


class WebhookDeliveryListView(generics.ListAPIView):
    """
    GET /api/webhooks/<id>/deliveries/
    List delivery attempts for a webhook.
    """
    serializer_class = WebhookDeliverySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):  # type: ignore[override]
        webhook_id = self.kwargs['id']
        try:
            webhook = Webhook.objects.get(id=webhook_id, user=self.request.user)
        except Webhook.DoesNotExist:
            return WebhookDelivery.objects.none()
        return webhook.deliveries.all()


# ── Phase 45: Multi-Target & Scope Management ───────────────────────────────

class ScopeDefinitionListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/scan/scopes/  — list the authenticated user’s scope definitions
    POST /api/scan/scopes/  — create a new scope definition
    """
    serializer_class = ScopeDefinitionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ScopeDefinition.objects.filter(user=self.request.user)


class ScopeDefinitionDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/scan/scopes/<id>/  — retrieve a scope definition
    PATCH  /api/scan/scopes/<id>/  — partial update
    DELETE /api/scan/scopes/<id>/  — delete
    """
    serializer_class = ScopeDefinitionSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        return ScopeDefinition.objects.filter(user=self.request.user)


class ScopeValidateView(views.APIView):
    """
    POST /api/scan/scopes/<id>/validate/
    Body: {"url": "https://app.example.com/login"}
    Returns: {in_scope: bool, host: str, matched_pattern: str|null, reason: str}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            scope = ScopeDefinition.objects.get(id=id, user=request.user)
        except ScopeDefinition.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        ser = ScopeValidateSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        from .engine.scope import ScopeManager
        sm = ScopeManager.from_scope_definition(scope)
        result = sm.check_target(ser.validated_data['url'])
        return Response(result)


class ScopeImportView(views.APIView):
    """
    POST /api/scan/scopes/import/
    Accepts a HackerOne / Bugcrowd / plain-text payload and creates a
    ScopeDefinition plus returns the parsed target list.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ser = ScopeImportSerializer(data=request.data)
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        from .engine.scope import TargetImporter
        platform = ser.validated_data['platform']
        raw_data = ser.validated_data.get('raw_data') or {}
        raw_text = ser.validated_data.get('raw_text', '')

        if platform == 'hackerone':
            targets, scope_dict = TargetImporter.from_hackerone(raw_data)
        elif platform == 'bugcrowd':
            targets, scope_dict = TargetImporter.from_bugcrowd(raw_data)
        else:  # text
            targets = TargetImporter.from_text(raw_text)
            scope_dict = {'in_scope': targets, 'out_of_scope': []}

        scope = ScopeDefinition.objects.create(
            user=request.user,
            name=ser.validated_data['name'],
            organization=ser.validated_data.get('organization', ''),
            in_scope=scope_dict['in_scope'],
            out_of_scope=scope_dict['out_of_scope'],
            import_format=platform,
        )

        return Response({
            'scope': ScopeDefinitionSerializer(scope, context={'request': request}).data,
            'parsed_targets': targets,
            'total': len(targets),
        }, status=status.HTTP_201_CREATED)


class MultiTargetScanListView(generics.ListAPIView):
    """
    GET /api/scan/multi/  — list the authenticated user’s multi-target scans
    """
    serializer_class = MultiTargetScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return MultiTargetScan.objects.filter(user=self.request.user)


class MultiTargetScanCreateView(views.APIView):
    """
    POST /api/scan/multi/create/
    Creates a MultiTargetScan and kicks off individual scans per target.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        ser = MultiTargetScanSerializer(data=request.data, context={'request': request})
        if not ser.is_valid():
            return Response(ser.errors, status=status.HTTP_400_BAD_REQUEST)

        targets = ser.validated_data.get('targets', [])
        if not targets:
            return Response({'detail': 'At least one target is required.'}, status=status.HTTP_400_BAD_REQUEST)

        # Optional scope filtering
        scope_obj = ser.validated_data.get('scope')
        if scope_obj:
            from .engine.scope import ScopeManager
            sm = ScopeManager.from_scope_definition(scope_obj)
            targets = sm.filter_in_scope(targets)
            if not targets:
                return Response(
                    {'detail': 'All provided targets were filtered out by the scope definition.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        multi_scan = MultiTargetScan.objects.create(
            user=request.user,
            name=ser.validated_data['name'],
            targets=targets,
            scope=scope_obj,
            scan_depth=ser.validated_data.get('scan_depth', 'medium'),
            parallel_limit=ser.validated_data.get('parallel_limit', 3),
            total_targets=len(targets),
            status='running',
        )

        # Create and queue individual scans
        from .engine.scope import TargetImporter
        for target in targets:
            asset_type = TargetImporter.classify_asset(target)
            scan = Scan.objects.create(
                user=request.user,
                target=target,
                scan_type='website',
                status='pending',
            )
            multi_scan.sub_scans.add(scan)
            _dispatch_scan_task(str(scan.id))

            # Upsert the discovered asset record
            DiscoveredAsset.objects.update_or_create(
                user=request.user,
                url=target,
                defaults={
                    'organization': scope_obj.organization if scope_obj else '',
                    'asset_type': asset_type,
                    'is_new': True,
                    'last_scan': scan,
                },
            )

        return Response(
            MultiTargetScanSerializer(multi_scan, context={'request': request}).data,
            status=status.HTTP_201_CREATED,
        )


class MultiTargetScanDetailView(generics.RetrieveAPIView):
    """
    GET /api/scan/multi/<id>/  — retrieve a multi-target scan with progress
    """
    serializer_class = MultiTargetScanSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        return MultiTargetScan.objects.filter(user=self.request.user)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        # Sync status from sub-scans dynamically
        sub_scans = list(instance.sub_scans.all())
        if sub_scans:
            statuses = [s.status for s in sub_scans]
            completed = sum(1 for s in statuses if s == 'completed')
            failed = sum(1 for s in statuses if s == 'failed')
            instance.completed_targets = completed
            instance.failed_targets = failed
            if completed + failed == len(sub_scans):
                instance.status = 'partial' if failed else 'completed'
                if not instance.completed_at:
                    instance.completed_at = timezone.now()
            instance.save(update_fields=['completed_targets', 'failed_targets', 'status', 'completed_at'])

        data = MultiTargetScanSerializer(instance, context={'request': request}).data
        data['sub_scans'] = ScanListSerializer(sub_scans, many=True).data
        return Response(data)


class AssetInventoryListView(generics.ListAPIView):
    """
    GET /api/scan/assets/?organization=&asset_type=&is_new=
    List discovered assets for the authenticated user.
    """
    serializer_class = DiscoveredAssetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = DiscoveredAsset.objects.filter(user=self.request.user)
        org = self.request.query_params.get('organization')
        asset_type = self.request.query_params.get('asset_type')
        is_new = self.request.query_params.get('is_new')
        if org:
            qs = qs.filter(organization__icontains=org)
        if asset_type:
            qs = qs.filter(asset_type=asset_type)
        if is_new is not None:
            qs = qs.filter(is_new=is_new.lower() in ('true', '1', 'yes'))
        return qs


class AssetInventoryDetailView(generics.RetrieveUpdateAPIView):
    """
    GET   /api/scan/assets/<id>/  — retrieve asset detail
    PATCH /api/scan/assets/<id>/  — update notes / is_new / is_active
    """
    serializer_class = DiscoveredAssetSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        return DiscoveredAsset.objects.filter(user=self.request.user)


# ── End Phase 45 ────────────────────────────────────────────────────────────────────────────────────────


# -- Phase 43/48 Sync: Scheduled Scans -- ------------------------------------

class ScheduledScanListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/scan/scheduled/  � list user's scheduled scans
    POST /api/scan/scheduled/  � create a new scheduled scan
    """
    serializer_class = ScheduledScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ScheduledScan.objects.filter(user=self.request.user).order_by('-created_at')


class ScheduledScanDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/scan/scheduled/<id>/  � retrieve
    PATCH  /api/scan/scheduled/<id>/  � update (including is_active toggle)
    DELETE /api/scan/scheduled/<id>/  � delete
    """
    serializer_class = ScheduledScanSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        return ScheduledScan.objects.filter(user=self.request.user)


# -- Phase 43/48 Sync: Asset Monitor Records ----------------------------------

class AssetMonitorRecordListView(generics.ListAPIView):
    """
    GET /api/scan/asset-monitor/?acknowledged=false  � list change records
    """
    serializer_class = AssetMonitorRecordSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = AssetMonitorRecord.objects.filter(
            scheduled_scan__user=self.request.user,
        )
        acknowledged = self.request.query_params.get('acknowledged')
        if acknowledged is not None:
            qs = qs.filter(acknowledged=acknowledged.lower() in ('true', '1', 'yes'))
        return qs


class AssetMonitorRecordAcknowledgeView(views.APIView):
    """
    POST /api/scan/asset-monitor/<id>/acknowledge/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        try:
            record = AssetMonitorRecord.objects.get(
                id=id, scheduled_scan__user=request.user,
            )
        except AssetMonitorRecord.DoesNotExist:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        record.acknowledged = True
        record.save(update_fields=['acknowledged'])
        return Response({'status': 'acknowledged'})


# -- Finding-level detail (false positive marking) ----------------------------

class FindingDetailView(generics.RetrieveUpdateAPIView):
    """
    GET   /api/scan/<scan_id>/findings/<vuln_id>/  � retrieve single finding
    PATCH /api/scan/<scan_id>/findings/<vuln_id>/  � mark false positive etc.
    """
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]
    lookup_url_kwarg = 'vuln_id'

    def get_queryset(self):
        return Vulnerability.objects.filter(
            scan__id=self.kwargs['scan_id'],
            scan__user=self.request.user,
        )

    def get_object(self):
        return generics.get_object_or_404(
            self.get_queryset(),
            id=self.kwargs['vuln_id'],
        )


# -- Nuclei template detail (toggle / delete) ---------------------------------

class NucleiTemplateDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/scan/nuclei-templates/<id>/
    PATCH  /api/scan/nuclei-templates/<id>/  � toggle is_active
    DELETE /api/scan/nuclei-templates/<id>/
    """
    serializer_class = NucleiTemplateSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'id'

    def get_queryset(self):
        return NucleiTemplate.objects.filter(uploaded_by=self.request.user)


class NucleiTemplateStatsView(views.APIView):
    """
    GET /api/scan/nuclei-templates/stats/
    Returns indexing stats for the community Nuclei template collection.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            from apps.scanning.engine.nuclei.template_manager import TemplateManager
            mgr = TemplateManager()
            mgr.setup(clone=False)
            return Response(mgr.get_stats())
        except Exception as exc:
            return Response({'error': str(exc)}, status=500)


class NucleiTemplateUpdateView(views.APIView):
    """
    POST /api/scan/nuclei-templates/update/
    Triggers a clone/pull of the community template repository.
    Returns indexing stats when done.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            from apps.scanning.engine.nuclei.template_manager import TemplateManager
            mgr = TemplateManager()
            ready = mgr.setup(clone=True)
            stats = mgr.get_stats()
            return Response({'ready': ready, **stats}, status=202)
        except Exception as exc:
            return Response({'error': str(exc)}, status=500)


class ToolHealthView(views.APIView):
    """
    GET /api/scan/tools/health/
    Returns availability status for all 61 registered external tool wrappers.
    Useful for admin dashboards to verify which tools are installed.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            from apps.scanning.engine.tools.registry import ToolRegistry
            registry = ToolRegistry()
            if len(registry.list_tools()) == 0:
                registry.register_all_tools()
            health = registry.health_check()
            total = len(health)
            available = sum(1 for v in health.values() if v)
            return Response({
                'total': total,
                'available': available,
                'unavailable': total - available,
                'tools': health,
            })
        except Exception as exc:
            return Response({'error': str(exc)}, status=500)


# -- Dashboard trends endpoint -------------------------------------------------

class DashboardTrendsView(views.APIView):
    """
    GET /api/dashboard/trends/?days=30
    Returns daily severity counts for the vulnerability trend chart.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from datetime import timedelta
        from django.db.models.functions import TruncDate

        days = int(request.query_params.get('days', 30))
        since = timezone.now() - timedelta(days=days)

        qs = (
            Vulnerability.objects
            .filter(scan__user=request.user, scan__completed_at__gte=since)
            .annotate(date=TruncDate('scan__completed_at'))
            .values('date', 'severity')
            .annotate(count=Count('id'))
            .order_by('date')
        )

        # Pivot: [{date, critical, high, medium, low, info}, ...]
        pivot: dict = {}
        for row in qs:
            d = str(row['date'])
            if d not in pivot:
                pivot[d] = {'date': d, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            pivot[d][row['severity']] = row['count']

        return Response(sorted(pivot.values(), key=lambda r: r['date']))

# -- Target Management --------------------------------------------------------

class TargetListCreateView(generics.ListCreateAPIView):
    """
    GET  /api/scan/targets/
    POST /api/scan/targets/
    """
    permission_classes = [IsAuthenticated]
    from .serializers import TargetSerializer
    serializer_class = TargetSerializer

    def get_queryset(self):
        from .models import Target
        from django.db.models import Q
        return Target.objects.filter(Q(organization__memberships__user=self.request.user) | Q(organization__owner=self.request.user)).distinct()

    def perform_create(self, serializer):
        from apps.accounts.middleware import get_current_organization
        org = get_current_organization()
        if not org and hasattr(self.request, 'user') and self.request.user.is_authenticated:
            org_id = self.request.headers.get('X-Organization-ID') or self.request.META.get('HTTP_X_ORGANIZATION_ID')
            if org_id:
                from apps.accounts.models import Organization
                org = Organization.objects.filter(id=org_id, memberships__user=self.request.user).first()
            if not org:
                from apps.accounts.models import OrganizationMembership, Organization
                first_mem = OrganizationMembership.objects.filter(user=self.request.user).first()
                if first_mem:
                    org = first_mem.organization
                else:
                    org = self.request.user.current_organization
                    if not org:
                        org_name = f"{self.request.user.username or self.request.user.email}'s Organization"
                        org, _ = Organization.objects.get_or_create(
                            name=org_name,
                            defaults={'owner': self.request.user}
                        )
                        OrganizationMembership.objects.get_or_create(user=self.request.user, organization=org, defaults={'role': 'owner'})
                        self.request.user.current_organization = org
                        self.request.user.save(update_fields=['current_organization'])

        if not org:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Organization context required.")

        domain = serializer.validated_data.get('domain', '')
        is_verified = False
        if domain:
            import socket
            try:
                # Remove scheme if provided
                clean_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
                socket.gethostbyname(clean_domain)
                is_verified = True
            except socket.gaierror:
                is_verified = False

        serializer.save(organization=org, is_dns_verified=is_verified)

class TargetDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    GET    /api/scan/targets/<id>/
    PATCH  /api/scan/targets/<id>/
    DELETE /api/scan/targets/<id>/
    """
    permission_classes = [IsAuthenticated]
    from .serializers import TargetSerializer
    serializer_class = TargetSerializer
    lookup_field = 'id'

    def get_queryset(self):
        from .models import Target
        return Target.objects.filter(organization__memberships__user=self.request.user)

# -- Shared Reports -----------------------------------------------------------

class SharedReportCreateView(generics.CreateAPIView):
    """
    POST /api/v1/scan/<scan_id>/share/
    Create a new shared report link.
    """
    permission_classes = [IsAuthenticated]
    from .serializers import SharedReportSerializer
    serializer_class = SharedReportSerializer

    def perform_create(self, serializer):
        scan_id = self.kwargs.get('scan_id')
        scan = generics.get_object_or_404(Scan, id=scan_id, user=self.request.user)
        # Optional password hashing could be added here if we want real security,
        # but for now we just save the raw or frontend-hashed password string.
        serializer.save(scan=scan)


class SharedReportDeleteView(generics.DestroyAPIView):
    """
    DELETE /api/v1/scan/share/<id>/
    """
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        return SharedReport.objects.filter(scan__user=self.request.user)


class PublicReportView(views.APIView):
    """
    POST /api/v1/scan/public/<access_token>/
    Returns scan details if token is valid and password (if any) matches.
    """
    permission_classes = []  # Publicly accessible

    def post(self, request, access_token):
        # We use POST to safely pass a password in the body if needed
        report = generics.get_object_or_404(SharedReport, access_token=access_token)
        
        # Check expiry
        if report.expires_at and report.expires_at < timezone.now():
            return Response({'error': 'Report link has expired.'}, status=status.HTTP_410_GONE)

        # Check password if configured
        if report.password_hash:
            pwd = request.data.get('password', '')
            if pwd != report.password_hash:
                return Response({'error': 'Invalid password.'}, status=status.HTTP_403_FORBIDDEN)

        # Return scan details
        from .serializers import ScanDetailSerializer
        serializer = ScanDetailSerializer(report.scan)
        return Response(serializer.data)
