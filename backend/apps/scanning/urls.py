from django.urls import path
from . import views

urlpatterns = [
    # ── Existing endpoints ────────────────────────────────────────────
    path('website/', views.WebsiteScanCreateView.as_view(), name='scan-website'),
    # DEACTIVATED: File/URL threat detection endpoints hidden (code preserved in views.py)
    # path('file/', views.FileScanCreateView.as_view(), name='scan-file'),
    # path('url/', views.URLScanCreateView.as_view(), name='scan-url'),
    path('<uuid:id>/', views.ScanDetailView.as_view(), name='scan-detail'),
    path('<uuid:id>/delete/', views.ScanDeleteView.as_view(), name='scan-delete'),
    path('<uuid:id>/rescan/', views.RescanView.as_view(), name='scan-rescan'),
    path('<uuid:id>/export/', views.ScanExportView.as_view(), name='scan-export'),

    # Scope resolution & confirmation (for wildcard/wide_scope)
    path('<uuid:id>/resolve/', views.ResolveScopeView.as_view(), name='scan-resolve'),
    path('<uuid:id>/confirm/', views.ConfirmWideScopeView.as_view(), name='scan-confirm'),

    # ── Phase 44: API-First endpoints ─────────────────────────────────

    # Full-config scan creation
    path('', views.ScanCreateFullView.as_view(), name='scan-create-full'),

    # Findings: paginated + filtered
    path('<uuid:id>/findings/', views.ScanFindingsListView.as_view(), name='scan-findings'),

    # Rescan a specific finding
    path('<uuid:id>/rescan-finding/', views.RescanFindingView.as_view(), name='scan-rescan-finding'),

    # SSE stream for real-time updates
    path('<uuid:id>/stream/', views.ScanStreamView.as_view(), name='scan-stream'),

    # Export with format in URL
    path('<uuid:id>/export/<str:fmt>/', views.ScanExportFormatView.as_view(), name='scan-export-format'),

    # Compare two scans
    path('compare/<uuid:id1>/<uuid:id2>/', views.ScanCompareView.as_view(), name='scan-compare'),

    # Nuclei templates
    path('templates/', views.NucleiTemplateListView.as_view(), name='templates-list'),
    path('templates/custom/', views.NucleiTemplateUploadView.as_view(), name='templates-custom'),

    # Scan profiles
    path('profiles/', views.ScanProfileListView.as_view(), name='profiles-list'),

    # Auth configs
    path('auth-configs/', views.AuthConfigCreateView.as_view(), name='auth-configs-create'),

    # Webhooks
    path('webhooks/', views.WebhookListCreateView.as_view(), name='webhooks-list'),
    path('webhooks/<uuid:id>/', views.WebhookDetailView.as_view(), name='webhooks-detail'),
    path('webhooks/<uuid:id>/test/', views.WebhookTestView.as_view(), name='webhooks-test'),
    path('webhooks/<uuid:id>/deliveries/', views.WebhookDeliveryListView.as_view(), name='webhooks-deliveries'),

    # ── Phase 45: Multi-Target & Scope Management ──────────────────────

    # Scope definitions
    path('scopes/', views.ScopeDefinitionListCreateView.as_view(), name='scopes-list'),
    path('scopes/import/', views.ScopeImportView.as_view(), name='scopes-import'),
    path('scopes/<uuid:id>/', views.ScopeDefinitionDetailView.as_view(), name='scopes-detail'),
    path('scopes/<uuid:id>/validate/', views.ScopeValidateView.as_view(), name='scopes-validate'),

    # Multi-target scans
    path('multi/', views.MultiTargetScanListView.as_view(), name='multi-scans-list'),
    path('multi/create/', views.MultiTargetScanCreateView.as_view(), name='multi-scans-create'),
    path('multi/<uuid:id>/', views.MultiTargetScanDetailView.as_view(), name='multi-scans-detail'),

    # Asset inventory
    path('assets/', views.AssetInventoryListView.as_view(), name='assets-list'),
    path('assets/<uuid:id>/', views.AssetInventoryDetailView.as_view(), name='assets-detail'),

    # ── Phase 43/48 Sync: Scheduled scans ─────────────────────────────────────
    path('scheduled/', views.ScheduledScanListCreateView.as_view(), name='scheduled-list'),
    path('scheduled/<uuid:id>/', views.ScheduledScanDetailView.as_view(), name='scheduled-detail'),

    # Asset monitor records
    path('asset-monitor/', views.AssetMonitorRecordListView.as_view(), name='asset-monitor-list'),
    path('asset-monitor/<uuid:id>/acknowledge/', views.AssetMonitorRecordAcknowledgeView.as_view(), name='asset-monitor-acknowledge'),

    # Finding-level detail (false positive marking)
    path('<uuid:scan_id>/findings/<uuid:vuln_id>/', views.FindingDetailView.as_view(), name='finding-detail'),

    # Nuclei template detail
    path('nuclei-templates/', views.NucleiTemplateListView.as_view(), name='nuclei-templates-list'),
    path('nuclei-templates/upload/', views.NucleiTemplateUploadView.as_view(), name='nuclei-templates-upload'),
    path('nuclei-templates/stats/', views.NucleiTemplateStatsView.as_view(), name='nuclei-templates-stats'),
    path('nuclei-templates/update/', views.NucleiTemplateUpdateView.as_view(), name='nuclei-templates-update'),
    path('nuclei-templates/<uuid:id>/', views.NucleiTemplateDetailView.as_view(), name='nuclei-templates-detail'),

    # Tool registry health check (admin)
    path('tools/health/', views.ToolHealthView.as_view(), name='tools-health'),

    # ── Target Management ────────────────────────────────────────────────
    path('targets/', views.TargetListCreateView.as_view(), name='targets-list'),
    path('targets/<uuid:id>/', views.TargetDetailView.as_view(), name='targets-detail'),

    # ── Shared Reports (Phase C) ─────────────────────────────────────────
    path('<uuid:scan_id>/share/', views.SharedReportCreateView.as_view(), name='scan-share-create'),
    path('share/<uuid:pk>/', views.SharedReportDeleteView.as_view(), name='scan-share-delete'),
    path('public/<uuid:access_token>/', views.PublicReportView.as_view(), name='scan-public-report'),
]
