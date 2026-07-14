from django.utils import timezone
from django.db.models import Q
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from apps.accounts.permissions import IsAdmin
from apps.accounts.models import User
from apps.accounts.utils import time_ago
from apps.scanning.models import Scan, Vulnerability
from apps.ml.models import MLModel
from .models import SystemAlert, SystemSettings
from .serializers import (
    AdminUserSerializer, AdminScanSerializer, SystemAlertSerializer,
    AdminContactSerializer, AdminJobApplicationSerializer,
)


class AdminDashboardView(APIView):
    """Admin dashboard with aggregated stats."""
    permission_classes = [IsAdmin]

    def get(self, request):
        time_range = request.query_params.get('timeRange', '30d')
        since = self._get_since(time_range)

        # User stats
        total_users = User.objects.count()
        User.objects.filter(last_login__gte=since).count()

        # Scan stats
        total_scans = Scan.objects.filter(created_at__gte=since).count()
        completed_scans = Scan.objects.filter(created_at__gte=since, status='completed').count()
        running_scans = Scan.objects.filter(status='scanning').count()
        failed_scans = Scan.objects.filter(created_at__gte=since, status='failed').count()

        # Vulnerability stats
        Vulnerability.objects.filter(scan__created_at__gte=since).count()
        critical_vulns = Vulnerability.objects.filter(
            scan__created_at__gte=since, severity='critical'
        ).count()

        stats = [
            {'label': 'Total Users', 'value': f'{total_users:,}', 'change': '+12.5%', 'trend': 'up'},
            {'label': 'Active Scans', 'value': str(running_scans), 'change': '', 'trend': 'up'},
            {'label': 'Total Scans', 'value': f'{total_scans:,}', 'change': '+8.2%', 'trend': 'up'},
            {'label': 'Critical Vulns', 'value': f'{critical_vulns:,}', 'change': '', 'trend': 'down'},
        ]

        # Recent users
        recent_users = User.objects.order_by('-date_joined')[:5]
        recent_users_data = [
            {
                'id': u.id,
                'name': u.name or u.email,
                'email': u.email,
                'plan': 'free',
                'status': 'active' if u.is_active else 'suspended',
                'joined': time_ago(u.date_joined),
            }
            for u in recent_users
        ]

        # System alerts
        alerts = SystemAlert.objects.filter(is_resolved=False)[:5]
        alerts_data = SystemAlertSerializer(alerts, many=True).data

        # Scan stats breakdown
        scan_stats = []
        if total_scans > 0:
            scan_stats = [
                {'status': 'Completed', 'count': completed_scans,
                 'percentage': round(completed_scans / max(total_scans, 1) * 100)},
                {'status': 'Running', 'count': running_scans,
                 'percentage': round(running_scans / max(total_scans, 1) * 100)},
                {'status': 'Failed', 'count': failed_scans,
                 'percentage': round(failed_scans / max(total_scans, 1) * 100)},
            ]

        return Response({
            'stats': stats,
            'recentUsers': recent_users_data,
            'systemAlerts': alerts_data,
            'scanStats': scan_stats,
        })

    def _get_since(self, time_range):
        now = timezone.now()
        mapping = {
            '24h': timezone.timedelta(hours=24),
            '7d': timezone.timedelta(days=7),
            '30d': timezone.timedelta(days=30),
            '90d': timezone.timedelta(days=90),
        }
        return now - mapping.get(time_range, timezone.timedelta(days=30))


class AdminUsersView(APIView):
    """Admin user management."""
    permission_classes = [IsAdmin]

    def get(self, request):
        queryset = User.objects.all()

        # Filters
        search = request.query_params.get('search', '')
        plan = request.query_params.get('plan', 'all')
        status_filter = request.query_params.get('status', 'all')

        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(email__icontains=search)
            )
        if plan != 'all':
            pass # Removed due to migration to Organization plans
        if status_filter == 'active':
            queryset = queryset.filter(is_active=True, last_login__isnull=False)
        elif status_filter == 'suspended':
            queryset = queryset.filter(is_active=False)
        elif status_filter == 'inactive':
            queryset = queryset.filter(is_active=True, last_login__isnull=True)

        total = queryset.count()
        users = queryset.order_by('-date_joined')[:50]
        serializer = AdminUserSerializer(users, many=True)

        # Summary stats
        summary = {
            'total_users': User.objects.count(),
            'active_users': User.objects.filter(is_active=True, last_login__isnull=False).count(),
            'pro_users': 0,
            'enterprise_users': 0,
        }

        return Response({
            'users': serializer.data,
            'total': total,
            'summary': summary,
        })

    def post(self, request):
        """Admin-create a new user."""
        data = request.data
        name = data.get('name', '')
        email = data.get('email', '')
        password = data.get('password', '')
        role = data.get('role', 'user')

        if not all([name, email, password]):
            return Response({'detail': 'Name, email, and password are required.'}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({'detail': 'A user with this email already exists.'}, status=400)

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password,
            name=name,
            role=role,
        )
        if role == 'admin':
            user.is_staff = True
            user.save(update_fields=['is_staff'])

        return Response({'detail': 'User created.', 'id': str(user.id)}, status=201)


class AdminUserDetailView(APIView):
    """Admin user detail/actions."""
    permission_classes = [IsAdmin]

    def patch(self, request, user_id):
        """Update user status or role."""
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        # Prevent admin from demoting or deactivating themselves
        if user == request.user:
            if 'role' in request.data and request.data['role'] != user.role:
                return Response(
                    {'detail': 'Cannot change your own role'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if 'is_active' in request.data and not request.data['is_active']:
                return Response(
                    {'detail': 'Cannot deactivate your own account'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        allowed_roles = {'user', 'admin'}

        if 'role' in request.data:
            if request.data['role'] in allowed_roles:
                user.role = request.data['role']
        if 'is_active' in request.data:
            user.is_active = bool(request.data['is_active'])
        user.save()

        serializer = AdminUserSerializer(user)
        return Response(serializer.data)

    def delete(self, request, user_id):
        """Delete a user account."""
        try:
            user = User.objects.get(id=user_id)
            if user == request.user:
                return Response({'detail': 'Cannot delete yourself'}, status=status.HTTP_400_BAD_REQUEST)
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response({'detail': 'User not found'}, status=status.HTTP_404_NOT_FOUND)


class AdminScansView(APIView):
    """Admin scan management."""
    permission_classes = [IsAdmin]

    def get(self, request):
        queryset = Scan.objects.select_related('user').all()

        # Filters
        search = request.query_params.get('search', '')
        status_filter = request.query_params.get('status', 'all')

        if search:
            queryset = queryset.filter(
                Q(target__icontains=search) | Q(user__email__icontains=search)
            )
        if status_filter != 'all':
            queryset = queryset.filter(status=status_filter)

        total = queryset.count()
        scans = queryset.order_by('-created_at')[:50]
        serializer = AdminScanSerializer(scans, many=True)

        # Summary stats
        today = timezone.now().date()
        stats = [
            {
                'label': 'Total Scans Today',
                'value': str(Scan.objects.filter(created_at__date=today).count()),
                'change': '',
            },
            {
                'label': 'Running',
                'value': str(Scan.objects.filter(status='scanning').count()),
                'change': '',
            },
            {
                'label': 'Completed Today',
                'value': str(Scan.objects.filter(created_at__date=today, status='completed').count()),
                'change': '',
            },
            {
                'label': 'Failed Today',
                'value': str(Scan.objects.filter(created_at__date=today, status='failed').count()),
                'change': '',
            },
        ]

        return Response({
            'scans': serializer.data,
            'total': total,
            'stats': stats,
        })


class AdminScanDetailView(APIView):
    """Admin scan actions."""
    permission_classes = [IsAdmin]

    def delete(self, request, scan_id):
        """Delete a scan."""
        try:
            scan = Scan.objects.get(id=scan_id)
            scan.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

    def patch(self, request, scan_id):
        """Cancel a running scan."""
        try:
            scan = Scan.objects.get(id=scan_id)
            if scan.status == 'running':
                scan.status = 'failed'
                scan.completed_at = timezone.now()
                scan.save()
            return Response({'status': scan.status})
        except Scan.DoesNotExist:
            return Response({'detail': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)


class AdminMLView(APIView):
    """Admin ML model management."""
    permission_classes = [IsAdmin]

    def get(self, request):
        ml_models = MLModel.objects.all()

        models_data = [
            {
                'id': str(m.id),
                'name': m.name,
                'status': 'active' if m.is_active else 'training',
                'accuracy': round(m.accuracy * 100, 1) if m.accuracy else 0,
                'lastTrained': m.trained_at.strftime('%Y-%m-%d') if m.trained_at else '-',
                'trainingData': f'{m.training_samples:,} samples',
                'version': m.version,
            }
            for m in ml_models
        ]

        metrics = [
            {'label': 'Total Models', 'value': str(ml_models.count()), 'change': ''},
            {'label': 'Active Models', 'value': str(ml_models.filter(is_active=True).count()), 'change': ''},
            {
                'label': 'Avg Accuracy',
                'value': f'{(sum(m.accuracy or 0 for m in ml_models) / max(ml_models.count(), 1) * 100):.1f}%',
                'change': '',
            },
        ]

        return Response({
            'models': models_data,
            'metrics': metrics,
            'trainingJobs': [],
            'datasets': [],
        })

    def post(self, request):
        """Trigger model training."""
        model_type = request.data.get('type', 'all')

        from apps.ml.model_trainer import train_phishing_model, train_malware_model
        results = []

        if model_type in ('phishing', 'all'):
            result = train_phishing_model()
            self._save_model(result)
            results.append(result)

        if model_type in ('malware', 'all'):
            result = train_malware_model()
            self._save_model(result)
            results.append(result)

        return Response({'message': 'Training complete', 'results': results})

    def _save_model(self, result):
        MLModel.objects.filter(
            model_type=result['model_type'], is_active=True
        ).update(is_active=False)

        MLModel.objects.create(
            name=result['name'],
            model_type=result['model_type'],
            version=result['version'],
            accuracy=result['accuracy'],
            precision_score=result['precision'],
            recall=result['recall'],
            f1_score=result['f1'],
            file_path=result['file_path'],
            is_active=True,
            training_samples=result['training_samples'],
            training_duration_seconds=result['training_duration_seconds'],
            trained_at=timezone.now(),
        )


class AdminSettingsView(APIView):
    """Admin system settings."""
    permission_classes = [IsAdmin]

    def get(self, request):
        settings_map = {
            'siteName': SystemSettings.get('site_name', 'SafeWeb AI'),
            'siteUrl': SystemSettings.get('site_url', 'https://safeweb-ai.com'),
            'adminEmail': SystemSettings.get('admin_email', 'admin@safeweb.ai'),
            'supportEmail': SystemSettings.get('support_email', 'support@safeweb.ai'),
            'maxScansPerUser': SystemSettings.get('max_scans_per_user', '100'),
            'scanTimeout': SystemSettings.get('scan_timeout', '300'),
            'apiRateLimit': SystemSettings.get('api_rate_limit', '1000'),
            'maintenanceMode': SystemSettings.get('maintenance_mode', 'false') == 'true',
            'registrationEnabled': SystemSettings.get('registration_enabled', 'true') == 'true',
            'emailNotifications': SystemSettings.get('email_notifications', 'true') == 'true',
        }

        system_info = {
            'version': '1.0.0',
            'database': 'SQLite' if 'sqlite' in str(
                __import__('django').conf.settings.DATABASES['default']['ENGINE']
            ) else 'PostgreSQL',
            'storageUsed': 'N/A',
            'lastBackup': 'N/A',
        }

        return Response({
            'settings': settings_map,
            'systemInfo': system_info,
        })

    def put(self, request):
        """Update system settings."""
        field_map = {
            'siteName': 'site_name',
            'siteUrl': 'site_url',
            'adminEmail': 'admin_email',
            'supportEmail': 'support_email',
            'maxScansPerUser': 'max_scans_per_user',
            'scanTimeout': 'scan_timeout',
            'apiRateLimit': 'api_rate_limit',
            'maintenanceMode': 'maintenance_mode',
            'registrationEnabled': 'registration_enabled',
            'emailNotifications': 'email_notifications',
        }

        for camel_key, db_key in field_map.items():
            if camel_key in request.data:
                value = request.data[camel_key]
                if isinstance(value, bool):
                    value = 'true' if value else 'false'
                SystemSettings.set(db_key, str(value))

        return Response({'message': 'Settings saved successfully'})


class AdminContactsView(APIView):
    """Admin contact message management."""
    permission_classes = [IsAdmin]

    def get(self, request):
        from apps.accounts.models import ContactMessage
        queryset = ContactMessage.objects.all()

        # Filters
        is_read = request.query_params.get('is_read')
        search = request.query_params.get('search', '')
        if is_read == 'true':
            queryset = queryset.filter(is_read=True)
        elif is_read == 'false':
            queryset = queryset.filter(is_read=False)
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(email__icontains=search) | Q(message__icontains=search)
            )

        total = queryset.count()
        messages = queryset.order_by('-created_at')[:50]
        serializer = AdminContactSerializer(messages, many=True)

        unread = ContactMessage.objects.filter(is_read=False).count()

        return Response({
            'messages': serializer.data,
            'total': total,
            'unread': unread,
        })


class AdminContactDetailView(APIView):
    """Admin contact message detail — reply, mark read, delete."""
    permission_classes = [IsAdmin]

    def patch(self, request, message_id):
        """Reply to a message or mark it read."""
        from apps.accounts.models import ContactMessage
        try:
            msg = ContactMessage.objects.get(id=message_id)
        except ContactMessage.DoesNotExist:
            return Response({'detail': 'Message not found.'}, status=status.HTTP_404_NOT_FOUND)

        if 'is_read' in request.data:
            msg.is_read = bool(request.data['is_read'])

        if 'reply' in request.data and request.data['reply']:
            msg.reply = request.data['reply']
            msg.replied_at = timezone.now()
            msg.replied_by = request.user
            msg.is_read = True

        msg.save()

        serializer = AdminContactSerializer(msg)
        return Response(serializer.data)

    def delete(self, request, message_id):
        from apps.accounts.models import ContactMessage
        try:
            msg = ContactMessage.objects.get(id=message_id)
            msg.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except ContactMessage.DoesNotExist:
            return Response({'detail': 'Message not found.'}, status=status.HTTP_404_NOT_FOUND)


class AdminJobApplicationsView(APIView):
    """Admin job application management."""
    permission_classes = [IsAdmin]

    def get(self, request):
        from apps.accounts.models import JobApplication
        queryset = JobApplication.objects.all()

        status_filter = request.query_params.get('status', 'all')
        search = request.query_params.get('search', '')
        if status_filter != 'all':
            queryset = queryset.filter(status=status_filter)
        if search:
            queryset = queryset.filter(
                Q(name__icontains=search) | Q(email__icontains=search) | Q(position__icontains=search)
            )

        total = queryset.count()
        applications = queryset.order_by('-created_at')[:50]
        serializer = AdminJobApplicationSerializer(applications, many=True)

        pending_count = JobApplication.objects.filter(status='pending').count()

        return Response({
            'applications': serializer.data,
            'total': total,
            'pending': pending_count,
        })


class AdminJobApplicationDetailView(APIView):
    """Admin job application detail — update status/notes, delete."""
    permission_classes = [IsAdmin]

    def patch(self, request, application_id):
        from apps.accounts.models import JobApplication
        try:
            app = JobApplication.objects.get(id=application_id)
        except JobApplication.DoesNotExist:
            return Response({'detail': 'Application not found.'}, status=status.HTTP_404_NOT_FOUND)

        if 'status' in request.data:
            allowed = {'pending', 'reviewed', 'shortlisted', 'rejected'}
            if request.data['status'] in allowed:
                app.status = request.data['status']
        if 'admin_notes' in request.data:
            app.admin_notes = request.data['admin_notes']

        app.save()
        serializer = AdminJobApplicationSerializer(app)
        return Response(serializer.data)

    def delete(self, request, application_id):
        from apps.accounts.models import JobApplication
        try:
            app = JobApplication.objects.get(id=application_id)
            app.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except JobApplication.DoesNotExist:
            return Response({'detail': 'Application not found.'}, status=status.HTTP_404_NOT_FOUND)
