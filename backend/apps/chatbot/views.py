import logging
from django.utils import timezone
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import ChatSession, ChatMessage
from .serializers import ChatInputSerializer, ChatSessionSerializer
from .engine import get_chat_engine

logger = logging.getLogger(__name__)


class ChatView(APIView):
    """Send a message and get an AI response."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChatInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data or {}

        message_text = data['message']
        session_id = data.get('session_id')
        scan_id = data.get('scan_id')

        # Get or create session
        session = self._get_or_create_session(request, session_id)

        # Link scan to session if provided
        if scan_id and not session.scan_id:
            try:
                from apps.scanning.models import Scan
                scan_obj = Scan.objects.get(id=scan_id, user=request.user)
                session.scan = scan_obj
                session.context_type = 'scan'
                session.save(update_fields=['scan', 'context_type'])
            except Exception:
                pass

        # Build rich context
        scan_context = ''
        effective_scan_id = scan_id or (session.scan_id if session.scan_id else None)
        if effective_scan_id:
            scan_context = self._get_scan_context(effective_scan_id, request.user)
        user_context = self._get_user_context(request.user)

        # Save user message
        ChatMessage.objects.create(
            session=session,
            role='user',
            content=message_text,
        )

        # Generate AI response
        engine = get_chat_engine()
        result = engine.generate_response(
            message_text, session, scan_context, user_context, request.user
        )

        # Save assistant message
        action_data = result.get('actions', [])
        assistant_msg = ChatMessage.objects.create(
            session=session,
            role='assistant',
            content=result['response'],
            tokens_used=result.get('tokens_used', 0),
            action_data=action_data if action_data else None,
        )

        # Update session title from first message
        if session.title == 'New Chat':
            session.title = message_text[:50]
            session.save(update_fields=['title'])

        return Response({
            'response': result['response'],
            'session_id': str(session.id),
            'sessionId': str(session.id),
            'message_id': str(assistant_msg.id),
            'tokens_used': result.get('tokens_used', 0),
            'actions': result.get('actions', []),
            'suggestions': result.get('suggestions', []),
            'source': result.get('source', 'local'),
        })

    def _get_or_create_session(self, request, session_id=None):
        if session_id:
            try:
                return ChatSession.objects.get(id=session_id, user=request.user)
            except ChatSession.DoesNotExist:
                pass
        return ChatSession.objects.create(
            user=request.user,
            session_key=request.session.session_key or '',
        )

    def _get_scan_context(self, scan_id, user):
        """Build rich context string from scan results."""
        try:
            from apps.scanning.models import Scan
            scan = Scan.objects.get(id=scan_id, user=user)

            parts = [
                f'Scan ID: {scan.id}',
                f'Target: {scan.target}',
                f'Type: {scan.scan_type}',
                f'Status: {scan.status}',
            ]
            if scan.score is not None:
                parts.append(f'Security Score: {scan.score}/100')
            if scan.started_at:
                parts.append(f'Started: {scan.started_at.isoformat()}')
            if scan.completed_at:
                parts.append(f'Completed: {scan.completed_at.isoformat()}')
            if getattr(scan, 'depth', None):
                parts.append(f'Depth: {scan.depth}')
            if getattr(scan, 'current_phase', None):
                parts.append(f'Current Phase: {scan.current_phase}')
            if getattr(scan, 'progress', None) is not None:
                parts.append(f'Progress: {scan.progress}%')

            # All vulnerabilities grouped by severity
            vulns = scan.vulnerabilities.all()
            if vulns.exists():
                total = vulns.count()
                severity_counts = {}
                for v in vulns:
                    sev = v.severity.upper()
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                parts.append(f'\nVulnerabilities ({total} total): ' +
                             ', '.join(f'{s}: {c}' for s, c in
                                       sorted(severity_counts.items(),
                                              key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x[0])
                                              if x[0] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] else 99)))
                for v in vulns[:20]:
                    line = f'- [{v.severity.upper()}] {v.name}'
                    if getattr(v, 'affected_url', ''):
                        line += f' @ {v.affected_url}'
                    if v.description:
                        line += f': {v.description[:150]}'
                    parts.append(line)
                if total > 20:
                    parts.append(f'... and {total - 20} more vulnerabilities')

            return '\n'.join(parts)
        except Exception as e:
            logger.debug(f'Failed to build scan context: {e}')
            return ''

    def _get_user_context(self, user):
        """Build user profile context for the LLM."""
        try:
            from apps.scanning.models import Scan
            from apps.accounts.middleware import get_current_organization

            org = get_current_organization()
            plan = org.plan_tier if org else 'free'
            
            total_scans = Scan.objects.filter(user=user).count()

            month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            monthly_scans = Scan.objects.filter(user=user, created_at__gte=month_start).count()

            parts = [
                f'Name: {getattr(user, "name", "") or user.email}',
                f'Active Org Plan: {plan}',
                f'Total scans: {total_scans}',
                f'Scans this month: {monthly_scans}',
            ]

            if plan == 'free':
                parts.append(f'Monthly limit: 5 (remaining: {max(0, 5 - monthly_scans)})')

            # Recent scans summary
            recent = Scan.objects.filter(user=user).order_by('-created_at')[:5]
            if recent:
                scores = [s.score for s in recent if s.score is not None]
                if scores:
                    parts.append(f'Avg recent score: {sum(scores) / len(scores):.0f}/100')
                last = recent[0]
                parts.append(f'Last scan: {last.target} ({last.status}, score: {last.score})')

            has_2fa = getattr(user, 'is_2fa_enabled', False)
            parts.append(f'2FA: {"enabled" if has_2fa else "not enabled"}')

            return '\n'.join(parts)
        except Exception as e:
            logger.debug(f'Failed to build user context: {e}')
            return ''


class ChatSessionListView(APIView):
    """List user's chat sessions."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sessions = ChatSession.objects.filter(user=request.user)[:20]
        serializer = ChatSessionSerializer(sessions, many=True)
        return Response(serializer.data)


class ChatSessionDetailView(APIView):
    """Get messages for a chat session."""
    permission_classes = [IsAuthenticated]

    def get(self, request, session_id):
        try:
            session = ChatSession.objects.get(id=session_id, user=request.user)
        except ChatSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ChatSessionSerializer(session)
        return Response(serializer.data)

    def delete(self, request, session_id):
        try:
            session = ChatSession.objects.get(id=session_id, user=request.user)
            session.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except ChatSession.DoesNotExist:
            return Response({'detail': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)


class MessageFeedbackView(APIView):
    """Submit feedback (thumbs up/down) for an assistant message."""
    permission_classes = [IsAuthenticated]

    def post(self, request, message_id):
        feedback = request.data.get('feedback', '')
        if feedback not in ('positive', 'negative'):
            return Response({'detail': 'feedback must be "positive" or "negative"'},
                            status=status.HTTP_400_BAD_REQUEST)
        try:
            msg = ChatMessage.objects.get(
                id=message_id,
                session__user=request.user,
                role='assistant',
            )
        except ChatMessage.DoesNotExist:
            return Response({'detail': 'Message not found'}, status=status.HTTP_404_NOT_FOUND)

        msg.feedback = feedback
        msg.save(update_fields=['feedback'])
        return Response({'status': 'ok'})


class SuggestionsView(APIView):
    """Return contextual suggested questions based on user's state."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scan_id = request.query_params.get('scan_id')
        suggestions = []

        if scan_id:
            # Scan-specific suggestions
            try:
                from apps.scanning.models import Scan
                scan = Scan.objects.get(id=scan_id, user=request.user)
                if scan.status == 'completed':
                    vuln_count = scan.vulnerabilities.count() if hasattr(scan, 'vulnerabilities') else 0
                    suggestions = [
                        f'Analyze the {vuln_count} findings from this scan',
                        'What are the most critical vulnerabilities?',
                        'How can I improve my security score?',
                        'Export this scan as PDF',
                        'Compare with my previous scan',
                    ]
                elif scan.status == 'scanning':
                    suggestions = [
                        'What is the current scan progress?',
                        'How long will this scan take?',
                        'What phases does the scan go through?',
                    ]
                elif scan.status == 'failed':
                    suggestions = [
                        'Why did my scan fail?',
                        'How can I troubleshoot scan issues?',
                        'Start a new scan on this target',
                    ]
            except Exception:
                pass

        if not suggestions:
            # General suggestions based on user state
            try:
                from apps.scanning.models import Scan
                recent = Scan.objects.filter(user=request.user).order_by('-created_at').first()
                if recent:
                    suggestions = [
                        'Show my recent scan results',
                        'How is my security score calculated?',
                        'What vulnerabilities should I fix first?',
                        'How do I schedule recurring scans?',
                    ]
                else:
                    suggestions = [
                        'How do I start my first scan?',
                        'What is OWASP Top 10?',
                        'What scan types are available?',
                        'Tell me about SafeWeb AI features',
                    ]
            except Exception:
                suggestions = [
                    'How do I start a scan?',
                    'What is OWASP Top 10?',
                    'Tell me about XSS',
                ]

        return Response({'suggestions': suggestions[:5]})


class ChatAnalyticsView(APIView):
    """Chat analytics for admin dashboard."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Only allow admin/staff
        if not (request.user.is_staff or getattr(request.user, 'is_admin', False)):
            return Response({'detail': 'Not authorized'}, status=status.HTTP_403_FORBIDDEN)

        time_range = request.query_params.get('timeRange', '30d')
        since = self._get_since(time_range)

        total_sessions = ChatSession.objects.filter(created_at__gte=since).count()
        total_messages = ChatMessage.objects.filter(created_at__gte=since).count()
        user_messages = ChatMessage.objects.filter(created_at__gte=since, role='user').count()
        bot_messages = ChatMessage.objects.filter(created_at__gte=since, role='assistant').count()

        # Feedback stats
        positive = ChatMessage.objects.filter(
            created_at__gte=since, feedback='positive'
        ).count()
        negative = ChatMessage.objects.filter(
            created_at__gte=since, feedback='negative'
        ).count()
        total_feedback = positive + negative

        # Token usage
        from django.db.models import Sum
        total_tokens = ChatMessage.objects.filter(
            created_at__gte=since, tokens_used__gt=0
        ).aggregate(total=Sum('tokens_used'))['total'] or 0
        llm_messages = ChatMessage.objects.filter(
            created_at__gte=since, tokens_used__gt=0
        ).count()

        # Unique users
        unique_users = ChatSession.objects.filter(
            created_at__gte=since, user__isnull=False
        ).values('user').distinct().count()

        # Scan-linked sessions
        scan_sessions = ChatSession.objects.filter(
            created_at__gte=since, scan__isnull=False
        ).count()

        # Daily message counts (last 7 days)
        from django.db.models.functions import TruncDate
        from django.db.models import Count
        daily = (
            ChatMessage.objects
            .filter(created_at__gte=since, role='user')
            .annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(count=Count('id'))
            .order_by('day')
        )
        daily_data = [{'date': d['day'].isoformat(), 'count': d['count']} for d in daily]

        # Top questions (most common first words in user messages)
        from collections import Counter
        recent_msgs = ChatMessage.objects.filter(
            created_at__gte=since, role='user'
        ).values_list('content', flat=True)[:500]
        topic_counter = Counter()
        for msg in recent_msgs:
            words = msg.lower().split()[:3]
            if len(words) >= 2:
                topic_counter[' '.join(words)] += 1
        top_topics = [{'topic': t, 'count': c} for t, c in topic_counter.most_common(10)]

        return Response({
            'totalSessions': total_sessions,
            'totalMessages': total_messages,
            'userMessages': user_messages,
            'botMessages': bot_messages,
            'uniqueUsers': unique_users,
            'feedback': {
                'positive': positive,
                'negative': negative,
                'total': total_feedback,
                'satisfactionRate': round(positive / total_feedback * 100) if total_feedback > 0 else 0,
            },
            'tokens': {
                'total': total_tokens,
                'llmMessages': llm_messages,
                'avgPerMessage': round(total_tokens / llm_messages) if llm_messages > 0 else 0,
            },
            'scanSessions': scan_sessions,
            'dailyMessages': daily_data,
            'topTopics': top_topics,
        })

    def _get_since(self, time_range):
        mapping = {
            '24h': timezone.timedelta(hours=24),
            '7d': timezone.timedelta(days=7),
            '30d': timezone.timedelta(days=30),
            '90d': timezone.timedelta(days=90),
        }
        return timezone.now() - mapping.get(time_range, timezone.timedelta(days=30))
