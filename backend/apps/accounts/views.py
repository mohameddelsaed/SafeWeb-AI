import logging
from django.utils import timezone
from rest_framework import generics, status, views
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User, APIKey, UserSession
from .serializers import (
    RegisterSerializer, LoginSerializer, ProfileSerializer, ProfileUpdateSerializer,
    ChangePasswordSerializer, ForgotPasswordSerializer,
    ResetPasswordSerializer, APIKeySerializer, APIKeyCreateSerializer,
    SessionSerializer, TwoFactorVerifySerializer,
    ContactMessageSerializer,
)
from .utils import get_client_ip

import pyotp
import qrcode
import io
import base64

logger = logging.getLogger(__name__)


def get_tokens_for_user(user, remember_me=False):
    """Generate JWT tokens for a user."""
    refresh = RefreshToken.for_user(user)
    if remember_me:
        from datetime import timedelta
        refresh.set_exp(lifetime=timedelta(days=30))
        refresh.access_token.set_exp(lifetime=timedelta(days=7))
    return {
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    }


def build_user_response(user, tokens=None):
    """Build standardized user response."""
    from apps.scanning.models import Target
    user_data = {
        'id': str(user.id),
        'email': user.email,
        'name': user.name,
        'role': 'admin' if user.is_admin else user.role,
        'avatar': user.avatar.url if user.avatar else None,
        'company': getattr(user, 'company', ''),
        'jobTitle': getattr(user, 'job_title', ''),
        'plan': getattr(user, 'plan', 'free'),
        'twoFactorEnabled': getattr(user, 'is_2fa_enabled', False),
        'createdAt': user.created_at.isoformat() if user.created_at else None,
        'lastLogin': user.last_login.isoformat() if user.last_login else None,
        'has_targets': Target.objects.filter(organization__memberships__user=user).exists() or
                       Target.objects.filter(organization__owner=user).exists(),
    }
    response = {'user': user_data}
    if tokens:
        response['tokens'] = tokens
    return response


class RegisterView(generics.GenericAPIView):
    """POST /api/auth/register"""
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        tokens = get_tokens_for_user(user)
        logger.info(f'New user registered: {user.email}')

        return Response(
            build_user_response(user, tokens),
            status=status.HTTP_201_CREATED,
        )


class LoginView(generics.GenericAPIView):
    """POST /api/auth/login"""
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        remember_me = serializer.validated_data.get('remember_me', False)

        # Update login info
        user.last_login = timezone.now()
        user.last_login_ip = get_client_ip(request)
        user.save(update_fields=['last_login', 'last_login_ip'])

        # Create session
        UserSession.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        tokens = get_tokens_for_user(user, remember_me)
        logger.info(f'User logged in: {user.email}')

        return Response(build_user_response(user, tokens))


class LogoutView(views.APIView):
    """POST /api/auth/logout"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh')
            if refresh_token:
                token = RefreshToken(refresh_token)
                token.blacklist()

            # Deactivate sessions
            UserSession.objects.filter(
                user=request.user, is_active=True
            ).update(is_active=False)

            logger.info(f'User logged out: {request.user.email}')
        except Exception:
            pass  # Token may already be blacklisted

        return Response({'detail': 'Successfully logged out.'})


class VerifyView(views.APIView):
    """POST /api/auth/verify — returns current user data."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        return Response(build_user_response(request.user))

    def get(self, request):
        return Response(build_user_response(request.user))


class RefreshView(views.APIView):
    """POST /api/auth/refresh"""
    permission_classes = [AllowAny]

    def post(self, request):
        refresh_token = request.data.get('refresh')
        if not refresh_token:
            return Response(
                {'detail': 'Refresh token is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            refresh = RefreshToken(refresh_token)
            return Response({'access': str(refresh.access_token)})
        except Exception:
            return Response(
                {'detail': 'Invalid or expired refresh token.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class GoogleAuthView(views.APIView):
    """POST /api/auth/google"""
    permission_classes = [AllowAny]

    def post(self, request):
        credential = request.data.get('credential')
        if not credential:
            return Response(
                {'detail': 'Google credential is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            # Verify Google ID token
            from google.oauth2 import id_token  # type: ignore[import-untyped]
            from google.auth.transport import requests as google_requests  # type: ignore[import-untyped]
            from django.conf import settings

            idinfo = id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                settings.GOOGLE_CLIENT_ID if hasattr(settings, 'GOOGLE_CLIENT_ID') else '',
            )

            email = idinfo.get('email', '')
            name = idinfo.get('name', '')

            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    'name': name,
                    'username': email,
                }
            )
            if created:
                user.set_unusable_password()
                user.save()

            tokens = get_tokens_for_user(user)
            return Response(build_user_response(user, tokens))

        except Exception as e:
            logger.error(f'Google auth failed: {e}')
            return Response(
                {'detail': 'Google authentication failed.'},
                status=status.HTTP_400_BAD_REQUEST,
            )


class ForgotPasswordView(generics.GenericAPIView):
    """POST /api/auth/forgot-password"""
    serializer_class = ForgotPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        try:
            user = User.objects.get(email=email)
            # Generate reset token
            from django.contrib.auth.tokens import default_token_generator
            token = default_token_generator.make_token(user)

            # In production, send email. In dev, log it.
            logger.info(f'Password reset token for {email}: {token}')

            # Send email
            from django.core.mail import send_mail
            send_mail(
                'SafeWeb AI - Password Reset',
                f'Your password reset token: {token}\n\nUse this token to reset your password.',
                'noreply@safeweb.ai',
                [email],
                fail_silently=True,
            )
        except User.DoesNotExist:
            pass  # Don't reveal if email exists

        return Response({'detail': 'Password reset email sent.'})


class ResetPasswordView(generics.GenericAPIView):
    """POST /api/auth/reset-password"""
    serializer_class = ResetPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        token = serializer.validated_data['token']
        password = serializer.validated_data['password']

        from django.contrib.auth.tokens import default_token_generator
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response(
                {'detail': 'Invalid or expired reset token.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if default_token_generator.check_token(user, token):
            user.set_password(password)
            user.save()
            logger.info(f'Password reset for: {user.email}')
            return Response({'detail': 'Password reset successfully.'})

        return Response(
            {'detail': 'Invalid or expired reset token.'},
            status=status.HTTP_400_BAD_REQUEST,
        )


class ChangePasswordView(generics.GenericAPIView):
    """POST /api/auth/change-password"""
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.get_serializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        request.user.set_password(serializer.validated_data['new_password'])
        request.user.save()
        logger.info(f'Password changed for: {request.user.email}')

        return Response({'detail': 'Password changed successfully.'})


# ── Profile Views ──────────────────────────────────

class ProfileView(generics.RetrieveUpdateAPIView):
    """GET/PUT /api/user/profile"""
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):  # type: ignore[override]
        if self.request.method == 'PUT':
            return ProfileUpdateSerializer
        return ProfileSerializer

    def get_object(self):  # type: ignore[override]
        return self.request.user

    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(
            self.get_object(), data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()
        # Return full profile
        full_serializer = ProfileSerializer(self.get_object())
        return Response(full_serializer.data)


class APIKeyListCreateView(views.APIView):
    """GET/POST /api/user/api-keys"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        keys = APIKey.objects.filter(user=request.user)
        serializer = APIKeySerializer(keys, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = APIKeyCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        key_value = APIKey.generate_key()
        key_id = APIKey.generate_id()

        api_key = APIKey.objects.create(
            id=key_id,
            user=request.user,
            key=key_value,
            name=serializer.validated_data['name'],  # type: ignore[index]
        )

        return Response(
            {
                'id': api_key.id,
                'name': api_key.name,
                'key': key_value,  # Only shown once
                'created': api_key.created_at.strftime('%Y-%m-%d'),
                'lastUsed': 'Never',
                'scans': 0,
                'isActive': True,
            },
            status=status.HTTP_201_CREATED,
        )


class APIKeyDeleteView(views.APIView):
    """DELETE /api/user/api-keys/{key_id}"""
    permission_classes = [IsAuthenticated]

    def delete(self, request, key_id):
        try:
            api_key = APIKey.objects.get(id=key_id, user=request.user)
            api_key.delete()
            return Response({'detail': 'API key revoked successfully.'})
        except APIKey.DoesNotExist:
            return Response(
                {'detail': 'API key not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )


class SessionListView(views.APIView):
    """GET /api/user/sessions"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sessions = UserSession.objects.filter(user=request.user)[:10]
        serializer = SessionSerializer(
            sessions, many=True, context={'request': request}
        )
        return Response(serializer.data)


class TwoFactorEnableView(views.APIView):
    """POST /api/user/2fa/enable"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        secret = pyotp.random_base32()
        request.user.two_fa_secret = secret
        request.user.save(update_fields=['two_fa_secret'])

        # Generate QR code
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(
            name=request.user.email,
            issuer_name='SafeWeb AI',
        )

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')

        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()

        return Response({
            'secret': secret,
            'qrCode': f'data:image/png;base64,{qr_base64}',
        })


class TwoFactorVerifyView(views.APIView):
    """POST /api/user/2fa/verify"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = TwoFactorVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data['code']  # type: ignore[index]
        user = request.user

        if not user.two_fa_secret:
            return Response(
                {'detail': 'Please enable 2FA first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        totp = pyotp.TOTP(user.two_fa_secret)
        if totp.verify(code):
            user.is_2fa_enabled = True
            user.save(update_fields=['is_2fa_enabled'])

            # Generate backup codes
            import secrets
            backup_codes = [secrets.token_hex(4) for _ in range(8)]

            return Response({
                'detail': '2FA enabled successfully.',
                'backupCodes': backup_codes,
            })

        return Response(
            {'detail': 'Invalid verification code.'},
            status=status.HTTP_400_BAD_REQUEST,
        )


from django.views.decorators.csrf import csrf_protect
from django.utils.decorators import method_decorator

@method_decorator(csrf_protect, name='dispatch')
class ContactView(generics.CreateAPIView):
    """Handle contact form submissions — no auth required."""
    serializer_class = ContactMessageSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            {'detail': 'Message sent successfully. We will get back to you soon.'},
            status=status.HTTP_201_CREATED,
        )


class JobApplicationView(views.APIView):
    """POST /api/careers/apply — Submit a job application (public)."""
    permission_classes = [AllowAny]

    def post(self, request):
        from .models import JobApplication
        data = request.data
        position = data.get('position', '').strip()
        name = data.get('name', '').strip()
        email = data.get('email', '').strip()

        if not all([position, name, email]):
            return Response(
                {'detail': 'Position, name, and email are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        JobApplication.objects.create(
            position=position,
            name=name,
            email=email,
            phone=data.get('phone', ''),
            cover_letter=data.get('coverLetter', ''),
            resume_url=data.get('resumeUrl', ''),
            portfolio_url=data.get('portfolioUrl', ''),
        )

        return Response(
            {'detail': 'Application submitted successfully. We will review it and get back to you soon.'},
            status=status.HTTP_201_CREATED,
        )


class UserSettingsView(views.APIView):
    """GET /api/user/settings"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        org = getattr(request, 'organization', None)
        from .models import AIConfiguration
        from .serializers import AIConfigurationSerializer
        
        response_data = {
            'organization': org.name if org else None,
        }
        
        if org:
            ai_config = AIConfiguration.objects.filter(organization=org).first()
            if ai_config:
                response_data['ai_configuration'] = AIConfigurationSerializer(ai_config).data
                
        return Response(response_data)
