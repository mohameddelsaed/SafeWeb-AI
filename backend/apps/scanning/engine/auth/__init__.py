"""
Authenticated Scanning Engine — Phase 21+.

Provides session management, login handling, multi-step auth sequences,
OAuth2/SSO/OIDC flows, and JWT security analysis.
"""
from .session_manager import AuthSessionManager
from .login_handler import LoginHandler
from .auth_sequence import AuthSequence, AuthStep
from .oauth_handler import OAuthHandler, OAuthConfig, OAuthTokens
from .jwt_analyzer import JWTAnalyzer, JWTAnalysis

__all__ = [
    'AuthSessionManager', 'LoginHandler', 'AuthSequence', 'AuthStep',
    'OAuthHandler', 'OAuthConfig', 'OAuthTokens',
    'JWTAnalyzer', 'JWTAnalysis',
]
