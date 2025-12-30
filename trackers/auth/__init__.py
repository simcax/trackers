"""
Authentication module for the Trackers application.

This module provides authentication services including Google OAuth 2.0 integration.
"""

from .auth_service import AuthRedirect, AuthResult, GoogleAuthService
from .config import GoogleOAuthConfig, google_oauth_config
from .oauth_client import GoogleOAuthClient, TokenResponse
from .session_manager import SessionManager, UserSession
from .token_validator import TokenValidator, UserInfo

__all__ = [
    "AuthRedirect",
    "AuthResult",
    "GoogleAuthService",
    "GoogleOAuthConfig",
    "google_oauth_config",
    "GoogleOAuthClient",
    "TokenResponse",
    "SessionManager",
    "UserSession",
    "TokenValidator",
    "UserInfo",
]
