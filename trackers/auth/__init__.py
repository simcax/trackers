"""
Authentication module for the Trackers application.

This module provides authentication services including Google OAuth 2.0 integration
and email/password authentication.
"""

from .auth_service import AuthRedirect, AuthResult, GoogleAuthService
from .config import GoogleOAuthConfig, google_oauth_config
from .email_password_auth_service import (
    AccountLockedError,
    DuplicateEmailError,
    EmailPasswordAuthError,
    EmailPasswordAuthService,
    InvalidCredentialsError,
)
from .email_password_auth_service import (
    AuthResult as EmailPasswordAuthResult,
)
from .email_password_auth_service import (
    PasswordValidationError as EmailPasswordValidationError,
)
from .oauth_client import GoogleOAuthClient, TokenResponse
from .password_hasher import (
    PasswordHasher,
    PasswordValidationError,
    create_password_hasher,
)
from .session_manager import SessionManager, UserSession
from .token_validator import TokenValidator, UserInfo

__all__ = [
    "AuthRedirect",
    "AuthResult",
    "GoogleAuthService",
    "GoogleOAuthConfig",
    "google_oauth_config",
    "EmailPasswordAuthService",
    "EmailPasswordAuthError",
    "EmailPasswordValidationError",
    "InvalidCredentialsError",
    "AccountLockedError",
    "DuplicateEmailError",
    "EmailPasswordAuthResult",
    "GoogleOAuthClient",
    "TokenResponse",
    "PasswordHasher",
    "PasswordValidationError",
    "create_password_hasher",
    "SessionManager",
    "UserSession",
    "TokenValidator",
    "UserInfo",
]
