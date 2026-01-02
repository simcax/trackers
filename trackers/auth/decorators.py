"""
Authentication decorators for route protection.

This module provides unified authentication decorators that support both
API key authentication and Google OAuth authentication, allowing routes
to be protected by either or both authentication methods.

Requirements: 5.3, 5.4 - Authentication decorators and user context management
"""

import logging
from functools import wraps
from typing import Optional, Union

from flask import current_app, g, jsonify, redirect, request, url_for

from .error_handling import get_client_ip
from .token_validator import UserInfo

# Configure logging
logger = logging.getLogger(__name__)


class AuthenticationContext:
    """
    Authentication context for the current request.

    This class provides unified access to authentication information
    regardless of whether the user authenticated via API key or Google OAuth.
    """

    def __init__(
        self,
        is_authenticated: bool = False,
        auth_method: Optional[str] = None,
        user_info: Optional[UserInfo] = None,
        api_key_valid: bool = False,
        public_access: bool = False,
    ):
        """
        Initialize authentication context.

        Args:
            is_authenticated: Whether the request is authenticated
            auth_method: Method used for authentication ('api_key', 'google_oauth', 'both', or 'public')
            user_info: Google OAuth user information (if available)
            api_key_valid: Whether API key authentication was successful
            public_access: Whether this is public access (no authentication required)
        """
        self.is_authenticated = is_authenticated
        self.auth_method = auth_method
        self.user_info = user_info
        self.api_key_valid = api_key_valid
        self.public_access = public_access

    @property
    def user_email(self) -> Optional[str]:
        """Get user email if available from Google OAuth."""
        return self.user_info.email if self.user_info else None

    @property
    def user_name(self) -> Optional[str]:
        """Get user name if available from Google OAuth."""
        return self.user_info.name if self.user_info else None

    @property
    def google_id(self) -> Optional[str]:
        """Get Google ID if available from Google OAuth."""
        return self.user_info.google_id if self.user_info else None

    def to_dict(self) -> dict:
        """Convert authentication context to dictionary for JSON responses."""
        result = {
            "is_authenticated": self.is_authenticated,
            "auth_method": self.auth_method,
            "api_key_valid": self.api_key_valid,
        }

        if self.user_info:
            result["user"] = {
                "email": self.user_info.email,
                "name": self.user_info.name,
                "google_id": self.user_info.google_id,
                "picture_url": self.user_info.picture_url,
                "verified_email": self.user_info.verified_email,
            }

        return result


def get_auth_context() -> AuthenticationContext:
    """
    Get the current authentication context for the request.

    Returns:
        AuthenticationContext: Current authentication context

    Requirements: 5.4 - Add user context management for authenticated requests
    """
    return getattr(g, "auth_context", AuthenticationContext())


def require_auth(
    allow_api_key: bool = True,
    allow_google_oauth: bool = True,
    allow_email_password: bool = True,
    redirect_to_login: bool = True,
) -> callable:
    """
    Decorator that requires authentication via API key, Google OAuth, email/password, or any combination.

    Args:
        allow_api_key: Whether to allow API key authentication
        allow_google_oauth: Whether to allow Google OAuth authentication
        allow_email_password: Whether to allow email/password authentication
        redirect_to_login: Whether to redirect to login page for web requests

    Returns:
        Decorator function for route protection

    Requirements: 5.3 - Create authentication decorators for route protection
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Initialize authentication context
                auth_context = AuthenticationContext()

                # Check if all authentication methods are disabled - only then allow public access
                api_key_enabled = (
                    allow_api_key
                    and hasattr(current_app, "key_validator")
                    and current_app.key_validator.is_authentication_enabled()
                )
                google_oauth_enabled = (
                    allow_google_oauth and _has_google_auth_configured()
                )
                email_password_enabled = (
                    allow_email_password and _has_email_password_auth_configured()
                )

                if (
                    not api_key_enabled
                    and not google_oauth_enabled
                    and not email_password_enabled
                ):
                    # All authentication methods are disabled, allow public access
                    auth_context = AuthenticationContext(
                        is_authenticated=False,
                        auth_method="public",
                        public_access=True,
                    )
                    g.auth_context = auth_context

                    client_ip = get_client_ip()
                    logger.info(
                        f"Public access to {request.endpoint} from {client_ip} "
                        "(all authentication methods disabled)"
                    )

                    return f(*args, **kwargs)

                # Check API key authentication if enabled
                api_key_valid = False
                api_key_user_info = None
                if api_key_enabled:
                    api_key_valid, api_key_user_info = _check_api_key_auth()

                # Check Google OAuth authentication if enabled
                google_oauth_valid = False
                google_user_info = None
                if google_oauth_enabled:
                    google_oauth_valid, google_user_info = _check_google_oauth_auth()

                # Check email/password authentication if enabled
                email_password_valid = False
                email_password_user_info = None
                if email_password_enabled:
                    email_password_valid, email_password_user_info = (
                        _check_email_password_auth()
                    )

                # Determine authentication status and method
                auth_methods = []
                user_info = None

                if api_key_valid:
                    auth_methods.append("api_key")
                if google_oauth_valid:
                    auth_methods.append("google_oauth")
                    user_info = google_user_info  # Prefer Google OAuth user info
                if email_password_valid:
                    auth_methods.append("email_password")
                    if not user_info:  # Use email/password user info if no Google OAuth
                        user_info = email_password_user_info

                if auth_methods:
                    # At least one method authenticated
                    auth_method = (
                        "_".join(auth_methods)
                        if len(auth_methods) > 1
                        else auth_methods[0]
                    )

                    # Handle API key user info for compatibility
                    if (
                        api_key_valid
                        and api_key_user_info
                        and api_key_user_info.get("auth_method") == "api_key"
                    ):
                        # User API key - create UserInfo object for compatibility
                        from .token_validator import UserInfo

                        api_user_info = UserInfo(
                            email=api_key_user_info.get("email", ""),
                            name=api_key_user_info.get("name", "API User"),
                            google_id=api_key_user_info.get("google_id", ""),
                            picture_url="",
                            verified_email=True,
                        )
                        if not user_info:
                            user_info = api_user_info

                    auth_context = AuthenticationContext(
                        is_authenticated=True,
                        auth_method=auth_method,
                        user_info=user_info,
                        api_key_valid=api_key_valid,
                    )
                else:
                    # No valid authentication found
                    auth_context = AuthenticationContext(is_authenticated=False)

                # Store authentication context in Flask g for access in route handlers
                g.auth_context = auth_context

                # If not authenticated, handle based on request type
                if not auth_context.is_authenticated:
                    return _handle_unauthenticated_request(redirect_to_login)

                # Log successful authentication
                client_ip = get_client_ip()
                logger.info(
                    f"Authenticated request to {request.endpoint} from {client_ip} "
                    f"using {auth_context.auth_method}"
                )

                # Authentication successful, call the original function
                return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"Authentication error in decorator: {str(e)}")
                return _handle_authentication_error(str(e))

        return decorated_function

    return decorator


def require_api_key_only() -> callable:
    """
    Decorator that requires only API key authentication.

    Returns:
        Decorator function for API-only route protection
    """
    return require_auth(
        allow_api_key=True, allow_google_oauth=False, redirect_to_login=False
    )


def require_google_oauth_only(redirect_to_login: bool = True) -> callable:
    """
    Decorator that requires only Google OAuth authentication.

    Args:
        redirect_to_login: Whether to redirect to login page for web requests

    Returns:
        Decorator function for OAuth-only route protection
    """
    return require_auth(
        allow_api_key=False,
        allow_google_oauth=True,
        redirect_to_login=redirect_to_login,
    )


def require_email_password_only(redirect_to_login: bool = True) -> callable:
    """
    Decorator that requires only email/password authentication.

    Args:
        redirect_to_login: Whether to redirect to login page for web requests

    Returns:
        Decorator function for email/password-only route protection
    """
    return require_auth(
        allow_api_key=False,
        allow_google_oauth=False,
        allow_email_password=True,
        redirect_to_login=redirect_to_login,
    )


def require_web_auth(redirect_to_login: bool = True) -> callable:
    """
    Decorator that requires web-based authentication (Google OAuth or email/password).

    This decorator is useful for web routes that should not accept API key authentication.

    Args:
        redirect_to_login: Whether to redirect to login page for web requests

    Returns:
        Decorator function for web authentication route protection
    """
    return require_auth(
        allow_api_key=False,
        allow_google_oauth=True,
        allow_email_password=True,
        redirect_to_login=redirect_to_login,
    )


def optional_auth() -> callable:
    """
    Decorator that provides authentication context but doesn't require authentication.

    This decorator sets up the authentication context but allows the request
    to proceed even if not authenticated. Useful for routes that behave
    differently based on authentication status.

    Returns:
        Decorator function for optional authentication
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Initialize authentication context
                auth_context = AuthenticationContext()

                # Check API key authentication if configured
                api_key_valid = False
                api_key_user_info = None
                if _has_api_key_auth_configured():
                    api_key_valid, api_key_user_info = _check_api_key_auth()

                # Check Google OAuth authentication if configured
                google_oauth_valid = False
                google_user_info = None
                if _has_google_auth_configured():
                    google_oauth_valid, google_user_info = _check_google_oauth_auth()

                # Check email/password authentication if configured
                email_password_valid = False
                email_password_user_info = None
                if _has_email_password_auth_configured():
                    email_password_valid, email_password_user_info = (
                        _check_email_password_auth()
                    )

                # Set authentication context based on what's available
                auth_methods = []
                user_info = None

                if api_key_valid:
                    auth_methods.append("api_key")
                if google_oauth_valid:
                    auth_methods.append("google_oauth")
                    user_info = google_user_info  # Prefer Google OAuth user info
                if email_password_valid:
                    auth_methods.append("email_password")
                    if not user_info:  # Use email/password user info if no Google OAuth
                        user_info = email_password_user_info

                if auth_methods:
                    # At least one method authenticated
                    auth_method = (
                        "_".join(auth_methods)
                        if len(auth_methods) > 1
                        else auth_methods[0]
                    )

                    # Handle API key user info for compatibility
                    if (
                        api_key_valid
                        and api_key_user_info
                        and api_key_user_info.get("auth_method") == "api_key"
                    ):
                        # User API key - create UserInfo object for compatibility
                        from .token_validator import UserInfo

                        api_user_info = UserInfo(
                            email=api_key_user_info.get("email", ""),
                            name=api_key_user_info.get("name", "API User"),
                            google_id=api_key_user_info.get("google_id", ""),
                            picture_url="",
                            verified_email=True,
                        )
                        if not user_info:
                            user_info = api_user_info

                    auth_context = AuthenticationContext(
                        is_authenticated=True,
                        auth_method=auth_method,
                        user_info=user_info,
                        api_key_valid=api_key_valid,
                    )

                # Store authentication context in Flask g
                g.auth_context = auth_context

                # Always proceed to the route handler
                return f(*args, **kwargs)

            except Exception as e:
                logger.error(f"Error in optional auth decorator: {str(e)}")
                # Set empty context and continue
                g.auth_context = AuthenticationContext()
                return f(*args, **kwargs)

        return decorated_function

    return decorator


def _has_email_password_auth_configured() -> bool:
    """Check if email/password authentication is configured and enabled."""
    return (
        hasattr(current_app, "email_password_service")
        and current_app.email_password_service is not None
    )


def _check_email_password_auth() -> tuple[bool, Optional[UserInfo]]:
    """
    Check email/password authentication for the current request.

    Returns:
        tuple: (is_authenticated, user_info)
    """
    try:
        if not hasattr(current_app, "email_password_service"):
            return False, None

        email_password_service = current_app.email_password_service

        # Check if user is authenticated via email/password session
        if email_password_service.is_authenticated():
            user_info = email_password_service.get_current_user()
            return True, user_info
        else:
            return False, None

    except Exception as e:
        logger.error(f"Error checking email/password authentication: {str(e)}")
        return False, None


def _has_api_key_auth_configured() -> bool:
    """Check if API key authentication is configured and enabled."""
    return (
        hasattr(current_app, "security_config")
        and hasattr(current_app.security_config, "api_keys")
        and len(current_app.security_config.api_keys) > 0
    )


def _has_google_auth_configured() -> bool:
    """Check if Google OAuth authentication is configured."""
    try:
        from .config import google_oauth_config

        return google_oauth_config is not None
    except ImportError:
        return False


def _check_api_key_auth() -> tuple[bool, Optional[dict]]:
    """
    Check API key authentication for the current request.

    Returns:
        tuple: (is_authenticated, user_info_dict) where user_info_dict contains
               user information for user API keys, None for environment keys
    """
    try:
        # Check if this route is protected by API key system
        if not hasattr(current_app, "security_config"):
            return False, None

        current_route = request.path
        if not current_app.security_config.is_route_protected(current_route):
            # Route is public for API key system, consider it valid
            return True, None

        # Extract and validate Authorization header
        from trackers.security.api_key_auth import validate_authorization_header

        auth_header = request.headers.get("Authorization")
        is_valid, api_key, error_message = validate_authorization_header(auth_header)

        if not is_valid:
            return False, None

        # Check if this is a user API key (starts with uk_)
        if api_key.startswith("uk_") and hasattr(current_app, "api_key_service"):
            try:
                # Validate user API key and get user information
                validation_result = current_app.api_key_service.validate_user_api_key(
                    api_key
                )
                if validation_result and validation_result.is_valid:
                    # Get user information from database
                    from trackers.db.database import SessionLocal
                    from trackers.services.user_service import UserService

                    db = SessionLocal()
                    try:
                        user_service = UserService(db)
                        user = user_service.get_user_by_id(validation_result.user_id)
                        if user:
                            # Return user information in a format compatible with Google OAuth
                            user_info = {
                                "user_id": user.id,
                                "email": user.email,
                                "name": user.name,
                                "google_id": user.google_user_id,
                                "auth_method": "api_key",
                            }
                            return True, user_info
                    finally:
                        db.close()

                return False, None
            except Exception as e:
                logger.error(f"Error validating user API key: {str(e)}")
                return False, None
        else:
            # Environment API key - validate against configured keys
            is_valid = current_app.key_validator.is_valid_key(api_key)
            if is_valid:
                # For environment keys, return a system user context
                return True, {
                    "auth_method": "environment_api_key",
                    "system_access": True,
                }
            return False, None

    except Exception as e:
        logger.error(f"Error checking API key authentication: {str(e)}")
        return False, None


def _check_google_oauth_auth() -> tuple[bool, Optional[UserInfo]]:
    """
    Check Google OAuth authentication for the current request.

    Returns:
        tuple: (is_authenticated, user_info)
    """
    try:
        from .config import google_oauth_config
        from .session_manager import SessionManager

        if not google_oauth_config:
            return False, None

        # Create session manager to check authentication
        session_manager = SessionManager()
        user_session = session_manager.get_user_session()

        if user_session:
            return True, user_session.user_info
        else:
            return False, None

    except Exception as e:
        logger.error(f"Error checking Google OAuth authentication: {str(e)}")
        return False, None


def _handle_unauthenticated_request(
    redirect_to_login: bool = True,
) -> Union[tuple, str]:
    """
    Handle unauthenticated requests based on request type.

    Args:
        redirect_to_login: Whether to redirect to login page for web requests

    Returns:
        Appropriate response for unauthenticated request
    """
    client_ip = get_client_ip()
    logger.warning(f"Unauthenticated request to {request.endpoint} from {client_ip}")

    # Determine available authentication methods for error message
    available_methods = []
    if _has_api_key_auth_configured():
        available_methods.append("api_key")
    if _has_google_auth_configured():
        available_methods.append("google_oauth")
    if _has_email_password_auth_configured():
        available_methods.append("email_password")

    # For API requests (JSON), return JSON error
    if request.is_json or request.headers.get("Accept", "").startswith(
        "application/json"
    ):
        return jsonify(
            {
                "error": "Authentication required",
                "message": "This endpoint requires authentication",
                "auth_methods": available_methods,
            }
        ), 401

    # For web requests, redirect to login or return error page
    if redirect_to_login and (
        _has_google_auth_configured() or _has_email_password_auth_configured()
    ):
        # Store the current URL for post-login redirect
        from flask import session

        session["post_login_redirect"] = request.url

        try:
            return redirect(url_for("auth.login"))
        except Exception:
            # Fallback if auth routes not available
            return redirect("/auth/login")
    else:
        # Return simple error response
        return jsonify(
            {
                "error": "Authentication required",
                "message": "This endpoint requires authentication",
            }
        ), 401


def _handle_authentication_error(error_message: str) -> tuple:
    """
    Handle authentication system errors.

    Args:
        error_message: Error message to log and return

    Returns:
        JSON error response
    """
    client_ip = get_client_ip()
    logger.error(f"Authentication system error from {client_ip}: {error_message}")

    return jsonify(
        {
            "error": "Authentication system error",
            "message": "Authentication system temporarily unavailable",
        }
    ), 500
