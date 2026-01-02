"""
User context management for authenticated requests.

This module provides user context management that integrates with both
API key authentication and Google OAuth authentication, allowing the
application to maintain consistent user context across different
authentication methods.

Requirements: 5.4 - Add user context management for authenticated requests
"""

import logging
from typing import Optional

from flask import current_app, g, has_request_context

from .decorators import get_auth_context
from .token_validator import UserInfo

# Configure logging
logger = logging.getLogger(__name__)


class UserContextManager:
    """
    Manages user context for authenticated requests.

    This class provides a unified interface for accessing user information
    and authentication status regardless of the authentication method used.
    """

    @staticmethod
    def get_current_user() -> Optional[UserInfo]:
        """
        Get the current authenticated user information.

        Returns:
            Optional[UserInfo]: Current user info from Google OAuth, or None if not authenticated via OAuth

        Requirements: 5.4 - Provide user context management
        """
        if not has_request_context():
            return None

        try:
            auth_context = get_auth_context()
            return auth_context.user_info
        except Exception as e:
            logger.error(f"Error getting current user: {str(e)}")
            return None

    @staticmethod
    def is_authenticated() -> bool:
        """
        Check if the current request is authenticated.

        Returns:
            bool: True if authenticated via any method, False otherwise

        Requirements: 5.3 - Provide methods to check authentication status
        """
        if not has_request_context():
            return False

        try:
            auth_context = get_auth_context()
            return auth_context.is_authenticated
        except Exception as e:
            logger.error(f"Error checking authentication status: {str(e)}")
            return False

    @staticmethod
    def get_auth_method() -> Optional[str]:
        """
        Get the authentication method used for the current request.

        Returns:
            Optional[str]: Authentication method ('api_key', 'google_oauth', 'both') or None
        """
        if not has_request_context():
            return None

        try:
            auth_context = get_auth_context()
            return auth_context.auth_method if auth_context.is_authenticated else None
        except Exception as e:
            logger.error(f"Error getting auth method: {str(e)}")
            return None

    @staticmethod
    def has_api_key_auth() -> bool:
        """
        Check if the current request was authenticated via API key.

        Returns:
            bool: True if API key authentication was successful
        """
        if not has_request_context():
            return False

        try:
            auth_context = get_auth_context()
            return auth_context.api_key_valid
        except Exception as e:
            logger.error(f"Error checking API key auth: {str(e)}")
            return False

    @staticmethod
    def has_google_oauth() -> bool:
        """
        Check if the current request was authenticated via Google OAuth.

        Returns:
            bool: True if Google OAuth authentication was successful
        """
        if not has_request_context():
            return False

        try:
            auth_context = get_auth_context()
            return auth_context.user_info is not None
        except Exception as e:
            logger.error(f"Error checking Google OAuth: {str(e)}")
            return False

    @staticmethod
    def get_user_email() -> Optional[str]:
        """
        Get the email of the current authenticated user.

        Returns:
            Optional[str]: User email from Google OAuth, or None if not available
        """
        user = UserContextManager.get_current_user()
        return user.email if user else None

    @staticmethod
    def get_user_name() -> Optional[str]:
        """
        Get the name of the current authenticated user.

        Returns:
            Optional[str]: User name from Google OAuth, or None if not available
        """
        user = UserContextManager.get_current_user()
        return user.name if user else None

    @staticmethod
    def get_google_id() -> Optional[str]:
        """
        Get the Google ID of the current authenticated user.

        Returns:
            Optional[str]: Google ID from OAuth, or None if not available
        """
        user = UserContextManager.get_current_user()
        return user.google_id if user else None

    @staticmethod
    def get_context_summary() -> dict:
        """
        Get a summary of the current authentication context.

        Returns:
            dict: Summary of authentication context for logging/debugging

        Requirements: 5.4 - Provide comprehensive user context information
        """
        if not has_request_context():
            return {"has_request_context": False}

        try:
            auth_context = get_auth_context()
            return {
                "has_request_context": True,
                "is_authenticated": auth_context.is_authenticated,
                "auth_method": auth_context.auth_method,
                "api_key_valid": auth_context.api_key_valid,
                "has_user_info": auth_context.user_info is not None,
                "user_email": auth_context.user_email,
                "user_name": auth_context.user_name,
            }
        except Exception as e:
            logger.error(f"Error getting context summary: {str(e)}")
            return {
                "has_request_context": True,
                "error": str(e),
            }


def configure_user_context(app):
    """
    Configure user context management for the Flask application.

    This function sets up template context processors and other integrations
    to make user context available throughout the application.

    Args:
        app: Flask application instance

    Requirements: 5.4 - Integrate user context with Flask application
    """

    @app.context_processor
    def inject_user_context():
        """
        Inject user context into all templates.

        This makes authentication information available in all Jinja2 templates
        without requiring explicit passing from route handlers.
        """
        try:
            # Import image utilities with defensive error handling
            try:
                from trackers.utils.image_utils import (
                    get_avatar_initials,
                    get_proxied_image_url,
                    get_safe_profile_image_url,
                )

                image_utils_available = True
            except ImportError as e:
                logger.warning(f"Image utilities not available: {e}")

                # Provide fallback functions
                def get_avatar_initials(name):
                    return name[0].upper() if name else "U"

                def get_proxied_image_url(url):
                    return url

                def get_safe_profile_image_url(url):
                    return url

                image_utils_available = False

            # Import admin functions with defensive error handling
            try:
                from trackers.auth.admin import is_admin_user

                admin_functions_available = True
            except ImportError as e:
                logger.warning(f"Admin functions not available: {e}")

                def is_admin_user(email=None):
                    return False

                admin_functions_available = False

            # For web interface, consider both Google OAuth and email/password authentication
            # API keys should only be used for API endpoints, not web pages
            try:
                from trackers.auth.decorators import (
                    _check_email_password_auth,
                    _check_google_oauth_auth,
                    _has_email_password_auth_configured,
                    _has_google_auth_configured,
                )

                current_user = None
                is_web_authenticated = False
                auth_method = None
                has_google_oauth = False
                has_email_password = False

                # Always check if authentication methods are configured
                if _has_google_auth_configured():
                    has_google_oauth = True

                if _has_email_password_auth_configured():
                    has_email_password = True

                # Check Google OAuth authentication first
                if has_google_oauth:
                    try:
                        google_oauth_valid, google_user_info = (
                            _check_google_oauth_auth()
                        )
                        if google_oauth_valid and google_user_info:
                            current_user = google_user_info
                            is_web_authenticated = True
                            auth_method = "google_oauth"
                    except Exception as e:
                        logger.debug(f"Google OAuth check failed: {str(e)}")

                # Check email/password authentication if not already authenticated
                if not is_web_authenticated and has_email_password:
                    try:
                        email_password_valid, email_password_user_info = (
                            _check_email_password_auth()
                        )
                        if email_password_valid and email_password_user_info:
                            current_user = email_password_user_info
                            is_web_authenticated = True
                            auth_method = "email_password"
                    except Exception as e:
                        logger.debug(f"Email/password check failed: {str(e)}")

            except Exception as e:
                logger.error(
                    f"Error checking authentication in context processor: {str(e)}"
                )
                current_user = None
                is_web_authenticated = False
                auth_method = None
                has_google_oauth = False
                has_email_password = False

            return {
                "current_user": current_user,
                "is_authenticated": is_web_authenticated,
                "auth_method": auth_method,
                "has_api_key_auth": False,  # Never show API key auth status in web UI
                "has_google_oauth": has_google_oauth,
                "has_email_password": has_email_password,
                # Image utility functions
                "get_proxied_image_url": get_proxied_image_url,
                "get_avatar_initials": get_avatar_initials,
                "get_safe_profile_image_url": get_safe_profile_image_url,
                "image_utils_available": image_utils_available,
                # Admin functions
                "is_admin_user": is_admin_user,
                "admin_functions_available": admin_functions_available,
            }
        except Exception as e:
            logger.error(f"Error injecting user context into templates: {str(e)}")
            return {
                "current_user": None,
                "is_authenticated": False,
                "auth_method": None,
                "has_api_key_auth": False,
                "has_google_oauth": False,
                "has_email_password": False,
            }

    @app.before_request
    def log_request_context():
        """
        Log request context for debugging and monitoring.

        This helps with troubleshooting authentication issues by providing
        detailed context information in the logs.
        """
        try:
            # Only log for protected routes to avoid noise
            if hasattr(current_app, "security_config"):
                current_route = g.get("request_path", "/")
                if current_app.security_config.is_route_protected(current_route):
                    context_summary = UserContextManager.get_context_summary()
                    logger.debug(
                        f"Request context for {current_route}: {context_summary}"
                    )
        except Exception as e:
            logger.error(f"Error logging request context: {str(e)}")

    logger.info("User context management configured for Flask application")


# Convenience functions for backward compatibility and ease of use
def get_current_user() -> Optional[UserInfo]:
    """Convenience function to get current user."""
    return UserContextManager.get_current_user()


def is_authenticated() -> bool:
    """Convenience function to check authentication status."""
    return UserContextManager.is_authenticated()


def get_auth_method() -> Optional[str]:
    """Convenience function to get authentication method."""
    return UserContextManager.get_auth_method()


def has_api_key_auth() -> bool:
    """Convenience function to check API key authentication."""
    return UserContextManager.has_api_key_auth()


def has_google_oauth() -> bool:
    """Convenience function to check Google OAuth authentication."""
    return UserContextManager.has_google_oauth()
