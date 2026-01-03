"""
Session Manager for Flask integration.

This module provides the SessionManager class for secure session storage,
session lifecycle management with expiration, and authentication status
checking methods for Google OAuth 2.0 authentication.
"""

import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Optional

from flask import session

from .token_validator import UserInfo


class UserSession:
    """User session data with authentication information and token metadata."""

    def __init__(
        self,
        user_info: UserInfo,
        access_token: str,
        token_expires_at: datetime,
        session_created_at: Optional[datetime] = None,
    ):
        """
        Initialize user session with authentication data.

        Args:
            user_info: User information from Google ID token
            access_token: OAuth access token for API calls
            token_expires_at: When the access token expires
            session_created_at: When the session was created (defaults to now)
        """
        self.user_info = user_info
        self.access_token = access_token
        self.token_expires_at = token_expires_at
        self.session_created_at = session_created_at or datetime.utcnow()

    def is_expired(self, session_timeout_hours: int = 24) -> bool:
        """
        Check if the session has expired.

        Args:
            session_timeout_hours: Session timeout in hours (default 24)

        Returns:
            bool: True if session has expired, False otherwise
        """
        # Check if session has exceeded maximum age
        session_age = datetime.utcnow() - self.session_created_at
        if session_age > timedelta(hours=session_timeout_hours):
            return True

        # Check if access token has expired
        if datetime.utcnow() >= self.token_expires_at:
            return True

        return False

    def to_dict(self) -> dict:
        """
        Convert session to dictionary for Flask session storage.

        Returns:
            dict: Session data suitable for Flask session storage
        """
        return {
            "user_info": {
                "google_id": self.user_info.google_id,
                "email": self.user_info.email,
                "name": self.user_info.name,
                "picture_url": self.user_info.picture_url,
                "verified_email": self.user_info.verified_email,
            },
            "access_token": self.access_token,
            "token_expires_at": self.token_expires_at.isoformat(),
            "session_created_at": self.session_created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "UserSession":
        """
        Create UserSession from dictionary stored in Flask session.

        Args:
            data: Session data from Flask session

        Returns:
            UserSession: Reconstructed session object

        Raises:
            ValueError: If session data is invalid or corrupted
        """
        try:
            # Reconstruct UserInfo
            user_info_data = data["user_info"]
            user_info = UserInfo(
                google_id=user_info_data["google_id"],
                email=user_info_data["email"],
                name=user_info_data["name"],
                picture_url=user_info_data.get("picture_url"),
                verified_email=user_info_data.get("verified_email", False),
            )

            # Parse datetime fields
            token_expires_at = datetime.fromisoformat(data["token_expires_at"])
            session_created_at = datetime.fromisoformat(data["session_created_at"])

            return cls(
                user_info=user_info,
                access_token=data["access_token"],
                token_expires_at=token_expires_at,
                session_created_at=session_created_at,
            )

        except (KeyError, ValueError, TypeError) as e:
            raise ValueError(f"Invalid session data: {str(e)}") from e


class SessionManager:
    """
    Session Manager for Flask integration with Google OAuth 2.0.

    This class provides secure session storage, session lifecycle management
    with expiration, and authentication status checking methods. It integrates
    with Flask's session system while providing additional security features.
    """

    # Session keys for storing authentication data
    SESSION_USER_KEY = "google_auth_user"
    SESSION_STATE_KEY = "google_auth_state"
    SESSION_NONCE_KEY = "google_auth_nonce"

    def __init__(self, session_timeout_hours: int = 24):
        """
        Initialize Session Manager with configuration.

        Args:
            session_timeout_hours: Session timeout in hours (default 24)

        Requirements: 5.1, 5.2, 5.3, 5.4
        """
        self.session_timeout_hours = session_timeout_hours

    def store_user_session(
        self, user_info: UserInfo, access_token: str, token_expires_in: int
    ) -> None:
        """
        Store user session information securely in Flask session.

        Args:
            user_info: User information from Google ID token
            access_token: OAuth access token
            token_expires_in: Token expiration time in seconds

        Requirements: 5.1 - Store user information securely when authentication succeeds
        """
        # Calculate token expiration time
        token_expires_at = datetime.utcnow() + timedelta(seconds=token_expires_in)

        # Create user session object
        user_session = UserSession(
            user_info=user_info,
            access_token=access_token,
            token_expires_at=token_expires_at,
        )

        # Store in Flask session
        session[self.SESSION_USER_KEY] = user_session.to_dict()

        # Mark session as permanent to enable expiration handling
        session.permanent = True

        # Clear any temporary authentication state
        self._clear_temporary_state()

    def get_user_session(self) -> Optional[UserSession]:
        """
        Retrieve current user session if valid.

        Returns:
            Optional[UserSession]: Current user session or None if not authenticated

        Requirements: 5.3 - Provide methods to check authentication status
        """
        # Check if user session exists in Flask session
        session_data = session.get(self.SESSION_USER_KEY)
        if not session_data:
            return None

        try:
            # Reconstruct user session from stored data
            user_session = UserSession.from_dict(session_data)

            # Check if session has expired
            if user_session.is_expired(self.session_timeout_hours):
                # Clear expired session
                self.clear_session()
                return None

            return user_session

        except ValueError:
            # Session data is corrupted, clear it
            self.clear_session()
            return None

    def clear_session(self) -> None:
        """
        Clear all session data and invalidate authentication.

        Requirements: 6.1, 6.2 - Clear local session and invalidate stored tokens
        Requirements: 8.5 - Proper session cleanup on logout
        """
        # Remove user session data
        session.pop(self.SESSION_USER_KEY, None)

        # Clear any temporary authentication state
        self._clear_temporary_state()

        # Clear any additional session data that might persist
        self._clear_additional_session_data()

        # Mark session as not permanent and regenerate session ID for security
        session.permanent = False

        # Force session regeneration by clearing the entire session
        # This prevents session fixation attacks
        session.clear()

    def _clear_additional_session_data(self) -> None:
        """
        Clear additional session data that might be stored by other components.

        This ensures complete session cleanup on logout.

        Requirements: 8.5 - Complete session cleanup
        """
        # Clear any post-login redirect URLs
        session.pop("post_login_redirect", None)

        # Clear any user preferences or cached data
        session.pop("user_preferences", None)
        session.pop("user_context", None)
        session.pop("database_user_id", None)

        # Clear any CSRF tokens or form data
        session.pop("csrf_token", None)
        session.pop("form_data", None)

        # Clear any temporary data that might be stored
        keys_to_clear = [key for key in session.keys() if key.startswith("temp_")]
        for key in keys_to_clear:
            session.pop(key, None)

    def generate_state_token(self) -> str:
        """
        Generate and store a secure state parameter for CSRF protection.

        Returns:
            str: Cryptographically secure state parameter

        Requirements: 2.3 - Generate secure state parameter to prevent CSRF attacks
        """
        # Generate cryptographically secure state parameter
        state_token = secrets.token_urlsafe(32)

        # Store in session for later validation
        session[self.SESSION_STATE_KEY] = {
            "token": state_token,
            "created_at": time.time(),
        }

        return state_token

    def validate_and_consume_state(self, received_state: str) -> bool:
        """
        Validate OAuth state parameter and consume it (one-time use).

        Args:
            received_state: State parameter received from OAuth callback

        Returns:
            bool: True if state is valid and matches stored state

        Requirements: 3.1 - Validate state parameter in OAuth callback
        """
        # Get stored state data
        stored_state_data = session.get(self.SESSION_STATE_KEY)
        if not stored_state_data:
            return False

        try:
            stored_state = stored_state_data["token"]
            created_at = stored_state_data["created_at"]

            # Check if state has expired (5 minute timeout)
            if time.time() - created_at > 300:
                self._clear_state_token()
                return False

            # Validate state parameter using constant-time comparison
            is_valid = secrets.compare_digest(received_state, stored_state)

            # Consume the state token (remove it after use)
            self._clear_state_token()

            return is_valid

        except (KeyError, TypeError):
            # Invalid state data format
            self._clear_state_token()
            return False

    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated with valid session.

        Returns:
            bool: True if user is authenticated, False otherwise

        Requirements: 5.3 - Provide methods to check authentication status
        """
        user_session = self.get_user_session()
        return user_session is not None

    def get_current_user(self) -> Optional[UserInfo]:
        """
        Get current authenticated user information.

        Returns:
            Optional[UserInfo]: Current user info or None if not authenticated

        Requirements: 5.3 - Provide methods to check authentication status
        """
        user_session = self.get_user_session()
        return user_session.user_info if user_session else None

    def get_access_token(self) -> Optional[str]:
        """
        Get current user's access token if authenticated.

        Returns:
            Optional[str]: Access token or None if not authenticated
        """
        user_session = self.get_user_session()
        return user_session.access_token if user_session else None

    def refresh_session(self) -> bool:
        """
        Refresh the current session to extend its lifetime.

        Returns:
            bool: True if session was refreshed, False if no valid session

        Requirements: 5.2 - Include session expiration and renewal mechanisms
        Requirements: 8.5 - Session persistence and renewal
        """
        user_session = self.get_user_session()
        if not user_session:
            return False

        # Check if token is still valid (not expired)
        if datetime.utcnow() >= user_session.token_expires_at:
            # Token has expired, cannot refresh
            self.clear_session()
            return False

        # Update session creation time to extend lifetime
        user_session.session_created_at = datetime.utcnow()

        # Store updated session
        session[self.SESSION_USER_KEY] = user_session.to_dict()

        # Ensure session is marked as permanent and modified
        session.permanent = True
        session.modified = True

        return True

    def extend_session_lifetime(self, additional_hours: int = None) -> bool:
        """
        Extend the current session lifetime by additional hours.

        Args:
            additional_hours: Additional hours to extend session (defaults to session_timeout_hours)

        Returns:
            bool: True if session was extended, False if no valid session

        Requirements: 8.5 - Session lifetime management
        """
        user_session = self.get_user_session()
        if not user_session:
            return False

        # Use default timeout if not specified
        if additional_hours is None:
            additional_hours = self.session_timeout_hours

        # Extend the session creation time
        user_session.session_created_at = datetime.utcnow()

        # Store updated session
        session[self.SESSION_USER_KEY] = user_session.to_dict()
        session.permanent = True
        session.modified = True

        return True

    def get_session_expiry_info(self) -> dict:
        """
        Get detailed information about session expiry times.

        Returns:
            dict: Session expiry information including remaining time

        Requirements: 8.5 - Session monitoring and management
        """
        user_session = self.get_user_session()
        if not user_session:
            return {
                "has_session": False,
                "is_expired": True,
            }

        now = datetime.utcnow()
        session_expires_at = user_session.session_created_at + timedelta(
            hours=self.session_timeout_hours
        )
        token_expires_at = user_session.token_expires_at

        # Calculate remaining times
        session_remaining = session_expires_at - now
        token_remaining = token_expires_at - now

        return {
            "has_session": True,
            "is_expired": user_session.is_expired(self.session_timeout_hours),
            "session_created_at": user_session.session_created_at.isoformat(),
            "session_expires_at": session_expires_at.isoformat(),
            "token_expires_at": token_expires_at.isoformat(),
            "session_remaining_seconds": max(0, int(session_remaining.total_seconds())),
            "token_remaining_seconds": max(0, int(token_remaining.total_seconds())),
            "session_remaining_minutes": max(
                0, int(session_remaining.total_seconds() / 60)
            ),
            "token_remaining_minutes": max(
                0, int(token_remaining.total_seconds() / 60)
            ),
            "will_expire_soon": session_remaining.total_seconds()
            < 3600,  # Less than 1 hour
        }

    def get_session_info(self) -> dict:
        """
        Get information about the current session for debugging/monitoring.

        Returns:
            dict: Session information including expiration times and status
        """
        user_session = self.get_user_session()
        if not user_session:
            return {
                "authenticated": False,
                "session_exists": False,
            }

        return {
            "authenticated": True,
            "session_exists": True,
            "user_email": user_session.user_info.email,
            "user_name": user_session.user_info.name,
            "session_created_at": user_session.session_created_at.isoformat(),
            "token_expires_at": user_session.token_expires_at.isoformat(),
            "session_age_minutes": (
                datetime.utcnow() - user_session.session_created_at
            ).total_seconds()
            / 60,
            "token_expires_in_minutes": (
                user_session.token_expires_at - datetime.utcnow()
            ).total_seconds()
            / 60,
            "is_expired": user_session.is_expired(self.session_timeout_hours),
        }

    def _clear_temporary_state(self) -> None:
        """Clear temporary authentication state (state tokens, nonces)."""
        self._clear_state_token()
        session.pop(self.SESSION_NONCE_KEY, None)

    def _clear_state_token(self) -> None:
        """Clear stored state token."""
        session.pop(self.SESSION_STATE_KEY, None)

    def configure_flask_session_security(self, app) -> None:
        """
        Configure Flask session security settings with comprehensive security flags.

        Args:
            app: Flask application instance

        Requirements: 8.3 - Implement secure session storage with appropriate flags
        Requirements: 8.5 - Authentication state persistence across page refreshes and browser sessions
        """
        import os
        from datetime import timedelta

        # Determine if we're in a secure environment
        environment = os.getenv("FLASK_ENV", "development")
        is_production = environment == "production"
        is_https = os.getenv("HTTPS", "false").lower() in ("true", "1", "yes")

        # Configure comprehensive session security settings
        app.config.update(
            {
                # Session security flags - Requirements: 8.3
                "SESSION_COOKIE_SECURE": is_production
                or is_https,  # HTTPS only in production
                "SESSION_COOKIE_HTTPONLY": True,  # Prevent JavaScript access
                "SESSION_COOKIE_SAMESITE": "Lax",  # CSRF protection while allowing OAuth redirects
                # Additional security settings
                "SESSION_COOKIE_NAME": "tracker_session",  # Custom session cookie name
                "SESSION_COOKIE_DOMAIN": None,  # Use default domain
                "SESSION_COOKIE_PATH": "/",  # Available for entire application
                # Session lifetime and management - Requirements: 8.5
                "PERMANENT_SESSION_LIFETIME": timedelta(
                    hours=self.session_timeout_hours
                ),
                "SESSION_REFRESH_EACH_REQUEST": True,  # Refresh session on each request
                # Enhanced session persistence settings
                "SESSION_PERMANENT": True,  # Make sessions permanent by default
                "SESSION_USE_SIGNER": True,  # Sign session cookies for integrity
                # Ensure we have a secure secret key
                "SECRET_KEY": app.config.get("SECRET_KEY")
                or self._generate_secure_secret_key(),
            }
        )

        # Validate secret key security
        self._validate_secret_key_security(app)

        # Configure session persistence hooks
        self._configure_session_persistence_hooks(app)

        # Log security configuration
        self._log_session_security_config(app, is_production, is_https)

    def _generate_secure_secret_key(self) -> str:
        """
        Generate a cryptographically secure secret key.

        Returns:
            str: Secure random secret key
        """
        return secrets.token_hex(32)  # 256-bit key

    def _validate_secret_key_security(self, app) -> None:
        """
        Validate that the secret key meets security requirements.

        Args:
            app: Flask application instance

        Requirements: 8.3 - Secure session storage
        """
        secret_key = app.config.get("SECRET_KEY", "")

        # Check secret key length and complexity
        if len(secret_key) < 32:
            app.logger.warning(
                f"SECRET_KEY is too short ({len(secret_key)} chars). "
                "Recommend at least 32 characters for security."
            )

        # Check for default/weak keys
        weak_keys = ["dev", "development", "secret", "key", "password", "123456"]
        if secret_key.lower() in weak_keys:
            app.logger.error(
                f"SECRET_KEY is using a weak/default value: {secret_key}. "
                "This is a serious security risk!"
            )

        # In production, ensure key is not the default
        environment = os.getenv("FLASK_ENV", "development")
        if environment == "production" and secret_key in ["dev", ""]:
            raise ValueError(
                "Production environment requires a secure SECRET_KEY. "
                "Set the SECRET_KEY environment variable."
            )

    def _log_session_security_config(
        self, app, is_production: bool, is_https: bool
    ) -> None:
        """
        Log session security configuration for monitoring.

        Args:
            app: Flask application instance
            is_production: Whether running in production
            is_https: Whether HTTPS is enabled
        """
        secure_cookie = app.config.get("SESSION_COOKIE_SECURE", False)
        httponly = app.config.get("SESSION_COOKIE_HTTPONLY", False)
        samesite = app.config.get("SESSION_COOKIE_SAMESITE", "None")
        permanent = app.config.get("SESSION_PERMANENT", False)

        app.logger.info("Session security configuration:")
        app.logger.info(f"  - Secure cookies: {secure_cookie}")
        app.logger.info(f"  - HttpOnly: {httponly}")
        app.logger.info(f"  - SameSite: {samesite}")
        app.logger.info(f"  - Session timeout: {self.session_timeout_hours} hours")
        app.logger.info(f"  - Permanent sessions: {permanent}")
        app.logger.info(
            f"  - Session refresh on request: {app.config.get('SESSION_REFRESH_EACH_REQUEST', False)}"
        )

        # Security warnings
        if is_production and not secure_cookie:
            app.logger.warning(
                "⚠ Secure cookies disabled in production environment. "
                "This may be a security risk if not using HTTPS."
            )

        if not httponly:
            app.logger.warning(
                "⚠ HttpOnly flag disabled. Session cookies accessible via JavaScript."
            )

        if samesite == "None":
            app.logger.warning(
                "⚠ SameSite=None allows cross-site requests. Ensure CSRF protection is enabled."
            )

        # Development warnings
        if not is_production and not is_https:
            app.logger.info(
                "Running in development mode - session cookies will not be secure over HTTP. "
                "This is normal for local development."
            )

    def _configure_session_persistence_hooks(self, app) -> None:
        """
        Configure session persistence hooks for enhanced session management.

        Args:
            app: Flask application instance

        Requirements: 8.5 - Authentication state persistence across page refreshes and browser sessions
        """
        from flask import session

        @app.before_request
        def ensure_session_persistence():
            """
            Ensure session persistence is properly configured for each request.

            This hook ensures that authenticated sessions are marked as permanent
            and have proper expiration handling.
            """
            try:
                # Check if user is authenticated
                user_session_data = session.get(self.SESSION_USER_KEY)
                if user_session_data:
                    # Mark session as permanent to enable proper expiration
                    session.permanent = True

                    # Validate session data integrity
                    try:
                        user_session = UserSession.from_dict(user_session_data)

                        # Check if session has expired
                        if user_session.is_expired(self.session_timeout_hours):
                            # Clear expired session
                            self.clear_session()
                            app.logger.info("Cleared expired user session")
                        else:
                            # Session is valid, ensure it's properly configured
                            app.logger.debug(
                                f"Valid session for user: {user_session.user_info.email}"
                            )

                    except ValueError as e:
                        # Session data is corrupted, clear it
                        self.clear_session()
                        app.logger.warning(f"Cleared corrupted session data: {str(e)}")

            except Exception as e:
                app.logger.error(f"Error in session persistence hook: {str(e)}")

        @app.after_request
        def refresh_session_on_activity(response):
            """
            Refresh session expiration on user activity.

            This extends the session lifetime when the user is actively using the application.

            Requirements: 8.5 - Session persistence and renewal
            """
            try:
                # Only refresh for authenticated users
                user_session_data = session.get(self.SESSION_USER_KEY)
                if user_session_data and session.permanent:
                    # Update session modified time to extend lifetime
                    session.modified = True
                    app.logger.debug("Refreshed session expiration on user activity")

            except Exception as e:
                app.logger.error(f"Error refreshing session: {str(e)}")

            return response

        app.logger.info("Session persistence hooks configured")
