"""
Google Authentication Service orchestrator.

This module provides the GoogleAuthService class that coordinates the complete
Google OAuth 2.0 authentication flow, including login initiation, callback
processing, and logout functionality with session cleanup.
"""

import logging
from typing import Optional
from urllib.parse import urlencode

from flask import redirect, request, url_for

from .config import GoogleOAuthConfig
from .error_handling import (
    AuthLogger,
    OAuthStateError,
    RateLimiter,
    RateLimitError,
    TokenExchangeError,
    TokenValidationError,
    get_client_ip,
)
from .oauth_client import GoogleOAuthClient
from .session_manager import SessionManager
from .token_validator import UserInfo

# Configure logging
logger = logging.getLogger(__name__)


class AuthRedirect:
    """Authentication redirect response."""

    def __init__(self, url: str, state: str):
        """
        Initialize authentication redirect.

        Args:
            url: URL to redirect user to
            state: State parameter for CSRF protection
        """
        self.url = url
        self.state = state


class AuthResult:
    """Authentication result from callback processing."""

    def __init__(
        self,
        success: bool,
        user_info: Optional[UserInfo] = None,
        error_message: Optional[str] = None,
        redirect_url: Optional[str] = None,
    ):
        """
        Initialize authentication result.

        Args:
            success: Whether authentication succeeded
            user_info: User information if successful
            error_message: Error message if failed
            redirect_url: URL to redirect to after processing
        """
        self.success = success
        self.user_info = user_info
        self.error_message = error_message
        self.redirect_url = redirect_url


class GoogleAuthService:
    """
    Central authentication service coordinating Google OAuth 2.0 flow.

    This class orchestrates the complete OAuth flow by coordinating between
    the OAuth client, session manager, and token validator components. It
    provides high-level methods for login initiation, callback processing,
    and logout functionality.
    """

    def __init__(
        self,
        config: GoogleOAuthConfig,
        session_manager: Optional[SessionManager] = None,
        rate_limiter: Optional[RateLimiter] = None,
    ):
        """
        Initialize Google Authentication Service.

        Args:
            config: Google OAuth configuration
            session_manager: Session manager instance (creates default if None)
            rate_limiter: Rate limiter instance (creates default if None)

        Requirements: 6.1, 6.2, 6.3, 6.4
        """
        self.config = config
        self.oauth_client = GoogleOAuthClient(config)
        self.session_manager = session_manager or SessionManager()
        self.rate_limiter = rate_limiter or RateLimiter()

        # Configure logging
        self.logger = AuthLogger()
        self.flask_logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def initiate_login(
        self, redirect_after_login: Optional[str] = None
    ) -> AuthRedirect:
        """
        Initiate Google OAuth login flow.

        Args:
            redirect_after_login: URL to redirect to after successful login

        Returns:
            AuthRedirect: Redirect information for sending user to Google

        Requirements: 6.1 - Implement login initiation
        """
        client_ip = get_client_ip()

        # Apply rate limiting manually since we need the instance rate_limiter
        is_limited, retry_after = self.rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            raise RateLimitError(
                f"Too many authentication attempts from {client_ip}",
                retry_after=retry_after,
            )

        try:
            # Generate secure state parameter for CSRF protection
            state = self.session_manager.generate_state_token()

            # Store redirect URL in session if provided
            if redirect_after_login:
                from flask import session

                session["post_login_redirect"] = redirect_after_login

            # Generate authorization URL
            auth_url = self.oauth_client.get_authorization_url(state)

            self.logger.log_oauth_initiation(client_ip, redirect_after_login)

            # Record successful attempt
            self.rate_limiter.record_attempt(client_ip, success=True)

            return AuthRedirect(url=auth_url, state=state)

        except Exception as e:
            # Record failed attempt
            self.rate_limiter.record_attempt(client_ip, success=False)

            self.logger.log_authentication_failure(
                client_ip, str(e), "login_initiation_failed"
            )
            raise

    def process_callback(
        self, code: Optional[str], state: Optional[str], error: Optional[str] = None
    ) -> AuthResult:
        """
        Process OAuth callback from Google.

        Args:
            code: Authorization code from Google
            state: State parameter for CSRF validation
            error: Error parameter if OAuth failed

        Returns:
            AuthResult: Result of authentication processing

        Requirements: 6.2 - Add callback processing methods
        """
        client_ip = get_client_ip()

        # Apply rate limiting for callback processing
        is_limited, retry_after = self.rate_limiter.is_rate_limited(client_ip)
        if is_limited:
            raise RateLimitError(
                f"Too many authentication attempts from {client_ip}",
                retry_after=retry_after,
            )

        try:
            # Check for OAuth errors first
            if error:
                error_msg = f"OAuth error: {error}"
                self.logger.log_oauth_callback(
                    client_ip, success=False, error=error_msg
                )
                self.rate_limiter.record_attempt(client_ip, success=False)
                return AuthResult(
                    success=False,
                    error_message=error_msg,
                    redirect_url=self._get_error_redirect_url(error),
                )

            # Validate required parameters
            if not code or not state:
                error_msg = "Missing required OAuth parameters (code or state)"
                self.logger.log_oauth_callback(
                    client_ip, success=False, error=error_msg
                )
                self.rate_limiter.record_attempt(client_ip, success=False)
                return AuthResult(
                    success=False,
                    error_message=error_msg,
                    redirect_url=self._get_error_redirect_url("missing_parameters"),
                )

            # Validate state parameter to prevent CSRF attacks
            if not self.session_manager.validate_and_consume_state(state):
                error_msg = "Invalid or expired state parameter"
                self.logger.log_oauth_callback(
                    client_ip, success=False, error=error_msg
                )
                self.rate_limiter.record_attempt(client_ip, success=False)
                raise OAuthStateError(error_msg)

            # Exchange authorization code for tokens
            token_response = self.oauth_client.exchange_code_for_tokens(code, state)

            # Validate and extract user information from ID token
            user_info_payload = self.oauth_client.validate_id_token(
                token_response.id_token
            )
            user_info = self.oauth_client._token_validator.extract_user_info(
                user_info_payload
            )

            # Store user session
            self.session_manager.store_user_session(
                user_info=user_info,
                access_token=token_response.access_token,
                token_expires_in=token_response.expires_in,
            )

            self.logger.log_authentication_success(user_info.email, client_ip)
            self.logger.log_oauth_callback(client_ip, success=True)

            # Record successful attempt
            self.rate_limiter.record_attempt(client_ip, success=True)

            # Get post-login redirect URL
            redirect_url = self._get_success_redirect_url()

            return AuthResult(
                success=True,
                user_info=user_info,
                redirect_url=redirect_url,
            )

        except (TokenExchangeError, TokenValidationError, OAuthStateError) as e:
            # These are expected authentication errors
            self.logger.log_authentication_failure(client_ip, str(e), e.error_code)
            self.rate_limiter.record_attempt(client_ip, success=False)
            return AuthResult(
                success=False,
                error_message=e.user_message,
                redirect_url=self._get_error_redirect_url(e.error_code),
            )
        except Exception as e:
            # Unexpected errors
            error_msg = f"Authentication failed: {str(e)}"
            self.logger.log_authentication_failure(
                client_ip, error_msg, "authentication_failed"
            )
            self.rate_limiter.record_attempt(client_ip, success=False)
            return AuthResult(
                success=False,
                error_message="An unexpected error occurred during authentication. Please try again.",
                redirect_url=self._get_error_redirect_url("authentication_failed"),
            )

    def get_current_user(self) -> Optional[UserInfo]:
        """
        Get current authenticated user information.

        Returns:
            Optional[UserInfo]: Current user info or None if not authenticated

        Requirements: 6.1 - Provide user context management
        """
        return self.session_manager.get_current_user()

    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated.

        Returns:
            bool: True if user is authenticated, False otherwise

        Requirements: 6.1 - Provide authentication status checking
        """
        return self.session_manager.is_authenticated()

    def logout(self, redirect_to_google: bool = False) -> str:
        """
        Log out the current user and clean up session.

        Args:
            redirect_to_google: Whether to also redirect to Google's logout

        Returns:
            str: URL to redirect to after logout

        Requirements: 6.3, 6.4 - Implement logout functionality with session cleanup
        """
        client_ip = get_client_ip()

        try:
            # Get current user info for logging
            current_user = self.get_current_user()
            user_email = current_user.email if current_user else "unknown"

            # Get access token for potential revocation
            access_token = self.session_manager.get_access_token()

            # Clear local session first
            self.session_manager.clear_session()

            # Optionally revoke tokens at Google
            if access_token:
                try:
                    self.oauth_client.revoke_token(access_token)
                    self.flask_logger.info(
                        f"Revoked Google tokens for user: {user_email}"
                    )
                except Exception as e:
                    # Token revocation failure shouldn't prevent logout
                    self.flask_logger.warning(f"Failed to revoke tokens: {str(e)}")

            self.logger.log_logout(user_email, client_ip)

            # Determine redirect URL
            if redirect_to_google:
                # Redirect to Google's logout endpoint
                google_logout_url = "https://accounts.google.com/logout"
                return google_logout_url
            else:
                # Redirect to local logout confirmation page
                return self._get_logout_redirect_url()

        except Exception as e:
            self.flask_logger.error(f"Error during logout: {str(e)}")
            # Even if logout fails, clear the session and redirect
            self.session_manager.clear_session()
            return self._get_logout_redirect_url()

    def refresh_authentication(self) -> bool:
        """
        Refresh the current authentication session.

        Returns:
            bool: True if session was refreshed, False if re-authentication needed

        Requirements: 6.1 - Provide session management
        """
        return self.session_manager.refresh_session()

    def get_session_info(self) -> dict:
        """
        Get information about the current session for debugging/monitoring.

        Returns:
            dict: Session information including expiration and status
        """
        return self.session_manager.get_session_info()

    def require_authentication(self, redirect_url: Optional[str] = None):
        """
        Decorator helper to require authentication for routes.

        Args:
            redirect_url: URL to redirect to after successful login

        Returns:
            Flask redirect response if not authenticated, None if authenticated

        Requirements: 6.1 - Provide route protection
        """
        if not self.is_authenticated():
            # Store the current URL for post-login redirect
            if not redirect_url:
                redirect_url = request.url

            # Initiate login flow
            auth_redirect = self.initiate_login(redirect_url)
            return redirect(auth_redirect.url)

        return None

    def _get_success_redirect_url(self) -> str:
        """
        Get URL to redirect to after successful authentication.

        Returns:
            str: Redirect URL
        """
        from flask import session

        # Check for stored post-login redirect
        redirect_url = session.pop("post_login_redirect", None)
        if redirect_url:
            return redirect_url

        # Default to dashboard or home page
        try:
            return url_for("web.dashboard")
        except Exception:
            # Fallback if route doesn't exist
            return "/"

    def _get_error_redirect_url(self, error_type: str) -> str:
        """
        Get URL to redirect to after authentication error.

        Args:
            error_type: Type of error that occurred

        Returns:
            str: Redirect URL with error information
        """
        try:
            # Try to redirect to login page with error
            base_url = url_for("auth.login")
            error_params = urlencode({"error": error_type})
            return f"{base_url}?{error_params}"
        except Exception:
            # Fallback if route doesn't exist
            return f"/?error={error_type}"

    def _get_logout_redirect_url(self) -> str:
        """
        Get URL to redirect to after logout.

        Returns:
            str: Redirect URL
        """
        try:
            return url_for("auth.logout_success")
        except Exception:
            # Fallback if route doesn't exist
            return "/?logged_out=true"

    def configure_flask_app(self, app):
        """
        Configure Flask application for Google authentication.

        Args:
            app: Flask application instance

        Requirements: 6.1 - Integration with Flask application
        """
        # Configure session security
        self.session_manager.configure_flask_session_security(app)

        # Add authentication context to templates
        @app.context_processor
        def inject_auth_context():
            return {
                "current_user": self.get_current_user(),
                "is_authenticated": self.is_authenticated(),
            }

        self.flask_logger.info("Configured Flask app for Google authentication")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if hasattr(self.oauth_client, "__exit__"):
            self.oauth_client.__exit__(exc_type, exc_val, exc_tb)
