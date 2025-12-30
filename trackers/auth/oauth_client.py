"""
Google OAuth 2.0 client implementation.

This module provides the GoogleOAuthClient class for handling Google OAuth 2.0
authentication flow including authorization URL generation, token exchange,
and state parameter management for CSRF protection.
"""

import secrets
import time
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse

import requests

from .config import GoogleOAuthConfig
from .error_handling import (
    AuthLogger,
    NetworkRetryHandler,
    OAuthConfigError,
    TokenExchangeError,
)
from .token_validator import TokenValidator


class TokenResponse:
    """Response from Google's token endpoint."""

    def __init__(self, data: Dict[str, Any]):
        """
        Initialize token response from Google's token endpoint.

        Args:
            data: Raw response data from Google's token endpoint
        """
        self.access_token: str = data.get("access_token", "")
        self.id_token: str = data.get("id_token", "")
        self.token_type: str = data.get("token_type", "Bearer")
        self.expires_in: int = data.get("expires_in", 3600)
        self.refresh_token: Optional[str] = data.get("refresh_token")
        self.scope: str = data.get("scope", "")

        # Calculate expiration timestamp
        self.expires_at = int(time.time()) + self.expires_in


class GoogleOAuthClient:
    """
    Google OAuth 2.0 client for handling authentication flow.

    This class implements the OAuth 2.0 Authorization Code flow for Google,
    including authorization URL generation, token exchange, and state validation
    for CSRF protection.
    """

    # Google OAuth 2.0 endpoints
    AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
    USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo"
    JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"

    def __init__(self, config: GoogleOAuthConfig):
        """
        Initialize OAuth client with Google configuration.

        Args:
            config: Google OAuth configuration containing credentials

        Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 8.1, 8.2
        """
        self.config = config
        self._session = requests.Session()

        # Initialize error handling components first
        self._logger = AuthLogger()
        self._retry_handler = NetworkRetryHandler()

        # Configure session for secure HTTPS communication with SSL validation
        self._configure_ssl_security()

        # Initialize token validator for JWT processing
        self._token_validator = TokenValidator(config.client_id)

        # Validate configuration on initialization
        self._validate_config()

    def generate_state_parameter(self) -> str:
        """
        Generate a cryptographically secure state parameter for CSRF protection.

        Returns:
            str: Secure random state parameter

        Requirements: 2.3 - Generate secure state parameter for CSRF protection
        """
        # Generate 32 bytes of random data and encode as URL-safe base64
        return secrets.token_urlsafe(32)

    def get_authorization_url(
        self, state: str, scopes: Optional[list[str]] = None
    ) -> str:
        """
        Generate Google OAuth authorization URL.

        Args:
            state: CSRF protection state parameter
            scopes: OAuth scopes to request (defaults to config scopes)

        Returns:
            str: Complete authorization URL for redirecting user to Google

        Requirements: 2.1, 2.2, 2.4 - Generate authorization URL with required parameters
        """
        if scopes is None:
            scopes = self.config.get_scopes()

        # Build authorization parameters
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(scopes),
            "response_type": "code",
            "state": state,
            "access_type": "offline",  # Request refresh token
            "prompt": "consent",  # Always show consent screen
        }

        # Construct full authorization URL
        auth_url = f"{self.AUTHORIZATION_ENDPOINT}?{urlencode(params)}"

        # Validate that we're using HTTPS for security
        self._validate_https_endpoint(auth_url)

        return auth_url

    def validate_state(self, received_state: str, stored_state: str) -> bool:
        """
        Validate OAuth state parameter to prevent CSRF attacks.

        Args:
            received_state: State parameter received from OAuth callback
            stored_state: State parameter that was originally generated and stored

        Returns:
            bool: True if state parameters match, False otherwise

        Requirements: 3.1 - Validate state parameter in callback
        """
        if not received_state or not stored_state:
            return False

        # Use constant-time comparison to prevent timing attacks
        return secrets.compare_digest(received_state, stored_state)

    def exchange_code_for_tokens(self, code: str, state: str) -> TokenResponse:
        """
        Exchange authorization code for access and ID tokens.

        Args:
            code: Authorization code received from Google
            state: State parameter for validation

        Returns:
            TokenResponse: Tokens and metadata from Google

        Raises:
            TokenExchangeError: If token exchange fails or response is invalid
            NetworkError: If network request fails

        Requirements: 3.2 - Exchange authorization code for tokens
        """
        # Prepare token exchange request
        token_data = {
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.config.redirect_uri,
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }

        def _make_token_request():
            """Internal function for token request with retry logic."""
            # Validate HTTPS endpoint before making request
            self._validate_https_endpoint(self.TOKEN_ENDPOINT)

            response = self._session.post(
                self.TOKEN_ENDPOINT,
                data=token_data,
                headers=headers,
                timeout=30,  # 30 second timeout
            )
            response.raise_for_status()
            return response

        try:
            # Make token exchange request with retry logic
            response = self._retry_handler.retry_with_backoff(_make_token_request)

            # Parse JSON response
            token_data = response.json()

            # Check for Google OAuth error response
            if "error" in token_data:
                error_description = token_data.get("error_description", "Unknown error")
                self._logger.log_token_exchange(
                    user_ip="unknown",  # Will be set by calling code
                    success=False,
                    error=f"{token_data['error']}: {error_description}",
                )
                raise TokenExchangeError(
                    f"Google OAuth error: {error_description}",
                    google_error=token_data["error"],
                )

            # Validate required fields are present
            required_fields = ["access_token", "id_token", "token_type"]
            missing_fields = [
                field for field in required_fields if field not in token_data
            ]

            if missing_fields:
                raise TokenExchangeError(
                    f"Token response missing required fields: {missing_fields}"
                )

            self._logger.log_token_exchange(
                user_ip="unknown",  # Will be set by calling code
                success=True,
            )

            return TokenResponse(token_data)

        except requests.RequestException as e:
            self._logger.log_token_exchange(
                user_ip="unknown",  # Will be set by calling code
                success=False,
                error=str(e),
            )
            # NetworkError will be raised by the @with_error_handling decorator
            raise e
        except (ValueError, KeyError) as e:
            raise TokenExchangeError(f"Invalid token response: {str(e)}")

    def validate_id_token(self, id_token: str) -> Dict[str, Any]:
        """
        Validate and decode Google ID token.

        Args:
            id_token: JWT ID token from Google

        Returns:
            dict: Decoded token payload with user information

        Raises:
            ValueError: If token validation fails

        Requirements: 3.4, 4.1, 4.3, 4.4 - Validate ID token signature and claims
        """
        # Use the dedicated TokenValidator for full JWT processing and validation
        return self._token_validator.validate_and_decode_token(id_token)

    def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Fetch user information using access token.

        Args:
            access_token: OAuth access token

        Returns:
            dict: User information from Google

        Raises:
            NetworkError: If API request fails

        Requirements: 4.2 - Extract user information from token
        """
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        def _make_userinfo_request():
            """Internal function for userinfo request with retry logic."""
            # Validate HTTPS endpoint before making request
            self._validate_https_endpoint(self.USERINFO_ENDPOINT)

            response = self._session.get(
                self.USERINFO_ENDPOINT, headers=headers, timeout=10
            )
            response.raise_for_status()
            return response

        try:
            response = self._retry_handler.retry_with_backoff(_make_userinfo_request)
            return response.json()
        except requests.RequestException as e:
            # NetworkError will be raised by the @with_error_handling decorator
            raise e

    def revoke_token(self, token: str) -> bool:
        """
        Revoke an access or refresh token.

        Args:
            token: Token to revoke

        Returns:
            bool: True if revocation succeeded

        Requirements: 6.2 - Invalidate stored tokens during logout
        """
        revoke_url = "https://oauth2.googleapis.com/revoke"

        def _make_revoke_request():
            """Internal function for token revocation with retry logic."""
            response = self._session.post(revoke_url, data={"token": token}, timeout=10)
            return response

        try:
            response = self._retry_handler.retry_with_backoff(_make_revoke_request)
            # Google returns 200 for successful revocation
            return response.status_code == 200
        except Exception:
            # If revocation fails, we'll still clear local session
            # This is not a critical failure
            return False

    def _validate_config(self):
        """
        Validate OAuth configuration on initialization.

        Raises:
            OAuthConfigError: If configuration is invalid or incomplete

        Requirements: 7.1, 7.2 - Detailed error logging and user-friendly messages
        """
        missing_config = []

        if not self.config.client_id:
            missing_config.append("client_id")
        if not self.config.client_secret:
            missing_config.append("client_secret")
        if not self.config.redirect_uri:
            missing_config.append("redirect_uri")

        if missing_config:
            error_msg = (
                f"Missing required OAuth configuration: {', '.join(missing_config)}"
            )
            self._logger.logger.error(error_msg)
            raise OAuthConfigError(error_msg, missing_config=missing_config)

    def _configure_ssl_security(self):
        """
        Configure SSL certificate validation and security settings for Google API calls.

        Requirements: 8.2 - Validate SSL certificates when communicating with Google
        """
        # Always verify SSL certificates - never disable verification
        self._session.verify = True

        # Configure additional SSL security settings
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        # Create retry strategy for SSL/connection errors
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],  # Updated parameter name
            backoff_factor=1,
        )

        # Create HTTP adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)

        # Mount adapter for HTTPS requests
        self._session.mount("https://", adapter)

        # Set secure headers for all requests
        self._session.headers.update(
            {
                "User-Agent": "TrackerApp-OAuth-Client/1.0",
                "Accept": "application/json",
                "Connection": "keep-alive",
            }
        )

        # Log SSL configuration
        self._logger.logger.info(
            "SSL certificate validation enabled for Google API calls"
        )

    def _validate_https_endpoint(self, url: str) -> None:
        """
        Validate that endpoint uses HTTPS protocol.

        Args:
            url: URL to validate

        Raises:
            ValueError: If URL does not use HTTPS

        Requirements: 8.1 - Use HTTPS for all OAuth communications
        """

        parsed_url = urlparse(url)
        if parsed_url.scheme != "https":
            raise ValueError(
                f"OAuth endpoint must use HTTPS protocol, got: {parsed_url.scheme}"
            )

    def _validate_config(self):
        """
        Validate OAuth configuration on initialization.

        Raises:
            OAuthConfigError: If configuration is invalid or incomplete

        Requirements: 7.1, 7.2 - Detailed error logging and user-friendly messages
        """
        missing_config = []

        if not self.config.client_id:
            missing_config.append("client_id")
        if not self.config.client_secret:
            missing_config.append("client_secret")
        if not self.config.redirect_uri:
            missing_config.append("redirect_uri")

        if missing_config:
            error_msg = (
                f"Missing required OAuth configuration: {', '.join(missing_config)}"
            )
            self._logger.logger.error(error_msg)
            raise OAuthConfigError(error_msg, missing_config=missing_config)

        # Validate that redirect URI uses HTTPS in production
        self._validate_redirect_uri_security()

    def _validate_redirect_uri_security(self):
        """
        Validate redirect URI security requirements.

        Requirements: 8.1 - HTTPS enforcement for OAuth endpoints
        """
        import os

        parsed_uri = urlparse(self.config.redirect_uri)
        environment = os.getenv("FLASK_ENV", "development")

        # In production, redirect URI must use HTTPS
        if environment == "production" and parsed_uri.scheme != "https":
            error_msg = f"Redirect URI must use HTTPS in production environment: {self.config.redirect_uri}"
            self._logger.logger.error(error_msg)
            raise OAuthConfigError(error_msg)

        # Warn about HTTP usage in development
        if environment != "production" and parsed_uri.scheme == "http":
            self._logger.logger.warning(
                f"Using HTTP redirect URI in {environment} environment: {self.config.redirect_uri}. "
                "This should only be used for local development."
            )

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self._session.close()
        self._token_validator.__exit__(exc_type, exc_val, exc_tb)
