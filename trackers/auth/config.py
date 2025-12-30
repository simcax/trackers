"""
Google OAuth configuration settings module.

This module manages Google OAuth 2.0 credentials and provides
configuration validation for authentication services.
"""

import os
from typing import Optional
from urllib.parse import urlparse


class GoogleOAuthConfig:
    """Google OAuth 2.0 configuration settings loaded from environment variables."""

    client_id: str
    client_secret: str
    redirect_uri: str

    def __init__(self) -> None:
        """
        Initialize Google OAuth configuration by loading from environment variables.

        Raises:
            ValueError: If any required environment variable is missing or invalid.
        """
        self._load_from_env()
        self._validate_configuration()

    def _load_from_env(self) -> None:
        """
        Load Google OAuth configuration from environment variables.

        Required environment variables:
        - GOOGLE_CLIENT_ID: OAuth client identifier from Google Cloud Console
        - GOOGLE_CLIENT_SECRET: OAuth client secret from Google Cloud Console
        - GOOGLE_REDIRECT_URI: Callback URL for OAuth flow

        Raises:
            ValueError: If any required environment variable is missing.

        Requirements: 1.1, 1.2 - Load OAuth credentials and provide clear error messages
        """
        missing_vars = []

        self.client_id = os.getenv("GOOGLE_CLIENT_ID", "")
        if not self.client_id:
            missing_vars.append("GOOGLE_CLIENT_ID")

        self.client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "")
        if not self.client_secret:
            missing_vars.append("GOOGLE_CLIENT_SECRET")

        self.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "")
        if not self.redirect_uri:
            missing_vars.append("GOOGLE_REDIRECT_URI")

        # Raise error if any variables are missing with helpful message
        if missing_vars:
            error_msg = (
                f"\n{'=' * 60}\n"
                f"MISSING REQUIRED GOOGLE OAUTH ENVIRONMENT VARIABLES\n"
                f"{'=' * 60}\n"
                f"Missing variables: {', '.join(missing_vars)}\n"
                f"\n"
                f"Required Google OAuth environment variables:\n"
                f"  GOOGLE_CLIENT_ID     - OAuth client identifier from Google Cloud Console\n"
                f"  GOOGLE_CLIENT_SECRET - OAuth client secret from Google Cloud Console\n"
                f"  GOOGLE_REDIRECT_URI  - Callback URL for OAuth flow\n"
                f"\n"
                f"How to set up Google OAuth:\n"
                f"  1. Go to Google Cloud Console (https://console.cloud.google.com/)\n"
                f"  2. Create a new project or select an existing one\n"
                f"  3. Enable the Google+ API\n"
                f"  4. Go to APIs & Services > Credentials\n"
                f"  5. Create OAuth 2.0 Client ID credentials\n"
                f"  6. Set authorized redirect URIs:\n"
                f"     - For development: http://localhost:5000/auth/google/callback\n"
                f"     - For production: https://your-domain.com/auth/google/callback\n"
                f"  7. Copy the Client ID and Client Secret\n"
                f"\n"
                f"How to configure:\n"
                f"  1. Create a .env file in the project root (if not exists)\n"
                f"  2. Add the missing variables:\n"
                f"     GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com\n"
                f"     GOOGLE_CLIENT_SECRET=your-client-secret\n"
                f"     GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback\n"
                f"  3. Or set them in your shell:\n"
                f"     export GOOGLE_CLIENT_ID=your-client-id\n"
                f"     export GOOGLE_CLIENT_SECRET=your-client-secret\n"
                f"     export GOOGLE_REDIRECT_URI=http://localhost:5000/auth/google/callback\n"
                f"{'=' * 60}\n"
            )
            raise ValueError(error_msg)

    def _validate_configuration(self) -> None:
        """
        Validate the loaded OAuth configuration parameters.

        Raises:
            ValueError: If any configuration parameter is invalid.

        Requirements: 1.3 - Validate required OAuth parameters
        """
        validation_errors = []

        # Validate client_id format (should end with .apps.googleusercontent.com)
        if not self.client_id.endswith(".apps.googleusercontent.com"):
            validation_errors.append(
                f"GOOGLE_CLIENT_ID should end with '.apps.googleusercontent.com', "
                f"got: {self.client_id}"
            )

        # Validate client_secret (should be non-empty and reasonably long)
        if len(self.client_secret) < 16:
            validation_errors.append(
                "GOOGLE_CLIENT_SECRET appears to be too short (should be at least 16 characters)"
            )

        # Validate redirect_uri format
        try:
            parsed_uri = urlparse(self.redirect_uri)
            if not parsed_uri.scheme or not parsed_uri.netloc:
                validation_errors.append(
                    f"GOOGLE_REDIRECT_URI must be a valid URL, got: {self.redirect_uri}"
                )
            elif parsed_uri.scheme not in ["http", "https"]:
                validation_errors.append(
                    f"GOOGLE_REDIRECT_URI must use http or https scheme, got: {parsed_uri.scheme}"
                )
        except Exception as e:
            validation_errors.append(
                f"GOOGLE_REDIRECT_URI is not a valid URL: {self.redirect_uri} ({str(e)})"
            )

        # Raise error if any validation issues found
        if validation_errors:
            error_msg = (
                f"\n{'=' * 60}\n"
                f"INVALID GOOGLE OAUTH CONFIGURATION\n"
                f"{'=' * 60}\n"
                f"Configuration validation errors:\n"
            )
            for i, error in enumerate(validation_errors, 1):
                error_msg += f"  {i}. {error}\n"

            error_msg += (
                f"\n"
                f"Please check your Google OAuth configuration:\n"
                f"  - Client ID should be from Google Cloud Console\n"
                f"  - Client Secret should be the full secret from Google Cloud Console\n"
                f"  - Redirect URI should match exactly what's configured in Google Cloud Console\n"
                f"{'=' * 60}\n"
            )
            raise ValueError(error_msg)

    def supports_environment(self, environment: Optional[str] = None) -> bool:
        """
        Check if configuration supports multiple environments.

        Args:
            environment: Environment name to check (e.g., 'development', 'production')

        Returns:
            bool: True if environment-specific redirect URIs are supported

        Requirements: 1.4 - Support environment-specific redirect URIs
        """
        if environment is None:
            environment = os.getenv("FLASK_ENV", "development")

        # Check if redirect URI is appropriate for the environment
        parsed_uri = urlparse(self.redirect_uri)

        if environment == "production":
            return parsed_uri.scheme == "https"
        elif environment in ["development", "testing"]:
            return (
                parsed_uri.hostname in ["localhost", "127.0.0.1"]
                or parsed_uri.scheme == "https"
            )
        else:
            # Unknown environment, assume it's valid
            return True

    def get_scopes(self) -> list[str]:
        """
        Get the OAuth scopes required for Google authentication.

        Returns:
            list[str]: List of OAuth scopes

        Requirements: 2.4 - Request appropriate OAuth scopes
        """
        return ["openid", "email", "profile"]

    def __repr__(self) -> str:
        """Return string representation with masked client secret."""
        masked_secret = (
            f"{self.client_secret[:4]}...{self.client_secret[-4:]}"
            if len(self.client_secret) > 8
            else "***"
        )
        return f"GoogleOAuthConfig(client_id='{self.client_id}', redirect_uri='{self.redirect_uri}', client_secret='{masked_secret}')"


# Global configuration instance
try:
    google_oauth_config = GoogleOAuthConfig()
except ValueError:
    # Configuration will be None if environment variables are not set
    # This allows the application to start without OAuth configured
    google_oauth_config = None
