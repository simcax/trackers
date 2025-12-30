"""
Tests for Google OAuth configuration module.

Tests verify that OAuth configuration loading and validation works correctly.
"""

import os
import sys
from unittest.mock import patch

import pytest


class TestGoogleOAuthConfig:
    """Test GoogleOAuthConfig class functionality."""

    def test_load_valid_configuration(self):
        """Test loading valid Google OAuth configuration from environment variables."""
        # Set up valid environment variables
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            # Import fresh to avoid cached module
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            config = GoogleOAuthConfig()

            # Verify all values are loaded correctly
            assert config.client_id == "test-client-id.apps.googleusercontent.com"
            assert config.client_secret == "test-client-secret-1234567890"
            assert config.redirect_uri == "http://localhost:5000/auth/google/callback"

    def test_missing_environment_variables(self):
        """Test error handling when required environment variables are missing."""
        # Clear all environment variables
        with patch.dict(os.environ, {}, clear=True):
            # Import fresh to avoid cached module
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            with pytest.raises(ValueError) as exc_info:
                GoogleOAuthConfig()

            error_message = str(exc_info.value)
            assert (
                "MISSING REQUIRED GOOGLE OAUTH ENVIRONMENT VARIABLES" in error_message
            )
            assert "GOOGLE_CLIENT_ID" in error_message
            assert "GOOGLE_CLIENT_SECRET" in error_message
            assert "GOOGLE_REDIRECT_URI" in error_message

    def test_invalid_client_id_format(self):
        """Test validation error for invalid client ID format."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "invalid-client-id",  # Missing .apps.googleusercontent.com
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            with pytest.raises(ValueError) as exc_info:
                GoogleOAuthConfig()

            error_message = str(exc_info.value)
            assert "INVALID GOOGLE OAUTH CONFIGURATION" in error_message
            assert "should end with '.apps.googleusercontent.com'" in error_message

    def test_invalid_client_secret_length(self):
        """Test validation error for client secret that's too short."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "short",  # Too short
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            with pytest.raises(ValueError) as exc_info:
                GoogleOAuthConfig()

            error_message = str(exc_info.value)
            assert "INVALID GOOGLE OAUTH CONFIGURATION" in error_message
            assert "appears to be too short" in error_message

    def test_invalid_redirect_uri_format(self):
        """Test validation error for invalid redirect URI format."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "not-a-valid-url",  # Invalid URL
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            with pytest.raises(ValueError) as exc_info:
                GoogleOAuthConfig()

            error_message = str(exc_info.value)
            assert "INVALID GOOGLE OAUTH CONFIGURATION" in error_message
            assert "must be a valid URL" in error_message

    def test_environment_support_production(self):
        """Test environment support validation for production."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "https://example.com/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            config = GoogleOAuthConfig()
            assert config.supports_environment("production") is True

    def test_environment_support_development(self):
        """Test environment support validation for development."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            config = GoogleOAuthConfig()
            assert config.supports_environment("development") is True

    def test_get_scopes(self):
        """Test that correct OAuth scopes are returned."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            config = GoogleOAuthConfig()
            scopes = config.get_scopes()

            assert scopes == ["openid", "email", "profile"]

    def test_repr_masks_client_secret(self):
        """Test that string representation masks the client secret."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            from trackers.auth.config import GoogleOAuthConfig

            config = GoogleOAuthConfig()
            repr_str = repr(config)

            assert "test-client-id.apps.googleusercontent.com" in repr_str
            assert "http://localhost:5000/auth/google/callback" in repr_str
            assert "test..." in repr_str  # Masked secret
            assert "...7890" in repr_str  # Masked secret
            assert (
                "test-client-secret-1234567890" not in repr_str
            )  # Full secret should not appear
