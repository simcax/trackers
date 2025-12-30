"""
Integration tests for OAuth client and configuration.

Tests verify that OAuth client integrates properly with configuration.
"""

import os
import sys
from unittest.mock import patch

from trackers.auth import GoogleOAuthClient, GoogleOAuthConfig


class TestOAuthIntegration:
    """Test OAuth client integration with configuration."""

    def test_oauth_client_with_valid_config(self):
        """Test OAuth client initialization with valid configuration."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            # Clear cached modules
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            # Import fresh configuration
            config = GoogleOAuthConfig()

            # Create OAuth client
            client = GoogleOAuthClient(config)

            # Test basic functionality
            state = client.generate_state_parameter()
            auth_url = client.get_authorization_url(state)

            # Verify URL contains expected parameters
            assert "client_id=test-client-id.apps.googleusercontent.com" in auth_url
            assert (
                "redirect_uri=http%3A%2F%2Flocalhost%3A5000%2Fauth%2Fgoogle%2Fcallback"
                in auth_url
            )
            assert f"state={state}" in auth_url
            assert "scope=openid+email+profile" in auth_url

    def test_oauth_client_state_validation_flow(self):
        """Test complete state validation flow."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            config = GoogleOAuthConfig()
            client = GoogleOAuthClient(config)

            # Generate state parameter
            original_state = client.generate_state_parameter()

            # Generate authorization URL
            auth_url = client.get_authorization_url(original_state)
            assert f"state={original_state}" in auth_url

            # Validate state (simulating callback)
            assert client.validate_state(original_state, original_state) is True
            assert client.validate_state("wrong-state", original_state) is False

    def test_oauth_client_scopes_configuration(self):
        """Test OAuth client uses configuration scopes correctly."""
        env_vars = {
            "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
            "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
            "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            if "trackers.auth.config" in sys.modules:
                del sys.modules["trackers.auth.config"]

            config = GoogleOAuthConfig()
            client = GoogleOAuthClient(config)

            # Test default scopes from config
            state = client.generate_state_parameter()
            auth_url = client.get_authorization_url(state)

            expected_scopes = config.get_scopes()
            assert expected_scopes == ["openid", "email", "profile"]
            assert "scope=openid+email+profile" in auth_url

            # Test custom scopes override
            custom_scopes = ["openid", "email"]
            custom_auth_url = client.get_authorization_url(state, custom_scopes)
            assert "scope=openid+email" in custom_auth_url
