"""
Tests for unified authentication system integration.

This module tests the integration between Google OAuth authentication
and the existing API key authentication system.

Requirements: 5.3, 5.4 - Integration with existing security system
"""

from unittest.mock import patch

from trackers.auth.context import UserContextManager
from trackers.auth.decorators import AuthenticationContext
from trackers.auth.integration import UnifiedAuthSystem
from trackers.auth.token_validator import UserInfo


class TestUnifiedAuthIntegration:
    """Test unified authentication system integration."""

    def test_unified_auth_system_initialization(self, app):
        """Test that unified auth system initializes correctly."""
        with app.app_context():
            # Check that unified auth system is initialized
            assert hasattr(app, "unified_auth")
            assert isinstance(app.unified_auth, UnifiedAuthSystem)

    def test_auth_context_creation(self):
        """Test authentication context creation."""
        # Test empty context
        context = AuthenticationContext()
        assert not context.is_authenticated
        assert context.auth_method is None
        assert context.user_info is None
        assert not context.api_key_valid

        # Test API key context
        context = AuthenticationContext(
            is_authenticated=True, auth_method="api_key", api_key_valid=True
        )
        assert context.is_authenticated
        assert context.auth_method == "api_key"
        assert context.api_key_valid
        assert context.user_info is None

        # Test Google OAuth context
        user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url="https://example.com/photo.jpg",
            verified_email=True,
        )
        context = AuthenticationContext(
            is_authenticated=True, auth_method="google_oauth", user_info=user_info
        )
        assert context.is_authenticated
        assert context.auth_method == "google_oauth"
        assert context.user_info == user_info
        assert context.user_email == "test@example.com"
        assert context.user_name == "Test User"
        assert context.google_id == "123456789"

    def test_auth_context_to_dict(self):
        """Test authentication context serialization."""
        user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url="https://example.com/photo.jpg",
            verified_email=True,
        )
        context = AuthenticationContext(
            is_authenticated=True,
            auth_method="both",
            user_info=user_info,
            api_key_valid=True,
        )

        result = context.to_dict()

        assert result["is_authenticated"] is True
        assert result["auth_method"] == "both"
        assert result["api_key_valid"] is True
        assert "user" in result
        assert result["user"]["email"] == "test@example.com"
        assert result["user"]["name"] == "Test User"
        assert result["user"]["google_id"] == "123456789"

    @patch("trackers.auth.context.has_request_context")
    @patch("trackers.auth.context.get_auth_context")
    def test_user_context_manager_no_request_context(
        self, mock_get_auth, mock_has_context
    ):
        """Test UserContextManager when no request context exists."""
        mock_has_context.return_value = False

        assert UserContextManager.get_current_user() is None
        assert UserContextManager.is_authenticated() is False
        assert UserContextManager.get_auth_method() is None
        assert UserContextManager.has_api_key_auth() is False
        assert UserContextManager.has_google_oauth() is False

    @patch("trackers.auth.context.has_request_context")
    @patch("trackers.auth.context.get_auth_context")
    def test_user_context_manager_with_api_key_auth(
        self, mock_get_auth, mock_has_context
    ):
        """Test UserContextManager with API key authentication."""
        mock_has_context.return_value = True
        mock_context = AuthenticationContext(
            is_authenticated=True, auth_method="api_key", api_key_valid=True
        )
        mock_get_auth.return_value = mock_context

        assert UserContextManager.is_authenticated() is True
        assert UserContextManager.get_auth_method() == "api_key"
        assert UserContextManager.has_api_key_auth() is True
        assert UserContextManager.has_google_oauth() is False
        assert UserContextManager.get_current_user() is None

    @patch("trackers.auth.context.has_request_context")
    @patch("trackers.auth.context.get_auth_context")
    def test_user_context_manager_with_google_oauth(
        self, mock_get_auth, mock_has_context
    ):
        """Test UserContextManager with Google OAuth authentication."""
        mock_has_context.return_value = True
        user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url="https://example.com/photo.jpg",
            verified_email=True,
        )
        mock_context = AuthenticationContext(
            is_authenticated=True, auth_method="google_oauth", user_info=user_info
        )
        mock_get_auth.return_value = mock_context

        assert UserContextManager.is_authenticated() is True
        assert UserContextManager.get_auth_method() == "google_oauth"
        assert UserContextManager.has_api_key_auth() is False
        assert UserContextManager.has_google_oauth() is True
        assert UserContextManager.get_current_user() == user_info
        assert UserContextManager.get_user_email() == "test@example.com"
        assert UserContextManager.get_user_name() == "Test User"
        assert UserContextManager.get_google_id() == "123456789"

    def test_unified_auth_system_detection(self, app):
        """Test authentication method detection."""
        with app.app_context():
            unified_auth = app.unified_auth

            # Should detect API key auth if configured
            if (
                hasattr(app, "key_validator")
                and app.key_validator.is_authentication_enabled()
            ):
                assert unified_auth.api_key_auth_enabled
                assert "api_key" in unified_auth.available_auth_methods

            # Should detect Google OAuth if configured
            try:
                from trackers.auth.config import google_oauth_config

                if google_oauth_config:
                    assert unified_auth.google_auth_enabled
                    assert "google_oauth" in unified_auth.available_auth_methods
            except ImportError:
                assert not unified_auth.google_auth_enabled

    def test_unified_auth_system_status(self, app):
        """Test unified auth system status reporting."""
        with app.app_context():
            unified_auth = app.unified_auth
            status = unified_auth.get_auth_status()

            assert isinstance(status, dict)
            assert "api_key_auth_enabled" in status
            assert "google_oauth_enabled" in status
            assert "any_auth_enabled" in status
            assert "available_methods" in status
            assert "api_key_count" in status

            assert isinstance(status["available_methods"], list)
            assert isinstance(status["api_key_count"], int)

    def test_decorator_api_key_only(self, app):
        """Test decorator with API key authentication only."""
        from trackers.auth.decorators import require_api_key_only

        @require_api_key_only()
        def test_route():
            return "success"

        # Test with Flask app context and request context
        with app.test_request_context("/test"):
            with patch(
                "trackers.auth.decorators._has_api_key_auth_configured"
            ) as mock_has_api:
                with patch(
                    "trackers.auth.decorators._check_api_key_auth"
                ) as mock_check_api:
                    with patch(
                        "trackers.auth.decorators._has_email_password_auth_configured"
                    ) as mock_has_email_password:
                        mock_has_api.return_value = True
                        mock_check_api.return_value = (
                            True,
                            None,
                        )  # Return tuple as expected
                        mock_has_email_password.return_value = False

                        result = test_route()
                        assert result == "success"

    def test_context_summary_no_request(self):
        """Test context summary when no request context exists."""
        summary = UserContextManager.get_context_summary()
        assert summary["has_request_context"] is False

    @patch("trackers.auth.context.has_request_context")
    @patch("trackers.auth.context.get_auth_context")
    def test_context_summary_with_request(self, mock_get_auth, mock_has_context):
        """Test context summary with request context."""
        mock_has_context.return_value = True
        user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url="https://example.com/photo.jpg",
            verified_email=True,
        )
        mock_context = AuthenticationContext(
            is_authenticated=True,
            auth_method="both",
            user_info=user_info,
            api_key_valid=True,
        )
        mock_get_auth.return_value = mock_context

        summary = UserContextManager.get_context_summary()

        assert summary["has_request_context"] is True
        assert summary["is_authenticated"] is True
        assert summary["auth_method"] == "both"
        assert summary["api_key_valid"] is True
        assert summary["has_user_info"] is True
        assert summary["user_email"] == "test@example.com"
        assert summary["user_name"] == "Test User"
