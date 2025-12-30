"""
Tests for GoogleAuthService orchestrator.

This module tests the central authentication service that coordinates
the complete Google OAuth 2.0 authentication flow.
"""

import os
from unittest.mock import Mock, patch

import pytest

from trackers.auth.auth_service import AuthRedirect, AuthResult, GoogleAuthService
from trackers.auth.config import GoogleOAuthConfig
from trackers.auth.oauth_client import TokenResponse
from trackers.auth.session_manager import SessionManager
from trackers.auth.token_validator import UserInfo


class TestGoogleAuthService:
    """Test cases for GoogleAuthService class."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock Google OAuth configuration."""
        with patch.dict(
            os.environ,
            {
                "GOOGLE_CLIENT_ID": "test-client-id.apps.googleusercontent.com",
                "GOOGLE_CLIENT_SECRET": "test-client-secret-1234567890",
                "GOOGLE_REDIRECT_URI": "http://localhost:5000/auth/google/callback",
            },
        ):
            return GoogleOAuthConfig()

    @pytest.fixture
    def mock_session_manager(self):
        """Create a mock session manager."""
        return Mock(spec=SessionManager)

    @pytest.fixture
    def auth_service(self, mock_config, mock_session_manager):
        """Create GoogleAuthService instance for testing."""
        return GoogleAuthService(mock_config, mock_session_manager)

    def test_auth_service_initialization(self, mock_config, mock_session_manager):
        """Test GoogleAuthService initialization."""
        service = GoogleAuthService(mock_config, mock_session_manager)

        assert service.config == mock_config
        assert service.session_manager == mock_session_manager
        assert service.oauth_client is not None

    def test_auth_service_initialization_with_default_session_manager(
        self, mock_config
    ):
        """Test GoogleAuthService initialization with default session manager."""
        service = GoogleAuthService(mock_config)

        assert service.config == mock_config
        assert service.session_manager is not None
        assert isinstance(service.session_manager, SessionManager)

    def test_initiate_login_success(self, auth_service, mock_session_manager, app):
        """Test successful login initiation."""
        # Mock session manager methods
        mock_session_manager.generate_state_token.return_value = "test-state-123"

        # Mock OAuth client
        with patch.object(
            auth_service.oauth_client, "get_authorization_url"
        ) as mock_auth_url:
            mock_auth_url.return_value = (
                "https://accounts.google.com/oauth/authorize?client_id=test"
            )

            # Use Flask request context
            with app.test_request_context("/"):
                result = auth_service.initiate_login()

                assert isinstance(result, AuthRedirect)
                assert (
                    result.url
                    == "https://accounts.google.com/oauth/authorize?client_id=test"
                )
                assert result.state == "test-state-123"

            # Verify session manager was called
            mock_session_manager.generate_state_token.assert_called_once()
            mock_auth_url.assert_called_once_with("test-state-123")

    def test_initiate_login_with_redirect_url(
        self, auth_service, mock_session_manager, app
    ):
        """Test login initiation with post-login redirect URL."""
        mock_session_manager.generate_state_token.return_value = "test-state-123"

        with patch.object(
            auth_service.oauth_client, "get_authorization_url"
        ) as mock_auth_url:
            mock_auth_url.return_value = (
                "https://accounts.google.com/oauth/authorize?client_id=test"
            )

            # Use Flask request context
            with app.test_request_context("/"):
                # Mock Flask session as a dictionary
                mock_flask_session = {}
                with patch("flask.session", mock_flask_session):
                    result = auth_service.initiate_login(
                        "https://example.com/dashboard"
                    )

                    assert isinstance(result, AuthRedirect)
                    assert (
                        mock_flask_session.get("post_login_redirect")
                        == "https://example.com/dashboard"
                    )

    def test_initiate_login_failure(self, auth_service, mock_session_manager, app):
        """Test login initiation failure."""
        mock_session_manager.generate_state_token.side_effect = Exception(
            "State generation failed"
        )

        # Use Flask request context
        with app.test_request_context("/"):
            with pytest.raises(Exception, match="State generation failed"):
                auth_service.initiate_login()

    def test_process_callback_oauth_error(self, auth_service, app):
        """Test callback processing with OAuth error."""
        # Use Flask request context
        with app.test_request_context("/"):
            result = auth_service.process_callback(None, None, "access_denied")

            assert isinstance(result, AuthResult)
            assert not result.success
            assert "OAuth error: access_denied" in result.error_message
            assert result.redirect_url is not None

    def test_process_callback_missing_parameters(self, auth_service, app):
        """Test callback processing with missing parameters."""
        # Use Flask request context
        with app.test_request_context("/"):
            result = auth_service.process_callback(None, "test-state")

            assert isinstance(result, AuthResult)
            assert not result.success
            assert "Missing required OAuth parameters" in result.error_message

    def test_process_callback_invalid_state(
        self, auth_service, mock_session_manager, app
    ):
        """Test callback processing with invalid state parameter."""
        mock_session_manager.validate_and_consume_state.return_value = False

        # Use Flask request context
        with app.test_request_context("/"):
            result = auth_service.process_callback("test-code", "invalid-state")

            assert isinstance(result, AuthResult)
            assert not result.success
            assert (
                "Authentication request has expired or is invalid"
                in result.error_message
            )
        mock_session_manager.validate_and_consume_state.assert_called_once_with(
            "invalid-state"
        )

    def test_process_callback_success(self, auth_service, mock_session_manager, app):
        """Test successful callback processing."""
        # Mock session manager
        mock_session_manager.validate_and_consume_state.return_value = True

        # Mock token response
        mock_token_response = Mock(spec=TokenResponse)
        mock_token_response.access_token = "access-token-123"
        mock_token_response.id_token = "id-token-123"
        mock_token_response.expires_in = 3600

        # Mock user info
        mock_user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url="https://example.com/photo.jpg",
            verified_email=True,
        )

        # Use Flask request context
        with app.test_request_context("/"):
            # Mock OAuth client methods
            with patch.object(
                auth_service.oauth_client, "exchange_code_for_tokens"
            ) as mock_exchange:
                with patch.object(
                    auth_service.oauth_client, "validate_id_token"
                ) as mock_validate:
                    with patch.object(
                        auth_service.oauth_client._token_validator, "extract_user_info"
                    ) as mock_extract:
                        # Mock Flask url_for and session to avoid request context issues
                        with patch(
                            "trackers.auth.auth_service.url_for"
                        ) as mock_url_for:
                            with patch("flask.session", {}) as mock_flask_session:
                                mock_exchange.return_value = mock_token_response
                                mock_validate.return_value = {
                                    "sub": "123456789",
                                    "email": "test@example.com",
                                }
                                mock_extract.return_value = mock_user_info
                                mock_url_for.return_value = "/dashboard"

                                result = auth_service.process_callback(
                                    "test-code", "test-state"
                                )

                        assert isinstance(result, AuthResult)
                        assert result.success
                        assert result.user_info == mock_user_info
                        assert result.redirect_url is not None

                    # Verify all methods were called
                    mock_session_manager.validate_and_consume_state.assert_called_once_with(
                        "test-state"
                    )
                    mock_exchange.assert_called_once_with("test-code", "test-state")
                    mock_validate.assert_called_once_with("id-token-123")
                    mock_extract.assert_called_once()
                    mock_session_manager.store_user_session.assert_called_once_with(
                        user_info=mock_user_info,
                        access_token="access-token-123",
                        token_expires_in=3600,
                    )

    def test_process_callback_token_exchange_failure(
        self, auth_service, mock_session_manager, app
    ):
        """Test callback processing with token exchange failure."""
        mock_session_manager.validate_and_consume_state.return_value = True

        # Use Flask request context
        with app.test_request_context("/"):
            with patch.object(
                auth_service.oauth_client, "exchange_code_for_tokens"
            ) as mock_exchange:
                mock_exchange.side_effect = Exception("Token exchange failed")

                result = auth_service.process_callback("test-code", "test-state")

                assert isinstance(result, AuthResult)
                assert not result.success
                assert (
                    "An unexpected error occurred during authentication"
                    in result.error_message
                )

    def test_get_current_user(self, auth_service, mock_session_manager):
        """Test getting current user information."""
        mock_user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url=None,
            verified_email=True,
        )
        mock_session_manager.get_current_user.return_value = mock_user_info

        result = auth_service.get_current_user()

        assert result == mock_user_info
        mock_session_manager.get_current_user.assert_called_once()

    def test_is_authenticated(self, auth_service, mock_session_manager):
        """Test authentication status checking."""
        mock_session_manager.is_authenticated.return_value = True

        result = auth_service.is_authenticated()

        assert result is True
        mock_session_manager.is_authenticated.assert_called_once()

    def test_logout_success(self, auth_service, mock_session_manager, app):
        """Test successful logout."""
        mock_user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url=None,
            verified_email=True,
        )
        mock_session_manager.get_current_user.return_value = mock_user_info
        mock_session_manager.get_access_token.return_value = "access-token-123"

        # Use Flask request context
        with app.test_request_context("/"):
            with patch.object(auth_service.oauth_client, "revoke_token") as mock_revoke:
                mock_revoke.return_value = True

                result = auth_service.logout()

                assert isinstance(result, str)
                assert result  # Should return a redirect URL

                # Verify session was cleared and token was revoked
                mock_session_manager.clear_session.assert_called_once()
                mock_revoke.assert_called_once_with("access-token-123")

    def test_logout_with_google_redirect(self, auth_service, mock_session_manager, app):
        """Test logout with redirect to Google."""
        mock_session_manager.get_current_user.return_value = None
        mock_session_manager.get_access_token.return_value = None

        # Use Flask request context
        with app.test_request_context("/"):
            result = auth_service.logout(redirect_to_google=True)

            assert result == "https://accounts.google.com/logout"
            mock_session_manager.clear_session.assert_called_once()

    def test_logout_token_revocation_failure(
        self, auth_service, mock_session_manager, app
    ):
        """Test logout when token revocation fails."""
        mock_user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url=None,
            verified_email=True,
        )
        mock_session_manager.get_current_user.return_value = mock_user_info
        mock_session_manager.get_access_token.return_value = "access-token-123"

        # Use Flask request context
        with app.test_request_context("/"):
            with patch.object(auth_service.oauth_client, "revoke_token") as mock_revoke:
                mock_revoke.side_effect = Exception("Revocation failed")

                result = auth_service.logout()

                # Should still complete logout despite revocation failure
                assert isinstance(result, str)
                mock_session_manager.clear_session.assert_called_once()

    def test_refresh_authentication(self, auth_service, mock_session_manager):
        """Test authentication refresh."""
        mock_session_manager.refresh_session.return_value = True

        result = auth_service.refresh_authentication()

        assert result is True
        mock_session_manager.refresh_session.assert_called_once()

    def test_get_session_info(self, auth_service, mock_session_manager):
        """Test getting session information."""
        mock_info = {
            "authenticated": True,
            "user_email": "test@example.com",
            "session_age_minutes": 30,
        }
        mock_session_manager.get_session_info.return_value = mock_info

        result = auth_service.get_session_info()

        assert result == mock_info
        mock_session_manager.get_session_info.assert_called_once()

    def test_require_authentication_not_authenticated(
        self, auth_service, mock_session_manager, app
    ):
        """Test require_authentication when user is not authenticated."""
        mock_session_manager.is_authenticated.return_value = False
        mock_session_manager.generate_state_token.return_value = "test-state"

        # Use Flask request context
        with app.test_request_context("https://example.com/protected"):
            with patch.object(
                auth_service.oauth_client, "get_authorization_url"
            ) as mock_auth_url:
                with patch("trackers.auth.auth_service.redirect") as mock_redirect:
                    with patch("flask.session", {}) as mock_flask_session:
                        mock_auth_url.return_value = (
                            "https://accounts.google.com/oauth/authorize"
                        )

                        result = auth_service.require_authentication()

                        # Should return a redirect response
                        mock_redirect.assert_called_once_with(
                            "https://accounts.google.com/oauth/authorize"
                        )

    def test_require_authentication_already_authenticated(
        self, auth_service, mock_session_manager
    ):
        """Test require_authentication when user is already authenticated."""
        mock_session_manager.is_authenticated.return_value = True

        result = auth_service.require_authentication()

        assert result is None  # Should return None when already authenticated

    def test_configure_flask_app(self, auth_service, mock_session_manager):
        """Test Flask app configuration."""
        mock_app = Mock()
        mock_app.context_processor = Mock()

        auth_service.configure_flask_app(mock_app)

        # Verify session security was configured
        mock_session_manager.configure_flask_session_security.assert_called_once_with(
            mock_app
        )

        # Verify context processor was added
        mock_app.context_processor.assert_called_once()

    def test_context_manager(self, auth_service):
        """Test GoogleAuthService as context manager."""
        with auth_service as service:
            assert service == auth_service

        # Context manager should complete without errors
