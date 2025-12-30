"""
Tests for Google OAuth client module.

Tests verify OAuth client functionality including authorization URL generation,
token exchange, state validation, and ID token verification.
"""

import time
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import requests

from trackers.auth.config import GoogleOAuthConfig
from trackers.auth.error_handling import (
    NetworkError,
    TokenExchangeError,
    TokenValidationError,
)
from trackers.auth.oauth_client import GoogleOAuthClient, TokenResponse


class TestTokenResponse:
    """Test TokenResponse class functionality."""

    def test_token_response_initialization(self):
        """Test TokenResponse initialization with complete data."""
        token_data = {
            "access_token": "test-access-token",
            "id_token": "test-id-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test-refresh-token",
            "scope": "openid email profile",
        }

        response = TokenResponse(token_data)

        assert response.access_token == "test-access-token"
        assert response.id_token == "test-id-token"
        assert response.token_type == "Bearer"
        assert response.expires_in == 3600
        assert response.refresh_token == "test-refresh-token"
        assert response.scope == "openid email profile"
        assert response.expires_at > int(time.time())

    def test_token_response_minimal_data(self):
        """Test TokenResponse initialization with minimal data."""
        token_data = {"access_token": "test-access-token", "id_token": "test-id-token"}

        response = TokenResponse(token_data)

        assert response.access_token == "test-access-token"
        assert response.id_token == "test-id-token"
        assert response.token_type == "Bearer"  # Default value
        assert response.expires_in == 3600  # Default value
        assert response.refresh_token is None
        assert response.scope == ""  # Default value


class TestGoogleOAuthClient:
    """Test GoogleOAuthClient class functionality."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock OAuth configuration for testing."""
        config = Mock(spec=GoogleOAuthConfig)
        config.client_id = "test-client-id.apps.googleusercontent.com"
        config.client_secret = "test-client-secret-1234567890"
        config.redirect_uri = "http://localhost:5000/auth/google/callback"
        config.get_scopes.return_value = ["openid", "email", "profile"]
        return config

    @pytest.fixture
    def oauth_client(self, mock_config):
        """Create OAuth client instance for testing."""
        return GoogleOAuthClient(mock_config)

    def test_client_initialization(self, mock_config):
        """Test OAuth client initialization."""
        client = GoogleOAuthClient(mock_config)

        assert client.config == mock_config
        assert client._session is not None
        assert client._session.verify is True  # SSL verification enabled

    def test_generate_state_parameter(self, oauth_client):
        """Test state parameter generation."""
        state1 = oauth_client.generate_state_parameter()
        state2 = oauth_client.generate_state_parameter()

        # State parameters should be different
        assert state1 != state2

        # Should be URL-safe strings
        assert isinstance(state1, str)
        assert isinstance(state2, str)
        assert len(state1) > 20  # Should be reasonably long
        assert len(state2) > 20

    def test_get_authorization_url_default_scopes(self, oauth_client):
        """Test authorization URL generation with default scopes."""
        state = "test-state-parameter"

        auth_url = oauth_client.get_authorization_url(state)

        # Parse the URL
        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        # Verify URL structure
        assert parsed_url.scheme == "https"
        assert parsed_url.netloc == "accounts.google.com"
        assert parsed_url.path == "/o/oauth2/v2/auth"

        # Verify required parameters
        assert (
            query_params["client_id"][0] == "test-client-id.apps.googleusercontent.com"
        )
        assert (
            query_params["redirect_uri"][0]
            == "http://localhost:5000/auth/google/callback"
        )
        assert query_params["scope"][0] == "openid email profile"
        assert query_params["response_type"][0] == "code"
        assert query_params["state"][0] == "test-state-parameter"
        assert query_params["access_type"][0] == "offline"
        assert query_params["prompt"][0] == "consent"

    def test_get_authorization_url_custom_scopes(self, oauth_client):
        """Test authorization URL generation with custom scopes."""
        state = "test-state-parameter"
        custom_scopes = ["openid", "email"]

        auth_url = oauth_client.get_authorization_url(state, custom_scopes)

        parsed_url = urlparse(auth_url)
        query_params = parse_qs(parsed_url.query)

        assert query_params["scope"][0] == "openid email"

    def test_validate_state_success(self, oauth_client):
        """Test successful state validation."""
        state = "test-state-parameter"

        result = oauth_client.validate_state(state, state)

        assert result is True

    def test_validate_state_failure(self, oauth_client):
        """Test state validation failure."""
        received_state = "received-state"
        stored_state = "stored-state"

        result = oauth_client.validate_state(received_state, stored_state)

        assert result is False

    def test_validate_state_empty_parameters(self, oauth_client):
        """Test state validation with empty parameters."""
        assert oauth_client.validate_state("", "test-state") is False
        assert oauth_client.validate_state("test-state", "") is False
        assert oauth_client.validate_state("", "") is False

    @patch("requests.Session.post")
    def test_exchange_code_for_tokens_success(self, mock_post, oauth_client):
        """Test successful token exchange."""
        # Mock successful response
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "test-access-token",
            "id_token": "test-id-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test-refresh-token",
        }
        mock_post.return_value = mock_response

        code = "test-authorization-code"
        state = "test-state"

        token_response = oauth_client.exchange_code_for_tokens(code, state)

        # Verify request was made correctly
        mock_post.assert_called_once()
        call_args = mock_post.call_args

        assert call_args[0][0] == GoogleOAuthClient.TOKEN_ENDPOINT
        assert (
            call_args[1]["data"]["client_id"]
            == "test-client-id.apps.googleusercontent.com"
        )
        assert call_args[1]["data"]["client_secret"] == "test-client-secret-1234567890"
        assert call_args[1]["data"]["code"] == "test-authorization-code"
        assert call_args[1]["data"]["grant_type"] == "authorization_code"
        assert (
            call_args[1]["data"]["redirect_uri"]
            == "http://localhost:5000/auth/google/callback"
        )

        # Verify response
        assert isinstance(token_response, TokenResponse)
        assert token_response.access_token == "test-access-token"
        assert token_response.id_token == "test-id-token"

    @patch("requests.Session.post")
    def test_exchange_code_for_tokens_http_error(self, mock_post, oauth_client):
        """Test token exchange with HTTP error."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "400 Bad Request"
        )
        mock_post.return_value = mock_response

        with pytest.raises(NetworkError) as exc_info:
            oauth_client.exchange_code_for_tokens("test-code", "test-state")

        assert "Network request failed after 3 retries" in str(exc_info.value)

    @patch("requests.Session.post")
    def test_exchange_code_for_tokens_missing_fields(self, mock_post, oauth_client):
        """Test token exchange with missing required fields."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "access_token": "test-access-token"
            # Missing id_token and token_type
        }
        mock_post.return_value = mock_response

        with pytest.raises(TokenExchangeError) as exc_info:
            oauth_client.exchange_code_for_tokens("test-code", "test-state")

        assert "missing required fields" in str(exc_info.value)

    @patch("requests.Session.get")
    def test_validate_id_token_success(self, mock_get, oauth_client):
        """Test successful ID token validation."""
        # Create a mock JWT token
        test_payload = {
            "sub": "123456789",
            "email": "test@example.com",
            "email_verified": True,
            "name": "Test User",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,
            "aud": "test-client-id.apps.googleusercontent.com",
            "iss": "https://accounts.google.com",
        }

        # Mock the JWKS response
        mock_jwks_response = Mock()
        mock_jwks_response.raise_for_status.return_value = None
        mock_jwks_response.json.return_value = {
            "keys": [
                {
                    "kid": "test-key-id",
                    "kty": "RSA",
                    "use": "sig",
                    "n": "test-n-value",
                    "e": "AQAB",
                }
            ]
        }
        mock_get.return_value = mock_jwks_response

        # Mock JWT operations
        with (
            patch("jwt.get_unverified_header") as mock_header,
            patch("jwt.algorithms.RSAAlgorithm.from_jwk") as mock_from_jwk,
            patch("jwt.decode") as mock_decode,
        ):
            mock_header.return_value = {"kid": "test-key-id"}
            mock_from_jwk.return_value = "mock-public-key"
            mock_decode.return_value = test_payload

            result = oauth_client.validate_id_token("mock-id-token")

            assert result == test_payload
            mock_decode.assert_called_once_with(
                "mock-id-token",
                "mock-public-key",
                algorithms=["RS256"],
                audience="test-client-id.apps.googleusercontent.com",
                issuer=["https://accounts.google.com", "accounts.google.com"],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )

    @patch("requests.Session.get")
    def test_validate_id_token_missing_kid(self, mock_get, oauth_client):
        """Test ID token validation with missing key ID."""
        with patch("jwt.get_unverified_header") as mock_header:
            mock_header.return_value = {}  # Missing kid

            with pytest.raises(TokenValidationError) as exc_info:
                oauth_client.validate_id_token("mock-id-token")

            assert "missing key ID" in str(exc_info.value)

    @patch("requests.Session.get")
    def test_get_user_info_success(self, mock_get, oauth_client):
        """Test successful user info retrieval."""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = {
            "id": "123456789",
            "email": "test@example.com",
            "verified_email": True,
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
        }
        mock_get.return_value = mock_response

        user_info = oauth_client.get_user_info("test-access-token")

        # Verify request
        mock_get.assert_called_once_with(
            GoogleOAuthClient.USERINFO_ENDPOINT,
            headers={
                "Authorization": "Bearer test-access-token",
                "Accept": "application/json",
            },
            timeout=10,
        )

        # Verify response
        assert user_info["email"] == "test@example.com"
        assert user_info["name"] == "Test User"

    @patch("requests.Session.get")
    def test_get_user_info_failure(self, mock_get, oauth_client):
        """Test user info retrieval failure."""
        mock_response = Mock()
        mock_response.raise_for_status.side_effect = requests.HTTPError(
            "401 Unauthorized"
        )
        mock_get.return_value = mock_response

        with pytest.raises(NetworkError) as exc_info:
            oauth_client.get_user_info("invalid-token")

        assert "Network request failed after 3 retries" in str(exc_info.value)

    @patch("requests.Session.post")
    def test_revoke_token_success(self, mock_post, oauth_client):
        """Test successful token revocation."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = oauth_client.revoke_token("test-token")

        assert result is True
        mock_post.assert_called_once_with(
            "https://oauth2.googleapis.com/revoke",
            data={"token": "test-token"},
            timeout=10,
        )

    @patch("requests.Session.post")
    def test_revoke_token_failure(self, mock_post, oauth_client):
        """Test token revocation failure."""
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        result = oauth_client.revoke_token("invalid-token")

        assert result is False

    @patch("requests.Session.post")
    def test_revoke_token_network_error(self, mock_post, oauth_client):
        """Test token revocation with network error."""
        mock_post.side_effect = requests.RequestException("Network error")

        result = oauth_client.revoke_token("test-token")

        assert result is False

    def test_context_manager(self, oauth_client):
        """Test OAuth client as context manager."""
        with patch.object(oauth_client._session, "close") as mock_close:
            with oauth_client as client:
                assert client is oauth_client

            mock_close.assert_called_once()
