"""
Tests for Google OAuth Token Validator.

This module tests the TokenValidator class for JWT token verification,
signature validation, and user information extraction.
"""

import time
from unittest.mock import Mock, patch

import pytest
import requests

from trackers.auth.error_handling import NetworkError, TokenValidationError
from trackers.auth.token_validator import TokenValidator, UserInfo


class TestUserInfo:
    """Test UserInfo dataclass."""

    def test_user_info_creation(self):
        """Test UserInfo dataclass creation with all fields."""
        user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url="https://example.com/photo.jpg",
            verified_email=True,
        )

        assert user_info.google_id == "123456789"
        assert user_info.email == "test@example.com"
        assert user_info.name == "Test User"
        assert user_info.picture_url == "https://example.com/photo.jpg"
        assert user_info.verified_email is True

    def test_user_info_creation_minimal(self):
        """Test UserInfo dataclass creation with minimal fields."""
        user_info = UserInfo(
            google_id="123456789",
            email="test@example.com",
            name="Test User",
            picture_url=None,
            verified_email=False,
        )

        assert user_info.google_id == "123456789"
        assert user_info.email == "test@example.com"
        assert user_info.name == "Test User"
        assert user_info.picture_url is None
        assert user_info.verified_email is False


class TestTokenValidator:
    """Test TokenValidator class."""

    @pytest.fixture
    def validator(self):
        """Create TokenValidator instance for testing."""
        return TokenValidator(client_id="test-client-id.apps.googleusercontent.com")

    @pytest.fixture
    def mock_jwks_response(self):
        """Mock JWKS response from Google."""
        return {
            "keys": [
                {
                    "kid": "test-key-id",
                    "kty": "RSA",
                    "use": "sig",
                    "n": "test-modulus",
                    "e": "AQAB",
                }
            ]
        }

    @pytest.fixture
    def valid_token_payload(self):
        """Valid token payload for testing."""
        current_time = int(time.time())
        return {
            "sub": "123456789",
            "email": "test@example.com",
            "name": "Test User",
            "picture": "https://example.com/photo.jpg",
            "email_verified": True,
            "aud": "test-client-id.apps.googleusercontent.com",
            "iss": "https://accounts.google.com",
            "iat": current_time - 300,  # 5 minutes ago
            "exp": current_time + 3600,  # 1 hour from now
        }

    def test_validator_initialization(self, validator):
        """Test TokenValidator initialization."""
        assert validator.client_id == "test-client-id.apps.googleusercontent.com"
        assert validator._jwks_cache is None
        assert validator._jwks_cache_time == 0
        assert validator._jwks_cache_ttl == 3600

    def test_extract_user_info_success(self, validator, valid_token_payload):
        """Test successful user information extraction."""
        user_info = validator.extract_user_info(valid_token_payload)

        assert isinstance(user_info, UserInfo)
        assert user_info.google_id == "123456789"
        assert user_info.email == "test@example.com"
        assert user_info.name == "Test User"
        assert user_info.picture_url == "https://example.com/photo.jpg"
        assert user_info.verified_email is True

    def test_extract_user_info_missing_claims(self, validator):
        """Test user information extraction with missing required claims."""
        incomplete_payload = {
            "sub": "123456789",
            # Missing email and name
        }

        with pytest.raises(TokenValidationError, match="Token missing required claims"):
            validator.extract_user_info(incomplete_payload)

    def test_extract_user_info_empty_claims(self, validator):
        """Test user information extraction with empty required claims."""
        empty_payload = {
            "sub": "123456789",
            "email": "",  # Empty email
            "name": "Test User",
        }

        with pytest.raises(TokenValidationError, match="Token missing required claims"):
            validator.extract_user_info(empty_payload)

    def test_check_token_expiry_valid(self, validator):
        """Test token expiry check with valid token."""
        current_time = int(time.time())
        payload = {"exp": current_time + 3600}  # 1 hour from now

        assert validator.check_token_expiry(payload) is True

    def test_check_token_expiry_expired(self, validator):
        """Test token expiry check with expired token."""
        current_time = int(time.time())
        payload = {"exp": current_time - 300}  # 5 minutes ago

        assert validator.check_token_expiry(payload) is False

    def test_check_token_expiry_missing_exp(self, validator):
        """Test token expiry check with missing exp claim."""
        payload = {}  # No exp claim

        assert validator.check_token_expiry(payload) is False

    @patch("requests.Session.get")
    def test_refresh_jwks_cache_success(self, mock_get, validator, mock_jwks_response):
        """Test successful JWKS cache refresh."""
        mock_response = Mock()
        mock_response.json.return_value = mock_jwks_response
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        validator._refresh_jwks_cache()

        assert validator._jwks_cache == mock_jwks_response
        assert validator._jwks_cache_time > 0
        mock_get.assert_called_once_with(validator.JWKS_URI, timeout=10)

    @patch("requests.Session.get")
    def test_refresh_jwks_cache_failure(self, mock_get, validator):
        """Test JWKS cache refresh failure."""
        mock_get.side_effect = requests.RequestException("Network error")

        with pytest.raises(
            NetworkError, match="Network request failed after 3 retries"
        ):
            validator._refresh_jwks_cache()

    def test_validate_token_claims_success(self, validator, valid_token_payload):
        """Test successful token claims validation."""
        # Should not raise any exception
        validator._validate_token_claims(valid_token_payload)

    def test_validate_token_claims_future_iat(self, validator, valid_token_payload):
        """Test token claims validation with future issued at time."""
        current_time = int(time.time())
        valid_token_payload["iat"] = current_time + 600  # 10 minutes in future

        with pytest.raises(
            TokenValidationError, match="Token issued too far in the future"
        ):
            validator._validate_token_claims(valid_token_payload)

    def test_validate_token_claims_wrong_audience(self, validator, valid_token_payload):
        """Test token claims validation with wrong audience."""
        valid_token_payload["aud"] = "wrong-client-id"

        with pytest.raises(TokenValidationError, match="Token audience mismatch"):
            validator._validate_token_claims(valid_token_payload)

    def test_validate_token_claims_invalid_issuer(self, validator, valid_token_payload):
        """Test token claims validation with invalid issuer."""
        valid_token_payload["iss"] = "https://evil.com"

        with pytest.raises(TokenValidationError, match="Invalid token issuer"):
            validator._validate_token_claims(valid_token_payload)

    def test_validate_token_claims_missing_subject(
        self, validator, valid_token_payload
    ):
        """Test token claims validation with missing subject."""
        del valid_token_payload["sub"]

        with pytest.raises(TokenValidationError, match="Token missing subject"):
            validator._validate_token_claims(valid_token_payload)

    def test_validate_token_claims_missing_email(self, validator, valid_token_payload):
        """Test token claims validation with missing email."""
        del valid_token_payload["email"]

        with pytest.raises(TokenValidationError, match="Token missing email claim"):
            validator._validate_token_claims(valid_token_payload)

    def test_context_manager(self, validator):
        """Test TokenValidator as context manager."""
        with patch.object(validator._session, "close") as mock_close:
            with validator as v:
                assert v is validator
            mock_close.assert_called_once()

    def test_verify_token_signature_invalid_header(self, validator):
        """Test token signature verification with invalid header."""
        invalid_token = "invalid.token.here"

        assert validator.verify_token_signature(invalid_token) is False

    @patch("jwt.get_unverified_header")
    def test_verify_token_signature_missing_kid(self, mock_header, validator):
        """Test token signature verification with missing key ID."""
        mock_header.return_value = {}  # No kid

        assert validator.verify_token_signature("test.token.here") is False
