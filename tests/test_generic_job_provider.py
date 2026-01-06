"""
Tests for GenericJobProvider.

This module tests the generic HTTP job provider functionality including
HTTP requests, JSONPath data extraction, authentication, and error handling.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

import json
from unittest.mock import Mock, patch

from trackers.models.job_model import JobModel
from trackers.services.job_providers.generic_job_provider import (
    GenericJobProvider,
)


class TestGenericJobProvider:
    """Test cases for GenericJobProvider class."""

    def create_mock_job_config(self, config_dict):
        """Create a mock JobModel with encrypted configuration."""
        job_config = Mock(spec=JobModel)
        job_config.id = 1
        job_config.name = "Test Generic Job"
        job_config.job_type = "generic"
        job_config.tracker_id = 1
        job_config.user_id = 1
        job_config.is_active = True
        job_config.cron_schedule = "0 9 * * *"
        job_config.config = json.dumps(config_dict)
        return job_config

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_generic_job_provider_initialization(self, mock_encryption):
        """
        Test GenericJobProvider initialization with valid configuration.

        Requirements: 4.1, 4.2
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        assert provider.url == "https://api.example.com/data"
        assert provider.method == "GET"
        assert provider.headers == {"Accept": "application/json"}
        assert provider.json_path == "$.value"
        assert provider.timeout == 30
        assert provider.retry_count == 3

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_valid(self, mock_encryption):
        """
        Test configuration validation with valid generic configuration.

        Requirements: 4.1, 4.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        errors = provider.validate_config()
        assert errors == []

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_invalid_url(self, mock_encryption):
        """
        Test configuration validation with invalid URL.

        Requirements: 4.1, 4.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "http://insecure.example.com/data",  # HTTP not allowed
            "method": "GET",
            "json_path": "$.value",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "http://insecure.example.com/data",
            "method": "GET",
            "json_path": "$.value",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any("Only HTTPS URLs are allowed" in error for error in errors)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_invalid_method(self, mock_encryption):
        """
        Test configuration validation with invalid HTTP method.

        Requirements: 4.1, 4.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "DELETE",  # Not supported
            "json_path": "$.value",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "DELETE",
            "json_path": "$.value",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any("HTTP method must be GET or POST" in error for error in errors)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_invalid_timeout(self, mock_encryption):
        """
        Test configuration validation with invalid timeout.

        Requirements: 4.1, 4.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 500,  # Too high
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 500,
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any(
            "Timeout must be a positive number between 1 and 300" in error
            for error in errors
        )

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_prepare_headers_no_auth(self, mock_encryption):
        """
        Test header preparation without authentication.

        Requirements: 4.2, 4.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json", "User-Agent": "TestApp"},
            "json_path": "$.value",
            "auth_type": "none",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json", "User-Agent": "TestApp"},
            "json_path": "$.value",
            "auth_type": "none",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        headers = provider._prepare_headers()

        assert headers["Accept"] == "application/json"
        assert headers["User-Agent"] == "TestApp"
        assert "Authorization" not in headers

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_prepare_headers_bearer_auth(self, mock_encryption):
        """
        Test header preparation with Bearer token authentication.

        Requirements: 4.4, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "bearer",
            "auth": {"token": "test_bearer_token"},
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "bearer",
            "auth": {"token": "test_bearer_token"},
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        headers = provider._prepare_headers()

        assert headers["Authorization"] == "Bearer test_bearer_token"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_prepare_headers_basic_auth(self, mock_encryption):
        """
        Test header preparation with Basic authentication.

        Requirements: 4.4, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "basic",
            "auth": {"username": "testuser", "password": "testpass"},
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "basic",
            "auth": {"username": "testuser", "password": "testpass"},
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        headers = provider._prepare_headers()

        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_prepare_headers_api_key_auth(self, mock_encryption):
        """
        Test header preparation with API key authentication.

        Requirements: 4.4, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "api_key",
            "auth": {"api_key": "test_api_key", "header_name": "X-API-Key"},
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "api_key",
            "auth": {"api_key": "test_api_key", "header_name": "X-API-Key"},
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        headers = provider._prepare_headers()

        assert headers["X-API-Key"] == "test_api_key"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_fetch_data_success(self, mock_encryption):
        """
        Test successful data fetching from HTTP API.

        Requirements: 4.1, 4.2, 4.3
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }
        mock_encryption.return_value = mock_encryptor

        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "value": 42.5,
            "timestamp": "2024-01-04T10:00:00Z",
        }
        mock_response.text = '{"value": 42.5, "timestamp": "2024-01-04T10:00:00Z"}'

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        # Mock the secure request method
        with patch.object(provider, "_make_secure_request", return_value=mock_response):
            import asyncio

            value = asyncio.run(provider.fetch_data())

        assert value == 42.5

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_fetch_data_json_path_extraction(self, mock_encryption):
        """
        Test JSONPath data extraction from complex response.

        Requirements: 4.3
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.data.metrics.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }
        mock_encryption.return_value = mock_encryptor

        # Mock HTTP response with nested data
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "status": "success",
            "data": {
                "metrics": {
                    "value": 123.45,
                    "unit": "USD",
                    "timestamp": "2024-01-04T10:00:00Z",
                }
            },
        }

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.data.metrics.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        # Mock the secure request method
        with patch.object(provider, "_make_secure_request", return_value=mock_response):
            import asyncio

            value = asyncio.run(provider.fetch_data())

        assert value == 123.45

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_fetch_data_unexpected_status_code(self, mock_encryption):
        """
        Test handling of unexpected HTTP status codes.

        Requirements: 4.2, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }
        mock_encryption.return_value = mock_encryptor

        # Mock HTTP response with unexpected status
        mock_response = Mock()
        mock_response.status_code = 404  # Not in expected_status_codes

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        # Mock the secure request method
        with patch.object(provider, "_make_secure_request", return_value=mock_response):
            import asyncio

            value = asyncio.run(provider.fetch_data())

        assert value is None  # Should return None on error

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_get_request_info(self, mock_encryption):
        """
        Test getting request configuration information.

        Requirements: 4.1
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "POST",
            "headers": {"Accept": "application/json", "Authorization": "Bearer secret"},
            "json_path": "$.result.value",
            "timeout": 45,
            "retry_count": 5,
            "auth_type": "bearer",
            "expected_status_codes": [200, 201],
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "POST",
            "headers": {"Accept": "application/json", "Authorization": "Bearer secret"},
            "json_path": "$.result.value",
            "timeout": 45,
            "retry_count": 5,
            "auth_type": "bearer",
            "expected_status_codes": [200, 201],
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        info = provider.get_request_info()

        assert info["url"] == "https://api.example.com/data"
        assert info["method"] == "POST"
        assert info["json_path"] == "$.result.value"
        assert info["timeout"] == 45
        assert info["retry_count"] == 5
        assert info["auth_type"] == "bearer"
        assert info["expected_status_codes"] == [200, 201]

        # Check that sensitive headers are redacted
        assert info["headers"]["Accept"] == "application/json"
        assert info["headers"]["Authorization"] == "[REDACTED]"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_get_supported_auth_types(self, mock_encryption):
        """
        Test getting list of supported authentication types.

        Requirements: 4.4, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        auth_types = provider.get_supported_auth_types()

        assert len(auth_types) == 5
        auth_type_names = [auth["type"] for auth in auth_types]
        assert "none" in auth_type_names
        assert "bearer" in auth_type_names
        assert "basic" in auth_type_names
        assert "api_key" in auth_type_names
        assert "custom" in auth_type_names

        # Check bearer auth details
        bearer_auth = next(auth for auth in auth_types if auth["type"] == "bearer")
        assert bearer_auth["name"] == "Bearer Token"
        assert "token" in bearer_auth["required_fields"]

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_test_connection_success(self, mock_encryption):
        """
        Test successful connection testing.

        Requirements: 4.1, 4.2
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "auth_type": "none",
        }
        mock_encryption.return_value = mock_encryptor

        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.elapsed.total_seconds.return_value = 0.5
        mock_response.headers = {
            "content-type": "application/json",
            "content-length": "1024",
            "server": "nginx/1.18.0",
        }

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "auth_type": "none",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        # Mock the secure request method
        with patch.object(provider, "_make_secure_request", return_value=mock_response):
            result = provider.test_connection()

        assert result["success"] is True
        assert result["status_code"] == 200
        assert result["response_time"] == 0.5
        assert result["content_type"] == "application/json"
        assert result["content_length"] == "1024"
        assert result["server"] == "nginx/1.18.0"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_test_connection_failure(self, mock_encryption):
        """
        Test connection testing with failure.

        Requirements: 4.1, 4.2
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "auth_type": "none",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "auth_type": "none",
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        # Mock the secure request method to raise an exception
        with patch.object(
            provider, "_make_secure_request", side_effect=Exception("Connection failed")
        ):
            result = provider.test_connection()

        assert result["success"] is False
        assert result["error"] == "Connection failed"
        assert result["error_type"] == "Exception"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_auth_config_bearer_missing_token(self, mock_encryption):
        """
        Test authentication validation with missing bearer token.

        Requirements: 4.4, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "bearer",
            "auth": {},  # Missing token
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "bearer",
            "auth": {},
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any("Bearer token is required" in error for error in errors)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_auth_config_basic_missing_credentials(self, mock_encryption):
        """
        Test authentication validation with missing basic auth credentials.

        Requirements: 4.4, 4.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "basic",
            "auth": {"username": "testuser"},  # Missing password
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "auth_type": "basic",
            "auth": {"username": "testuser"},
        }

        job_config = self.create_mock_job_config(config)
        provider = GenericJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any("Username and password are required" in error for error in errors)
