"""
Integration tests for Generic Job Provider with Job Scheduler.

This module tests the integration between the Generic Job Provider and
the Job Scheduler to ensure they work together correctly.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

import json
from unittest.mock import Mock, patch

from trackers.models.job_model import JobModel
from trackers.services.job_scheduler import JobScheduler


class TestGenericJobIntegration:
    """Integration test cases for Generic Job Provider with Job Scheduler."""

    def create_mock_job_config(self, config_dict):
        """Create a mock JobModel with encrypted configuration."""
        job_config = Mock(spec=JobModel)
        job_config.id = 1
        job_config.name = "Test Generic Integration Job"
        job_config.job_type = "generic"
        job_config.tracker_id = 1
        job_config.user_id = 1
        job_config.is_active = True
        job_config.cron_schedule = "0 9 * * *"
        job_config.config = json.dumps(config_dict)
        return job_config

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    @patch("trackers.services.job_scheduler.get_db_session")
    def test_job_scheduler_creates_generic_provider(
        self, mock_get_db_session, mock_encryption
    ):
        """
        Test that JobScheduler can create and use GenericJobProvider.

        Requirements: 4.1, 4.2
        """
        from flask import Flask

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

        # Create mock job
        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }

        mock_job = self.create_mock_job_config(config)

        # Mock database session
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_job
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Create Flask app and scheduler
        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Test that the scheduler can create a generic job provider
        job_provider = scheduler._create_job_provider(mock_job)

        assert job_provider is not None
        assert job_provider.__class__.__name__ == "GenericJobProvider"
        assert job_provider.url == "https://api.example.com/data"
        assert job_provider.method == "GET"
        assert job_provider.json_path == "$.value"

    @patch(
        "trackers.services.job_providers.base_job_provider.BaseJobProvider._store_tracker_value"
    )
    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    @patch("trackers.services.job_scheduler.get_db_session")
    @patch("requests.Session.request")
    def test_generic_job_end_to_end_execution(
        self, mock_request, mock_get_db_session, mock_encryption, mock_store_value
    ):
        """
        Test end-to-end execution of a generic job through the scheduler.

        Requirements: 4.1, 4.2, 4.3
        """
        from flask import Flask

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
            "value": 123.45,
            "timestamp": "2024-01-04T10:00:00Z",
        }
        mock_response.text = '{"value": 123.45, "timestamp": "2024-01-04T10:00:00Z"}'
        mock_request.return_value = mock_response

        # Create mock job
        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "json_path": "$.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "none",
        }

        mock_job = self.create_mock_job_config(config)

        # Mock database session
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_job
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Mock tracker value storage to avoid database constraints
        mock_store_value.return_value = None

        # Create Flask app and scheduler
        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Execute the job
        result = scheduler.execute_job_now(1)

        # Verify the result
        assert result.success is True
        assert result.value == 123.45
        assert result.error_message is None

        # Verify HTTP request was made
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        # The call is made with positional and keyword arguments
        # Check that the URL was passed correctly
        assert "https://api.example.com/data" in str(call_args)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    @patch("trackers.services.job_scheduler.get_db_session")
    def test_generic_job_with_authentication(
        self, mock_get_db_session, mock_encryption
    ):
        """
        Test generic job provider creation with authentication.

        Requirements: 4.4, 4.5
        """
        from flask import Flask

        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "https://api.example.com/secure-data",
            "method": "GET",
            "json_path": "$.result.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "bearer",
            "auth": {"token": "secret_bearer_token"},
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        # Create mock job with authentication
        config = {
            "url": "https://api.example.com/secure-data",
            "method": "GET",
            "json_path": "$.result.value",
            "timeout": 30,
            "retry_count": 3,
            "expected_status_codes": [200],
            "auth_type": "bearer",
            "auth": {"token": "secret_bearer_token"},
        }

        mock_job = self.create_mock_job_config(config)

        # Mock database session
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_job
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Create Flask app and scheduler
        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Test that the scheduler can create a generic job provider with auth
        job_provider = scheduler._create_job_provider(mock_job)

        assert job_provider is not None
        assert job_provider.__class__.__name__ == "GenericJobProvider"
        assert job_provider.url == "https://api.example.com/secure-data"
        assert job_provider.auth_type == "bearer"
        assert job_provider.auth_config == {"token": "secret_bearer_token"}

        # Test header preparation
        headers = job_provider._prepare_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer secret_bearer_token"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_generic_job_validation_integration(self, mock_encryption):
        """
        Test generic job provider validation integration.

        Requirements: 4.1, 4.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "url": "http://insecure.example.com/data",  # Invalid - not HTTPS
            "method": "DELETE",  # Invalid - not supported
            "json_path": "$.value",
            "timeout": 500,  # Invalid - too high
            "retry_count": 15,  # Invalid - too high
        }
        mock_encryption.return_value = mock_encryptor

        # Create mock job with invalid configuration
        config = {
            "url": "http://insecure.example.com/data",
            "method": "DELETE",
            "json_path": "$.value",
            "timeout": 500,
            "retry_count": 15,
        }

        mock_job = self.create_mock_job_config(config)

        # Create job provider
        from trackers.services.job_providers import GenericJobProvider

        job_provider = GenericJobProvider(mock_job)

        # Validate configuration
        errors = job_provider.validate_config()

        # Should have multiple validation errors
        assert len(errors) > 0
        assert any("Only HTTPS URLs are allowed" in error for error in errors)
        assert any("HTTP method must be GET or POST" in error for error in errors)
        assert any(
            "Timeout must be a positive number between 1 and 300" in error
            for error in errors
        )
        assert any(
            "Retry count must be an integer between 0 and 10" in error
            for error in errors
        )

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_generic_job_supported_auth_types(self, mock_encryption):
        """
        Test that generic job provider supports all required authentication types.

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

        mock_job = self.create_mock_job_config(config)

        # Create job provider
        from trackers.services.job_providers import GenericJobProvider

        job_provider = GenericJobProvider(mock_job)

        # Get supported authentication types
        auth_types = job_provider.get_supported_auth_types()

        # Verify all required auth types are supported
        auth_type_names = [auth["type"] for auth in auth_types]
        required_auth_types = ["none", "bearer", "basic", "api_key", "custom"]

        for required_type in required_auth_types:
            assert required_type in auth_type_names, (
                f"Missing auth type: {required_type}"
            )

        # Verify each auth type has proper metadata
        for auth_type in auth_types:
            assert "type" in auth_type
            assert "name" in auth_type
            assert "description" in auth_type
            assert "required_fields" in auth_type
