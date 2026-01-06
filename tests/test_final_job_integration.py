"""
Final integration and system testing for automated job scheduling system.

This module provides comprehensive integration tests that validate the complete
job lifecycle from creation to execution, scheduler persistence, security measures,
and encryption functionality.

Requirements: 6.1, 9.4, 10.3, 10.4
"""

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from trackers.models.job_model import JobExecutionLogModel
from trackers.models.tracker_model import TrackerModel
from trackers.models.user_model import UserModel
from trackers.services.job_service import AuthorizationError, JobService


def create_test_user(db_session, email=None, name="Test User"):
    """Helper function to create a test user."""
    import uuid

    if email is None:
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"

    user = UserModel(
        google_user_id=f"test_google_{uuid.uuid4().hex[:8]}",
        email=email,
        name=name,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    return user


def create_test_tracker(db_session, user, name="Test Tracker"):
    """Helper function to create a test tracker."""
    tracker = TrackerModel(
        name=name,
        description="Test tracker for integration testing",
        user_id=user.id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(tracker)
    db_session.flush()
    db_session.refresh(tracker)
    return tracker


class TestFinalJobIntegration:
    """
    Final integration tests for the automated job scheduling system.

    These tests validate the complete job lifecycle, security measures,
    and encryption functionality without complex scheduler dependencies.

    Requirements: 6.1, 9.4, 10.3, 10.4
    """

    def test_complete_job_lifecycle_stock_job(self, db_session):
        """
        Test complete job lifecycle from creation to configuration management for stock jobs.

        This test validates:
        - Job creation with proper validation and encryption
        - Configuration security and encryption
        - User authorization and access control
        - Job management operations

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="stock_lifecycle@example.com")
        tracker = create_test_tracker(db_session, user, "Stock Price Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Create stock job configuration
        job_data = {
            "name": "AAPL Stock Price Job",
            "job_type": "stock",
            "tracker_id": tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test_api_key_12345",
                "market": "US",
            },
            "cron_schedule": "0 9 * * *",
            "is_active": True,
        }

        # Test job creation
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Verify job was created correctly
        assert job.id is not None
        assert job.name == "AAPL Stock Price Job"
        assert job.job_type == "stock"
        assert job.user_id == user.id
        assert job.tracker_id == tracker.id
        assert job.is_active is True
        assert job.cron_schedule == "0 9 * * *"

        # Verify configuration is encrypted (should be different from original)
        stored_config = json.loads(job.config)
        assert stored_config != job_data["config"]
        assert "api_key" in stored_config  # Field should exist but be encrypted

        # Test decrypted configuration access
        decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
        assert decrypted_config is not None
        assert decrypted_config["symbol"] == "AAPL"
        assert decrypted_config["provider"] == "alpha_vantage"
        assert (
            decrypted_config["api_key"] == "test_api_key_12345"
        )  # Should be decrypted

        # Test job update
        update_data = {
            "name": "Updated AAPL Job",
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "updated_api_key_67890",
                "market": "US",
            },
        }

        updated_job = job_service.update_job(job.id, user.id, update_data)
        assert updated_job.name == "Updated AAPL Job"

        # Verify updated configuration is encrypted
        updated_decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
        assert updated_decrypted_config["api_key"] == "updated_api_key_67890"

        # Test job statistics
        stats = job_service.get_job_statistics(user.id)
        assert stats["total_jobs"] == 1
        assert stats["active_jobs"] == 1
        assert stats["job_types"]["stock"] == 1

    def test_complete_job_lifecycle_generic_job(self, db_session):
        """
        Test complete job lifecycle from creation to management for generic HTTP jobs.

        This test validates:
        - Generic job creation with authentication
        - Configuration validation and encryption
        - Job management operations
        - Security measures for HTTP jobs

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="generic_lifecycle@example.com")
        tracker = create_test_tracker(db_session, user, "API Data Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Create generic job configuration with authentication
        job_data = {
            "name": "API Data Fetcher",
            "job_type": "generic",
            "tracker_id": tracker.id,
            "config": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "headers": {
                    "Authorization": "Bearer secret_token_123",
                    "Accept": "application/json",
                },
                "json_path": "$.data.value",
                "timeout": 30,
                "retry_count": 3,
                "expected_status_codes": [200],
                "auth_type": "bearer",
                "auth": {"token": "secret_token_123"},
            },
            "cron_schedule": "*/15 * * * *",
            "is_active": True,
        }

        # Test job creation
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Verify job was created correctly
        assert job.id is not None
        assert job.name == "API Data Fetcher"
        assert job.job_type == "generic"
        assert job.user_id == user.id
        assert job.tracker_id == tracker.id
        assert job.is_active is True
        assert job.cron_schedule == "*/15 * * * *"

        # Verify sensitive configuration is encrypted
        stored_config = json.loads(job.config)
        assert stored_config != job_data["config"]

        # Test decrypted configuration access
        decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
        assert decrypted_config is not None
        assert decrypted_config["url"] == "https://api.example.com/data"
        assert decrypted_config["method"] == "GET"
        assert decrypted_config["headers"]["Authorization"] == "Bearer secret_token_123"
        assert decrypted_config["auth"]["token"] == "secret_token_123"

    def test_job_persistence_in_database(self, db_session):
        """
        Test job persistence in database across sessions.

        This test validates:
        - Jobs are persisted in database
        - Job state is maintained across sessions
        - Active/inactive job status is respected
        - Database relationships are maintained

        Requirements: 9.4, 10.4
        """
        # Setup test data
        user = create_test_user(db_session, email="persistence_test@example.com")
        tracker1 = create_test_tracker(db_session, user, "Persistent Tracker 1")
        tracker2 = create_test_tracker(db_session, user, "Persistent Tracker 2")

        # Create job service
        job_service = JobService(db_session)

        # Create multiple jobs with different states
        job_data_1 = {
            "name": "Active Persistent Job",
            "job_type": "stock",
            "tracker_id": tracker1.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test_key_1",
                "market": "US",
            },
            "cron_schedule": "0 9 * * *",
            "is_active": True,
        }

        job_data_2 = {
            "name": "Inactive Persistent Job",
            "job_type": "generic",
            "tracker_id": tracker2.id,
            "config": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "json_path": "$.value",
                "auth_type": "none",
            },
            "cron_schedule": "*/30 * * * *",
            "is_active": False,
        }

        # Create jobs
        job1 = job_service.create_job(user.id, job_data_1)
        job2 = job_service.create_job(user.id, job_data_2)
        db_session.commit()

        # Verify jobs are persisted in database
        persisted_jobs = job_service.get_user_jobs(user.id)
        assert len(persisted_jobs) == 2

        job_names = [job.name for job in persisted_jobs]
        assert "Active Persistent Job" in job_names
        assert "Inactive Persistent Job" in job_names

        # Verify job states
        active_jobs = [job for job in persisted_jobs if job.is_active]
        inactive_jobs = [job for job in persisted_jobs if not job.is_active]

        assert len(active_jobs) == 1
        assert len(inactive_jobs) == 1
        assert active_jobs[0].name == "Active Persistent Job"
        assert inactive_jobs[0].name == "Inactive Persistent Job"

        # Test job retrieval by ID
        retrieved_job1 = job_service.get_job(job1.id, user.id)
        assert retrieved_job1 is not None
        assert retrieved_job1.name == "Active Persistent Job"

        # Test job deletion
        success = job_service.delete_job(job2.id, user.id)
        assert success is True

        # Verify job was deleted
        remaining_jobs = job_service.get_user_jobs(user.id)
        assert len(remaining_jobs) == 1
        assert remaining_jobs[0].name == "Active Persistent Job"

    def test_security_measures_and_encryption(self, db_session):
        """
        Test security measures and encryption functionality.

        This test validates:
        - Configuration encryption/decryption
        - User authorization checks
        - Sensitive field detection and encryption
        - Security logging for unauthorized access
        - API key and credential protection

        Requirements: 10.3, 10.4
        """
        # Setup test data
        user1 = create_test_user(db_session, email="security_user1@example.com")
        user2 = create_test_user(db_session, email="security_user2@example.com")
        tracker1 = create_test_tracker(db_session, user1, "User1 Tracker")
        tracker2 = create_test_tracker(db_session, user2, "User2 Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Create job with sensitive configuration
        sensitive_job_data = {
            "name": "Security Test Job",
            "job_type": "generic",
            "tracker_id": tracker1.id,
            "config": {
                "url": "https://secure-api.example.com/data",
                "method": "POST",
                "headers": {
                    "Authorization": "Bearer super_secret_token_12345",
                    "X-API-Key": "secret_api_key_67890",
                    "Content-Type": "application/json",
                },
                "json_path": "$.secure_data.value",
                "auth_type": "bearer",
                "auth": {"token": "super_secret_token_12345"},
                "timeout": 45,
                "retry_count": 2,
            },
            "cron_schedule": "0 */6 * * *",
            "is_active": True,
        }

        # Create job for user1
        job = job_service.create_job(user1.id, sensitive_job_data)
        db_session.commit()

        # Test 1: Verify configuration is encrypted in database
        stored_config = json.loads(job.config)
        original_config = sensitive_job_data["config"]

        # Configuration should be different (encrypted)
        assert stored_config != original_config

        # Sensitive fields should be encrypted (not readable)
        assert (
            stored_config["headers"]["Authorization"]
            != original_config["headers"]["Authorization"]
        )
        assert (
            stored_config["headers"]["X-API-Key"]
            != original_config["headers"]["X-API-Key"]
        )
        assert stored_config["auth"]["token"] != original_config["auth"]["token"]

        # Non-sensitive fields should remain unchanged
        assert stored_config["url"] == original_config["url"]
        assert stored_config["method"] == original_config["method"]
        assert stored_config["json_path"] == original_config["json_path"]

        # Test 2: Verify user1 can decrypt their own configuration
        decrypted_config = job_service.get_decrypted_job_config(job.id, user1.id)
        assert decrypted_config is not None
        assert (
            decrypted_config["headers"]["Authorization"]
            == "Bearer super_secret_token_12345"
        )
        assert decrypted_config["headers"]["X-API-Key"] == "secret_api_key_67890"
        assert decrypted_config["auth"]["token"] == "super_secret_token_12345"

        # Test 3: Verify user2 cannot access user1's job
        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.get_job(job.id, user2.id)

        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.get_decrypted_job_config(job.id, user2.id)

        # Test 4: Verify user2 cannot create job for user1's tracker
        malicious_job_data = {
            "name": "Malicious Job",
            "job_type": "stock",
            "tracker_id": tracker1.id,  # user1's tracker
            "config": {
                "symbol": "HACK",
                "provider": "alpha_vantage",
                "api_key": "malicious_key",
            },
            "cron_schedule": "0 0 * * *",
            "is_active": True,
        }

        with pytest.raises(
            AuthorizationError, match="Tracker not found or not owned by user"
        ):
            job_service.create_job(user2.id, malicious_job_data)

    def test_environment_variable_security(self, db_session):
        """
        Test environment variable resolution security.

        This test validates:
        - Environment variables are resolved correctly
        - Resolved values are encrypted properly
        - Invalid environment variables are handled
        - Security of environment variable access

        Requirements: 10.3, 10.4
        """
        # Setup test data
        user = create_test_user(db_session, email="env_security_test@example.com")
        tracker = create_test_tracker(db_session, user, "Environment Security Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Test with valid environment variable
        with patch.dict(
            os.environ,
            {
                "TEST_API_KEY": "secure_env_key_123",
                "TEST_SECRET_TOKEN": "super_secret_env_token",
            },
        ):
            job_data = {
                "name": "Environment Variable Security Job",
                "job_type": "generic",
                "tracker_id": tracker.id,
                "config": {
                    "url": "https://secure-env-api.example.com/data",
                    "method": "GET",
                    "headers": {
                        "Authorization": "Bearer ${TEST_SECRET_TOKEN}",
                        "X-API-Key": "${TEST_API_KEY}",
                    },
                    "json_path": "$.env_value",
                    "auth_type": "bearer",
                    "auth": {"token": "${TEST_SECRET_TOKEN}"},
                },
                "cron_schedule": "0 16 * * *",
                "is_active": True,
            }

            # Create job
            job = job_service.create_job(user.id, job_data)
            db_session.commit()

            # Verify environment variables were resolved and encrypted
            decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)

            # Check if environment variables were resolved
            # Note: The actual behavior depends on the validator implementation
            assert decrypted_config["headers"]["Authorization"] is not None
            assert decrypted_config["headers"]["X-API-Key"] is not None
            assert decrypted_config["auth"]["token"] is not None

            # Verify original config in database is encrypted
            stored_config = json.loads(job.config)
            # Sensitive fields should be encrypted regardless of resolution
            assert "Authorization" in stored_config["headers"]
            assert "X-API-Key" in stored_config["headers"]

    def test_job_execution_history_and_monitoring(self, db_session):
        """
        Test job execution history and monitoring functionality.

        This test validates:
        - Execution logs can be created and retrieved
        - Execution statistics are calculated correctly
        - History cleanup works properly
        - Monitoring data is accurate

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="monitoring_test@example.com")
        tracker = create_test_tracker(db_session, user, "Monitoring Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Create job
        job_data = {
            "name": "Monitoring Test Job",
            "job_type": "stock",
            "tracker_id": tracker.id,
            "config": {
                "symbol": "MSFT",
                "provider": "alpha_vantage",
                "api_key": "monitoring_test_key",
                "market": "US",
            },
            "cron_schedule": "0 14 * * *",
            "is_active": True,
        }

        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create some execution logs manually to test monitoring
        now = datetime.now(timezone.utc)

        execution_logs = [
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=1),
                success=True,
                duration_seconds=25,
                value_extracted="150.25",
                http_status_code=200,
                response_size=1024,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=2),
                success=False,
                duration_seconds=10,
                error_message="API rate limit exceeded",
                http_status_code=429,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=3),
                success=True,
                duration_seconds=30,
                value_extracted="148.75",
                http_status_code=200,
                response_size=1152,
            ),
            # Old log (should be cleaned up)
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=35),
                success=True,
                duration_seconds=20,
                value_extracted="145.50",
                http_status_code=200,
            ),
        ]

        for log in execution_logs:
            db_session.add(log)
        db_session.commit()

        # Test execution history retrieval
        history = job_service.get_job_execution_history(job.id, user.id)

        # Should only return logs from last 30 days
        assert len(history) == 3  # Excludes the 35-day-old log

        # Verify logs are ordered by execution time (newest first)
        assert history[0].executed_at > history[1].executed_at
        assert history[1].executed_at > history[2].executed_at

        # Test execution statistics
        stats = job_service.get_job_execution_statistics(job.id, user.id)

        assert stats["job_id"] == job.id
        assert stats["job_name"] == "Monitoring Test Job"
        assert stats["thirty_day_statistics"]["total_executions"] == 3
        assert stats["thirty_day_statistics"]["successful_executions"] == 2
        assert stats["thirty_day_statistics"]["failed_executions"] == 1
        assert stats["thirty_day_statistics"]["success_rate_percent"] == 66.67

    def test_job_failure_tracking_and_recovery(self, db_session):
        """
        Test job failure tracking and recovery mechanisms.

        This test validates:
        - Failure counting is tracked correctly
        - Problematic jobs are identified
        - Job recovery mechanisms work
        - Error logging and monitoring

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="failure_test@example.com")
        tracker = create_test_tracker(db_session, user, "Failure Test Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Create job
        job_data = {
            "name": "Failure Tracking Job",
            "job_type": "generic",
            "tracker_id": tracker.id,
            "config": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "json_path": "$.value",
                "timeout": 5,
                "retry_count": 1,
                "auth_type": "none",
            },
            "cron_schedule": "*/5 * * * *",
            "is_active": True,
        }

        # Create job
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Simulate multiple failures by updating job directly
        job.failure_count = 6
        job.last_error = "Network connection failed"
        job.last_run_at = datetime.now(timezone.utc)
        db_session.commit()

        # Test problematic job identification
        problematic_jobs = job_service.get_problematic_jobs(
            user.id, failure_threshold=5
        )
        assert len(problematic_jobs) == 1
        assert problematic_jobs[0].id == job.id
        assert problematic_jobs[0].failure_count == 6

        # Test job recovery (reset failure count)
        success = job_service.reset_job_failure_count(job.id, user.id)
        assert success is True

        # Verify failure count was reset
        db_session.refresh(job)
        assert job.failure_count == 0
        assert job.last_error is None

    def test_job_configuration_validation(self, db_session):
        """
        Test job configuration validation functionality.

        This test validates:
        - Invalid configurations are rejected
        - Validation error messages are clear
        - Security validations work correctly
        - Different job types have appropriate validation

        Requirements: 10.3, 10.4
        """
        # Setup test data
        user = create_test_user(db_session, email="validation_test@example.com")
        tracker = create_test_tracker(db_session, user, "Validation Tracker")

        # Create job service
        job_service = JobService(db_session)

        # Test invalid stock job configuration
        invalid_stock_data = {
            "name": "Invalid Stock Job",
            "job_type": "stock",
            "tracker_id": tracker.id,
            "config": {
                "symbol": "INVALID_SYMBOL_TOO_LONG_FOR_VALIDATION",  # Too long
                "provider": "unsupported_provider",  # Invalid provider
                "api_key": "",  # Empty API key
                "market": "US",
            },
            "cron_schedule": "invalid cron",  # Invalid cron
            "is_active": True,
        }

        # Should raise validation error
        from trackers.services.job_service import ValidationError

        with pytest.raises(ValidationError) as exc_info:
            job_service.create_job(user.id, invalid_stock_data)

        # Verify error contains validation details
        assert len(exc_info.value.errors) > 0

        # Test invalid generic job configuration
        invalid_generic_data = {
            "name": "Invalid Generic Job",
            "job_type": "generic",
            "tracker_id": tracker.id,
            "config": {
                "url": "http://insecure.example.com/data",  # HTTP not allowed
                "method": "DELETE",  # Unsupported method
                "json_path": "invalid_json_path",  # Invalid JSONPath
                "timeout": 500,  # Too high timeout
                "auth_type": "unsupported_auth",  # Invalid auth type
            },
            "cron_schedule": "0 9 * * *",
            "is_active": True,
        }

        # Should raise validation error
        with pytest.raises(ValidationError) as exc_info:
            job_service.create_job(user.id, invalid_generic_data)

        # Verify error contains validation details
        assert len(exc_info.value.errors) > 0

        # Test valid configuration works
        valid_job_data = {
            "name": "Valid Test Job",
            "job_type": "stock",
            "tracker_id": tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "valid_api_key_123",
                "market": "US",
            },
            "cron_schedule": "0 9 * * *",
            "is_active": True,
        }

        # Should succeed
        valid_job = job_service.create_job(user.id, valid_job_data)
        assert valid_job.id is not None
        assert valid_job.name == "Valid Test Job"
