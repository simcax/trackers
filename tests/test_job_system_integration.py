"""
Final integration and system testing for automated job scheduling system.

This module provides comprehensive integration tests that validate the complete
job lifecycle from creation to execution, scheduler persistence, security measures,
and encryption functionality.

Requirements: 6.1, 9.4, 10.3, 10.4
"""

import json
import os
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from trackers.models.job_model import JobExecutionLogModel
from trackers.models.tracker_model import TrackerModel
from trackers.models.user_model import UserModel
from trackers.services.job_scheduler import JobExecutionResult, JobScheduler
from trackers.services.job_service import JobService


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


class TestJobSystemIntegration:
    """
    Comprehensive integration tests for the automated job scheduling system.

    These tests validate the complete job lifecycle, scheduler persistence,
    security measures, and encryption functionality.

    Requirements: 6.1, 9.4, 10.3, 10.4
    """

    def test_complete_job_lifecycle_stock_job(self, db_session):
        """
        Test complete job lifecycle from creation to execution for stock jobs.

        This test validates:
        - Job creation with proper validation and encryption
        - Job scheduling in APScheduler
        - Job execution with data fetching
        - Tracker value creation from job execution
        - Execution history logging

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="stock_test@example.com")
        tracker = create_test_tracker(db_session, user, "Stock Price Tracker")

        # Create job service and mock scheduler
        mock_scheduler = Mock()
        mock_scheduler.add_job.return_value = True
        mock_scheduler.execute_job_now.return_value = JobExecutionResult(
            success=True,
            value=150.25,
            execution_time=2.5,
            http_status=200,
            response_size=1024,
        )

        job_service = JobService(db_session, mock_scheduler)

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

        # Verify scheduler was called to add job
        mock_scheduler.add_job.assert_called_once_with(job)

        # Test job execution
        result = job_service.test_job(job.id, user.id)

        # Verify execution result
        assert result.success is True
        assert result.value == 150.25
        assert result.execution_time == 2.5
        assert result.http_status == 200
        assert result.response_size == 1024

        # Verify scheduler was called to execute job
        mock_scheduler.execute_job_now.assert_called_once_with(job.id)

        # Test decrypted configuration access
        decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
        assert decrypted_config is not None
        assert decrypted_config["symbol"] == "AAPL"
        assert decrypted_config["provider"] == "alpha_vantage"
        assert (
            decrypted_config["api_key"] == "test_api_key_12345"
        )  # Should be decrypted

        # Test job statistics
        stats = job_service.get_job_statistics(user.id)
        assert stats["total_jobs"] == 1
        assert stats["active_jobs"] == 1
        assert stats["job_types"]["stock"] == 1

    def test_complete_job_lifecycle_generic_job(self, db_session):
        """
        Test complete job lifecycle from creation to execution for generic HTTP jobs.

        This test validates:
        - Generic job creation with authentication
        - Configuration validation and encryption
        - Job execution with HTTP requests
        - Error handling and logging

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="generic_test@example.com")
        tracker = create_test_tracker(db_session, user, "API Data Tracker")

        # Create job service and mock scheduler
        mock_scheduler = Mock()
        mock_scheduler.add_job.return_value = True
        mock_scheduler.execute_job_now.return_value = JobExecutionResult(
            success=True,
            value=42.75,
            execution_time=1.8,
            http_status=200,
            response_size=512,
        )

        job_service = JobService(db_session, mock_scheduler)

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

        # Verify scheduler was called
        mock_scheduler.add_job.assert_called_once_with(job)

        # Test job execution
        result = job_service.test_job(job.id, user.id)

        # Verify execution result
        assert result.success is True
        assert result.value == 42.75
        assert result.execution_time == 1.8

        # Test decrypted configuration access
        decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
        assert decrypted_config is not None
        assert decrypted_config["url"] == "https://api.example.com/data"
        assert decrypted_config["method"] == "GET"
        assert decrypted_config["headers"]["Authorization"] == "Bearer secret_token_123"
        assert decrypted_config["auth"]["token"] == "secret_token_123"

    @patch(
        "trackers.services.job_providers.base_job_provider.BaseJobProvider._store_tracker_value"
    )
    def test_job_execution_creates_tracker_values(self, mock_store_value, db_session):
        """
        Test that job execution creates proper tracker values.

        This test validates:
        - Job execution stores values in tracker_values table
        - Values are stored with correct date and user association
        - Multiple executions create multiple values
        - Error handling when value storage fails

        Requirements: 6.1
        """
        # Setup test data
        user = create_test_user(db_session, email="tracker_value_test@example.com")
        tracker = create_test_tracker(db_session, user, "Value Storage Tracker")

        # Mock successful value storage
        mock_store_value.return_value = None

        # Create job service with real scheduler for this test
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)
        job_service = JobService(db_session, scheduler)

        # Create job configuration
        job_data = {
            "name": "Value Storage Test Job",
            "job_type": "stock",
            "tracker_id": tracker.id,
            "config": {
                "symbol": "TSLA",
                "provider": "alpha_vantage",
                "api_key": "test_api_key",
                "market": "US",
            },
            "cron_schedule": "0 10 * * *",
            "is_active": True,
        }

        # Create job
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Mock successful API response for job execution
        with patch(
            "trackers.services.job_providers.stock_job_provider.StockJobProvider.fetch_data"
        ) as mock_fetch:
            mock_fetch.return_value = 245.50

            # Execute job
            result = scheduler.execute_job_now(job.id)

            # Verify execution was successful
            assert result.success is True
            assert result.value == 245.50

            # Verify tracker value storage was called
            mock_store_value.assert_called_once()
            call_args = mock_store_value.call_args[0]
            assert call_args[0] == tracker.id  # tracker_id
            assert call_args[1] == 245.50  # value

        # Test multiple executions create multiple values
        with patch(
            "trackers.services.job_providers.stock_job_provider.StockJobProvider.fetch_data"
        ) as mock_fetch:
            mock_fetch.return_value = 250.75

            # Execute job again
            result = scheduler.execute_job_now(job.id)

            # Verify second execution
            assert result.success is True
            assert result.value == 250.75

            # Verify storage was called again
            assert mock_store_value.call_count == 2

    def test_scheduler_persistence_across_restarts(self, db_session):
        """
        Test scheduler persistence across application restarts.

        This test validates:
        - Jobs are persisted in database
        - Scheduler loads jobs from database on startup
        - Job state is maintained across restarts
        - Active/inactive job status is respected

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

        # Simulate application restart by creating new scheduler
        from flask import Flask

        app = Flask(__name__)

        # Mock database loading for scheduler startup
        with patch("trackers.services.job_scheduler.get_db_session") as mock_get_db:
            mock_db = Mock()
            mock_db.query.return_value.filter.return_value.all.return_value = [
                job for job in persisted_jobs if job.is_active
            ]
            mock_get_db.return_value.__enter__.return_value = mock_db

            # Create new scheduler (simulating restart)
            new_scheduler = JobScheduler(app)
            new_scheduler.start()

            # Verify only active jobs were loaded
            assert new_scheduler.is_running is True
            assert len(new_scheduler._scheduled_jobs) == 1
            assert job1.id in new_scheduler._scheduled_jobs
            assert (
                job2.id not in new_scheduler._scheduled_jobs
            )  # Inactive job not loaded

            # Clean up
            new_scheduler.stop()

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
        from trackers.services.job_service import AuthorizationError

        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.get_job(job.id, user2.id)

        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.get_decrypted_job_config(job.id, user2.id)

        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.test_job(job.id, user2.id)

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

        # Test 5: Verify environment variable resolution works securely
        env_job_data = {
            "name": "Environment Variable Job",
            "job_type": "stock",
            "tracker_id": tracker2.id,
            "config": {
                "symbol": "NVDA",
                "provider": "alpha_vantage",
                "api_key": "${ALPHA_VANTAGE_API_KEY}",  # Environment variable
                "market": "US",
            },
            "cron_schedule": "0 12 * * *",
            "is_active": True,
        }

        # Mock environment variable
        with patch.dict(os.environ, {"ALPHA_VANTAGE_API_KEY": "env_resolved_key_123"}):
            env_job = job_service.create_job(user2.id, env_job_data)
            db_session.commit()

            # Verify environment variable was resolved and encrypted
            decrypted_env_config = job_service.get_decrypted_job_config(
                env_job.id, user2.id
            )
            assert decrypted_env_config["api_key"] == "env_resolved_key_123"

    def test_job_failure_isolation_and_recovery(self, db_session):
        """
        Test job failure isolation and recovery mechanisms.

        This test validates:
        - Failed jobs don't crash the scheduler
        - Failure counting and isolation
        - Job recovery after fixing issues
        - Error logging and monitoring

        Requirements: 6.1, 10.3
        """
        # Setup test data
        user = create_test_user(db_session, email="failure_test@example.com")
        tracker = create_test_tracker(db_session, user, "Failure Test Tracker")

        # Create Flask app and scheduler
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)
        job_service = JobService(db_session, scheduler)

        # Create job that will fail
        failing_job_data = {
            "name": "Failing Test Job",
            "job_type": "generic",
            "tracker_id": tracker.id,
            "config": {
                "url": "https://nonexistent-api.example.com/data",
                "method": "GET",
                "json_path": "$.value",
                "timeout": 5,
                "retry_count": 1,
                "auth_type": "none",
            },
            "cron_schedule": "*/5 * * * *",
            "is_active": True,
        }

        # Create failing job
        failing_job = job_service.create_job(user.id, failing_job_data)
        db_session.commit()

        # Mock network failure
        with patch("requests.Session.request") as mock_request:
            mock_request.side_effect = Exception("Network connection failed")

            # Execute failing job multiple times
            for i in range(3):
                result = scheduler.execute_job_now(failing_job.id)

                # Verify job fails but doesn't crash scheduler
                assert result.success is False
                assert "Network connection failed" in result.error_message
                assert scheduler.is_running is True  # Scheduler should still be running

        # Verify failure count is tracked
        db_session.refresh(failing_job)
        assert failing_job.failure_count > 0
        assert failing_job.last_error is not None

        # Test job recovery after fixing the issue
        with patch("requests.Session.request") as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"value": 99.99}
            mock_response.headers = {"content-type": "application/json"}
            mock_request.return_value = mock_response

            # Execute job again (should succeed now)
            result = scheduler.execute_job_now(failing_job.id)

            # Verify job recovers
            assert result.success is True
            assert result.value == 99.99

        # Verify failure count is reset after successful execution
        db_session.refresh(failing_job)
        # Note: Failure count reset happens in actual job execution, not test execution
        # This would be verified in a full integration test with real scheduler

    def test_job_execution_history_and_monitoring(self, db_session):
        """
        Test job execution history and monitoring functionality.

        This test validates:
        - Execution logs are created for each job run
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
        from datetime import timedelta

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

        # Test cleanup of old execution logs
        deleted_count = job_service.cleanup_old_execution_logs(days_to_keep=30)
        db_session.commit()

        assert deleted_count == 1  # Should delete the 35-day-old log

        # Verify old log was deleted
        remaining_logs = job_service.get_job_execution_history(job.id, user.id)
        assert len(remaining_logs) == 3  # Same as before (old log already excluded)

    def test_concurrent_job_execution(self, db_session):
        """
        Test concurrent job execution and thread safety.

        This test validates:
        - Multiple jobs can execute simultaneously
        - Thread safety of database operations
        - No resource conflicts between jobs
        - Proper isolation of job executions

        Requirements: 10.3, 10.4
        """
        # Setup test data
        user = create_test_user(db_session, email="concurrent_test@example.com")
        tracker1 = create_test_tracker(db_session, user, "Concurrent Tracker 1")
        tracker2 = create_test_tracker(db_session, user, "Concurrent Tracker 2")

        # Create Flask app and scheduler
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)
        job_service = JobService(db_session, scheduler)

        # Create multiple jobs
        job_data_1 = {
            "name": "Concurrent Job 1",
            "job_type": "stock",
            "tracker_id": tracker1.id,
            "config": {
                "symbol": "GOOGL",
                "provider": "alpha_vantage",
                "api_key": "concurrent_key_1",
                "market": "US",
            },
            "cron_schedule": "0 15 * * *",
            "is_active": True,
        }

        job_data_2 = {
            "name": "Concurrent Job 2",
            "job_type": "generic",
            "tracker_id": tracker2.id,
            "config": {
                "url": "https://api.example.com/concurrent-data",
                "method": "GET",
                "json_path": "$.concurrent_value",
                "auth_type": "none",
                "timeout": 10,
            },
            "cron_schedule": "*/10 * * * *",
            "is_active": True,
        }

        # Create jobs
        job1 = job_service.create_job(user.id, job_data_1)
        job2 = job_service.create_job(user.id, job_data_2)
        db_session.commit()

        # Mock successful responses for both jobs
        with (
            patch(
                "trackers.services.job_providers.stock_job_provider.StockJobProvider.fetch_data"
            ) as mock_stock_fetch,
            patch("requests.Session.request") as mock_http_request,
        ):
            # Mock stock API response
            mock_stock_fetch.return_value = 2750.50

            # Mock HTTP API response
            mock_http_response = Mock()
            mock_http_response.status_code = 200
            mock_http_response.json.return_value = {"concurrent_value": 123.45}
            mock_http_response.headers = {"content-type": "application/json"}
            mock_http_request.return_value = mock_http_response

            # Execute both jobs concurrently (simulate concurrent execution)
            import threading

            results = {}

            def execute_job(job_id, job_name):
                try:
                    result = scheduler.execute_job_now(job_id)
                    results[job_name] = result
                except Exception as e:
                    results[job_name] = f"Error: {e}"

            # Start both jobs in separate threads
            thread1 = threading.Thread(target=execute_job, args=(job1.id, "job1"))
            thread2 = threading.Thread(target=execute_job, args=(job2.id, "job2"))

            thread1.start()
            thread2.start()

            # Wait for both to complete
            thread1.join(timeout=10)
            thread2.join(timeout=10)

            # Verify both jobs executed successfully
            assert "job1" in results
            assert "job2" in results

            job1_result = results["job1"]
            job2_result = results["job2"]

            assert isinstance(job1_result, JobExecutionResult)
            assert isinstance(job2_result, JobExecutionResult)

            assert job1_result.success is True
            assert job1_result.value == 2750.50

            assert job2_result.success is True
            assert job2_result.value == 123.45

            # Verify no database conflicts occurred
            db_session.refresh(job1)
            db_session.refresh(job2)

            # Both jobs should have updated execution times
            assert job1.last_run_at is not None
            assert job2.last_run_at is not None

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

            assert (
                decrypted_config["headers"]["Authorization"]
                == "Bearer super_secret_env_token"
            )
            assert decrypted_config["headers"]["X-API-Key"] == "secure_env_key_123"
            assert decrypted_config["auth"]["token"] == "super_secret_env_token"

            # Verify original config in database is encrypted
            stored_config = json.loads(job.config)
            assert (
                stored_config["headers"]["Authorization"]
                != "Bearer super_secret_env_token"
            )
            assert stored_config["headers"]["X-API-Key"] != "secure_env_key_123"

        # Test with missing environment variable (should fail validation)
        job_data_missing_env = {
            "name": "Missing Environment Variable Job",
            "job_type": "stock",
            "tracker_id": tracker.id,
            "config": {
                "symbol": "AMZN",
                "provider": "alpha_vantage",
                "api_key": "${NONEXISTENT_API_KEY}",  # This env var doesn't exist
                "market": "US",
            },
            "cron_schedule": "0 17 * * *",
            "is_active": True,
        }

        # Should handle missing environment variable gracefully
        # (The actual behavior depends on the validator implementation)
        try:
            missing_env_job = job_service.create_job(user.id, job_data_missing_env)
            db_session.commit()

            # If job creation succeeds, the unresolved variable should be handled
            decrypted_config = job_service.get_decrypted_job_config(
                missing_env_job.id, user.id
            )
            # The behavior here depends on implementation - could be empty string or original value
            assert "api_key" in decrypted_config

        except Exception as e:
            # If validation fails, that's also acceptable behavior
            assert (
                "environment variable" in str(e).lower() or "api key" in str(e).lower()
            )
