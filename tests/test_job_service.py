"""
Tests for Job Service operations.

This module tests the JobService class for CRUD operations on jobs,
security controls, user authorization, audit logging, and monitoring functionality.

Requirements: 1.4, 1.5, 5.3, 7.1, 7.2, 7.3, 7.4, 7.5, 8.2, 8.3
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch

import pytest

from trackers.models.job_model import JobExecutionLogModel, JobModel
from trackers.models.tracker_model import TrackerModel
from trackers.models.user_model import UserModel
from trackers.services.job_scheduler import JobExecutionResult
from trackers.services.job_service import (
    AuthorizationError,
    JobService,
    ValidationError,
)


def create_test_user(db_session, email=None, name="Test User"):
    """Helper function to create a test user."""
    import uuid

    # Generate unique email if not provided
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
        description="Test tracker description",
        user_id=user.id,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(tracker)
    db_session.flush()
    db_session.refresh(tracker)
    return tracker


def create_test_job_data(tracker_id, job_type="stock"):
    """Helper function to create test job data."""
    if job_type == "stock":
        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_123",
            "market": "US",
        }
    else:  # generic
        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Authorization": "Bearer test_token"},
            "json_path": "$.value",
            "timeout": 30,
        }

    return {
        "name": "Test Job",
        "job_type": job_type,
        "tracker_id": tracker_id,
        "config": config,
        "cron_schedule": "0 9 * * *",
        "is_active": True,
    }


class TestJobService:
    """Test cases for JobService class."""

    def test_create_job_success(self, db_session):
        """Test successful job creation with security validation."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        # Mock scheduler
        mock_scheduler = Mock()
        mock_scheduler.add_job.return_value = True

        job_service = JobService(db_session, mock_scheduler)

        # Create job
        job = job_service.create_job(user.id, job_data)

        # Verify job creation
        assert job.id is not None
        assert job.name == "Test Job"
        assert job.job_type == "stock"
        assert job.user_id == user.id
        assert job.tracker_id == tracker.id
        assert job.is_active is True
        assert job.created_at is not None
        assert job.updated_at is not None

        # Verify configuration is encrypted (should be different from original)
        stored_config = json.loads(job.config)
        assert stored_config != job_data["config"]
        assert "api_key" in stored_config  # Field should exist but be encrypted

        # Verify scheduler was called
        mock_scheduler.add_job.assert_called_once_with(job)

    def test_create_job_invalid_user(self, db_session):
        """Test job creation with invalid user ID."""
        job_service = JobService(db_session)
        job_data = create_test_job_data(1)

        with pytest.raises(ValueError, match="Invalid user ID"):
            job_service.create_job(0, job_data)

    def test_create_job_missing_fields(self, db_session):
        """Test job creation with missing required fields."""
        user = create_test_user(db_session)
        job_service = JobService(db_session)

        # Missing name field
        incomplete_data = {"job_type": "stock", "tracker_id": 1}

        with pytest.raises(ValueError, match="Missing required field: name"):
            job_service.create_job(user.id, incomplete_data)

    def test_create_job_unauthorized_tracker(self, db_session):
        """Test job creation with tracker not owned by user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user2)  # Owned by user2
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)

        with pytest.raises(
            AuthorizationError, match="Tracker not found or not owned by user"
        ):
            job_service.create_job(
                user1.id, job_data
            )  # user1 tries to use user2's tracker

    def test_create_job_invalid_config(self, db_session):
        """Test job creation with invalid configuration."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        # Invalid stock symbol
        job_data["config"]["symbol"] = "INVALID_SYMBOL_TOO_LONG"

        job_service = JobService(db_session)

        with pytest.raises(ValidationError) as exc_info:
            job_service.create_job(user.id, job_data)

        assert "Stock symbol must be 1-10 alphanumeric characters" in str(
            exc_info.value.errors
        )

    def test_create_job_invalid_cron(self, db_session):
        """Test job creation with invalid cron schedule."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        # Invalid cron expression
        job_data["cron_schedule"] = "invalid cron"

        job_service = JobService(db_session)

        with pytest.raises(ValidationError) as exc_info:
            job_service.create_job(user.id, job_data)

        assert "Cron expression must have exactly 5 parts" in str(exc_info.value.errors)

    def test_update_job_success(self, db_session):
        """Test successful job update with security validation."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        mock_scheduler = Mock()
        mock_scheduler.add_job.return_value = True

        job_service = JobService(db_session, mock_scheduler)

        # Create job
        job = job_service.create_job(user.id, job_data)
        original_updated_at = job.updated_at

        # Update job
        update_data = {
            "name": "Updated Job Name",
            "is_active": False,
            "config": {
                "symbol": "GOOGL",
                "provider": "alpha_vantage",
                "api_key": "updated_api_key",
                "market": "US",
            },
        }

        updated_job = job_service.update_job(job.id, user.id, update_data)

        # Verify updates
        assert updated_job.name == "Updated Job Name"
        assert updated_job.is_active is False
        # Instead of comparing datetimes directly, check that updated_at changed
        assert updated_job.updated_at != original_updated_at
        # Verify the updated_at is recent (within last few seconds)
        from datetime import timedelta

        time_diff = datetime.now(timezone.utc) - updated_job.updated_at
        assert time_diff < timedelta(seconds=5)

        # Verify scheduler was called to remove inactive job
        mock_scheduler.remove_job.assert_called_with(job.id)

    def test_update_job_unauthorized(self, db_session):
        """Test job update with unauthorized user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)

        # user2 tries to update user1's job
        update_data = {"name": "Unauthorized Update"}

        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.update_job(job.id, user2.id, update_data)

    def test_delete_job_success(self, db_session):
        """Test successful job deletion with security validation."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        mock_scheduler = Mock()
        mock_scheduler.add_job.return_value = True
        mock_scheduler.remove_job.return_value = True

        job_service = JobService(db_session, mock_scheduler)

        # Create job
        job = job_service.create_job(user.id, job_data)
        job_id = job.id

        # Delete job
        result = job_service.delete_job(job_id, user.id)

        # Verify deletion
        assert result is True

        # Verify job is removed from database
        deleted_job = db_session.query(JobModel).filter(JobModel.id == job_id).first()
        assert deleted_job is None

        # Verify scheduler was called
        mock_scheduler.remove_job.assert_called_with(job_id)

    def test_delete_job_unauthorized(self, db_session):
        """Test job deletion with unauthorized user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)

        # user2 tries to delete user1's job
        with pytest.raises(
            AuthorizationError, match="Job not found or not owned by user"
        ):
            job_service.delete_job(job.id, user2.id)

    def test_get_user_jobs(self, db_session):
        """Test getting all jobs for a user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker1 = create_test_tracker(db_session, user1, "Tracker 1")
        tracker2 = create_test_tracker(db_session, user2, "Tracker 2")

        job_service = JobService(db_session)

        # Create jobs for both users
        job1_data = create_test_job_data(tracker1.id)
        job1_data["name"] = "User 1 Job"
        job1 = job_service.create_job(user1.id, job1_data)

        job2_data = create_test_job_data(tracker2.id)
        job2_data["name"] = "User 2 Job"
        job2 = job_service.create_job(user2.id, job2_data)

        # Get jobs for user1
        user1_jobs = job_service.get_user_jobs(user1.id)
        assert len(user1_jobs) == 1
        assert user1_jobs[0].id == job1.id
        assert user1_jobs[0].name == "User 1 Job"

        # Get jobs for user2
        user2_jobs = job_service.get_user_jobs(user2.id)
        assert len(user2_jobs) == 1
        assert user2_jobs[0].id == job2.id
        assert user2_jobs[0].name == "User 2 Job"

    def test_get_job_with_authorization(self, db_session):
        """Test getting specific job with ownership verification."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)

        # user1 can get their own job
        retrieved_job = job_service.get_job(job.id, user1.id)
        assert retrieved_job is not None
        assert retrieved_job.id == job.id

        # user2 cannot get user1's job
        with pytest.raises(AuthorizationError):
            job_service.get_job(job.id, user2.id)

    def test_test_job_execution(self, db_session):
        """Test job test execution with security validation."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        # Mock scheduler
        mock_scheduler = Mock()
        mock_scheduler.add_job.return_value = True
        mock_scheduler.execute_job_now.return_value = JobExecutionResult(
            success=True,
            value=150.25,
            execution_time=2.5,
        )

        job_service = JobService(db_session, mock_scheduler)
        job = job_service.create_job(user.id, job_data)

        # Test job execution
        result = job_service.test_job(job.id, user.id)

        # Verify result
        assert result.success is True
        assert result.value == 150.25
        assert result.execution_time == 2.5

        # Verify scheduler was called
        mock_scheduler.execute_job_now.assert_called_once_with(job.id)

    def test_test_job_unauthorized(self, db_session):
        """Test job test execution with unauthorized user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)

        # user2 tries to test user1's job
        with pytest.raises(AuthorizationError):
            job_service.test_job(job.id, user2.id)

    def test_test_job_no_scheduler(self, db_session):
        """Test job test execution when scheduler is not available."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)  # No scheduler
        job = job_service.create_job(user.id, job_data)

        # Test job execution without scheduler
        result = job_service.test_job(job.id, user.id)

        # Should return failure result
        assert result.success is False
        assert "Job scheduler not available" in result.error_message

    def test_get_decrypted_job_config(self, db_session):
        """Test getting decrypted job configuration with security logging."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)

        # Get decrypted config
        decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)

        # Verify decryption
        assert decrypted_config is not None
        assert decrypted_config["symbol"] == "AAPL"
        assert decrypted_config["provider"] == "alpha_vantage"
        assert decrypted_config["api_key"] == "test_api_key_123"  # Should be decrypted

    def test_get_decrypted_job_config_unauthorized(self, db_session):
        """Test getting decrypted config with unauthorized user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)

        # user2 tries to get user1's job config
        with pytest.raises(AuthorizationError):
            job_service.get_decrypted_job_config(job.id, user2.id)

    def test_get_job_statistics(self, db_session):
        """Test getting job statistics for a user."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)

        job_service = JobService(db_session)

        # Create multiple jobs
        for i in range(3):
            job_data = create_test_job_data(tracker.id)
            job_data["name"] = f"Job {i + 1}"
            job_data["is_active"] = i < 2  # First 2 active, last one inactive
            job_service.create_job(user.id, job_data)

        # Get statistics
        stats = job_service.get_job_statistics(user.id)

        # Verify statistics
        assert stats["total_jobs"] == 3
        assert stats["active_jobs"] == 2
        assert stats["inactive_jobs"] == 1
        assert stats["job_types"]["stock"] == 3
        assert "today_executions" in stats
        assert "today_success_rate" in stats

    def test_environment_variable_resolution(self, db_session):
        """Test that environment variables are resolved in job configuration."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)

        # Job data with environment variable reference
        job_data = create_test_job_data(tracker.id)
        job_data["config"]["api_key"] = "${ALPHA_VANTAGE_API_KEY}"

        job_service = JobService(db_session)

        # Mock environment variable
        with patch.dict("os.environ", {"ALPHA_VANTAGE_API_KEY": "env_api_key_123"}):
            job = job_service.create_job(user.id, job_data)

            # Get decrypted config to verify resolution
            decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
            assert decrypted_config["api_key"] == "env_api_key_123"

    def test_generic_job_creation(self, db_session):
        """Test creating a generic HTTP job."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id, job_type="generic")

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)

        # Verify job creation
        assert job.job_type == "generic"
        assert job.name == "Test Job"

        # Verify configuration is encrypted
        decrypted_config = job_service.get_decrypted_job_config(job.id, user.id)
        assert decrypted_config["url"] == "https://api.example.com/data"
        assert decrypted_config["method"] == "GET"
        assert decrypted_config["headers"]["Authorization"] == "Bearer test_token"

    def test_invalid_generic_job_config(self, db_session):
        """Test creating generic job with invalid configuration."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id, job_type="generic")

        # Invalid URL (not HTTPS)
        job_data["config"]["url"] = "http://insecure.example.com/data"

        job_service = JobService(db_session)

        with pytest.raises(ValidationError) as exc_info:
            job_service.create_job(user.id, job_data)

        assert "Only HTTPS URLs are allowed" in str(exc_info.value.errors)

    @patch("trackers.services.job_service.logger")
    def test_security_logging(self, mock_logger, db_session):
        """Test that security events are properly logged."""
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)

        # Create job (should log creation)
        job = job_service.create_job(user.id, job_data)

        # Verify logging occurred
        mock_logger.info.assert_called()

        # Test unauthorized access logging
        user2 = create_test_user(db_session, email="user2@example.com")

        with pytest.raises(AuthorizationError):
            job_service.get_job(job.id, user2.id)

        # Security logger should have been called for unauthorized access
        # (This would be verified by checking the security logger mock)

    def test_job_execution_history_access(self, db_session):
        """Test getting job execution history with proper authorization."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)

        # user1 can get execution history
        history = job_service.get_job_execution_history(job.id, user1.id)
        assert isinstance(history, list)

        # user2 cannot get user1's job execution history
        with pytest.raises(AuthorizationError):
            job_service.get_job_execution_history(job.id, user2.id)

    def test_get_job_execution_statistics(self, db_session):
        """Test getting detailed execution statistics for a job."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create some execution logs
        now = datetime.now(timezone.utc)
        logs = [
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=1),
                success=True,
                duration_seconds=30,
                value_extracted="100.50",
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=2),
                success=False,
                duration_seconds=15,
                error_message="API error",
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=3),
                success=True,
                duration_seconds=25,
                value_extracted="99.75",
            ),
        ]
        for log in logs:
            db_session.add(log)
        db_session.commit()

        # Test
        statistics = job_service.get_job_execution_statistics(job.id, user.id)

        # Verify
        assert statistics["job_id"] == job.id
        assert statistics["job_name"] == job.name
        assert "thirty_day_statistics" in statistics
        assert statistics["thirty_day_statistics"]["total_executions"] == 3
        assert statistics["thirty_day_statistics"]["successful_executions"] == 2
        assert statistics["thirty_day_statistics"]["success_rate_percent"] == 66.67
        assert "last_execution" in statistics
        assert "last_successful_execution" in statistics

    def test_get_job_execution_statistics_unauthorized(self, db_session):
        """Test getting execution statistics with unauthorized user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)
        db_session.commit()

        # Test unauthorized access
        with pytest.raises(AuthorizationError):
            job_service.get_job_execution_statistics(job.id, user2.id)

    def test_get_problematic_jobs(self, db_session):
        """Test getting jobs marked as problematic due to repeated failures."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)

        # Create jobs with different failure counts
        job_data1 = create_test_job_data(tracker.id)
        job_data1["name"] = "Healthy Job"
        job_data2 = create_test_job_data(tracker.id)
        job_data2["name"] = "Problematic Job"

        job_service = JobService(db_session)
        healthy_job = job_service.create_job(user.id, job_data1)
        problematic_job = job_service.create_job(user.id, job_data2)

        # Set failure counts
        healthy_job.failure_count = 2
        problematic_job.failure_count = 6  # Above threshold
        db_session.commit()

        # Test
        problematic_jobs = job_service.get_problematic_jobs(
            user.id, failure_threshold=5
        )

        # Verify
        assert len(problematic_jobs) == 1
        assert problematic_jobs[0].id == problematic_job.id
        assert problematic_jobs[0].name == "Problematic Job"
        assert problematic_jobs[0].failure_count == 6

    def test_reset_job_failure_count(self, db_session):
        """Test resetting job failure count."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)

        # Set failure count and error
        job.failure_count = 5
        job.last_error = "Some error"
        db_session.commit()

        # Test
        success = job_service.reset_job_failure_count(job.id, user.id)
        db_session.commit()

        # Verify
        assert success is True
        db_session.refresh(job)
        assert job.failure_count == 0
        assert job.last_error is None

    def test_reset_job_failure_count_unauthorized(self, db_session):
        """Test resetting failure count with unauthorized user."""
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker = create_test_tracker(db_session, user1)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user1.id, job_data)
        db_session.commit()

        # Test unauthorized access
        with pytest.raises(AuthorizationError):
            job_service.reset_job_failure_count(job.id, user2.id)

    def test_cleanup_old_execution_logs(self, db_session):
        """Test cleanup of old execution logs."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create logs with different ages
        now = datetime.now(timezone.utc)
        old_log = JobExecutionLogModel(
            job_id=job.id,
            executed_at=now - timedelta(days=35),  # Older than 30 days
            success=True,
            duration_seconds=30,
        )
        recent_log = JobExecutionLogModel(
            job_id=job.id,
            executed_at=now - timedelta(days=5),  # Within 30 days
            success=True,
            duration_seconds=25,
        )
        db_session.add(old_log)
        db_session.add(recent_log)
        db_session.commit()

        # Test cleanup
        deleted_count = job_service.cleanup_old_execution_logs(days_to_keep=30)
        db_session.commit()

        # Verify
        assert deleted_count == 1
        remaining_logs = (
            db_session.query(JobExecutionLogModel)
            .filter(JobExecutionLogModel.job_id == job.id)
            .all()
        )
        assert len(remaining_logs) == 1
        assert remaining_logs[0].id == recent_log.id

    def test_get_job_execution_history_thirty_day_limit(self, db_session):
        """Test that execution history is limited to last 30 days."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create logs with different ages
        now = datetime.now(timezone.utc)
        old_log = JobExecutionLogModel(
            job_id=job.id,
            executed_at=now - timedelta(days=35),  # Older than 30 days
            success=True,
            duration_seconds=30,
        )
        recent_log = JobExecutionLogModel(
            job_id=job.id,
            executed_at=now - timedelta(days=5),  # Within 30 days
            success=True,
            duration_seconds=25,
        )
        db_session.add(old_log)
        db_session.add(recent_log)
        db_session.commit()

        # Test
        history = job_service.get_job_execution_history(job.id, user.id)

        # Verify - should only return logs from last 30 days
        assert len(history) == 1
        assert history[0].id == recent_log.id

    def test_enhanced_job_statistics(self, db_session):
        """Test enhanced job statistics with monthly data."""
        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create execution logs for statistics
        now = datetime.now(timezone.utc)
        logs = [
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=1),
                success=True,
                duration_seconds=30,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=2),
                success=False,
                duration_seconds=15,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=10),
                success=True,
                duration_seconds=25,
            ),
        ]
        for log in logs:
            db_session.add(log)
        db_session.commit()

        # Test
        statistics = job_service.get_job_statistics(user.id)

        # Verify enhanced statistics
        assert "monthly_executions" in statistics
        assert "monthly_successful" in statistics
        assert "monthly_success_rate" in statistics
        assert "average_execution_time_seconds" in statistics
        assert statistics["monthly_executions"] == 3
        assert statistics["monthly_successful"] == 2
        assert statistics["monthly_success_rate"] == pytest.approx(66.67, rel=1e-2)


class TestJobMonitoringService:
    """Test cases for JobMonitoringService class."""

    def test_get_system_job_statistics(self, db_session):
        """Test getting system-wide job statistics."""
        from trackers.services.job_monitoring import JobMonitoringService

        # Setup
        user1 = create_test_user(db_session, email="user1@example.com")
        user2 = create_test_user(db_session, email="user2@example.com")
        tracker1 = create_test_tracker(db_session, user1)
        tracker2 = create_test_tracker(db_session, user2)

        job_service = JobService(db_session)

        # Create jobs for different users
        job_data1 = create_test_job_data(tracker1.id, "stock")
        job_data2 = create_test_job_data(tracker2.id, "generic")

        job1 = job_service.create_job(user1.id, job_data1)
        job2 = job_service.create_job(user2.id, job_data2)

        # Set one job as problematic
        job1.failure_count = 6
        db_session.commit()

        # Test
        monitoring_service = JobMonitoringService(db_session)
        statistics = monitoring_service.get_system_job_statistics()

        # Verify
        assert statistics["total_jobs"] == 2
        assert statistics["active_jobs"] == 2
        assert statistics["problematic_jobs"] == 1
        assert "stock" in statistics["job_types"]
        assert "generic" in statistics["job_types"]
        assert statistics["job_types"]["stock"] == 1
        assert statistics["job_types"]["generic"] == 1

    def test_get_job_health_report(self, db_session):
        """Test getting job health report."""
        from trackers.services.job_monitoring import JobMonitoringService

        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)

        job_service = JobService(db_session)

        # Create jobs with different health statuses
        healthy_job_data = create_test_job_data(tracker.id)
        healthy_job_data["name"] = "Healthy Job"

        problematic_job_data = create_test_job_data(tracker.id)
        problematic_job_data["name"] = "Problematic Job"

        disabled_job_data = create_test_job_data(tracker.id)
        disabled_job_data["name"] = "Disabled Job"
        disabled_job_data["is_active"] = False

        healthy_job = job_service.create_job(user.id, healthy_job_data)
        problematic_job = job_service.create_job(user.id, problematic_job_data)
        disabled_job = job_service.create_job(user.id, disabled_job_data)

        # Set failure counts and run times
        healthy_job.failure_count = 0
        healthy_job.last_success_at = datetime.now(timezone.utc)
        healthy_job.last_run_at = datetime.now(
            timezone.utc
        )  # Make it appear as if it has run
        problematic_job.failure_count = 6
        db_session.commit()

        # Test
        monitoring_service = JobMonitoringService(db_session)
        health_report = monitoring_service.get_job_health_report(user.id)

        # Verify
        assert health_report["total_jobs"] == 3
        assert health_report["healthy_jobs"]["count"] == 1
        assert health_report["problematic_jobs"]["count"] == 1
        assert health_report["disabled_jobs"]["count"] == 1
        assert health_report["health_summary"]["needs_attention"] == 1

    def test_identify_jobs_needing_attention(self, db_session):
        """Test identifying jobs that need attention."""
        from trackers.services.job_monitoring import JobMonitoringService

        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)

        job_service = JobService(db_session)

        # Create jobs with different issues
        problematic_job_data = create_test_job_data(tracker.id)
        problematic_job_data["name"] = "Problematic Job"

        never_run_job_data = create_test_job_data(tracker.id)
        never_run_job_data["name"] = "Never Run Job"

        problematic_job = job_service.create_job(user.id, problematic_job_data)
        never_run_job = job_service.create_job(user.id, never_run_job_data)

        # Set up issues
        problematic_job.failure_count = 6
        problematic_job.last_run_at = datetime.now(timezone.utc) - timedelta(days=1)

        # Make never_run_job appear old
        never_run_job.created_at = datetime.now(timezone.utc) - timedelta(days=3)
        never_run_job.last_run_at = None

        db_session.commit()

        # Test
        monitoring_service = JobMonitoringService(db_session)
        jobs_needing_attention = monitoring_service.identify_jobs_needing_attention(
            user.id
        )

        # Verify
        assert len(jobs_needing_attention) == 2

        # Find jobs by name
        problematic = next(
            j for j in jobs_needing_attention if j["name"] == "Problematic Job"
        )
        never_run = next(
            j for j in jobs_needing_attention if j["name"] == "Never Run Job"
        )

        assert problematic["priority"] == "high"
        assert "6 consecutive failures" in problematic["reasons"][0]

        assert never_run["priority"] == "medium"
        assert "Has never run" in never_run["reasons"][0]

    def test_cleanup_old_execution_logs_monitoring_service(self, db_session):
        """Test cleanup functionality in monitoring service."""
        from trackers.services.job_monitoring import JobMonitoringService

        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create logs with different ages
        now = datetime.now(timezone.utc)
        old_logs = [
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=35),
                success=True,
                duration_seconds=30,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=40),
                success=False,
                duration_seconds=15,
            ),
        ]
        recent_log = JobExecutionLogModel(
            job_id=job.id,
            executed_at=now - timedelta(days=5),
            success=True,
            duration_seconds=25,
        )

        for log in old_logs:
            db_session.add(log)
        db_session.add(recent_log)
        db_session.commit()

        # Test
        monitoring_service = JobMonitoringService(db_session)
        result = monitoring_service.cleanup_old_execution_logs(days_to_keep=30)
        db_session.commit()

        # Verify
        assert result["deleted_count"] == 2
        assert "Successfully deleted 2 execution logs" in result["message"]

        remaining_logs = (
            db_session.query(JobExecutionLogModel)
            .filter(JobExecutionLogModel.job_id == job.id)
            .all()
        )
        assert len(remaining_logs) == 1
        assert remaining_logs[0].id == recent_log.id

    def test_get_execution_trends(self, db_session):
        """Test getting execution trends over time."""
        from trackers.services.job_monitoring import JobMonitoringService

        # Setup
        user = create_test_user(db_session)
        tracker = create_test_tracker(db_session, user)
        job_data = create_test_job_data(tracker.id)

        job_service = JobService(db_session)
        job = job_service.create_job(user.id, job_data)
        db_session.commit()

        # Create logs over several days
        now = datetime.now(timezone.utc)
        logs = [
            # Day 1: 2 successful, 1 failed
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=1),
                success=True,
                duration_seconds=30,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=1),
                success=True,
                duration_seconds=25,
            ),
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=1),
                success=False,
                duration_seconds=15,
            ),
            # Day 2: 1 successful
            JobExecutionLogModel(
                job_id=job.id,
                executed_at=now - timedelta(days=2),
                success=True,
                duration_seconds=20,
            ),
        ]

        for log in logs:
            db_session.add(log)
        db_session.commit()

        # Test
        monitoring_service = JobMonitoringService(db_session)
        trends = monitoring_service.get_execution_trends(days=3, user_id=user.id)

        # Verify
        assert trends["period_days"] == 3
        assert len(trends["daily_statistics"]) == 3
        assert trends["period_summary"]["total_executions"] == 4
        assert trends["period_summary"]["successful_executions"] == 3
        assert trends["period_summary"]["overall_success_rate_percent"] == 75.0
