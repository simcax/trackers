"""
Tests for JobScheduler service.

This module tests the APScheduler integration and job lifecycle management
functionality of the JobScheduler class.

Requirements: 2.1, 2.2, 2.4
"""

from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from trackers.models.job_model import JobModel
from trackers.services.job_scheduler import JobExecutionResult, JobScheduler


class TestJobScheduler:
    """Test cases for JobScheduler class."""

    def test_job_scheduler_initialization(self):
        """
        Test JobScheduler initialization without Flask app.

        Requirements: 2.1
        """
        scheduler = JobScheduler()

        assert scheduler.app is None
        assert scheduler.scheduler is None
        assert not scheduler.is_running
        assert scheduler._scheduled_jobs == {}

    def test_job_scheduler_init_app(self):
        """
        Test JobScheduler initialization with Flask app.

        Requirements: 2.1
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler()
        scheduler.init_app(app)

        assert scheduler.app is app
        assert scheduler.scheduler is not None
        assert not scheduler.is_running  # Not started yet
        assert app.config.get("SCHEDULER_TIMEZONE") == "UTC"
        assert app.config.get("SCHEDULER_API_ENABLED") is False

    def test_job_scheduler_with_flask_app(self):
        """
        Test JobScheduler initialization with Flask app in constructor.

        Requirements: 2.1
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        assert scheduler.app is app
        assert scheduler.scheduler is not None
        assert not scheduler.is_running

    def test_job_execution_result_creation(self):
        """
        Test JobExecutionResult creation and conversion to dict.

        Requirements: 2.2
        """
        timestamp = datetime.now(timezone.utc)
        result = JobExecutionResult(
            success=True,
            value=123.45,
            error_message=None,
            execution_time=1.5,
            timestamp=timestamp,
            http_status=200,
            response_size=1024,
        )

        assert result.success is True
        assert result.value == 123.45
        assert result.error_message is None
        assert result.execution_time == 1.5
        assert result.timestamp == timestamp
        assert result.http_status == 200
        assert result.response_size == 1024

        result_dict = result.to_dict()
        assert result_dict["success"] is True
        assert result_dict["value"] == 123.45
        assert result_dict["error_message"] is None
        assert result_dict["execution_time"] == 1.5
        assert result_dict["timestamp"] == timestamp.isoformat()
        assert result_dict["http_status"] == 200
        assert result_dict["response_size"] == 1024

    def test_job_execution_result_failure(self):
        """
        Test JobExecutionResult for failed execution.

        Requirements: 2.2
        """
        result = JobExecutionResult(
            success=False,
            error_message="API request failed",
            execution_time=0.5,
        )

        assert result.success is False
        assert result.value is None
        assert result.error_message == "API request failed"
        assert result.execution_time == 0.5
        assert result.timestamp is not None  # Should be set automatically

    @patch("trackers.services.job_scheduler.get_db_session")
    def test_scheduler_start_without_jobs(self, mock_get_db_session):
        """
        Test scheduler start with no active jobs in database.

        Requirements: 2.1, 2.2
        """
        from flask import Flask

        # Mock database session with no jobs
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.all.return_value = []
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Start scheduler
        scheduler.start()

        assert scheduler.is_running is True
        assert len(scheduler._scheduled_jobs) == 0
        assert scheduler.scheduler.running is True

        # Clean up
        scheduler.stop()
        assert scheduler.is_running is False

    @patch("trackers.services.job_scheduler.get_db_session")
    def test_scheduler_start_with_active_jobs(self, mock_get_db_session):
        """
        Test scheduler start with active jobs in database.

        Requirements: 2.1, 2.2
        """
        from flask import Flask

        # Create mock job
        mock_job = Mock(spec=JobModel)
        mock_job.id = 1
        mock_job.name = "Test Job"
        mock_job.job_type = "stock"
        mock_job.cron_schedule = "0 9 * * *"
        mock_job.is_active = True

        # Mock database session with one active job
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_job]
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Start scheduler
        scheduler.start()

        assert scheduler.is_running is True
        assert len(scheduler._scheduled_jobs) == 1
        assert 1 in scheduler._scheduled_jobs

        # Clean up
        scheduler.stop()

    def test_scheduler_stop_gracefully(self):
        """
        Test scheduler stops gracefully.

        Requirements: 2.4
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Start and then stop
        with patch(
            "trackers.services.job_scheduler.get_db_session"
        ) as mock_get_db_session:
            mock_db = Mock()
            mock_db.query.return_value.filter.return_value.all.return_value = []
            mock_get_db_session.return_value.__enter__.return_value = mock_db

            scheduler.start()
            assert scheduler.is_running is True

            scheduler.stop()
            assert scheduler.is_running is False
            assert len(scheduler._scheduled_jobs) == 0

    def test_scheduler_status(self):
        """
        Test scheduler status reporting.

        Requirements: 2.2
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Test status when not running
        status = scheduler.get_scheduler_status()
        assert status["is_running"] is False
        assert status["scheduled_jobs_count"] == 0
        assert status["scheduler_state"] is not None
        assert status["scheduler_running"] is False

    def test_add_job_when_not_running(self):
        """
        Test adding job when scheduler is not running.

        Requirements: 2.2
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Create mock job
        mock_job = Mock(spec=JobModel)
        mock_job.id = 1
        mock_job.is_active = True
        mock_job.cron_schedule = "0 9 * * *"

        # Try to add job when scheduler is not running
        result = scheduler.add_job(mock_job)

        assert result is False

    def test_remove_job_when_not_running(self):
        """
        Test removing job when scheduler is not running.

        Requirements: 2.2
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Try to remove job when scheduler is not running
        result = scheduler.remove_job(1)

        assert result is False

    @patch("trackers.services.job_scheduler.get_db_session")
    def test_execute_job_now_job_not_found(self, mock_get_db_session):
        """
        Test immediate job execution when job is not found.

        Requirements: 2.2
        """
        from flask import Flask

        # Mock database session with no job found
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = None
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Execute non-existent job
        result = scheduler.execute_job_now(999)

        assert result.success is False
        assert "not found" in result.error_message.lower()

    @patch("trackers.services.job_scheduler.get_db_session")
    @patch("trackers.services.job_scheduler.StockJobProvider")
    def test_execute_job_now_inactive_job(
        self, mock_stock_provider, mock_get_db_session
    ):
        """
        Test immediate job execution with inactive job.

        Requirements: 2.2
        """
        from flask import Flask

        # Create mock inactive job
        mock_job = Mock(spec=JobModel)
        mock_job.id = 1
        mock_job.name = "Test Job"
        mock_job.job_type = "stock"
        mock_job.is_active = False

        # Mock database session
        mock_db = Mock()
        mock_db.query.return_value.filter.return_value.first.return_value = mock_job
        mock_get_db_session.return_value.__enter__.return_value = mock_db

        # Mock job provider
        mock_provider_instance = Mock()

        async def mock_execute():
            return JobExecutionResult(success=True, value=42.5, execution_time=0.1)

        mock_provider_instance.execute = mock_execute
        mock_stock_provider.return_value = mock_provider_instance

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Execute inactive job (should work for testing)
        result = scheduler.execute_job_now(1)

        # For test execution, inactive jobs should still execute
        assert result.success is True

    def test_scheduler_not_initialized_error(self):
        """
        Test error when trying to start scheduler without Flask app.

        Requirements: 2.1
        """
        scheduler = JobScheduler()

        with pytest.raises(RuntimeError, match="not initialized"):
            scheduler.start()

    def test_get_scheduled_jobs_when_not_running(self):
        """
        Test getting scheduled jobs when scheduler is not running.

        Requirements: 2.2
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        jobs = scheduler.get_scheduled_jobs()
        assert jobs == []

    def test_scheduler_destructor(self):
        """
        Test scheduler destructor stops scheduler if running.

        Requirements: 2.4
        """
        from flask import Flask

        app = Flask(__name__)
        scheduler = JobScheduler(app)

        # Mock the stop method to verify it's called
        scheduler.stop = Mock()
        scheduler.is_running = True

        # Call destructor
        scheduler.__del__()

        # Verify stop was called
        scheduler.stop.assert_called_once()
