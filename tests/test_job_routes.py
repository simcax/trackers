"""
Tests for Job Management API Routes.

This module tests the job management endpoints for CRUD operations,
authentication, authorization, and error handling.

Requirements: 1.1, 1.2, 1.3, 1.4, 5.3, 7.1
"""

import json
from unittest.mock import Mock, patch

import pytest

from trackers.models.tracker_model import TrackerModel
from trackers.models.user_model import UserModel


@pytest.fixture
def auth_headers():
    """Create authentication headers for API requests."""
    return {"Authorization": "Bearer test-api-key", "Content-Type": "application/json"}


def create_test_user(db_session, email=None, name="Test User"):
    """Create a test user."""
    import uuid

    # Generate unique email if not provided
    if email is None:
        email = f"test_{uuid.uuid4().hex[:8]}@example.com"

    user = UserModel(
        email=email, name=name, google_user_id=f"google_{email}", is_active=True
    )
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    return user


def create_test_tracker(db_session, user, name="Test Tracker"):
    """Create a test tracker."""
    tracker = TrackerModel(
        name=name, description="Test tracker description", user_id=user.id
    )
    db_session.add(tracker)
    db_session.flush()
    db_session.refresh(tracker)
    return tracker


def create_test_job_data(tracker_id, job_type="stock"):
    """Create test job data."""
    if job_type == "stock":
        return {
            "name": "Test Stock Job",
            "job_type": "stock",
            "tracker_id": tracker_id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test-api-key",
            },
            "cron_schedule": "0 9 * * *",
            "is_active": True,
        }
    else:  # generic
        return {
            "name": "Test Generic Job",
            "job_type": "generic",
            "tracker_id": tracker_id,
            "config": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "json_path": "$.value",
            },
            "cron_schedule": "0 */6 * * *",
            "is_active": True,
        }


class TestJobRoutes:
    """Test cases for job management API routes."""

    def test_list_jobs_unauthenticated(self, client):
        """Test listing jobs without authentication."""
        response = client.get("/api/jobs")
        assert response.status_code == 401

        data = json.loads(response.data)
        assert data["error"] == "Authentication required"

    def test_create_job_unauthenticated(self, client):
        """Test creating job without authentication."""
        job_data = {
            "name": "Test Job",
            "job_type": "stock",
            "tracker_id": 1,
            "config": {"symbol": "AAPL"},
            "cron_schedule": "0 9 * * *",
        }

        response = client.post(
            "/api/jobs", json=job_data, content_type="application/json"
        )
        assert response.status_code == 401

        data = json.loads(response.data)
        assert data["error"] == "Authentication required"

    @patch("trackers.routes.job_routes._get_job_service")
    def test_list_jobs_authenticated(self, mock_get_service, client, auth_headers):
        """Test listing jobs with authentication."""
        # Mock job service
        mock_service = Mock()
        mock_service.get_user_jobs.return_value = []
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "jobs" in data
        assert "total" in data
        assert data["total"] == 0

    @patch("trackers.routes.job_routes._get_job_service")
    def test_create_job_authenticated(self, mock_get_service, client, auth_headers):
        """Test creating job with authentication."""
        # Mock job service
        mock_service = Mock()
        mock_job = Mock()
        mock_job.id = 1
        mock_job.name = "Test Job"
        mock_job.job_type = "stock"
        mock_job.tracker_id = 1
        mock_job.cron_schedule = "0 9 * * *"
        mock_job.is_active = True
        mock_job.created_at = None
        mock_job.updated_at = None
        mock_job.last_run_at = None
        mock_job.last_success_at = None
        mock_job.failure_count = 0
        mock_job.last_error = None

        mock_service.create_job.return_value = mock_job
        mock_service.db.commit = Mock()
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        job_data = {
            "name": "Test Job",
            "job_type": "stock",
            "tracker_id": 1,
            "config": {"symbol": "AAPL"},
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201

        data = json.loads(response.data)
        assert data["message"] == "Job created successfully"
        assert "job" in data
        assert data["job"]["name"] == "Test Job"

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_get_job_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test getting specific job with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_job = Mock()
        mock_job.id = 1
        mock_job.name = "Test Job"
        mock_job.job_type = "stock"
        mock_job.tracker_id = 1
        mock_job.cron_schedule = "0 9 * * *"
        mock_job.is_active = True
        mock_job.created_at = None
        mock_job.updated_at = None
        mock_job.last_run_at = None
        mock_job.last_success_at = None
        mock_job.failure_count = 0
        mock_job.last_error = None

        mock_service.get_job.return_value = mock_job
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs/1", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert "job" in data
        assert data["job"]["id"] == 1
        assert data["job"]["name"] == "Test Job"

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_get_job_not_found(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test getting non-existent job."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_service.get_job.return_value = None
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs/999", headers=auth_headers)
        assert response.status_code == 404

        data = json.loads(response.data)
        assert data["error"] == "Not Found"

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_update_job_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test updating job with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_job = Mock()
        mock_job.id = 1
        mock_job.name = "Updated Job"
        mock_job.job_type = "stock"
        mock_job.tracker_id = 1
        mock_job.cron_schedule = "0 10 * * *"
        mock_job.is_active = False
        mock_job.created_at = None
        mock_job.updated_at = None
        mock_job.last_run_at = None
        mock_job.last_success_at = None
        mock_job.failure_count = 0
        mock_job.last_error = None

        mock_service.update_job.return_value = mock_job
        mock_service.db.commit = Mock()
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        update_data = {
            "name": "Updated Job",
            "cron_schedule": "0 10 * * *",
            "is_active": False,
        }

        response = client.put("/api/jobs/1", json=update_data, headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["message"] == "Job updated successfully"
        assert data["job"]["name"] == "Updated Job"
        assert data["job"]["is_active"] == False

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_delete_job_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test deleting job with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_service.delete_job.return_value = True
        mock_service.db.commit = Mock()
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.delete("/api/jobs/1", headers=auth_headers)
        assert response.status_code == 204

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_test_job_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test executing job test with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service and execution result
        from datetime import datetime, timezone

        from trackers.services.job_scheduler import JobExecutionResult

        mock_result = JobExecutionResult(
            success=True,
            value=150.25,
            error_message=None,
            execution_time=1.5,
            timestamp=datetime.now(timezone.utc),
            http_status=200,
            response_size=1024,
        )

        mock_service = Mock()
        mock_service.test_job.return_value = mock_result
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.post("/api/jobs/1/test", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["success"] == True
        assert data["message"] == "Job test completed"
        assert "result" in data
        assert data["result"]["success"] == True
        assert data["result"]["value"] == 150.25

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_get_job_status_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test getting job status with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_job = Mock()
        mock_job.id = 1
        mock_job.name = "Test Job"
        mock_job.is_active = True
        mock_job.last_run_at = None
        mock_job.last_success_at = None
        mock_job.failure_count = 0
        mock_job.last_error = None

        mock_service.get_job.return_value = mock_job
        mock_service.get_job_execution_history.return_value = []
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs/1/status", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["job_id"] == 1
        assert data["name"] == "Test Job"
        assert data["status"] == "active"
        assert data["is_active"] == True

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_get_job_history_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test getting job execution history with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_service.get_job_execution_history.return_value = []
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs/1/history", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["job_id"] == 1
        assert "execution_history" in data
        assert "summary" in data
        assert data["summary"]["total_executions"] == 0

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_get_job_statistics_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test getting job statistics with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_service.get_job_statistics.return_value = {
            "total_jobs": 5,
            "active_jobs": 3,
            "inactive_jobs": 2,
            "job_types": {"stock": 3, "generic": 2},
            "problematic_jobs": 0,
            "today_executions": 10,
            "today_successful": 8,
            "today_success_rate": 80.0,
        }
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs/statistics", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["user_id"] == 1
        assert "statistics" in data
        assert data["statistics"]["total_jobs"] == 5
        assert data["statistics"]["active_jobs"] == 3

    def test_create_job_missing_fields(self, client, auth_headers):
        """Test creating job with missing required fields."""
        job_data = {
            "name": "Test Job"
            # Missing required fields
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 400

        data = json.loads(response.data)
        assert data["error"] == "Bad Request"
        assert "Missing required fields" in data["message"]

    def test_create_job_no_body(self, client, auth_headers):
        """Test creating job without request body."""
        response = client.post("/api/jobs", headers=auth_headers)
        assert response.status_code == 400

        data = json.loads(response.data)
        assert data["error"] == "Bad Request"
        assert data["message"] == "Request body is required"

    def test_update_job_no_body(self, client, auth_headers):
        """Test updating job without request body."""
        response = client.put("/api/jobs/1", headers=auth_headers)
        assert response.status_code == 400

        data = json.loads(response.data)
        assert data["error"] == "Bad Request"
        assert data["message"] == "Request body is required"

    def test_update_job_no_fields(self, client, auth_headers):
        """Test updating job with no updatable fields."""
        update_data = {"invalid_field": "value"}

        response = client.put("/api/jobs/1", json=update_data, headers=auth_headers)
        assert response.status_code == 400

        data = json.loads(response.data)
        assert data["error"] == "Bad Request"
        assert "At least one field must be provided" in data["message"]

    @patch("trackers.routes.job_routes._get_current_user_id")
    @patch("trackers.routes.job_routes._get_job_service")
    def test_get_job_config_authenticated(
        self, mock_get_service, mock_get_user_id, client, auth_headers
    ):
        """Test getting job configuration with authentication."""
        # Mock user ID
        mock_get_user_id.return_value = 1

        # Mock job service
        mock_service = Mock()
        mock_job = Mock()
        mock_job.id = 1
        mock_job.job_type = "stock"

        mock_service.get_job.return_value = mock_job
        mock_service.get_decrypted_job_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "secret-key-12345",
        }
        mock_service.db.close = Mock()
        mock_get_service.return_value = mock_service

        response = client.get("/api/jobs/1/config", headers=auth_headers)
        assert response.status_code == 200

        data = json.loads(response.data)
        assert data["job_id"] == 1
        assert data["job_type"] == "stock"
        assert "config" in data
        # Check that sensitive field is masked
        assert data["config"]["api_key"] == "secr*************"
        assert data["config"]["symbol"] == "AAPL"  # Non-sensitive field not masked

    def test_job_routes_error_handlers(self, client):
        """Test job routes error handlers."""
        # Test 404 handler
        response = client.get("/api/jobs/nonexistent")
        assert response.status_code == 404

        data = json.loads(response.data)
        assert data["error"] == "Not Found"
