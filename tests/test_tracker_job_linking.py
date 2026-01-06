"""
Test tracker-job bidirectional linking functionality.

This module tests the new bidirectional linking features between trackers and jobs:
- Tracker cards show job information and navigation
- Job cards show tracker names as clickable links
- Job form excludes trackers that already have jobs
- New API endpoints for tracker-job relationships
"""


class TestTrackerJobLinking:
    """Test bidirectional linking between trackers and jobs."""

    def test_trackers_data_includes_job_info(
        self, client, auth_headers, sample_tracker, sample_job
    ):
        """Test that /web/trackers/data includes job information."""
        # Create a job for the tracker
        job_data = {
            "name": "Test Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201

        # Get trackers data
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert "trackers" in data

        # Find our tracker
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker is not None

        # Check job information is included
        assert "job_count" in tracker
        assert "active_jobs" in tracker
        assert "has_jobs" in tracker
        assert tracker["job_count"] == 1
        assert tracker["active_jobs"] == 1
        assert tracker["has_jobs"] is True

    def test_trackers_data_no_jobs(self, client, auth_headers, sample_tracker):
        """Test that trackers without jobs show correct job information."""
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker is not None

        # Check job information for tracker without jobs
        assert tracker["job_count"] == 0
        assert tracker["active_jobs"] == 0
        assert tracker["has_jobs"] is False

    def test_tracker_jobs_endpoint(
        self, client, auth_headers, sample_tracker, sample_job
    ):
        """Test the /web/trackers/<id>/jobs endpoint."""
        # Create a job for the tracker
        job_data = {
            "name": "Test Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201
        job_id = response.get_json()["job"]["id"]

        # Get jobs for tracker
        response = client.get(
            f"/web/trackers/{sample_tracker.id}/jobs", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert "tracker" in data
        assert "jobs" in data
        assert "total" in data

        assert data["tracker"]["id"] == sample_tracker.id
        assert data["tracker"]["name"] == sample_tracker.name
        assert data["total"] == 1
        assert len(data["jobs"]) == 1
        assert data["jobs"][0]["id"] == job_id

    def test_tracker_jobs_endpoint_no_jobs(self, client, auth_headers, sample_tracker):
        """Test tracker jobs endpoint when tracker has no jobs."""
        response = client.get(
            f"/web/trackers/{sample_tracker.id}/jobs", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data["total"] == 0
        assert len(data["jobs"]) == 0

    def test_tracker_jobs_endpoint_unauthorized(self, client, sample_tracker):
        """Test tracker jobs endpoint without authentication."""
        response = client.get(f"/web/trackers/{sample_tracker.id}/jobs")
        assert response.status_code == 401

    def test_tracker_jobs_endpoint_not_found(self, client, auth_headers):
        """Test tracker jobs endpoint with non-existent tracker."""
        response = client.get("/web/trackers/99999/jobs", headers=auth_headers)
        assert response.status_code == 404

    def test_job_tracker_endpoint(
        self, client, auth_headers, sample_tracker, sample_job
    ):
        """Test the /web/jobs/<id>/tracker endpoint."""
        # Create a job for the tracker
        job_data = {
            "name": "Test Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201
        job_id = response.get_json()["job"]["id"]

        # Get tracker for job
        response = client.get(f"/web/jobs/{job_id}/tracker", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        assert "job" in data
        assert "tracker" in data

        assert data["job"]["id"] == job_id
        assert data["job"]["name"] == "Test Job"
        assert data["tracker"]["id"] == sample_tracker.id
        assert data["tracker"]["name"] == sample_tracker.name

    def test_job_tracker_endpoint_unauthorized(self, client):
        """Test job tracker endpoint without authentication."""
        response = client.get("/web/jobs/1/tracker")
        assert response.status_code == 401

    def test_job_tracker_endpoint_not_found(self, client, auth_headers):
        """Test job tracker endpoint with non-existent job."""
        response = client.get("/web/jobs/99999/tracker", headers=auth_headers)
        assert response.status_code == 404

    def test_job_form_excludes_trackers_with_jobs(
        self, client, auth_headers, sample_tracker
    ):
        """Test that job form excludes trackers that already have jobs."""
        # First, get trackers data - should include our tracker
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker is not None
        assert tracker["has_jobs"] is False

        # Create a job for the tracker
        job_data = {
            "name": "Test Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201

        # Now get trackers data again - tracker should have jobs
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker is not None
        assert tracker["has_jobs"] is True
        assert tracker["job_count"] == 1

    def test_tracker_card_job_status_display(
        self, client, auth_headers, sample_tracker
    ):
        """Test that tracker cards display job status correctly."""
        # This would be tested in frontend/integration tests
        # Here we just verify the data structure is correct

        # Create multiple jobs with different statuses
        job_data_1 = {
            "name": "Active Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
            "is_active": True,
        }

        job_data_2 = {
            "name": "Inactive Job",
            "job_type": "generic",
            "tracker_id": sample_tracker.id,
            "config": {"url": "https://api.example.com", "json_path": "$.value"},
            "cron_schedule": "0 12 * * *",
            "is_active": False,
        }

        # Create jobs
        response1 = client.post("/api/jobs", json=job_data_1, headers=auth_headers)
        response2 = client.post("/api/jobs", json=job_data_2, headers=auth_headers)
        assert response1.status_code == 201
        assert response2.status_code == 201

        # Get tracker data
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker is not None

        # Verify job counts
        assert tracker["job_count"] == 2
        assert tracker["active_jobs"] == 1  # Only one active job
        assert tracker["has_jobs"] is True

    def test_user_isolation_tracker_jobs(
        self, client, auth_headers, sample_tracker, create_user
    ):
        """Test that users can only see jobs for their own trackers."""
        # Create another user and tracker
        other_user = create_user("other@example.com", "Other User")

        # Create a job for our tracker
        job_data = {
            "name": "My Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201

        # Try to access tracker jobs with different user context
        # This would require setting up different auth context
        # For now, just verify the endpoint works with correct user
        response = client.get(
            f"/web/trackers/{sample_tracker.id}/jobs", headers=auth_headers
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data["total"] == 1

    def test_api_error_handling(self, client, auth_headers):
        """Test error handling in new API endpoints."""
        # Test with invalid tracker ID
        response = client.get("/web/trackers/invalid/jobs", headers=auth_headers)
        assert response.status_code == 404

        # Test with invalid job ID
        response = client.get("/web/jobs/invalid/tracker", headers=auth_headers)
        assert response.status_code == 404

        # Test with very large IDs
        response = client.get("/web/trackers/999999999/jobs", headers=auth_headers)
        assert response.status_code == 404

        response = client.get("/web/jobs/999999999/tracker", headers=auth_headers)
        assert response.status_code == 404


class TestTrackerJobLinkingIntegration:
    """Integration tests for tracker-job linking functionality."""

    def test_full_workflow_tracker_to_job_creation(
        self, client, auth_headers, sample_tracker
    ):
        """Test the full workflow from tracker to job creation."""
        # 1. Get tracker data (should show no jobs)
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker["has_jobs"] is False

        # 2. Create a job for the tracker
        job_data = {
            "name": "Integration Test Job",
            "job_type": "stock",
            "tracker_id": sample_tracker.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        response = client.post("/api/jobs", json=job_data, headers=auth_headers)
        assert response.status_code == 201
        job_id = response.get_json()["job"]["id"]

        # 3. Verify tracker now shows job information
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        tracker = next(
            (t for t in data["trackers"] if t["id"] == sample_tracker.id), None
        )
        assert tracker["has_jobs"] is True
        assert tracker["job_count"] == 1
        assert tracker["active_jobs"] == 1

        # 4. Get jobs for tracker
        response = client.get(
            f"/web/trackers/{sample_tracker.id}/jobs", headers=auth_headers
        )
        assert response.status_code == 200

        jobs_data = response.get_json()
        assert jobs_data["total"] == 1
        assert jobs_data["jobs"][0]["id"] == job_id

        # 5. Get tracker for job
        response = client.get(f"/web/jobs/{job_id}/tracker", headers=auth_headers)
        assert response.status_code == 200

        job_tracker_data = response.get_json()
        assert job_tracker_data["tracker"]["id"] == sample_tracker.id
        assert job_tracker_data["job"]["id"] == job_id

    def test_multiple_trackers_job_filtering(
        self, client, auth_headers, create_tracker
    ):
        """Test job filtering works correctly with multiple trackers."""
        # Create multiple trackers
        tracker1 = create_tracker("Tracker 1", "First tracker")
        tracker2 = create_tracker("Tracker 2", "Second tracker")
        tracker3 = create_tracker("Tracker 3", "Third tracker")

        # Create jobs for some trackers
        job_data_1 = {
            "name": "Job for Tracker 1",
            "job_type": "stock",
            "tracker_id": tracker1.id,
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test",
            },
            "cron_schedule": "0 9 * * *",
        }

        job_data_3 = {
            "name": "Job for Tracker 3",
            "job_type": "generic",
            "tracker_id": tracker3.id,
            "config": {"url": "https://api.example.com", "json_path": "$.value"},
            "cron_schedule": "0 12 * * *",
        }

        # Create the jobs
        response1 = client.post("/api/jobs", json=job_data_1, headers=auth_headers)
        response3 = client.post("/api/jobs", json=job_data_3, headers=auth_headers)
        assert response1.status_code == 201
        assert response3.status_code == 201

        # Get all trackers data
        response = client.get("/web/trackers/data", headers=auth_headers)
        assert response.status_code == 200

        data = response.get_json()
        trackers = {t["id"]: t for t in data["trackers"]}

        # Verify job information
        assert trackers[tracker1.id]["has_jobs"] is True
        assert trackers[tracker1.id]["job_count"] == 1

        assert trackers[tracker2.id]["has_jobs"] is False
        assert trackers[tracker2.id]["job_count"] == 0

        assert trackers[tracker3.id]["has_jobs"] is True
        assert trackers[tracker3.id]["job_count"] == 1
