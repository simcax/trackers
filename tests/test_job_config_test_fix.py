"""
Test for the job configuration test fix.

This test verifies that the job configuration testing endpoint works correctly
and that the JavaScript handles the response properly.
"""

import pytest

from trackers import create_app


class TestJobConfigTestFix:
    """Test the job configuration test fix."""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        return create_app()

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_job_config_test_endpoint_exists(self, client):
        """Test that the /api/jobs/test/config endpoint exists."""
        # Test with API key authentication
        response = client.post(
            "/api/jobs/test/config",
            json={
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",
                    "provider": "alpha_vantage",
                    "api_key": "test_key",
                },
                "cron_schedule": "0 9 * * *",
                "use_mocks": True,
            },
            headers={"Content-Type": "application/json", "X-API-Key": "dev-key-12345"},
        )

        # Should return 200 with test results, not 404
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_job_config_test_response_structure(self, client):
        """Test that the endpoint returns the correct response structure."""
        response = client.post(
            "/api/jobs/test/config",
            json={
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",
                    "provider": "alpha_vantage",
                    "api_key": "test_key",
                },
                "cron_schedule": "0 9 * * *",
                "use_mocks": True,
            },
            headers={"Content-Type": "application/json", "X-API-Key": "dev-key-12345"},
        )

        assert response.status_code == 200
        data = response.get_json()

        # Check that all expected fields are present
        required_fields = [
            "overall_valid",
            "config_validation",
            "cron_validation",
            "execution_test",
            "recommendations",
            "timestamp",
        ]

        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

        # Check field types
        assert isinstance(data["overall_valid"], bool), (
            "overall_valid should be boolean"
        )
        assert isinstance(data["config_validation"], dict), (
            "config_validation should be dict"
        )
        assert isinstance(data["cron_validation"], dict), (
            "cron_validation should be dict"
        )
        assert isinstance(data["execution_test"], dict), "execution_test should be dict"
        assert isinstance(data["recommendations"], list), (
            "recommendations should be list"
        )
        assert isinstance(data["timestamp"], str), "timestamp should be string"

    def test_job_config_test_with_valid_config(self, client):
        """Test job configuration testing with valid configuration."""
        response = client.post(
            "/api/jobs/test/config",
            json={
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",
                    "provider": "alpha_vantage",
                    "api_key": "test_key",
                },
                "cron_schedule": "0 9 * * *",
                "use_mocks": True,
            },
            headers={"Content-Type": "application/json", "X-API-Key": "dev-key-12345"},
        )

        assert response.status_code == 200
        data = response.get_json()

        # With mocks enabled, the test should generally pass
        assert "overall_valid" in data
        assert "config_validation" in data
        assert "cron_validation" in data

        # Cron validation should pass for valid expression
        assert data["cron_validation"]["is_valid"] is True

    def test_job_config_test_with_invalid_cron(self, client):
        """Test job configuration testing with invalid cron expression."""
        response = client.post(
            "/api/jobs/test/config",
            json={
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",
                    "provider": "alpha_vantage",
                    "api_key": "test_key",
                },
                "cron_schedule": "invalid cron",
                "use_mocks": True,
            },
            headers={"Content-Type": "application/json", "X-API-Key": "dev-key-12345"},
        )

        assert response.status_code == 200
        data = response.get_json()

        # Should fail due to invalid cron
        assert data["overall_valid"] is False
        assert data["cron_validation"]["is_valid"] is False
        assert len(data["cron_validation"]["errors"]) > 0

    def test_job_config_test_missing_data(self, client):
        """Test job configuration testing with missing required data."""
        response = client.post(
            "/api/jobs/test/config",
            json={},  # Missing required fields
            headers={"Content-Type": "application/json", "X-API-Key": "dev-key-12345"},
        )

        # Should return 400 for missing required fields
        assert response.status_code == 400

    def test_job_config_test_authentication_required(self, client):
        """Test that the endpoint requires authentication."""
        response = client.post(
            "/api/jobs/test/config",
            json={
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",
                    "provider": "alpha_vantage",
                    "api_key": "test_key",
                },
                "cron_schedule": "0 9 * * *",
                "use_mocks": True,
            },
            headers={"Content-Type": "application/json"},
            # No API key provided
        )

        # Should require authentication
        assert response.status_code in [401, 403], (
            f"Expected 401 or 403, got {response.status_code}"
        )

    def test_job_form_template_uses_correct_structure(self):
        """Test that the job form template handles the correct response structure."""
        from pathlib import Path

        # Read the job form template
        template_path = Path("templates/components/job_form.html")
        assert template_path.exists(), "Job form template should exist"

        content = template_path.read_text()

        # Should check for overall_valid instead of success
        assert "data.overall_valid" in content, (
            "Job form should check data.overall_valid"
        )

        # Should handle the correct error structure
        assert "data.config_validation" in content, (
            "Job form should handle config_validation errors"
        )
        assert "data.cron_validation" in content, (
            "Job form should handle cron_validation errors"
        )
        assert "data.execution_test" in content, (
            "Job form should handle execution_test errors"
        )

        # Should include API key for authentication
        assert "X-API-Key" in content, (
            "Job form should include API key for authentication"
        )
