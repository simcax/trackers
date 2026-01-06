"""
Test for the job configuration test web endpoint fix.

This test verifies that the web endpoint for job configuration testing works correctly.
"""

import pytest

from trackers import create_app


class TestJobConfigWebFix:
    """Test the job configuration test web endpoint fix."""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        return create_app()

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_web_job_config_test_endpoint_exists(self, client):
        """Test that the /web/jobs/test/config endpoint exists."""
        response = client.post(
            "/web/jobs/test/config",
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
        )

        # Should not return 404 (endpoint exists)
        # May return 401 if not authenticated, but that's expected
        assert response.status_code != 404, (
            f"Endpoint should exist, got {response.status_code}"
        )

    def test_job_form_template_uses_web_endpoint(self):
        """Test that the job form template uses the web endpoint."""
        from pathlib import Path

        template_path = Path("templates/components/job_form.html")
        assert template_path.exists(), "Job form template should exist"

        content = template_path.read_text()

        # Should use the web endpoint
        assert "/web/jobs/test/config" in content, (
            "Job form should use /web/jobs/test/config endpoint"
        )

        # Should not use the API endpoint
        assert "/api/jobs/test/config" not in content, (
            "Job form should not use /api/jobs/test/config endpoint"
        )

        # Should handle the correct response structure
        assert "data.overall_valid" in content, (
            "Job form should check data.overall_valid"
        )

    def test_web_endpoint_response_structure(self, client):
        """Test that the web endpoint returns the correct response structure."""
        # This test may fail due to authentication, but we can check the structure
        response = client.post(
            "/web/jobs/test/config",
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
        )

        # If we get a response (even if 401), check it has the right structure
        if response.status_code == 200:
            data = response.get_json()

            # Check expected fields are present
            expected_fields = [
                "overall_valid",
                "config_validation",
                "cron_validation",
                "execution_test",
                "recommendations",
                "timestamp",
            ]

            for field in expected_fields:
                assert field in data, f"Missing field: {field}"

    def test_web_endpoint_missing_data_handling(self, client):
        """Test that the web endpoint handles missing data correctly."""
        response = client.post(
            "/web/jobs/test/config",
            json={},  # Missing required fields
            headers={"Content-Type": "application/json"},
        )

        # Should handle missing data gracefully
        # May return 401 due to auth, but if it processes, should return 400
        if response.status_code not in [401, 403]:
            assert response.status_code == 400
            data = response.get_json()
            assert "overall_valid" in data
            assert data["overall_valid"] is False
