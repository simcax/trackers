"""
Tests for Job Testing API Endpoints.

This module tests the new job configuration testing and validation
API endpoints added to the job routes.

Requirements: 5.1, 5.4, 10.1, 10.2
"""

import json
from unittest.mock import patch

import pytest

from trackers.routes.job_routes import job_bp


class TestJobTestingEndpoints:
    """Test cases for job testing API endpoints."""

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        app.register_blueprint(job_bp)
        return app.test_client()

    @pytest.fixture
    def auth_headers(self):
        """Create authentication headers for testing."""
        return {"Authorization": "Bearer test-api-key"}

    def test_validate_cron_expression_valid(self, client, auth_headers):
        """Test cron expression validation endpoint with valid expression."""
        data = {"cron_expression": "0 9 * * *"}

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/cron",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "is_valid" in result
        assert "errors" in result
        assert "suggestions" in result

    def test_validate_cron_expression_invalid(self, client, auth_headers):
        """Test cron expression validation endpoint with invalid expression."""
        data = {"cron_expression": "invalid cron"}

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/cron",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "is_valid" in result
        assert not result["is_valid"]
        assert len(result["errors"]) > 0

    def test_validate_cron_expression_missing_data(self, client, auth_headers):
        """Test cron expression validation endpoint with missing data."""
        data = {}  # Missing cron_expression

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/cron",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result
        assert "cron_expression" in result["message"]

    def test_validate_job_config_stock(self, client, auth_headers):
        """Test job configuration validation endpoint for stock jobs."""
        data = {
            "job_type": "stock",
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test_key_12345",
            },
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/config",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "is_valid" in result
        assert "errors" in result
        assert "resolved_config" in result

    def test_validate_job_config_generic(self, client, auth_headers):
        """Test job configuration validation endpoint for generic jobs."""
        data = {
            "job_type": "generic",
            "config": {
                "url": "https://api.example.com/data",
                "method": "GET",
                "json_path": "$.value",
            },
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/config",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "is_valid" in result
        assert "errors" in result

    def test_validate_job_config_invalid(self, client, auth_headers):
        """Test job configuration validation endpoint with invalid config."""
        data = {
            "job_type": "stock",
            "config": {
                "symbol": "",  # Invalid empty symbol
                "provider": "invalid_provider",
            },
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/config",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "is_valid" in result
        assert not result["is_valid"]
        assert len(result["errors"]) > 0

    def test_validate_job_config_missing_data(self, client, auth_headers):
        """Test job configuration validation endpoint with missing data."""
        data = {"job_type": "stock"}  # Missing config

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/config",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result

    def test_test_job_configuration_complete(self, client, auth_headers):
        """Test complete job configuration testing endpoint."""
        data = {
            "job_type": "stock",
            "config": {
                "symbol": "AAPL",
                "provider": "alpha_vantage",
                "api_key": "test_key_12345",
            },
            "cron_schedule": "0 9 * * *",
            "use_mocks": True,
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/test/config",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "overall_valid" in result
        assert "config_validation" in result
        assert "cron_validation" in result
        assert "execution_test" in result
        assert "recommendations" in result

    def test_test_job_configuration_missing_data(self, client, auth_headers):
        """Test job configuration testing endpoint with missing data."""
        data = {
            "job_type": "stock",
            "config": {"symbol": "AAPL"},
            # Missing cron_schedule
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/test/config",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result

    def test_get_job_examples_all(self, client, auth_headers):
        """Test getting all job examples."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get("/api/jobs/examples", headers=auth_headers)

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "stock_examples" in result
        assert "generic_examples" in result
        assert "cron_examples" in result

    def test_get_job_examples_filtered(self, client, auth_headers):
        """Test getting filtered job examples."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get(
                "/api/jobs/examples?job_type=stock", headers=auth_headers
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "stock_examples" in result
        assert "generic_examples" not in result

    def test_get_configuration_template_stock(self, client, auth_headers):
        """Test getting stock configuration template."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get("/api/jobs/templates/stock", headers=auth_headers)

        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["job_type"] == "stock"
        assert "config" in result
        assert "cron_schedule" in result

    def test_get_configuration_template_generic(self, client, auth_headers):
        """Test getting generic configuration template."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get("/api/jobs/templates/generic", headers=auth_headers)

        assert response.status_code == 200
        result = json.loads(response.data)
        assert result["job_type"] == "generic"
        assert "config" in result
        assert "cron_schedule" in result

    def test_get_configuration_template_invalid(self, client, auth_headers):
        """Test getting template for invalid job type."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get("/api/jobs/templates/invalid", headers=auth_headers)

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result

    def test_get_validation_help_stock(self, client, auth_headers):
        """Test getting validation help for stock jobs."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get(
                "/api/jobs/help/validation?job_type=stock", headers=auth_headers
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "stock_help" in result
        assert "cron_help" in result
        assert "validation_info" in result

    def test_get_validation_help_generic(self, client, auth_headers):
        """Test getting validation help for generic jobs."""
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.get(
                "/api/jobs/help/validation?job_type=generic", headers=auth_headers
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "generic_help" in result
        assert "cron_help" in result
        assert "validation_info" in result

    def test_test_api_scenarios(self, client, auth_headers):
        """Test API scenarios testing endpoint."""
        data = {
            "job_type": "stock",
            "config": {"symbol": "AAPL", "provider": "alpha_vantage"},
            "scenarios": ["success", "rate_limit", "timeout"],
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/test/scenarios",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 200
        result = json.loads(response.data)
        assert "job_type" in result
        assert "scenarios_tested" in result
        assert "results" in result
        assert "success" in result["results"]
        assert "rate_limit" in result["results"]
        assert "timeout" in result["results"]

    def test_test_api_scenarios_missing_data(self, client, auth_headers):
        """Test API scenarios testing endpoint with missing data."""
        data = {
            "job_type": "stock",
            "config": {"symbol": "AAPL"},
            # Missing scenarios
        }

        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/test/scenarios",
                data=json.dumps(data),
                content_type="application/json",
                headers=auth_headers,
            )

        assert response.status_code == 400
        result = json.loads(response.data)
        assert "error" in result

    def test_authentication_required(self, client):
        """Test that authentication is required for all endpoints."""
        endpoints = [
            ("/api/jobs/validate/cron", "POST", {"cron_expression": "0 9 * * *"}),
            ("/api/jobs/validate/config", "POST", {"job_type": "stock", "config": {}}),
            (
                "/api/jobs/test/config",
                "POST",
                {"job_type": "stock", "config": {}, "cron_schedule": "0 9 * * *"},
            ),
            ("/api/jobs/examples", "GET", None),
            ("/api/jobs/templates/stock", "GET", None),
            ("/api/jobs/help/validation", "GET", None),
            (
                "/api/jobs/test/scenarios",
                "POST",
                {"job_type": "stock", "config": {}, "scenarios": []},
            ),
        ]

        for endpoint, method, data in endpoints:
            if method == "POST":
                response = client.post(
                    endpoint,
                    data=json.dumps(data) if data else None,
                    content_type="application/json",
                )
            else:
                response = client.get(endpoint)

            # Should require authentication (exact status depends on auth implementation)
            assert response.status_code in [
                401,
                403,
                302,
            ]  # Unauthorized, Forbidden, or Redirect

    def test_error_handling(self, client, auth_headers):
        """Test error handling in endpoints."""
        # Test with malformed JSON
        with patch("trackers.routes.job_routes.require_auth") as mock_auth:
            mock_auth.return_value = lambda f: f  # Bypass auth for testing

            response = client.post(
                "/api/jobs/validate/cron",
                data="invalid json",
                content_type="application/json",
                headers=auth_headers,
            )

        # Should handle JSON parsing error gracefully
        assert response.status_code in [400, 500]
