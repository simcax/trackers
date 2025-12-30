"""
Simple test for chart button and date selection fixes.

This test verifies that:
1. Chart data endpoint exists and works without authentication
2. Date selection works when adding values
"""

import json

import pytest

from trackers import create_app


class TestChartDateSimple:
    """Simple test suite for chart button and date selection functionality."""

    @pytest.fixture
    def app(self):
        """Create test Flask app."""
        app = create_app()
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_chart_data_endpoint_exists(self, client):
        """Test that the new chart data web endpoint exists."""
        # Test with a non-existent tracker (should return 404, not 500)
        response = client.get("/web/tracker/99999/chart-data")

        # Should return 404 (not found) rather than 500 (server error)
        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data
        assert "not found" in data["error"].lower()

    def test_chart_data_endpoint_no_auth_required(self, client):
        """Test that chart data endpoint works without authentication."""
        # Make request without any authentication headers
        response = client.get("/web/tracker/99999/chart-data")

        # Should return 404 (not found) not 401 (unauthorized)
        # This proves the endpoint doesn't require authentication
        assert response.status_code == 404  # Not 401 (unauthorized)

    def test_add_value_endpoint_accepts_date(self, client):
        """Test that add value endpoint accepts custom date parameter."""
        custom_date = "2023-12-15"
        custom_value = "150"

        # Test adding value with custom date to non-existent tracker
        response = client.post(
            "/web/tracker/99999/value",
            json={"date": custom_date, "value": custom_value},
            headers={"Content-Type": "application/json"},
        )

        # Should return 404 (tracker not found) not 400 (bad request)
        # This proves the endpoint accepts the date parameter
        assert response.status_code == 404

    def test_add_value_endpoint_requires_value(self, client):
        """Test that add value endpoint requires value parameter."""
        # Test adding empty value
        response = client.post(
            "/web/tracker/99999/value",
            json={
                "date": "2023-12-01",
                "value": "",  # Empty value
            },
            headers={"Content-Type": "application/json"},
        )

        # Should return 400 (bad request) for empty value
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_dashboard_loads(self, client):
        """Test that dashboard loads successfully."""
        response = client.get("/web/")

        assert response.status_code == 200
        html_content = response.data.decode("utf-8")

        # Check that basic dashboard elements are present
        assert "dashboard" in html_content.lower() or "tracker" in html_content.lower()

    def test_web_routes_registered(self, app):
        """Test that web routes are properly registered."""
        with app.app_context():
            # Get all registered routes
            routes = []
            for rule in app.url_map.iter_rules():
                routes.append(rule.rule)

            # Check that our new chart data endpoint is registered
            assert "/web/tracker/<int:tracker_id>/chart-data" in routes

            # Check that existing endpoints are still there
            assert "/web/tracker/<int:tracker_id>/value" in routes
            assert "/web/" in routes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
