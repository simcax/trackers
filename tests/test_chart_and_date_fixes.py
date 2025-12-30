"""
Test suite for chart button and date selection fixes.

This test verifies that:
1. Chart button now works by using web endpoints instead of API endpoints
2. Date selection is available when adding values
3. Both features work without authentication requirements

Validates the fixes for:
- Chart button showing toast instead of chart
- Missing date selection when adding values
"""

import json
from datetime import datetime, timedelta

import pytest

from trackers import create_app
from trackers.db import database as db_module
from trackers.db.tracker_values_db import create_or_update_value
from trackers.db.trackerdb import create_tracker


class TestChartAndDateFixes:
    """Test suite for chart button and date selection functionality."""

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

    @pytest.fixture
    def sample_tracker_with_values(self, app):
        """Create a sample tracker with some values for testing."""
        with app.app_context():
            db = db_module.SessionLocal()
            try:
                # Create tracker
                tracker = create_tracker(
                    db, name="Test Chart Tracker", description="For testing charts"
                )
                db.commit()

                # Add some sample values with different dates
                today = datetime.now().date()
                dates_and_values = [
                    (today, "100"),
                    (today - timedelta(days=1), "95"),
                    (today - timedelta(days=2), "90"),
                    (today - timedelta(days=3), "85"),
                    (today - timedelta(days=4), "80"),
                ]

                for date, value in dates_and_values:
                    create_or_update_value(
                        db, tracker.id, date.strftime("%Y-%m-%d"), value
                    )

                db.commit()
                return tracker
            finally:
                db.close()

    def test_chart_data_endpoint_exists(self, client, sample_tracker_with_values):
        """Test that the new chart data web endpoint exists and works."""
        tracker_id = sample_tracker_with_values.id

        # Test the new web endpoint for chart data
        response = client.get(f"/web/tracker/{tracker_id}/chart-data")

        assert response.status_code == 200
        data = json.loads(response.data)

        # Verify response structure
        assert data["success"] is True
        assert "tracker" in data
        assert "values" in data
        assert data["tracker"]["id"] == tracker_id
        assert data["tracker"]["name"] == "Test Chart Tracker"
        assert len(data["values"]) == 5  # Should have 5 values we added

    def test_chart_data_endpoint_no_auth_required(
        self, client, sample_tracker_with_values
    ):
        """Test that chart data endpoint works without authentication."""
        tracker_id = sample_tracker_with_values.id

        # Make request without any authentication headers
        response = client.get(f"/web/tracker/{tracker_id}/chart-data")

        # Should work without authentication (unlike API endpoints)
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["success"] is True

    def test_chart_data_endpoint_nonexistent_tracker(self, client):
        """Test chart data endpoint with non-existent tracker."""
        response = client.get("/web/tracker/99999/chart-data")

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "error" in data
        assert "not found" in data["error"].lower()

    def test_add_value_with_custom_date(self, client, sample_tracker_with_values):
        """Test adding a value with a custom date (not today)."""
        tracker_id = sample_tracker_with_values.id
        custom_date = "2023-12-15"  # Custom date in the past
        custom_value = "150"

        # Test adding value with custom date
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            json={"date": custom_date, "value": custom_value},
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["message"] == "Value added successfully"
        assert data["value"]["date"] == custom_date
        assert data["value"]["value"] == custom_value

    def test_add_value_without_date_defaults_to_today(
        self, client, sample_tracker_with_values
    ):
        """Test that adding value without date defaults to today."""
        tracker_id = sample_tracker_with_values.id
        test_value = "200"
        today = datetime.now().strftime("%Y-%m-%d")

        # Test adding value without specifying date
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            json={
                "value": test_value
                # No date specified
            },
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["message"] == "Value added successfully"
        assert data["value"]["date"] == today
        assert data["value"]["value"] == test_value

    def test_chart_data_values_format(self, client, sample_tracker_with_values):
        """Test that chart data values are properly formatted."""
        tracker_id = sample_tracker_with_values.id

        response = client.get(f"/web/tracker/{tracker_id}/chart-data")

        assert response.status_code == 200
        data = json.loads(response.data)

        # Check that values have the expected format
        values = data["values"]
        assert len(values) > 0

        for value in values:
            assert "date" in value
            assert "value" in value
            assert "created_at" in value

            # Verify date format (should be ISO format)
            try:
                datetime.fromisoformat(value["date"])
            except ValueError:
                pytest.fail(f"Invalid date format: {value['date']}")

    def test_dashboard_loads_with_chart_buttons(
        self, client, sample_tracker_with_values
    ):
        """Test that dashboard loads and contains chart buttons."""
        response = client.get("/web/")

        assert response.status_code == 200
        html_content = response.data.decode("utf-8")

        # Check that chart buttons are present
        assert 'data-action="view-chart"' in html_content
        assert "View Chart" in html_content

    def test_integration_chart_workflow(self, client, sample_tracker_with_values):
        """Test the complete workflow: dashboard -> chart data."""
        tracker_id = sample_tracker_with_values.id

        # 1. Load dashboard
        dashboard_response = client.get("/web/")
        assert dashboard_response.status_code == 200

        # 2. Get chart data (simulating what JavaScript would do)
        chart_response = client.get(f"/web/tracker/{tracker_id}/chart-data")
        assert chart_response.status_code == 200

        chart_data = json.loads(chart_response.data)
        assert chart_data["success"] is True
        assert len(chart_data["values"]) > 0

    def test_integration_add_value_workflow(self, client, sample_tracker_with_values):
        """Test the complete workflow: dashboard -> add value with date."""
        tracker_id = sample_tracker_with_values.id
        custom_date = "2023-11-20"
        custom_value = "175"

        # 1. Load dashboard
        dashboard_response = client.get("/web/")
        assert dashboard_response.status_code == 200

        # 2. Add value with custom date (simulating what JavaScript would do)
        add_response = client.post(
            f"/web/tracker/{tracker_id}/value",
            json={"date": custom_date, "value": custom_value},
            headers={"Content-Type": "application/json"},
        )
        assert add_response.status_code == 201

        # 3. Verify the value was added by checking chart data
        chart_response = client.get(f"/web/tracker/{tracker_id}/chart-data")
        chart_data = json.loads(chart_response.data)

        # Should now have one more value
        assert len(chart_data["values"]) == 6  # Original 5 + 1 new

        # Find our added value
        added_value = next(
            (v for v in chart_data["values"] if v["date"] == custom_date), None
        )
        assert added_value is not None
        assert added_value["value"] == custom_value

    def test_error_handling_chart_data(self, client):
        """Test error handling for chart data endpoint."""
        # Test with invalid tracker ID
        response = client.get("/web/tracker/invalid/chart-data")
        assert response.status_code == 404

    def test_error_handling_add_value(self, client, sample_tracker_with_values):
        """Test error handling for add value endpoint."""
        tracker_id = sample_tracker_with_values.id

        # Test with empty value
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            json={
                "date": "2023-12-01",
                "value": "",  # Empty value
            },
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_date_validation(self, client, sample_tracker_with_values):
        """Test that various date formats work correctly."""
        tracker_id = sample_tracker_with_values.id

        # Test valid date formats
        valid_dates = [
            "2023-12-01",
            "2023-01-15",
            "2024-02-29",  # Leap year
        ]

        for date in valid_dates:
            response = client.post(
                f"/web/tracker/{tracker_id}/value",
                json={"date": date, "value": "100"},
                headers={"Content-Type": "application/json"},
            )
            assert response.status_code == 201, f"Failed for date: {date}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
