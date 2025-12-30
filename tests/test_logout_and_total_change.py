"""
Tests for logout button improvements and total change calculation.

This module tests the enhanced logout button display and the new total change
calculation feature that shows the difference between first and most recent entries.
"""

from datetime import datetime, timedelta

from trackers.models.tracker_model import TrackerModel
from trackers.models.tracker_value_model import TrackerValueModel
from trackers.routes.web_routes import TrackerDisplayData, format_tracker_for_display


class TestLogoutAndTotalChange:
    """Test suite for logout button and total change functionality."""

    def test_tracker_display_data_has_total_change_fields(self):
        """Test that TrackerDisplayData includes total change fields."""
        # Create a simple TrackerDisplayData instance
        display_data = TrackerDisplayData(
            id=1,
            name="Test Tracker",
            description="Test description",
            icon="📊",
            color="blue",
            current_value="100",
            change=5.0,
            change_text="+5",
            recent_values=["100", "95", "90"],
            recent_dates=["30-12-2025", "29-12-2025", "28-12-2025"],
            trend_data=[0.5, 0.7, 1.0],
            unit="kg",
            total_change=10.0,
            total_change_text="+10 total",
        )

        # Verify total change fields exist
        assert hasattr(display_data, "total_change")
        assert hasattr(display_data, "total_change_text")
        assert display_data.total_change == 10.0
        assert display_data.total_change_text == "+10 total"

    def test_total_change_calculation_positive(self):
        """Test total change calculation for positive change (increase)."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Weight", description="Unit: kg")

        # Create mock values (most recent first, as returned by database)
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(
                id=1, tracker_id=1, date=base_date, value="75.5"
            ),  # Most recent
            TrackerValueModel(
                id=2, tracker_id=1, date=base_date - timedelta(days=1), value="74.0"
            ),
            TrackerValueModel(
                id=3, tracker_id=1, date=base_date - timedelta(days=2), value="72.5"
            ),  # Oldest
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify total change calculation (75.5 - 72.5 = 3.0)
        assert display_data.total_change == 3.0
        assert "+3" in display_data.total_change_text
        assert "total" in display_data.total_change_text

    def test_total_change_calculation_negative(self):
        """Test total change calculation for negative change (decrease)."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Weight", description="Unit: kg")

        # Create mock values (most recent first, as returned by database)
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(
                id=1, tracker_id=1, date=base_date, value="70.0"
            ),  # Most recent
            TrackerValueModel(
                id=2, tracker_id=1, date=base_date - timedelta(days=1), value="72.0"
            ),
            TrackerValueModel(
                id=3, tracker_id=1, date=base_date - timedelta(days=2), value="75.0"
            ),  # Oldest
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify total change calculation (70.0 - 75.0 = -5.0)
        assert display_data.total_change == -5.0
        assert "-5" in display_data.total_change_text
        assert "total" in display_data.total_change_text

    def test_total_change_calculation_no_change(self):
        """Test total change calculation when there's no change."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Weight", description="Unit: kg")

        # Create mock values (most recent first, as returned by database)
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(
                id=1, tracker_id=1, date=base_date, value="75.0"
            ),  # Most recent
            TrackerValueModel(
                id=2, tracker_id=1, date=base_date - timedelta(days=1), value="75.0"
            ),
            TrackerValueModel(
                id=3, tracker_id=1, date=base_date - timedelta(days=2), value="75.0"
            ),  # Oldest
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify total change calculation (75.0 - 75.0 = 0.0)
        assert display_data.total_change == 0.0
        assert "No change total" in display_data.total_change_text

    def test_total_change_calculation_single_value(self):
        """Test total change calculation with only one value."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Weight", description="Unit: kg")

        # Create mock values with only one entry
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(
                id=1, tracker_id=1, date=base_date, value="75.0"
            ),  # Only value
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify total change shows no data for single value
        assert display_data.total_change == 0.0
        assert display_data.total_change_text == "No data"

    def test_total_change_calculation_no_values(self):
        """Test total change calculation with no values."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Weight", description="Unit: kg")

        # Format for display with no values
        display_data = format_tracker_for_display(tracker, [])

        # Verify total change shows no data
        assert display_data.total_change == 0.0
        assert display_data.total_change_text == "No data"

    def test_total_change_with_danish_formatting(self):
        """Test total change calculation with Danish number formatting."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Steps", description="Unit: steps")

        # Create mock values with large numbers
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(
                id=1, tracker_id=1, date=base_date, value="12500"
            ),  # Most recent
            TrackerValueModel(
                id=2, tracker_id=1, date=base_date - timedelta(days=1), value="11000"
            ),
            TrackerValueModel(
                id=3, tracker_id=1, date=base_date - timedelta(days=2), value="10000"
            ),  # Oldest
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify total change calculation (12500 - 10000 = 2500)
        assert display_data.total_change == 2500.0
        # Should use Danish formatting (2.500)
        assert "2.500" in display_data.total_change_text
        assert "total" in display_data.total_change_text

    def test_total_change_with_invalid_values(self):
        """Test total change calculation with invalid numeric values."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Mood", description="Unit: rating")

        # Create mock values with non-numeric data
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(
                id=1, tracker_id=1, date=base_date, value="good"
            ),  # Most recent
            TrackerValueModel(
                id=2, tracker_id=1, date=base_date - timedelta(days=1), value="okay"
            ),
            TrackerValueModel(
                id=3, tracker_id=1, date=base_date - timedelta(days=2), value="bad"
            ),  # Oldest
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify total change shows no data for non-numeric values
        assert display_data.total_change == 0.0
        assert display_data.total_change_text == "No data"

    def test_format_tracker_for_display_includes_all_fields(self):
        """Test that format_tracker_for_display includes all required fields."""
        # Create mock tracker
        tracker = TrackerModel(id=1, name="Test", description="Unit: test")

        # Create mock values
        base_date = datetime.now().date()
        recent_values = [
            TrackerValueModel(id=1, tracker_id=1, date=base_date, value="100"),
            TrackerValueModel(
                id=2, tracker_id=1, date=base_date - timedelta(days=1), value="90"
            ),
        ]

        # Format for display
        display_data = format_tracker_for_display(tracker, recent_values)

        # Verify all fields are present
        required_fields = [
            "id",
            "name",
            "description",
            "icon",
            "color",
            "current_value",
            "change",
            "change_text",
            "recent_values",
            "recent_dates",
            "trend_data",
            "unit",
            "total_change",
            "total_change_text",
        ]

        for field in required_fields:
            assert hasattr(display_data, field), f"Missing field: {field}"
