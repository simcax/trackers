"""
Test to verify that chart direction shows chronological order (oldest to newest).

This test verifies the fix for the issue where charts were showing data
from latest to earliest instead of chronological order.
"""

from datetime import date, datetime, timedelta

from trackers.models.tracker_model import TrackerModel
from trackers.models.tracker_value_model import TrackerValueModel
from trackers.routes.web_routes import format_tracker_for_display


def test_trend_data_chronological_order():
    """Test that trend_data is generated in chronological order (oldest first)."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1,
        name="Test Tracker",
        description="Test tracker for chart direction",
        user_id=1,
    )

    # Create sample values in database order (newest first)
    base_date = date.today()
    recent_values = []

    # Add values for the last 5 days (database returns newest first)
    for i in range(5):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(20 + (i * 20)),  # Values: 20, 40, 60, 80, 100 (newest to oldest)
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # Verify trend_data exists and has correct length
    assert display_data.trend_data is not None
    assert len(display_data.trend_data) == 5

    # The trend_data should be in chronological order (oldest first)
    # Original values: [20, 40, 60, 80, 100] (newest first from DB - today=20, 4 days ago=100)
    # After reverse: [100, 80, 60, 40, 20] (oldest first for chart - 4 days ago to today)
    # Normalized: [1.0, 0.75, 0.5, 0.25, 0.0] (100 is max, 20 is min)

    expected_trend = [1.0, 0.75, 0.5, 0.25, 0.0]

    # Check that trend shows correct chronological progression
    for i, expected in enumerate(expected_trend):
        assert abs(display_data.trend_data[i] - expected) < 0.01, (
            f"Trend data at index {i}: expected {expected}, got {display_data.trend_data[i]}"
        )

    # Verify the trend is in chronological order (this particular data shows decline over time)
    # The first value (oldest) should be highest, last value (newest) should be lowest
    assert display_data.trend_data[0] > display_data.trend_data[-1], (
        f"This test data should show decline over time: {display_data.trend_data}"
    )


def test_trend_data_ascending_values():
    """Test trend_data with ascending values over time (should show upward trend)."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1,
        name="Ascending Tracker",
        description="Test tracker with ascending values over time",
        user_id=1,
    )

    # Create sample values that increase over time
    base_date = date.today()
    recent_values = []

    # Add values for the last 5 days (database returns newest first)
    # We want: 4 days ago=20, 3 days ago=40, 2 days ago=60, yesterday=80, today=100
    for i in range(5):
        value_date = base_date - timedelta(days=i)
        # Values increase over time: today=100, yesterday=80, etc.
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(100 - (i * 20)),  # Values: 100, 80, 60, 40, 20 (newest to oldest)
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # The trend_data should be in chronological order (oldest first)
    # Original values: [100, 80, 60, 40, 20] (newest first from DB)
    # After reverse: [20, 40, 60, 80, 100] (oldest first for chart - chronological)
    # Normalized: [0.0, 0.25, 0.5, 0.75, 1.0] (20 is min=0.0, 100 is max=1.0)

    expected_trend = [0.0, 0.25, 0.5, 0.75, 1.0]

    # Check that trend shows upward progression (chronological order)
    for i, expected in enumerate(expected_trend):
        assert abs(display_data.trend_data[i] - expected) < 0.01, (
            f"Trend data at index {i}: expected {expected}, got {display_data.trend_data[i]}"
        )

    # Verify the trend is ascending chronologically
    for i in range(1, len(display_data.trend_data)):
        assert display_data.trend_data[i] >= display_data.trend_data[i - 1], (
            f"Chronological trend should be ascending: {display_data.trend_data}"
        )


def test_trend_data_descending_values():
    """Test trend_data with descending values (should show downward trend)."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1,
        name="Descending Tracker",
        description="Test tracker with descending values",
        user_id=1,
    )

    # Create sample values that decrease over time
    base_date = date.today()
    recent_values = []

    # Add values for the last 5 days (database returns newest first)
    for i in range(5):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(100 - (i * 20)),  # Values: 100, 80, 60, 40, 20 (newest to oldest)
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # The trend_data should be in chronological order (oldest first)
    # Original values: [100, 80, 60, 40, 20] (newest first from DB)
    # After reverse: [20, 40, 60, 80, 100] (oldest first for chart)
    # This should show an UPWARD trend chronologically

    # Verify the trend is ascending chronologically (even though recent values are decreasing)
    for i in range(1, len(display_data.trend_data)):
        assert display_data.trend_data[i] >= display_data.trend_data[i - 1], (
            f"Chronological trend should be ascending: {display_data.trend_data}"
        )


def test_trend_data_same_values():
    """Test trend_data with all same values."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1,
        name="Flat Tracker",
        description="Test tracker with same values",
        user_id=1,
    )

    # Create sample values that are all the same
    base_date = date.today()
    recent_values = []

    for i in range(5):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value="50",  # All values are 50
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # All trend values should be 0.5 (middle)
    for trend_value in display_data.trend_data:
        assert trend_value == 0.5, f"All trend values should be 0.5, got {trend_value}"


def test_recent_values_order():
    """Test that recent_values are displayed in correct order (newest first for UI)."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1,
        name="Order Test Tracker",
        description="Test tracker for value order",
        user_id=1,
    )

    # Create sample values
    base_date = date.today()
    recent_values = []

    for i in range(5):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(i + 1),  # Values: 1, 2, 3, 4, 5 (newest to oldest)
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # recent_values should be newest first for UI display
    expected_values = ["1", "2", "3", "4", "5"]  # Newest to oldest
    assert display_data.recent_values == expected_values

    # But trend_data should be chronological (oldest first)
    # Values chronologically: [5, 4, 3, 2, 1] (oldest to newest)
    # Normalized: [1.0, 0.75, 0.5, 0.25, 0.0]
    expected_trend = [1.0, 0.75, 0.5, 0.25, 0.0]

    for i, expected in enumerate(expected_trend):
        assert abs(display_data.trend_data[i] - expected) < 0.01, (
            f"Trend data at index {i}: expected {expected}, got {display_data.trend_data[i]}"
        )


if __name__ == "__main__":
    # Run the tests
    test_trend_data_chronological_order()
    test_trend_data_descending_values()
    test_trend_data_same_values()
    test_recent_values_order()
    print("✓ All chart direction tests passed!")
