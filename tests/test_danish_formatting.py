"""
Test Danish number and date formatting functionality.

This test verifies:
1. Danish number formatting (. for thousands, , for decimals)
2. Danish date formatting (dd-mm-yyyy)
3. Number parsing from Danish format
"""

from datetime import date, datetime, timedelta

from trackers.models.tracker_model import TrackerModel
from trackers.models.tracker_value_model import TrackerValueModel
from trackers.routes.web_routes import format_danish_number, format_tracker_for_display


def test_format_danish_number():
    """Test Danish number formatting."""

    # Test integers
    assert format_danish_number(1000) == "1.000"
    assert format_danish_number(1234567) == "1.234.567"
    assert format_danish_number(42) == "42"

    # Test decimals
    assert format_danish_number(1234.56) == "1.234,56"
    assert format_danish_number(42.5) == "42,5"
    assert format_danish_number(0.123) == "0,12"  # Rounded to 2 decimals

    # Test edge cases
    assert format_danish_number(0) == "0"
    assert format_danish_number(0.0) == "0"
    assert format_danish_number(1.0) == "1"

    # Test string input
    assert format_danish_number("1234.56") == "1.234,56"
    assert format_danish_number("42") == "42"

    # Test invalid input
    assert format_danish_number("invalid") == "invalid"
    assert format_danish_number(None) == "None"


def test_danish_date_formatting_in_tracker_display():
    """Test that tracker display uses Danish date format."""

    # Create a mock tracker
    tracker = TrackerModel(id=1, name="Test Tracker", description="Unit: kg", user_id=1)

    # Create sample values with specific dates
    base_date = date(2025, 12, 30)  # 30th December 2025
    recent_values = []

    for i in range(3):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(1234.56 + i),  # Values: 1234.56, 1235.56, 1236.56
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # Verify Danish date format (dd-mm-yyyy)
    expected_dates = ["30-12-2025", "29-12-2025", "28-12-2025"]
    assert display_data.recent_dates == expected_dates

    # Verify Danish number format
    expected_values = ["1.234,56", "1.235,56", "1.236,56"]
    assert display_data.recent_values == expected_values

    # Verify current value is Danish formatted
    assert display_data.current_value == "1.234,56"


def test_danish_number_formatting_with_change_calculation():
    """Test that change calculations use Danish number formatting."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1, name="Weight Tracker", description="Unit: kg", user_id=1
    )

    # Create values with a clear change
    base_date = date.today()
    recent_values = []

    # Today: 70.5 kg, Yesterday: 69.2 kg (change: +1.3)
    values_data = [70.5, 69.2]

    for i, value in enumerate(values_data):
        value_date = base_date - timedelta(days=i)
        tracker_value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(value),
            created_at=datetime.now(),
        )
        recent_values.append(tracker_value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # Verify change is Danish formatted
    # Change should be +1,3 (70.5 - 69.2 = 1.3)
    assert display_data.change_text == "+1,3"

    # Verify current value is Danish formatted
    assert display_data.current_value == "70,5"


def test_danish_formatting_edge_cases():
    """Test edge cases for Danish formatting."""

    # Test very large numbers
    assert format_danish_number(1234567890) == "1.234.567.890"
    assert format_danish_number(1234567890.12) == "1.234.567.890,12"

    # Test very small numbers
    assert format_danish_number(0.01) == "0,01"
    assert format_danish_number(0.001) == "0"  # Rounded to 2 decimals

    # Test negative numbers
    assert format_danish_number(-1234.56) == "-1.234,56"
    assert format_danish_number(-42) == "-42"

    # Test numbers that don't need decimal places
    assert format_danish_number(1234.00) == "1.234"
    assert format_danish_number(42.0) == "42"


def test_tracker_display_with_no_values():
    """Test tracker display when there are no values."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1, name="Empty Tracker", description="Unit: steps", user_id=1
    )

    # Format for display with no values
    display_data = format_tracker_for_display(tracker, [])

    # Verify defaults
    assert display_data.current_value == "No data"
    assert display_data.change_text == "No change"
    assert display_data.recent_values == []
    assert display_data.recent_dates == []


def test_tracker_display_with_single_value():
    """Test tracker display with only one value (no change calculation)."""

    # Create a mock tracker
    tracker = TrackerModel(
        id=1, name="Single Value Tracker", description="Unit: liters", user_id=1
    )

    # Create single value
    value = TrackerValueModel(
        id=1, tracker_id=1, date=date.today(), value="2.5", created_at=datetime.now()
    )

    # Format for display
    display_data = format_tracker_for_display(tracker, [value])

    # Verify single value handling
    assert display_data.current_value == "2,5"
    assert display_data.change_text == "No change"  # No previous value to compare
    assert len(display_data.recent_values) == 1
    assert display_data.recent_values[0] == "2,5"


if __name__ == "__main__":
    # Run the tests
    test_format_danish_number()
    test_danish_date_formatting_in_tracker_display()
    test_danish_number_formatting_with_change_calculation()
    test_danish_formatting_edge_cases()
    test_tracker_display_with_no_values()
    test_tracker_display_with_single_value()
    print("✓ All Danish formatting tests passed!")
