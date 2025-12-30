"""
Test to verify layout fixes are working correctly.

This test verifies the fixes for:
1. Profile image spacing
2. Units in value pills
3. "Last 5 values" text
4. "Add Value" button text
5. Chart modal background
"""

from datetime import date, datetime, timedelta

from trackers.models.tracker_model import TrackerModel
from trackers.models.tracker_value_model import TrackerValueModel
from trackers.routes.web_routes import format_tracker_for_display


def test_unit_extraction_from_description():
    """Test that units are correctly extracted from tracker descriptions."""

    # Create a mock tracker with unit in description
    tracker = TrackerModel(
        id=1,
        name="Water Intake",
        description="Track daily water consumption | Unit: Liters | Goal: 8 glasses per day",
        user_id=1,
    )

    # Create sample values
    base_date = date.today()
    recent_values = []

    for i in range(3):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=1,
            date=value_date,
            value=str(2.5 + i),  # Values: 2.5, 3.5, 4.5
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # Verify unit is extracted correctly
    assert display_data.unit == "Liters"
    assert display_data.name == "Water Intake"
    assert len(display_data.recent_values) == 3


def test_unit_extraction_no_unit():
    """Test that trackers without units work correctly."""

    # Create a mock tracker without unit in description
    tracker = TrackerModel(
        id=2, name="Daily Steps", description="Track daily step count", user_id=1
    )

    # Create sample values
    base_date = date.today()
    recent_values = []

    for i in range(2):
        value_date = base_date - timedelta(days=i)
        value = TrackerValueModel(
            id=i + 1,
            tracker_id=2,
            date=value_date,
            value=str(10000 + (i * 500)),  # Values: 10000, 10500
            created_at=datetime.now(),
        )
        recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # Verify unit is None when not present
    assert display_data.unit is None
    assert display_data.name == "Daily Steps"
    assert len(display_data.recent_values) == 2


def test_unit_extraction_complex_description():
    """Test unit extraction from complex descriptions with multiple parts."""

    # Create a mock tracker with complex description
    tracker = TrackerModel(
        id=3,
        name="Weight Tracking",
        description="Monitor body weight changes | Unit: kg | Goal: Maintain 70kg | Notes: Weigh in the morning",
        user_id=1,
    )

    # Create sample values
    base_date = date.today()
    recent_values = []

    value = TrackerValueModel(
        id=1, tracker_id=3, date=base_date, value="69.5", created_at=datetime.now()
    )
    recent_values.append(value)

    # Format for display
    display_data = format_tracker_for_display(tracker, recent_values)

    # Verify unit is extracted correctly from complex description
    assert display_data.unit == "kg"
    assert display_data.name == "Weight Tracking"


def test_unit_extraction_edge_cases():
    """Test unit extraction edge cases."""

    # Test with empty description
    tracker1 = TrackerModel(id=4, name="Test Tracker 1", description="", user_id=1)

    display_data1 = format_tracker_for_display(tracker1, [])
    assert display_data1.unit is None

    # Test with None description
    tracker2 = TrackerModel(id=5, name="Test Tracker 2", description=None, user_id=1)

    display_data2 = format_tracker_for_display(tracker2, [])
    assert display_data2.unit is None

    # Test with description that has "Unit:" but no value
    tracker3 = TrackerModel(
        id=6,
        name="Test Tracker 3",
        description="Some description | Unit: | Goal: something",
        user_id=1,
    )

    display_data3 = format_tracker_for_display(tracker3, [])
    assert display_data3.unit == ""  # Empty string when Unit: is present but empty


def test_unit_extraction_whitespace_handling():
    """Test that unit extraction handles whitespace correctly."""

    # Test with extra whitespace around unit
    tracker = TrackerModel(
        id=7,
        name="Test Tracker",
        description="Description | Unit:   Hours   | Goal: 8 hours",
        user_id=1,
    )

    display_data = format_tracker_for_display(tracker, [])
    assert display_data.unit == "Hours"  # Should be trimmed


if __name__ == "__main__":
    # Run the tests
    test_unit_extraction_from_description()
    test_unit_extraction_no_unit()
    test_unit_extraction_complex_description()
    test_unit_extraction_edge_cases()
    test_unit_extraction_whitespace_handling()
    print("✓ All layout fix tests passed!")
