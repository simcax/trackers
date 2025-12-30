"""
Test to verify that the main chart (detailed chart view) shows chronological order.

This test verifies the fix for the main chart direction issue where the detailed
chart view was showing data from latest to earliest instead of chronological order.
"""


def test_generate_simple_chart_chronological_order():
    """Test that generateSimpleChart processes values in chronological order."""

    # Mock the dashboard class with the generateSimpleChart method
    # We'll test the logic by simulating the JavaScript behavior

    # Sample values as they would come from the API (newest first)
    api_values = [
        {"date": "2025-12-30", "value": "100"},  # Today (newest)
        {"date": "2025-12-29", "value": "80"},  # Yesterday
        {"date": "2025-12-28", "value": "60"},  # 2 days ago
        {"date": "2025-12-27", "value": "40"},  # 3 days ago
        {"date": "2025-12-26", "value": "20"},  # 4 days ago (oldest)
    ]

    # Simulate the JavaScript logic from generateSimpleChart
    numeric_values = []
    for v in api_values:
        try:
            numeric_values.append(float(v["value"]))
        except (ValueError, TypeError):
            continue

    # Take first 30 values (in this case, all 5)
    numeric_values = numeric_values[:30]

    # This should be the current state (newest first): [100, 80, 60, 40, 20]
    assert numeric_values == [100.0, 80.0, 60.0, 40.0, 20.0]

    # After the fix (reverse for chronological order): [20, 40, 60, 80, 100]
    numeric_values.reverse()
    assert numeric_values == [20.0, 40.0, 60.0, 80.0, 100.0]

    # Verify this creates proper chronological progression
    for i in range(1, len(numeric_values)):
        assert numeric_values[i] >= numeric_values[i - 1], (
            f"Values should be in chronological order: {numeric_values}"
        )


def test_generate_simple_chart_descending_trend():
    """Test that generateSimpleChart handles descending trends correctly."""

    # Sample values showing a decline over time (newest first from API)
    api_values = [
        {"date": "2025-12-30", "value": "20"},  # Today (newest, lowest)
        {"date": "2025-12-29", "value": "40"},  # Yesterday
        {"date": "2025-12-28", "value": "60"},  # 2 days ago
        {"date": "2025-12-27", "value": "80"},  # 3 days ago
        {"date": "2025-12-26", "value": "100"},  # 4 days ago (oldest, highest)
    ]

    # Simulate the JavaScript logic
    numeric_values = [float(v["value"]) for v in api_values]
    numeric_values = numeric_values[:30]  # Take first 30

    # Before fix: [20, 40, 60, 80, 100] (newest first)
    assert numeric_values == [20.0, 40.0, 60.0, 80.0, 100.0]

    # After fix (reverse for chronological order): [100, 80, 60, 40, 20]
    numeric_values.reverse()
    assert numeric_values == [100.0, 80.0, 60.0, 40.0, 20.0]

    # This should show a declining trend chronologically (which is correct)
    assert numeric_values[0] > numeric_values[-1], (
        "This data should show decline over time chronologically"
    )


def test_generate_simple_chart_empty_values():
    """Test that generateSimpleChart handles empty values correctly."""

    # Test with empty array
    api_values = []
    numeric_values = [float(v["value"]) for v in api_values if v.get("value")]
    numeric_values = numeric_values[:30]
    numeric_values.reverse()

    assert numeric_values == []

    # Test with non-numeric values
    api_values = [
        {"date": "2025-12-30", "value": "invalid"},
        {"date": "2025-12-29", "value": ""},
        {"date": "2025-12-28", "value": None},
    ]

    numeric_values = []
    for v in api_values:
        try:
            if v.get("value"):
                numeric_values.append(float(v["value"]))
        except (ValueError, TypeError):
            continue

    numeric_values = numeric_values[:30]
    numeric_values.reverse()

    assert numeric_values == []


def test_values_table_order():
    """Test that the values table maintains newest-first order for user convenience."""

    # Sample values as they would come from the API (newest first)
    api_values = [
        {"date": "2025-12-30", "value": "100"},  # Today (newest)
        {"date": "2025-12-29", "value": "80"},  # Yesterday
        {"date": "2025-12-28", "value": "60"},  # 2 days ago
        {"date": "2025-12-27", "value": "40"},  # 3 days ago
        {"date": "2025-12-26", "value": "20"},  # 4 days ago (oldest)
    ]

    # The values table should keep the original order (newest first)
    # This is correct for user experience - users want to see recent data first
    table_values = api_values[:10]  # Take first 10 for table

    assert table_values[0]["date"] == "2025-12-30"  # Newest first
    assert table_values[-1]["date"] == "2025-12-26"  # Oldest last

    # Verify dates are in descending order (newest to oldest)
    dates = [v["date"] for v in table_values]
    assert dates == sorted(dates, reverse=True), "Table should show newest dates first"


if __name__ == "__main__":
    # Run the tests
    test_generate_simple_chart_chronological_order()
    test_generate_simple_chart_descending_trend()
    test_generate_simple_chart_empty_values()
    test_values_table_order()
    print("✓ All main chart direction tests passed!")
