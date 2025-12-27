"""
Integration tests for tracker values feature.

These tests cover end-to-end workflows including create → read → update → delete cycles,
error scenarios, edge cases, and interaction with existing tracker functionality.
They verify database state consistency after operations.

Validates: All requirements
"""

from datetime import datetime

from trackers.db.tracker_values_db import get_tracker_values, get_value
from trackers.db.trackerdb import create_tracker, get_tracker


class TestTrackerValueCRUDWorkflows:
    """Test complete CRUD workflows for tracker values."""

    def test_complete_crud_cycle_single_value(self, client, db_session):
        """
        Test complete create → read → update → delete cycle for a single value.

        Validates: Requirements 1.1, 1.2, 2.1, 3.1, 4.1, 5.1
        """
        # Setup: Create a tracker
        tracker = create_tracker(db_session, "CRUD Test Tracker", "For CRUD testing")
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # 1. CREATE: Add a new value
        create_data = {"date": "2024-01-15", "value": "Initial Value"}
        create_response = client.post(
            f"/api/trackers/{tracker_id}/values", json=create_data
        )

        assert create_response.status_code == 201
        assert create_response.json["message"] == "Value created successfully"
        created_value = create_response.json["value"]
        assert created_value["date"] == "2024-01-15"
        assert created_value["value"] == "Initial Value"
        assert created_value["tracker_id"] == tracker_id
        assert "id" in created_value
        assert "created_at" in created_value
        assert "updated_at" in created_value

        value_id = created_value["id"]

        # Verify database state after creation
        db_value = get_value(db_session, tracker_id, "2024-01-15")
        assert db_value is not None
        assert db_value.id == value_id
        assert db_value.value == "Initial Value"

        # 2. READ: Retrieve the created value
        read_response = client.get(f"/api/trackers/{tracker_id}/values/2024-01-15")

        assert read_response.status_code == 200
        read_value = read_response.json["value"]
        assert read_value["id"] == value_id
        assert read_value["date"] == "2024-01-15"
        assert read_value["value"] == "Initial Value"
        assert read_value["tracker_id"] == tracker_id

        # 3. UPDATE: Modify the value
        update_data = {"value": "Updated Value"}
        update_response = client.put(
            f"/api/trackers/{tracker_id}/values/2024-01-15", json=update_data
        )

        assert update_response.status_code == 200
        assert update_response.json["message"] == "Value updated successfully"
        updated_value = update_response.json["value"]
        assert updated_value["id"] == value_id  # Same ID
        assert updated_value["value"] == "Updated Value"
        assert updated_value["created_at"] == created_value["created_at"]  # Unchanged
        assert updated_value["updated_at"] != created_value["updated_at"]  # Changed

        # Verify database state after update
        db_session.expire_all()  # Expire all cached objects to force fresh queries
        db_value_updated = get_value(db_session, tracker_id, "2024-01-15")
        assert db_value_updated.value == "Updated Value"
        assert db_value_updated.id == value_id

        # 4. DELETE: Remove the value
        delete_response = client.delete(f"/api/trackers/{tracker_id}/values/2024-01-15")

        assert delete_response.status_code == 204
        assert delete_response.data == b""  # No content

        # Verify database state after deletion
        db_session.expire_all()  # Expire all cached objects to force fresh queries
        db_value_deleted = get_value(db_session, tracker_id, "2024-01-15")
        assert db_value_deleted is None

        # Verify value is no longer accessible via API
        read_after_delete = client.get(f"/api/trackers/{tracker_id}/values/2024-01-15")
        assert read_after_delete.status_code == 404

    def test_upsert_behavior_workflow(self, client, db_session):
        """
        Test upsert behavior - creating then updating via POST endpoint.

        Validates: Requirements 1.2, 2.1, 6.4
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Upsert Test Tracker", "For upsert testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # First POST: Create new value
        create_data = {"date": "2024-02-01", "value": "First Value"}
        first_response = client.post(
            f"/api/trackers/{tracker_id}/values", json=create_data
        )

        assert first_response.status_code == 201
        assert first_response.json["message"] == "Value created successfully"
        first_value = first_response.json["value"]
        first_id = first_value["id"]
        first_created_at = first_value["created_at"]

        # Second POST: Update existing value (upsert)
        update_data = {"date": "2024-02-01", "value": "Updated Value"}
        second_response = client.post(
            f"/api/trackers/{tracker_id}/values", json=update_data
        )

        assert second_response.status_code == 200  # 200 for update, not 201
        assert second_response.json["message"] == "Value updated successfully"
        second_value = second_response.json["value"]
        assert second_value["id"] == first_id  # Same ID
        assert second_value["value"] == "Updated Value"
        assert second_value["created_at"] == first_created_at  # Unchanged
        assert second_value["updated_at"] != first_value["updated_at"]  # Changed

        # Verify only one record exists in database
        db_session.expire_all()  # Expire all cached objects to force fresh queries
        db_values = get_tracker_values(db_session, tracker_id)
        assert len(db_values) == 1
        assert db_values[0].value == "Updated Value"

    def test_multiple_values_workflow(self, client, db_session):
        """
        Test managing multiple values for a single tracker.

        Validates: Requirements 1.1, 3.3, 3.5, 5.4
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Multi Value Tracker", "For multiple values testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Create multiple values for different dates
        test_values = [
            {"date": "2024-01-01", "value": "New Year"},
            {"date": "2024-01-15", "value": "Mid January"},
            {"date": "2024-02-01", "value": "February Start"},
            {"date": "2024-02-14", "value": "Valentine's Day"},
            {"date": "2024-03-01", "value": "March Beginning"},
        ]

        created_ids = []
        for value_data in test_values:
            response = client.post(
                f"/api/trackers/{tracker_id}/values", json=value_data
            )
            assert response.status_code == 201
            created_ids.append(response.json["value"]["id"])

        # Retrieve all values (should be ordered by date descending)
        all_values_response = client.get(f"/api/trackers/{tracker_id}/values")
        assert all_values_response.status_code == 200
        all_values = all_values_response.json["values"]
        assert len(all_values) == 5

        # Verify ordering (newest first)
        dates = [value["date"] for value in all_values]
        assert dates == [
            "2024-03-01",
            "2024-02-14",
            "2024-02-01",
            "2024-01-15",
            "2024-01-01",
        ]

        # Test date range filtering
        range_response = client.get(
            f"/api/trackers/{tracker_id}/values?start_date=2024-01-15&end_date=2024-02-14"
        )
        assert range_response.status_code == 200
        range_values = range_response.json["values"]
        assert len(range_values) == 3
        range_dates = [value["date"] for value in range_values]
        assert range_dates == ["2024-02-14", "2024-02-01", "2024-01-15"]

        # Delete all values for the tracker
        delete_all_response = client.delete(f"/api/trackers/{tracker_id}/values")
        assert delete_all_response.status_code == 200
        assert delete_all_response.json["deleted_count"] == 5

        # Verify all values are gone
        empty_response = client.get(f"/api/trackers/{tracker_id}/values")
        assert empty_response.status_code == 200
        assert empty_response.json["values"] == []


class TestTrackerValueErrorScenarios:
    """Test error scenarios and edge cases."""

    def test_non_existent_tracker_errors(self, client, db_session):
        """
        Test all endpoints with non-existent tracker ID.

        Validates: Requirements 2.2, 3.2, 4.2, 5.2, 7.4
        """
        non_existent_id = 99999

        # Test CREATE with non-existent tracker
        create_response = client.post(
            f"/api/trackers/{non_existent_id}/values",
            json={"date": "2024-01-01", "value": "test"},
        )
        assert create_response.status_code == 404
        assert "error" in create_response.json
        assert "not found" in create_response.json["error"]["message"].lower()
        assert str(non_existent_id) in create_response.json["error"]["message"]

        # Test READ single with non-existent tracker
        read_response = client.get(f"/api/trackers/{non_existent_id}/values/2024-01-01")
        assert read_response.status_code == 404
        assert "not found" in read_response.json["error"]["message"].lower()

        # Test READ list with non-existent tracker
        list_response = client.get(f"/api/trackers/{non_existent_id}/values")
        assert list_response.status_code == 404
        assert "not found" in list_response.json["error"]["message"].lower()

        # Test UPDATE with non-existent tracker
        update_response = client.put(
            f"/api/trackers/{non_existent_id}/values/2024-01-01",
            json={"value": "test"},
        )
        assert update_response.status_code == 404
        assert "not found" in update_response.json["error"]["message"].lower()

        # Test DELETE single with non-existent tracker
        delete_response = client.delete(
            f"/api/trackers/{non_existent_id}/values/2024-01-01"
        )
        assert delete_response.status_code == 404
        assert "not found" in delete_response.json["error"]["message"].lower()

        # Test DELETE all with non-existent tracker
        delete_all_response = client.delete(f"/api/trackers/{non_existent_id}/values")
        assert delete_all_response.status_code == 404
        assert "not found" in delete_all_response.json["error"]["message"].lower()

    def test_non_existent_value_errors(self, client, db_session):
        """
        Test operations on non-existent values.

        Validates: Requirements 3.2, 4.2, 5.2, 7.4
        """
        # Setup: Create a tracker
        tracker = create_tracker(db_session, "Error Test Tracker", "For error testing")
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Test READ non-existent value
        read_response = client.get(f"/api/trackers/{tracker_id}/values/2024-01-01")
        assert read_response.status_code == 404
        assert "not found" in read_response.json["error"]["message"].lower()

        # Test UPDATE non-existent value
        update_response = client.put(
            f"/api/trackers/{tracker_id}/values/2024-01-01", json={"value": "test"}
        )
        assert update_response.status_code == 404
        assert "not found" in update_response.json["error"]["message"].lower()

        # Test DELETE non-existent value
        delete_response = client.delete(f"/api/trackers/{tracker_id}/values/2024-01-01")
        assert delete_response.status_code == 404
        assert "not found" in delete_response.json["error"]["message"].lower()

    def test_validation_errors(self, client, db_session):
        """
        Test various validation error scenarios.

        Validates: Requirements 2.3, 2.4, 4.3, 6.2, 6.3, 7.1, 7.5
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Validation Test Tracker", "For validation testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Test missing required fields in CREATE
        missing_date_response = client.post(
            f"/api/trackers/{tracker_id}/values", json={"value": "test"}
        )
        assert missing_date_response.status_code == 400
        assert "validation" in missing_date_response.json["error"]["message"].lower()

        missing_value_response = client.post(
            f"/api/trackers/{tracker_id}/values", json={"date": "2024-01-01"}
        )
        assert missing_value_response.status_code == 400
        assert "validation" in missing_value_response.json["error"]["message"].lower()

        # Test invalid date format
        invalid_date_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "invalid-date", "value": "test"},
        )
        assert invalid_date_response.status_code == 400
        assert "validation" in invalid_date_response.json["error"]["message"].lower()

        # Test empty value
        empty_value_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "2024-01-01", "value": ""},
        )
        assert empty_value_response.status_code == 400
        assert "validation" in empty_value_response.json["error"]["message"].lower()

        # Test null value
        null_value_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "2024-01-01", "value": None},
        )
        assert null_value_response.status_code == 400
        assert "validation" in null_value_response.json["error"]["message"].lower()

        # Test missing value in UPDATE
        missing_update_value = client.put(
            f"/api/trackers/{tracker_id}/values/2024-01-01", json={}
        )
        assert missing_update_value.status_code == 400
        assert "validation" in missing_update_value.json["error"]["message"].lower()

    def test_invalid_date_formats_in_urls(self, client, db_session):
        """
        Test invalid date formats in URL paths.

        Validates: Requirements 6.2, 7.1
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Date Format Test Tracker", "For date format testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        invalid_dates = [
            "2024-13-01",  # Invalid month
            "2024-01-32",  # Invalid day
            "24-01-01",  # Wrong year format
            "2024/01/01",  # Wrong separator
            "invalid",  # Not a date
            "2024-1-1",  # Missing zero padding
        ]

        for invalid_date in invalid_dates:
            # Test GET with invalid date
            get_response = client.get(
                f"/api/trackers/{tracker_id}/values/{invalid_date}"
            )
            assert get_response.status_code in [
                400,
                404,
            ]  # Either validation error or not found

            # Test PUT with invalid date
            put_response = client.put(
                f"/api/trackers/{tracker_id}/values/{invalid_date}",
                json={"value": "test"},
            )
            assert put_response.status_code in [400, 404]

            # Test DELETE with invalid date
            delete_response = client.delete(
                f"/api/trackers/{tracker_id}/values/{invalid_date}"
            )
            assert delete_response.status_code in [400, 404]


class TestTrackerValueInteractionWithExistingFunctionality:
    """Test interaction with existing tracker functionality."""

    def test_tracker_deletion_cascades_to_values(self, client, db_session):
        """
        Test that deleting a tracker also deletes its values (cascade delete).

        Validates: Requirements 5.5
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Cascade Test Tracker", "For cascade testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Add some values to the tracker
        test_values = [
            {"date": "2024-01-01", "value": "Value 1"},
            {"date": "2024-01-02", "value": "Value 2"},
            {"date": "2024-01-03", "value": "Value 3"},
        ]

        for value_data in test_values:
            response = client.post(
                f"/api/trackers/{tracker_id}/values", json=value_data
            )
            assert response.status_code == 201

        # Verify values exist
        values_response = client.get(f"/api/trackers/{tracker_id}/values")
        assert values_response.status_code == 200
        assert len(values_response.json["values"]) == 3

        # Delete the tracker (assuming delete endpoint exists)
        # Note: This test assumes a delete tracker endpoint exists
        # If not, we can test cascade behavior at the database level
        from trackers.db.trackerdb import delete_tracker

        # Delete tracker via repository function
        deleted = delete_tracker(db_session, tracker_id)
        assert deleted is True
        db_session.commit()  # Ensure deletion is committed

        # Verify tracker is gone
        deleted_tracker = get_tracker(db_session, tracker_id)
        assert deleted_tracker is None

        # Verify values are also gone (cascade delete)
        db_session.expire_all()  # Expire all cached objects to force fresh queries
        db_values = get_tracker_values(db_session, tracker_id)
        assert len(db_values) == 0

        # Verify API also reflects the deletion
        values_after_delete = client.get(f"/api/trackers/{tracker_id}/values")
        assert values_after_delete.status_code == 404  # Tracker not found

    def test_tracker_values_relationship(self, client, db_session):
        """
        Test that tracker-value relationships work correctly.

        Validates: Requirements 1.1, 1.5
        """
        # Setup: Create multiple trackers
        tracker1 = create_tracker(db_session, "Tracker 1", "First tracker")
        tracker2 = create_tracker(db_session, "Tracker 2", "Second tracker")
        db_session.commit()  # Ensure trackers are committed to database

        # Add values to both trackers
        client.post(
            f"/api/trackers/{tracker1.id}/values",
            json={"date": "2024-01-01", "value": "Tracker 1 Value"},
        )
        client.post(
            f"/api/trackers/{tracker2.id}/values",
            json={"date": "2024-01-01", "value": "Tracker 2 Value"},
        )

        # Verify each tracker only sees its own values
        tracker1_values = client.get(f"/api/trackers/{tracker1.id}/values")
        assert tracker1_values.status_code == 200
        assert len(tracker1_values.json["values"]) == 1
        assert tracker1_values.json["values"][0]["value"] == "Tracker 1 Value"

        tracker2_values = client.get(f"/api/trackers/{tracker2.id}/values")
        assert tracker2_values.status_code == 200
        assert len(tracker2_values.json["values"]) == 1
        assert tracker2_values.json["values"][0]["value"] == "Tracker 2 Value"

    def test_date_uniqueness_constraint(self, client, db_session):
        """
        Test that the date uniqueness constraint is properly enforced.

        Validates: Requirements 1.5
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Uniqueness Test Tracker", "For uniqueness testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Create a value
        first_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "2024-01-01", "value": "First Value"},
        )
        assert first_response.status_code == 201

        # Try to create another value for the same date (should update, not create new)
        second_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "2024-01-01", "value": "Second Value"},
        )
        assert second_response.status_code == 200  # Update, not create
        assert second_response.json["message"] == "Value updated successfully"

        # Verify only one value exists
        all_values = client.get(f"/api/trackers/{tracker_id}/values")
        assert len(all_values.json["values"]) == 1
        assert all_values.json["values"][0]["value"] == "Second Value"


class TestTrackerValueDatabaseStateConsistency:
    """Test database state consistency after operations."""

    def test_transaction_rollback_on_error(self, client, db_session):
        """
        Test that database transactions are properly rolled back on errors.

        This test verifies that failed operations don't leave the database
        in an inconsistent state.

        Validates: Requirements 7.2
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Transaction Test Tracker", "For transaction testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Get initial state
        initial_values = get_tracker_values(db_session, tracker_id)
        initial_count = len(initial_values)

        # Attempt to create a value with invalid data that should fail validation
        invalid_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "invalid-date", "value": "test"},
        )
        assert invalid_response.status_code == 400

        # Verify database state is unchanged
        after_error_values = get_tracker_values(db_session, tracker_id)
        assert len(after_error_values) == initial_count

    def test_concurrent_operations_consistency(self, client, db_session):
        """
        Test database consistency with multiple operations.

        Validates: Requirements 1.1, 1.2, 4.1, 5.1
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Consistency Test Tracker", "For consistency testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Perform multiple operations in sequence
        operations = [
            ("POST", {"date": "2024-01-01", "value": "Value 1"}),
            ("POST", {"date": "2024-01-02", "value": "Value 2"}),
            ("POST", {"date": "2024-01-01", "value": "Updated Value 1"}),  # Update
            (
                "PUT",
                {"date": "2024-01-02", "value": "Updated Value 2"},
            ),  # Update via PUT
        ]

        for method, data in operations:
            if method == "POST":
                response = client.post(f"/api/trackers/{tracker_id}/values", json=data)
                assert response.status_code in [200, 201]
            elif method == "PUT":
                response = client.put(
                    f"/api/trackers/{tracker_id}/values/{data['date']}",
                    json={"value": data["value"]},
                )
                assert response.status_code == 200

        # Verify final state
        final_values = client.get(f"/api/trackers/{tracker_id}/values")
        assert final_values.status_code == 200
        values = final_values.json["values"]
        assert len(values) == 2

        # Verify values are correct
        values_by_date = {v["date"]: v["value"] for v in values}
        assert values_by_date["2024-01-01"] == "Updated Value 1"
        assert values_by_date["2024-01-02"] == "Updated Value 2"

    def test_timestamp_accuracy_and_consistency(self, client, db_session):
        """
        Test that timestamps are accurate and consistent.

        Validates: Requirements 1.3, 1.4, 4.5
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Timestamp Test Tracker", "For timestamp testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Record time before creation
        before_create = datetime.utcnow()

        # Create a value
        create_response = client.post(
            f"/api/trackers/{tracker_id}/values",
            json={"date": "2024-01-01", "value": "Initial Value"},
        )
        assert create_response.status_code == 201

        # Record time after creation
        after_create = datetime.utcnow()

        created_value = create_response.json["value"]
        created_at = datetime.fromisoformat(
            created_value["created_at"].replace("Z", "+00:00")
        )
        updated_at = datetime.fromisoformat(
            created_value["updated_at"].replace("Z", "+00:00")
        )

        # Verify creation timestamps are within reasonable range
        assert before_create <= created_at <= after_create
        assert before_create <= updated_at <= after_create
        # For new records, created_at and updated_at should be very close (within 1 second)
        assert abs((created_at - updated_at).total_seconds()) < 1.0

        # Wait a moment and update
        import time

        time.sleep(0.1)

        before_update = datetime.utcnow()
        update_response = client.put(
            f"/api/trackers/{tracker_id}/values/2024-01-01",
            json={"value": "Updated Value"},
        )
        assert update_response.status_code == 200
        after_update = datetime.utcnow()

        updated_value = update_response.json["value"]
        new_created_at = datetime.fromisoformat(
            updated_value["created_at"].replace("Z", "+00:00")
        )
        new_updated_at = datetime.fromisoformat(
            updated_value["updated_at"].replace("Z", "+00:00")
        )

        # Verify timestamps after update
        assert new_created_at == created_at  # Created timestamp should not change
        assert (
            before_update <= new_updated_at <= after_update
        )  # Updated timestamp should change
        assert new_updated_at > created_at  # Updated should be after created


class TestTrackerValueEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_tracker_values_list(self, client, db_session):
        """
        Test retrieving values from a tracker with no values.

        Validates: Requirements 3.4
        """
        # Setup: Create a tracker
        tracker = create_tracker(db_session, "Empty Tracker", "Has no values")
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Get values (should be empty)
        response = client.get(f"/api/trackers/{tracker_id}/values")
        assert response.status_code == 200
        assert response.json["values"] == []

        # Test with date range filters (should still be empty)
        range_response = client.get(
            f"/api/trackers/{tracker_id}/values?start_date=2024-01-01&end_date=2024-12-31"
        )
        assert range_response.status_code == 200
        assert range_response.json["values"] == []

    def test_date_range_edge_cases(self, client, db_session):
        """
        Test date range filtering edge cases.

        Validates: Requirements 3.5
        """
        # Setup: Create a tracker with values
        tracker = create_tracker(db_session, "Range Test Tracker", "For range testing")
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Create values spanning multiple months
        dates = ["2024-01-01", "2024-01-15", "2024-02-01", "2024-02-15", "2024-03-01"]
        for i, date_str in enumerate(dates):
            client.post(
                f"/api/trackers/{tracker_id}/values",
                json={"date": date_str, "value": f"Value {i + 1}"},
            )

        # Test exact boundary matches
        exact_start = client.get(
            f"/api/trackers/{tracker_id}/values?start_date=2024-02-01"
        )
        assert (
            len(exact_start.json["values"]) == 3
        )  # 2024-02-01, 2024-02-15, 2024-03-01

        exact_end = client.get(f"/api/trackers/{tracker_id}/values?end_date=2024-02-01")
        assert len(exact_end.json["values"]) == 3  # 2024-01-01, 2024-01-15, 2024-02-01

        # Test single day range
        single_day = client.get(
            f"/api/trackers/{tracker_id}/values?start_date=2024-02-01&end_date=2024-02-01"
        )
        assert len(single_day.json["values"]) == 1
        assert single_day.json["values"][0]["date"] == "2024-02-01"

        # Test range with no matches
        no_match = client.get(
            f"/api/trackers/{tracker_id}/values?start_date=2024-04-01&end_date=2024-04-30"
        )
        assert len(no_match.json["values"]) == 0

    def test_special_characters_in_values(self, client, db_session):
        """
        Test handling of special characters and various data types in values.

        Validates: Requirements 6.3, 7.1
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Special Chars Tracker", "For special character testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        special_values = [
            "Simple text",
            "Text with spaces and punctuation!",
            "Unicode: 🚀 ñáéíóú",
            "JSON-like: {key: value}",  # Quotes removed by sanitization
            "Numbers: 123.456",
            "Special chars: @#$%^*()",  # & removed by sanitization
            "Newlines\nand\ttabs",
            "Very long text " * 100,  # Long text
        ]

        for i, value in enumerate(special_values):
            date_str = f"2024-01-{i + 1:02d}"
            response = client.post(
                f"/api/trackers/{tracker_id}/values",
                json={"date": date_str, "value": value},
            )
            assert response.status_code == 201
            # The sanitization function strips whitespace, so we need to compare with the sanitized version
            expected_value = value.strip()
            # Remove dangerous characters that are sanitized
            for char in ["<", ">", '"', "'", "&"]:
                expected_value = expected_value.replace(char, "")
            assert response.json["value"]["value"] == expected_value

            # Verify retrieval
            get_response = client.get(f"/api/trackers/{tracker_id}/values/{date_str}")
            assert get_response.status_code == 200
            assert get_response.json["value"]["value"] == expected_value

    def test_bulk_delete_edge_cases(self, client, db_session):
        """
        Test bulk delete operation edge cases.

        Validates: Requirements 5.4
        """
        # Setup: Create a tracker
        tracker = create_tracker(
            db_session, "Bulk Delete Tracker", "For bulk delete testing"
        )
        db_session.commit()  # Ensure tracker is committed to database
        tracker_id = tracker.id

        # Test delete all on empty tracker
        empty_delete = client.delete(f"/api/trackers/{tracker_id}/values")
        assert empty_delete.status_code == 200
        assert empty_delete.json["deleted_count"] == 0

        # Add some values
        for i in range(5):
            client.post(
                f"/api/trackers/{tracker_id}/values",
                json={"date": f"2024-01-{i + 1:02d}", "value": f"Value {i + 1}"},
            )

        # Delete all values
        delete_all = client.delete(f"/api/trackers/{tracker_id}/values")
        assert delete_all.status_code == 200
        assert delete_all.json["deleted_count"] == 5

        # Verify all values are gone
        verify_empty = client.get(f"/api/trackers/{tracker_id}/values")
        assert verify_empty.status_code == 200
        assert len(verify_empty.json["values"]) == 0

        # Test delete all again (should return 0)
        delete_again = client.delete(f"/api/trackers/{tracker_id}/values")
        assert delete_again.status_code == 200
        assert delete_again.json["deleted_count"] == 0
