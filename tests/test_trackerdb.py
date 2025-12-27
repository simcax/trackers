"""Tests for tracker repository operations."""

from datetime import date

from trackers.db.trackerdb import (
    create_tracker,
    delete_tracker,
    get_all_trackers,
    get_tracker,
)
from trackers.models.tracker_value_model import TrackerValueModel


def test_create_tracker(db_session):
    """Test creating a tracker using the repository function."""
    tracker = create_tracker(db_session, "My Tracker", "Test description")

    assert tracker.id is not None
    assert tracker.name == "My Tracker"
    assert tracker.description == "Test description"


def test_get_tracker(db_session):
    """Test retrieving a tracker by ID."""
    # Create a tracker first
    created = create_tracker(db_session, "Tracker to Get", "Description")

    # Retrieve it
    retrieved = get_tracker(db_session, created.id)

    assert retrieved is not None
    assert retrieved.id == created.id
    assert retrieved.name == "Tracker to Get"
    assert retrieved.description == "Description"


def test_get_tracker_not_found(db_session):
    """Test retrieving a non-existent tracker returns None."""
    result = get_tracker(db_session, 99999)
    assert result is None


def test_get_all_trackers(db_session):
    """Test retrieving all trackers."""
    # Get initial count
    initial_trackers = get_all_trackers(db_session)
    initial_count = len(initial_trackers)

    # Create multiple trackers with unique names
    import uuid

    suffix = str(uuid.uuid4())[:8]
    create_tracker(db_session, f"Tracker 1 {suffix}", "First")
    create_tracker(db_session, f"Tracker 2 {suffix}", "Second")
    create_tracker(db_session, f"Tracker 3 {suffix}", "Third")

    # Get all trackers
    all_trackers = get_all_trackers(db_session)

    assert len(all_trackers) == initial_count + 3
    names = [t.name for t in all_trackers]
    assert f"Tracker 1 {suffix}" in names
    assert f"Tracker 2 {suffix}" in names
    assert f"Tracker 3 {suffix}" in names


def test_delete_tracker(db_session):
    """Test deleting a tracker."""
    # Create a tracker
    tracker = create_tracker(db_session, "Tracker to Delete", "Will be deleted")
    tracker_id = tracker.id

    # Delete it
    result = delete_tracker(db_session, tracker_id)

    assert result is True

    # Verify it's gone
    deleted = get_tracker(db_session, tracker_id)
    assert deleted is None


def test_delete_tracker_not_found(db_session):
    """Test deleting a non-existent tracker returns False."""
    result = delete_tracker(db_session, 99999)
    assert result is False


def test_tracker_with_values_relationship(db_session):
    """Test that trackers work correctly with the new values relationship."""
    # Create a tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = create_tracker(db_session, f"Tracker with Values {suffix}", "Has values")
    db_session.flush()

    # Initially should have no values
    assert tracker.values == []

    # Add some values directly via ORM
    value1 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 1), value="Test Value 1"
    )
    value2 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 2), value="Test Value 2"
    )

    db_session.add_all([value1, value2])
    db_session.flush()

    # Refresh tracker to load the relationship
    db_session.refresh(tracker)

    # Verify the relationship works
    assert len(tracker.values) == 2

    # Verify ordering (should be descending by date)
    dates = [v.date for v in tracker.values]
    assert dates == [date(2024, 1, 2), date(2024, 1, 1)]


def test_delete_tracker_with_values_cascade(db_session):
    """Test that deleting a tracker with values works correctly (cascade delete)."""
    # Create a tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = create_tracker(
        db_session, f"Tracker with Values to Delete {suffix}", "Will be deleted"
    )
    db_session.flush()
    tracker_id = tracker.id

    # Add some values
    value1 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 1), value="Value 1"
    )
    value2 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 2), value="Value 2"
    )

    db_session.add_all([value1, value2])
    db_session.flush()

    # Verify values exist
    values_before = (
        db_session.query(TrackerValueModel).filter_by(tracker_id=tracker_id).all()
    )
    assert len(values_before) == 2

    # Delete the tracker using repository function
    result = delete_tracker(db_session, tracker_id)
    assert result is True

    # Verify values are also deleted (cascade delete)
    values_after = (
        db_session.query(TrackerValueModel).filter_by(tracker_id=tracker_id).all()
    )
    assert len(values_after) == 0

    # Verify tracker is deleted
    deleted_tracker = get_tracker(db_session, tracker_id)
    assert deleted_tracker is None
