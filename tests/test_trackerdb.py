"""Tests for tracker repository operations."""

from trackers.db.trackerdb import (
    create_tracker,
    delete_tracker,
    get_all_trackers,
    get_tracker,
)


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

    # Create multiple trackers
    create_tracker(db_session, "Tracker 1", "First")
    create_tracker(db_session, "Tracker 2", "Second")
    create_tracker(db_session, "Tracker 3", "Third")

    # Get all trackers
    all_trackers = get_all_trackers(db_session)

    assert len(all_trackers) == initial_count + 3
    names = [t.name for t in all_trackers]
    assert "Tracker 1" in names
    assert "Tracker 2" in names
    assert "Tracker 3" in names


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
