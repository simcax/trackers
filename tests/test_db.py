# Test db operations with an ORM towards a postgresql database

from trackers.models.tracker_model import TrackerModel


def test_create_and_query_tracker(db_session):
    """Test creating a tracker and querying it back from the database."""
    # Create a new tracker
    tracker = TrackerModel(
        name="Test Tracker", description="A test tracker for testing"
    )
    db_session.add(tracker)
    db_session.flush()  # Flush to get ID without committing

    # Query the tracker back
    queried_tracker = (
        db_session.query(TrackerModel).filter_by(name="Test Tracker").first()
    )

    # Verify the tracker was persisted correctly
    assert queried_tracker is not None
    assert queried_tracker.name == "Test Tracker"
    assert queried_tracker.description == "A test tracker for testing"
    assert queried_tracker.id is not None
