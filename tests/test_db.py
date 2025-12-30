# Test db operations with an ORM towards a postgresql database

from datetime import date

from trackers.auth.token_validator import UserInfo
from trackers.models.tracker_model import TrackerModel
from trackers.models.tracker_value_model import TrackerValueModel
from trackers.services.user_service import UserService


def create_test_user_info(
    google_id="test_google_123",
    email="test@example.com",
    name="Test User",
    picture_url="https://example.com/profile.jpg",
    verified_email=True,
):
    """Helper function to create test UserInfo object."""
    return UserInfo(
        google_id=google_id,
        email=email,
        name=name,
        picture_url=picture_url,
        verified_email=verified_email,
    )


def create_test_user(db_session, google_id="test_google_123", email="test@example.com"):
    """Helper function to create a test user and return the user model."""
    user_service = UserService(db_session)
    user_info = create_test_user_info(google_id=google_id, email=email)
    user = user_service.create_or_update_user(user_info)
    db_session.commit()
    return user


def test_create_and_query_tracker(db_session):
    """Test creating a tracker and querying it back from the database."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create a new tracker
    tracker = TrackerModel(
        name="Test Tracker", description="A test tracker for testing", user_id=user.id
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
    assert queried_tracker.user_id == user.id


def test_tracker_values_relationship_empty(db_session):
    """Test that a new tracker has an empty values relationship."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create a new tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = TrackerModel(
        name=f"Empty Values Tracker {suffix}",
        description="Should have no values initially",
        user_id=user.id,
    )
    db_session.add(tracker)
    db_session.flush()

    # Verify the values relationship is empty
    assert tracker.values == []
    assert len(tracker.values) == 0


def test_tracker_values_relationship_with_values(db_session):
    """Test that tracker values relationship works correctly with actual values."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create a tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = TrackerModel(
        name=f"Values Test Tracker {suffix}",
        description="For testing values relationship",
        user_id=user.id,
    )
    db_session.add(tracker)
    db_session.flush()

    # Add some values to the tracker
    value1 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 1), value="First Value"
    )
    value2 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 2), value="Second Value"
    )
    value3 = TrackerValueModel(
        tracker_id=tracker.id, date=date(2024, 1, 3), value="Third Value"
    )

    db_session.add_all([value1, value2, value3])
    db_session.flush()

    # Refresh the tracker to load the relationship
    db_session.refresh(tracker)

    # Verify the relationship works
    assert len(tracker.values) == 3

    # Verify ordering (should be descending by date as per model definition)
    dates = [v.date for v in tracker.values]
    assert dates == [date(2024, 1, 3), date(2024, 1, 2), date(2024, 1, 1)]

    # Verify values are correct
    values_by_date = {v.date: v.value for v in tracker.values}
    assert values_by_date[date(2024, 1, 1)] == "First Value"
    assert values_by_date[date(2024, 1, 2)] == "Second Value"
    assert values_by_date[date(2024, 1, 3)] == "Third Value"


def test_tracker_cascade_delete_orm_level(db_session):
    """Test that deleting a tracker cascades to delete its values at ORM level."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create a tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = TrackerModel(
        name=f"Cascade Delete Tracker {suffix}",
        description="Will be deleted with values",
        user_id=user.id,
    )
    db_session.add(tracker)
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

    # Delete the tracker
    db_session.delete(tracker)
    db_session.flush()

    # Verify values are also deleted (cascade delete)
    values_after = (
        db_session.query(TrackerValueModel).filter_by(tracker_id=tracker_id).all()
    )
    assert len(values_after) == 0

    # Verify tracker is deleted
    deleted_tracker = db_session.query(TrackerModel).filter_by(id=tracker_id).first()
    assert deleted_tracker is None


def test_tracker_values_relationship_isolation(db_session):
    """Test that values are properly isolated between different trackers."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create two trackers with unique names
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker1 = TrackerModel(
        name=f"Tracker 1 {suffix}", description="First tracker", user_id=user.id
    )
    tracker2 = TrackerModel(
        name=f"Tracker 2 {suffix}", description="Second tracker", user_id=user.id
    )
    db_session.add_all([tracker1, tracker2])
    db_session.flush()

    # Add values to each tracker
    value1_t1 = TrackerValueModel(
        tracker_id=tracker1.id, date=date(2024, 1, 1), value="Tracker 1 Value"
    )
    value1_t2 = TrackerValueModel(
        tracker_id=tracker2.id, date=date(2024, 1, 1), value="Tracker 2 Value"
    )

    db_session.add_all([value1_t1, value1_t2])
    db_session.flush()

    # Refresh trackers to load relationships
    db_session.refresh(tracker1)
    db_session.refresh(tracker2)

    # Verify each tracker only sees its own values
    assert len(tracker1.values) == 1
    assert len(tracker2.values) == 1
    assert tracker1.values[0].value == "Tracker 1 Value"
    assert tracker2.values[0].value == "Tracker 2 Value"
    assert tracker1.values[0].tracker_id == tracker1.id
    assert tracker2.values[0].tracker_id == tracker2.id
