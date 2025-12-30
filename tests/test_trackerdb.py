"""Tests for tracker repository operations."""

from datetime import date

from trackers.db.trackerdb import (
    TrackerDB,
    create_tracker,
    delete_tracker,
    get_all_trackers,
    get_tracker,
)
from trackers.models.tracker_value_model import TrackerValueModel
from trackers.models.user_model import UserModel


def create_test_user(
    db_session,
    google_user_id="test_user_123",
    email="test@example.com",
    name="Test User",
):
    """Helper function to create a test user."""
    user = UserModel(
        google_user_id=google_user_id,
        email=email,
        name=name,
        profile_picture_url="https://example.com/profile.jpg",
    )
    db_session.add(user)
    db_session.flush()
    db_session.refresh(user)
    return user


def test_create_tracker(db_session):
    """Test creating a tracker using the repository function."""
    # Create a test user first
    user = create_test_user(db_session)

    tracker = create_tracker(db_session, "My Tracker", "Test description", user.id)

    assert tracker.id is not None
    assert tracker.name == "My Tracker"
    assert tracker.description == "Test description"
    assert tracker.user_id == user.id


def test_get_tracker(db_session):
    """Test retrieving a tracker by ID."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create a tracker first
    created = create_tracker(db_session, "Tracker to Get", "Description", user.id)

    # Retrieve it
    retrieved = get_tracker(db_session, created.id)

    assert retrieved is not None
    assert retrieved.id == created.id
    assert retrieved.name == "Tracker to Get"
    assert retrieved.description == "Description"
    assert retrieved.user_id == user.id


def test_get_tracker_not_found(db_session):
    """Test retrieving a non-existent tracker returns None."""
    result = get_tracker(db_session, 99999)
    assert result is None


def test_get_all_trackers(db_session):
    """Test retrieving all trackers."""
    # Create a test user first
    user = create_test_user(db_session)

    # Get initial count
    initial_trackers = get_all_trackers(db_session)
    initial_count = len(initial_trackers)

    # Create multiple trackers with unique names
    import uuid

    suffix = str(uuid.uuid4())[:8]
    create_tracker(db_session, f"Tracker 1 {suffix}", "First", user.id)
    create_tracker(db_session, f"Tracker 2 {suffix}", "Second", user.id)
    create_tracker(db_session, f"Tracker 3 {suffix}", "Third", user.id)

    # Get all trackers
    all_trackers = get_all_trackers(db_session)

    assert len(all_trackers) == initial_count + 3
    names = [t.name for t in all_trackers]
    assert f"Tracker 1 {suffix}" in names
    assert f"Tracker 2 {suffix}" in names
    assert f"Tracker 3 {suffix}" in names


def test_delete_tracker(db_session):
    """Test deleting a tracker."""
    # Create a test user first
    user = create_test_user(db_session)

    # Create a tracker
    tracker = create_tracker(
        db_session, "Tracker to Delete", "Will be deleted", user.id
    )
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
    # Create a test user first
    user = create_test_user(db_session)

    # Create a tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = create_tracker(
        db_session, f"Tracker with Values {suffix}", "Has values", user.id
    )
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
    # Create a test user first
    user = create_test_user(db_session)

    # Create a tracker with unique name
    import uuid

    suffix = str(uuid.uuid4())[:8]
    tracker = create_tracker(
        db_session,
        f"Tracker with Values to Delete {suffix}",
        "Will be deleted",
        user.id,
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


def test_tracker_db_class_user_filtering(db_session):
    """Test the TrackerDB class with user filtering functionality."""
    # Create two test users
    user1 = create_test_user(db_session, "user1_123", "user1@example.com", "User One")
    user2 = create_test_user(db_session, "user2_456", "user2@example.com", "User Two")

    # Create TrackerDB instances for each user
    tracker_db_user1 = TrackerDB(db_session, user1.id)
    tracker_db_user2 = TrackerDB(db_session, user2.id)

    # Create trackers for each user
    tracker1 = tracker_db_user1.create_tracker("User 1 Tracker", "Belongs to user 1")
    tracker2 = tracker_db_user2.create_tracker("User 2 Tracker", "Belongs to user 2")

    db_session.flush()

    # Test that each user can only see their own trackers
    user1_trackers = tracker_db_user1.get_all_trackers()
    user2_trackers = tracker_db_user2.get_all_trackers()

    assert len(user1_trackers) == 1
    assert len(user2_trackers) == 1
    assert user1_trackers[0].name == "User 1 Tracker"
    assert user2_trackers[0].name == "User 2 Tracker"

    # Test that users cannot access each other's trackers
    user1_cannot_see_tracker2 = tracker_db_user1.get_tracker(tracker2.id)
    user2_cannot_see_tracker1 = tracker_db_user2.get_tracker(tracker1.id)

    assert user1_cannot_see_tracker2 is None
    assert user2_cannot_see_tracker1 is None

    # Test that users can access their own trackers
    user1_can_see_tracker1 = tracker_db_user1.get_tracker(tracker1.id)
    user2_can_see_tracker2 = tracker_db_user2.get_tracker(tracker2.id)

    assert user1_can_see_tracker1 is not None
    assert user2_can_see_tracker2 is not None
    assert user1_can_see_tracker1.name == "User 1 Tracker"
    assert user2_can_see_tracker2.name == "User 2 Tracker"


def test_tracker_db_class_without_user_context(db_session):
    """Test the TrackerDB class without user context (should see all trackers)."""
    # Create two test users
    user1 = create_test_user(
        db_session, "user1_789", "user1b@example.com", "User One B"
    )
    user2 = create_test_user(
        db_session, "user2_012", "user2b@example.com", "User Two B"
    )

    # Create TrackerDB instance without user context
    tracker_db_no_user = TrackerDB(db_session)

    # Create trackers for each user using the standalone functions
    tracker1 = create_tracker(
        db_session, "No Context Tracker 1", "First tracker", user1.id
    )
    tracker2 = create_tracker(
        db_session, "No Context Tracker 2", "Second tracker", user2.id
    )

    db_session.flush()

    # TrackerDB without user context should see all trackers
    all_trackers = tracker_db_no_user.get_all_trackers()

    # Should see at least the 2 trackers we just created (may see more from other tests)
    tracker_names = [t.name for t in all_trackers]
    assert "No Context Tracker 1" in tracker_names
    assert "No Context Tracker 2" in tracker_names

    # Should be able to access any tracker by ID
    found_tracker1 = tracker_db_no_user.get_tracker(tracker1.id)
    found_tracker2 = tracker_db_no_user.get_tracker(tracker2.id)

    assert found_tracker1 is not None
    assert found_tracker2 is not None
    assert found_tracker1.name == "No Context Tracker 1"
    assert found_tracker2.name == "No Context Tracker 2"


def test_tracker_db_class_user_context_management(db_session):
    """Test setting and getting user context on TrackerDB instances."""
    # Create test users
    user1 = create_test_user(
        db_session, "user1_345", "user1c@example.com", "User One C"
    )
    user2 = create_test_user(
        db_session, "user2_678", "user2c@example.com", "User Two C"
    )

    # Create TrackerDB instance without initial user context
    tracker_db = TrackerDB(db_session)

    # Test initial state
    assert tracker_db.get_user_context() is None

    # Set user context
    tracker_db.set_user_context(user1.id)
    assert tracker_db.get_user_context() == user1.id

    # Create a tracker - should be assigned to user1
    tracker = tracker_db.create_tracker("Context Test Tracker", "Testing context")
    db_session.flush()

    assert tracker.user_id == user1.id

    # Change user context
    tracker_db.set_user_context(user2.id)
    assert tracker_db.get_user_context() == user2.id

    # Now should not be able to see the tracker created for user1
    found_tracker = tracker_db.get_tracker(tracker.id)
    assert found_tracker is None

    # Clear user context
    tracker_db.set_user_context(None)
    assert tracker_db.get_user_context() is None

    # Now should be able to see the tracker again
    found_tracker = tracker_db.get_tracker(tracker.id)
    assert found_tracker is not None
    assert found_tracker.name == "Context Test Tracker"


def test_tracker_db_class_create_tracker_requires_user_id(db_session):
    """Test that creating a tracker requires a user ID."""
    # Create TrackerDB instance without user context
    tracker_db = TrackerDB(db_session)

    # Attempting to create a tracker without user_id should raise ValueError
    try:
        tracker_db.create_tracker("No User Tracker", "Should fail")
        assert False, "Expected ValueError when creating tracker without user ID"
    except ValueError as e:
        assert "User ID is required" in str(e)


def test_tracker_db_class_update_and_delete_operations(db_session):
    """Test update and delete operations with user filtering."""
    # Create test users
    user1 = create_test_user(
        db_session, "user1_901", "user1d@example.com", "User One D"
    )
    user2 = create_test_user(
        db_session, "user2_234", "user2d@example.com", "User Two D"
    )

    # Create TrackerDB instances
    tracker_db_user1 = TrackerDB(db_session, user1.id)
    tracker_db_user2 = TrackerDB(db_session, user2.id)

    # Create trackers
    tracker1 = tracker_db_user1.create_tracker("Update Test 1", "Original description")
    tracker2 = tracker_db_user2.create_tracker("Update Test 2", "Another description")

    db_session.flush()

    # Test update operations
    # User 1 should be able to update their own tracker
    updated_tracker = tracker_db_user1.update_tracker(
        tracker1.id, name="Updated Tracker 1", description="Updated description"
    )
    assert updated_tracker is not None
    assert updated_tracker.name == "Updated Tracker 1"
    assert updated_tracker.description == "Updated description"

    # User 1 should NOT be able to update user 2's tracker
    failed_update = tracker_db_user1.update_tracker(tracker2.id, name="Should not work")
    assert failed_update is None

    # Test delete operations
    # User 2 should be able to delete their own tracker
    delete_result = tracker_db_user2.delete_tracker(tracker2.id)
    assert delete_result is True

    # User 2 should NOT be able to delete user 1's tracker
    delete_result = tracker_db_user2.delete_tracker(tracker1.id)
    assert delete_result is False

    # Verify tracker1 still exists
    found_tracker = tracker_db_user1.get_tracker(tracker1.id)
    assert found_tracker is not None
    assert found_tracker.name == "Updated Tracker 1"


def test_tracker_db_class_utility_methods(db_session):
    """Test utility methods like tracker_exists and get_tracker_count."""
    # Create test user
    user = create_test_user(db_session, "user_util", "util@example.com", "Util User")

    # Create TrackerDB instance
    tracker_db = TrackerDB(db_session, user.id)

    # Initially no trackers
    assert tracker_db.get_tracker_count() == 0
    assert not tracker_db.tracker_exists("Nonexistent Tracker")

    # Create some trackers
    tracker1 = tracker_db.create_tracker("Utility Test 1", "First")
    tracker2 = tracker_db.create_tracker("Utility Test 2", "Second")

    db_session.flush()

    # Test count
    assert tracker_db.get_tracker_count() == 2

    # Test exists
    assert tracker_db.tracker_exists("Utility Test 1")
    assert tracker_db.tracker_exists("Utility Test 2")
    assert not tracker_db.tracker_exists("Nonexistent Tracker")

    # Create another user and verify isolation
    user2 = create_test_user(
        db_session, "user_util2", "util2@example.com", "Util User 2"
    )
    tracker_db_user2 = TrackerDB(db_session, user2.id)

    # User 2 should see no trackers
    assert tracker_db_user2.get_tracker_count() == 0
    assert not tracker_db_user2.tracker_exists("Utility Test 1")
