"""
Tests for User Service operations.

This module tests the UserService class for CRUD operations on users,
OAuth integration, and session management helpers.

Requirements: 5.1, 5.2, 5.3
"""

from datetime import datetime

import pytest

from trackers.auth.token_validator import UserInfo
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


def test_create_or_update_user_new_user(db_session):
    """Test creating a new user from Google OAuth info."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create new user
    user = user_service.create_or_update_user(user_info)

    assert user.id is not None
    assert user.google_user_id == "test_google_123"
    assert user.email == "test@example.com"
    assert user.name == "Test User"
    assert user.profile_picture_url == "https://example.com/profile.jpg"
    assert user.created_at is not None
    assert user.updated_at is not None


def test_create_or_update_user_existing_user(db_session):
    """Test updating an existing user from Google OAuth info."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create initial user
    user1 = user_service.create_or_update_user(user_info)
    original_created_at = user1.created_at

    # Update with new information
    updated_user_info = create_test_user_info(
        name="Updated Test User",
        picture_url="https://example.com/new_profile.jpg",
    )
    user2 = user_service.create_or_update_user(updated_user_info)

    # Should be the same user, but updated
    assert user1.id == user2.id
    assert user2.name == "Updated Test User"
    assert user2.profile_picture_url == "https://example.com/new_profile.jpg"
    assert user2.created_at == original_created_at  # Should not change
    assert user2.updated_at > original_created_at  # Should be updated


def test_create_or_update_user_email_conflict(db_session):
    """Test handling user with same email but different Google ID."""
    user_service = UserService(db_session)

    # Create user with first Google ID
    user_info1 = create_test_user_info(
        google_id="google_123",
        email="test@example.com",
        name="Test User 1",
    )
    user1 = user_service.create_or_update_user(user_info1)

    # Try to create user with same email but different Google ID
    user_info2 = create_test_user_info(
        google_id="google_456",
        email="test@example.com",
        name="Test User 2",
    )
    user2 = user_service.create_or_update_user(user_info2)

    # Should update the existing user's Google ID
    assert user1.id == user2.id
    assert user2.google_user_id == "google_456"
    assert user2.name == "Test User 2"


def test_create_or_update_user_invalid_data(db_session):
    """Test error handling for invalid user data."""
    user_service = UserService(db_session)

    # Test with None user info
    with pytest.raises(ValueError, match="Invalid Google user information"):
        user_service.create_or_update_user(None)

    # Test with missing Google ID
    user_info = UserInfo(
        google_id="",
        email="test@example.com",
        name="Test User",
        picture_url=None,
        verified_email=True,
    )
    with pytest.raises(ValueError, match="Invalid Google user information"):
        user_service.create_or_update_user(user_info)

    # Test with missing email
    user_info = UserInfo(
        google_id="test_123",
        email="",
        name="Test User",
        picture_url=None,
        verified_email=True,
    )
    with pytest.raises(ValueError, match="User email is required"):
        user_service.create_or_update_user(user_info)

    # Test with missing name
    user_info = UserInfo(
        google_id="test_123",
        email="test@example.com",
        name="",
        picture_url=None,
        verified_email=True,
    )
    with pytest.raises(ValueError, match="User name is required"):
        user_service.create_or_update_user(user_info)


def test_get_user_by_google_id(db_session):
    """Test retrieving user by Google ID."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create user
    created_user = user_service.create_or_update_user(user_info)

    # Retrieve by Google ID
    retrieved_user = user_service.get_user_by_google_id("test_google_123")

    assert retrieved_user is not None
    assert retrieved_user.id == created_user.id
    assert retrieved_user.google_user_id == "test_google_123"

    # Test with non-existent Google ID
    non_existent = user_service.get_user_by_google_id("non_existent")
    assert non_existent is None

    # Test with empty Google ID
    empty_result = user_service.get_user_by_google_id("")
    assert empty_result is None


def test_get_user_by_email(db_session):
    """Test retrieving user by email."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create user
    created_user = user_service.create_or_update_user(user_info)

    # Retrieve by email
    retrieved_user = user_service.get_user_by_email("test@example.com")

    assert retrieved_user is not None
    assert retrieved_user.id == created_user.id
    assert retrieved_user.email == "test@example.com"

    # Test with non-existent email
    non_existent = user_service.get_user_by_email("nonexistent@example.com")
    assert non_existent is None

    # Test with empty email
    empty_result = user_service.get_user_by_email("")
    assert empty_result is None


def test_get_user_by_id(db_session):
    """Test retrieving user by database ID."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create user
    created_user = user_service.create_or_update_user(user_info)

    # Retrieve by ID
    retrieved_user = user_service.get_user_by_id(created_user.id)

    assert retrieved_user is not None
    assert retrieved_user.id == created_user.id

    # Test with non-existent ID
    non_existent = user_service.get_user_by_id(99999)
    assert non_existent is None

    # Test with invalid ID
    invalid_result = user_service.get_user_by_id(0)
    assert invalid_result is None

    negative_result = user_service.get_user_by_id(-1)
    assert negative_result is None


def test_update_last_login(db_session):
    """Test updating user's last login timestamp."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create user
    user = user_service.create_or_update_user(user_info)
    assert user.last_login_at is None

    # Update last login
    success = user_service.update_last_login(user.id)
    assert success is True

    # Refresh user from database
    db_session.refresh(user)
    assert user.last_login_at is not None
    assert isinstance(user.last_login_at, datetime)

    # Test with non-existent user ID
    failure = user_service.update_last_login(99999)
    assert failure is False

    # Test with invalid user ID
    invalid_failure = user_service.update_last_login(0)
    assert invalid_failure is False


def test_get_current_user_from_session(db_session, app):
    """Test getting current user from Flask session."""
    with app.test_request_context():
        from flask import session

        user_service = UserService(db_session)
        user_info = create_test_user_info()

        # Create user in database
        user = user_service.create_or_update_user(user_info)

        # Set up Flask session data directly
        session["google_auth_user"] = {
            "user_info": {
                "google_id": "test_google_123",
                "email": "test@example.com",
                "name": "Test User",
            }
        }

        # Get current user from session
        current_user = user_service.get_current_user_from_session()

        assert current_user is not None
        assert current_user.id == user.id
        assert current_user.google_user_id == "test_google_123"

        # Test with no session data
        session.clear()
        no_user = user_service.get_current_user_from_session()
        assert no_user is None

        # Test with invalid session data
        session["google_auth_user"] = {"invalid": "data"}
        invalid_user = user_service.get_current_user_from_session()
        assert invalid_user is None


def test_require_authenticated_user(db_session, app):
    """Test requiring authenticated user."""
    with app.test_request_context():
        from flask import session

        user_service = UserService(db_session)
        user_info = create_test_user_info()

        # Create user in database
        user = user_service.create_or_update_user(user_info)

        # Set up Flask session data directly
        session["google_auth_user"] = {
            "user_info": {
                "google_id": "test_google_123",
                "email": "test@example.com",
                "name": "Test User",
            }
        }

        # Should return user when authenticated
        authenticated_user = user_service.require_authenticated_user()
        assert authenticated_user.id == user.id

        # Should raise exception when not authenticated
        session.clear()
        with pytest.raises(ValueError, match="User authentication required"):
            user_service.require_authenticated_user()


def test_is_user_authenticated(db_session, app):
    """Test checking if user is authenticated."""
    with app.test_request_context():
        from flask import session

        user_service = UserService(db_session)
        user_info = create_test_user_info()

        # Create user in database
        user = user_service.create_or_update_user(user_info)

        # Set up Flask session data directly
        session["google_auth_user"] = {
            "user_info": {
                "google_id": "test_google_123",
                "email": "test@example.com",
                "name": "Test User",
            }
        }

        # Should return True when authenticated
        assert user_service.is_user_authenticated() is True

        # Should return False when not authenticated
        session.clear()
        assert user_service.is_user_authenticated() is False


def test_get_user_session_info(db_session, app):
    """Test getting user session information."""
    with app.test_request_context():
        from flask import session

        user_service = UserService(db_session)
        user_info = create_test_user_info()

        # Create user in database
        user = user_service.create_or_update_user(user_info)

        # Set up Flask session data directly
        session["google_auth_user"] = {
            "user_info": {
                "google_id": "test_google_123",
                "email": "test@example.com",
                "name": "Test User",
            }
        }

        # Get session info when authenticated
        session_info = user_service.get_user_session_info()

        assert session_info["authenticated"] is True
        assert session_info["user_id"] == user.id
        assert session_info["email"] == "test@example.com"
        assert session_info["name"] == "Test User"
        assert session_info["google_user_id"] == "test_google_123"

        # Get session info when not authenticated
        session.clear()
        no_auth_info = user_service.get_user_session_info()

        assert no_auth_info["authenticated"] is False
        assert no_auth_info["user_id"] is None
        assert no_auth_info["email"] is None
        assert no_auth_info["name"] is None


def test_delete_user(db_session):
    """Test deleting a user."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create user
    user = user_service.create_or_update_user(user_info)
    user_id = user.id

    # Delete user
    success = user_service.delete_user(user_id)
    assert success is True

    # Verify user is deleted
    deleted_user = user_service.get_user_by_id(user_id)
    assert deleted_user is None

    # Test deleting non-existent user
    failure = user_service.delete_user(99999)
    assert failure is False

    # Test with invalid user ID
    invalid_failure = user_service.delete_user(0)
    assert invalid_failure is False


def test_update_user_profile(db_session):
    """Test updating user profile information."""
    user_service = UserService(db_session)
    user_info = create_test_user_info()

    # Create user
    user = user_service.create_or_update_user(user_info)
    original_updated_at = user.updated_at

    # Update profile
    updated_user = user_service.update_user_profile(
        user.id,
        name="Updated Name",
        profile_picture_url="https://example.com/new.jpg",
    )

    assert updated_user is not None
    assert updated_user.name == "Updated Name"
    assert updated_user.profile_picture_url == "https://example.com/new.jpg"
    assert updated_user.updated_at > original_updated_at

    # Test updating only name
    name_only_user = user_service.update_user_profile(user.id, name="Name Only")
    assert name_only_user.name == "Name Only"
    assert (
        name_only_user.profile_picture_url == "https://example.com/new.jpg"
    )  # Should remain

    # Test with non-existent user
    no_user = user_service.update_user_profile(99999, name="Test")
    assert no_user is None

    # Test with invalid user ID
    invalid_user = user_service.update_user_profile(0, name="Test")
    assert invalid_user is None


def test_get_all_users(db_session):
    """Test getting all users with pagination."""
    user_service = UserService(db_session)

    # Create multiple users
    users = []
    for i in range(5):
        user_info = create_test_user_info(
            google_id=f"google_{i}",
            email=f"user{i}@example.com",
            name=f"User {i}",
        )
        user = user_service.create_or_update_user(user_info)
        users.append(user)

    # Get all users
    all_users = user_service.get_all_users()
    assert len(all_users) == 5

    # Test with limit
    limited_users = user_service.get_all_users(limit=3)
    assert len(limited_users) == 3

    # Test with offset
    offset_users = user_service.get_all_users(offset=2)
    assert len(offset_users) == 3

    # Test with limit and offset
    paginated_users = user_service.get_all_users(limit=2, offset=1)
    assert len(paginated_users) == 2


def test_get_user_count(db_session):
    """Test getting total user count."""
    user_service = UserService(db_session)

    # Initially should be 0
    assert user_service.get_user_count() == 0

    # Create users
    for i in range(3):
        user_info = create_test_user_info(
            google_id=f"google_{i}",
            email=f"user{i}@example.com",
            name=f"User {i}",
        )
        user_service.create_or_update_user(user_info)

    # Should now be 3
    assert user_service.get_user_count() == 3
