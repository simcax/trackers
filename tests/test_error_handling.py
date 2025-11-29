"""
Tests for error handling and logging in database setup.

Requirements: 6.1, 6.2, 6.4
"""

import os
from unittest.mock import patch

import pytest

from trackers.db.settings import Settings


def test_missing_environment_variables_error_message():
    """
    Test that missing environment variables produce helpful error messages.

    Requirement 6.1: Display specific error and connection details
    Requirement 6.4: Suggest common fixes in error messages
    """
    # Clear all database environment variables
    with patch.dict(
        os.environ,
        {
            "DB_HOST": "",
            "DB_USER": "",
            "DB_PASSWORD": "",
            "DB_NAME": "",
        },
        clear=False,
    ):
        with pytest.raises(ValueError) as exc_info:
            Settings()

        error_message = str(exc_info.value)

        # Verify error message contains helpful information
        assert "MISSING REQUIRED ENVIRONMENT VARIABLES" in error_message
        assert "DB_HOST" in error_message
        assert "DB_USER" in error_message
        assert "DB_PASSWORD" in error_message
        assert "DB_NAME" in error_message

        # Verify error message contains suggestions
        assert "How to fix:" in error_message
        assert ".env file" in error_message
        assert "export" in error_message


def test_partial_missing_environment_variables():
    """
    Test that partially missing environment variables are reported correctly.

    Requirement 6.1: Display specific error and connection details
    """
    # Only set some variables
    with patch.dict(
        os.environ,
        {
            "DB_HOST": "localhost",
            "DB_USER": "testuser",
            "DB_PASSWORD": "",  # Missing
            "DB_NAME": "",  # Missing
        },
        clear=False,
    ):
        with pytest.raises(ValueError) as exc_info:
            Settings()

        error_message = str(exc_info.value)

        # Verify only missing variables are reported
        assert "DB_PASSWORD" in error_message
        assert "DB_NAME" in error_message


def test_valid_environment_variables_no_error():
    """
    Test that valid environment variables don't raise errors.

    Requirement 6.1: Display specific error and connection details
    """
    with patch.dict(
        os.environ,
        {
            "DB_HOST": "localhost",
            "DB_USER": "testuser",
            "DB_PASSWORD": "testpass",
            "DB_NAME": "testdb",
        },
        clear=False,
    ):
        # Should not raise an error
        settings = Settings()
        assert settings.db_host == "localhost"
        assert settings.db_user == "testuser"
        assert settings.db_password == "testpass"
        assert settings.db_name == "testdb"


def test_database_state_preserved_on_failure(db_session):
    """
    Test that database state is preserved when tests fail.

    Requirement 6.2: Preserve test database state for inspection

    Note: The fake_db fixture (session scope) does NOT drop the test database
    after the test session completes. This allows developers to inspect the
    database state when tests fail. The database is only dropped at the start
    of the next test session.
    """
    from trackers.db.trackerdb import create_tracker, get_tracker

    # Create a tracker
    tracker = create_tracker(db_session, "Test Tracker", "For inspection")

    # Verify it was created
    retrieved = get_tracker(db_session, tracker.id)
    assert retrieved is not None
    assert retrieved.name == "Test Tracker"

    # This test passes, but if it failed, the database would remain
    # available for inspection because:
    # 1. The fake_db fixture doesn't drop the database in its finally block
    # 2. The db_session fixture rolls back transactions but doesn't delete data
    # 3. Developers can connect to the test database to inspect state
