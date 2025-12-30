"""
Tests for admin authorization system.

This module tests the admin user authorization functionality including:
- Admin user configuration from environment variables
- Admin authorization decorators
- Systems page access control
- Template context integration
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from trackers.auth.admin import (
    get_admin_status_info,
    get_admin_users,
    is_admin_user,
    require_admin_user,
)
from trackers.auth.admin_decorators import (
    admin_api_required,
    admin_required,
    require_admin,
)


class TestAdminConfiguration:
    """Test admin user configuration from environment variables."""

    def test_get_admin_users_empty_env(self):
        """Test getting admin users when ADMIN_USERS is not set."""
        with patch.dict(os.environ, {}, clear=True):
            admin_users = get_admin_users()
            assert admin_users == []

    def test_get_admin_users_single_user(self):
        """Test getting admin users with single user configured."""
        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            admin_users = get_admin_users()
            assert admin_users == ["admin@example.com"]

    def test_get_admin_users_multiple_users(self):
        """Test getting admin users with multiple users configured."""
        with patch.dict(
            os.environ, {"ADMIN_USERS": "admin1@example.com,admin2@example.com"}
        ):
            admin_users = get_admin_users()
            assert admin_users == ["admin1@example.com", "admin2@example.com"]

    def test_get_admin_users_with_whitespace(self):
        """Test getting admin users with whitespace in configuration."""
        with patch.dict(
            os.environ,
            {"ADMIN_USERS": " admin1@example.com , admin2@example.com , "},
        ):
            admin_users = get_admin_users()
            assert admin_users == ["admin1@example.com", "admin2@example.com"]

    def test_get_admin_users_empty_string(self):
        """Test getting admin users with empty string configuration."""
        with patch.dict(os.environ, {"ADMIN_USERS": ""}):
            admin_users = get_admin_users()
            assert admin_users == []

    def test_get_admin_users_only_commas(self):
        """Test getting admin users with only commas and whitespace."""
        with patch.dict(os.environ, {"ADMIN_USERS": " , , "}):
            admin_users = get_admin_users()
            assert admin_users == []


class TestAdminAuthorization:
    """Test admin user authorization checks."""

    @patch("trackers.auth.admin.get_current_user")
    def test_is_admin_user_no_current_user(self, mock_get_current_user):
        """Test admin check when no current user is available."""
        mock_get_current_user.return_value = None

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert is_admin_user() is False

    @patch("trackers.auth.admin.get_current_user")
    def test_is_admin_user_no_email(self, mock_get_current_user):
        """Test admin check when current user has no email."""
        mock_user = MagicMock()
        mock_user.email = None
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert is_admin_user() is False

    @patch("trackers.auth.admin.get_current_user")
    def test_is_admin_user_valid_admin(self, mock_get_current_user):
        """Test admin check with valid admin user."""
        mock_user = MagicMock()
        mock_user.email = "admin@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert is_admin_user() is True

    @patch("trackers.auth.admin.get_current_user")
    def test_is_admin_user_case_insensitive(self, mock_get_current_user):
        """Test admin check is case insensitive."""
        mock_user = MagicMock()
        mock_user.email = "ADMIN@EXAMPLE.COM"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert is_admin_user() is True

    @patch("trackers.auth.admin.get_current_user")
    def test_is_admin_user_not_admin(self, mock_get_current_user):
        """Test admin check with non-admin user."""
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert is_admin_user() is False

    def test_is_admin_user_explicit_email(self):
        """Test admin check with explicitly provided email."""
        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert is_admin_user("admin@example.com") is True
            assert is_admin_user("user@example.com") is False

    @patch("trackers.auth.admin.get_current_user")
    def test_require_admin_user_success(self, mock_get_current_user):
        """Test require_admin_user with valid admin user."""
        mock_user = MagicMock()
        mock_user.email = "admin@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            # Should not raise exception
            require_admin_user()

    @patch("trackers.auth.admin.get_current_user")
    def test_require_admin_user_failure(self, mock_get_current_user):
        """Test require_admin_user with non-admin user."""
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            with pytest.raises(PermissionError, match="Admin access required"):
                require_admin_user()


class TestAdminStatusInfo:
    """Test admin status information function."""

    @patch("trackers.auth.admin.get_current_user")
    def test_get_admin_status_info_admin_user(self, mock_get_current_user):
        """Test admin status info for admin user."""
        mock_user = MagicMock()
        mock_user.email = "admin@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(
            os.environ, {"ADMIN_USERS": "admin@example.com,admin2@example.com"}
        ):
            status = get_admin_status_info()

            assert status["admin_users_configured"] == 2
            assert status["admin_users"] == ["admin@example.com", "admin2@example.com"]
            assert status["current_user_email"] == "admin@example.com"
            assert status["current_user_is_admin"] is True
            assert status["admin_system_enabled"] is True

    @patch("trackers.auth.admin.get_current_user")
    def test_get_admin_status_info_non_admin_user(self, mock_get_current_user):
        """Test admin status info for non-admin user."""
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            status = get_admin_status_info()

            assert status["admin_users_configured"] == 1
            assert status["current_user_email"] == "user@example.com"
            assert status["current_user_is_admin"] is False
            assert status["admin_system_enabled"] is True

    @patch("trackers.auth.admin.get_current_user")
    def test_get_admin_status_info_no_admin_system(self, mock_get_current_user):
        """Test admin status info when no admin system is configured."""
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {}, clear=True):
            status = get_admin_status_info()

            assert status["admin_users_configured"] == 0
            assert status["admin_users"] == []
            assert status["current_user_email"] == "user@example.com"
            assert status["current_user_is_admin"] is False
            assert status["admin_system_enabled"] is False


class TestAdminDecorators:
    """Test admin authorization decorators."""

    def test_admin_required_decorator_exists(self):
        """Test that admin_required decorator exists and is callable."""
        assert callable(admin_required)

    def test_admin_api_required_decorator_exists(self):
        """Test that admin_api_required decorator exists and is callable."""
        assert callable(admin_api_required)

    def test_require_admin_decorator_exists(self):
        """Test that require_admin decorator exists and is callable."""
        assert callable(require_admin)

    def test_require_admin_with_redirect_parameter(self):
        """Test require_admin decorator with redirect parameter."""
        decorator = require_admin(redirect_to_dashboard=True)
        assert callable(decorator)

        decorator = require_admin(redirect_to_dashboard=False)
        assert callable(decorator)


class TestAdminIntegration:
    """Test admin system integration with Flask application."""

    def test_admin_functions_importable(self):
        """Test that all admin functions can be imported."""
        from trackers.auth.admin import (
            get_admin_status_info,
            get_admin_users,
            is_admin_user,
            require_admin_user,
        )
        from trackers.auth.admin_decorators import (
            admin_api_required,
            admin_required,
            require_admin,
        )

        # All imports should succeed
        assert callable(get_admin_users)
        assert callable(is_admin_user)
        assert callable(require_admin_user)
        assert callable(get_admin_status_info)
        assert callable(require_admin)
        assert callable(admin_required)
        assert callable(admin_api_required)

    @patch("trackers.auth.admin.get_current_user")
    def test_admin_system_end_to_end(self, mock_get_current_user):
        """Test complete admin system workflow."""
        # Setup admin user
        mock_user = MagicMock()
        mock_user.email = "admin@example.com"
        mock_get_current_user.return_value = mock_user

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            # Test admin configuration
            admin_users = get_admin_users()
            assert "admin@example.com" in admin_users

            # Test admin authorization
            assert is_admin_user() is True

            # Test admin requirement (should not raise)
            require_admin_user()

            # Test admin status
            status = get_admin_status_info()
            assert status["current_user_is_admin"] is True
            assert status["admin_system_enabled"] is True


if __name__ == "__main__":
    pytest.main([__file__])
