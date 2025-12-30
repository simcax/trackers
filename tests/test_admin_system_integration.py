"""
Integration tests for the complete admin authorization system.

This module tests the end-to-end functionality of the admin system
including environment configuration, route protection, and user experience.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from trackers import create_app


class TestAdminSystemIntegration:
    """Test complete admin system integration."""

    @pytest.fixture
    def app(self):
        """Create test Flask application."""
        app = create_app()
        app.config["TESTING"] = True
        return app

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_admin_system_disabled_by_default(self, client):
        """Test that admin system is disabled when no ADMIN_USERS is configured."""
        with patch.dict(os.environ, {}, clear=True):
            # Systems page should redirect to login (no admin access)
            response = client.get("/web/systems")
            assert response.status_code == 302
            assert "/auth/login" in response.location

    def test_admin_system_enabled_with_configuration(self, client):
        """Test that admin system works when ADMIN_USERS is configured."""
        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            # Non-authenticated access should still redirect to login
            response = client.get("/web/systems")
            assert response.status_code == 302
            assert "/auth/login" in response.location

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_non_admin_user_blocked(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test that non-admin authenticated users are blocked from systems page."""
        # Setup non-admin user
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_user.name = "Regular User"
        mock_get_current_user.return_value = mock_user
        mock_is_authenticated.return_value = True

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            response = client.get("/web/systems")
            # Should redirect to dashboard with admin_required error
            assert response.status_code == 302
            assert "/web/" in response.location
            assert "error=admin_required" in response.location

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_admin_user_allowed(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test that admin users can access the systems page."""
        # Setup admin user
        mock_user = MagicMock()
        mock_user.email = "admin@example.com"
        mock_user.name = "Admin User"
        mock_user.google_id = "123456789"
        mock_get_current_user.return_value = mock_user
        mock_is_authenticated.return_value = True

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            response = client.get("/web/systems")
            assert response.status_code == 200

            # Verify it's the systems page
            response_text = response.get_data(as_text=True)
            assert "Systems Administration" in response_text

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_case_insensitive_admin_matching(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test that admin email matching is case insensitive."""
        # Setup admin user with different case
        mock_user = MagicMock()
        mock_user.email = "ADMIN@EXAMPLE.COM"  # Uppercase
        mock_user.name = "Admin User"
        mock_get_current_user.return_value = mock_user
        mock_is_authenticated.return_value = True

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):  # Lowercase
            response = client.get("/web/systems")
            assert response.status_code == 200

            response_text = response.get_data(as_text=True)
            assert "Systems Administration" in response_text

    def test_multiple_admin_users_configuration(self, client):
        """Test configuration with multiple admin users."""
        admin_emails = "admin1@example.com,admin2@example.com,admin3@example.com"

        with patch.dict(os.environ, {"ADMIN_USERS": admin_emails}):
            # Test each admin user can access
            for email in [
                "admin1@example.com",
                "admin2@example.com",
                "admin3@example.com",
            ]:
                with patch(
                    "trackers.auth.context.UserContextManager.get_current_user"
                ) as mock_get_user:
                    with patch(
                        "trackers.auth.context.UserContextManager.is_authenticated"
                    ) as mock_auth:
                        mock_user = MagicMock()
                        mock_user.email = email
                        mock_user.name = f"Admin User {email}"
                        mock_get_user.return_value = mock_user
                        mock_auth.return_value = True

                        response = client.get("/web/systems")
                        assert response.status_code == 200, (
                            f"Admin user {email} should have access"
                        )

    def test_learn_more_page_remains_public(self, client):
        """Test that learn more page remains publicly accessible regardless of admin config."""
        # Test without admin configuration
        with patch.dict(os.environ, {}, clear=True):
            response = client.get("/web/learn-more")
            assert response.status_code == 200

        # Test with admin configuration
        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            response = client.get("/web/learn-more")
            assert response.status_code == 200

    def test_dashboard_remains_accessible(self, client):
        """Test that dashboard remains accessible regardless of admin config."""
        # Mock database operations to avoid database dependency
        with patch("trackers.routes.web_routes.get_all_trackers") as mock_get_trackers:
            with patch(
                "trackers.services.user_service.UserService"
            ) as mock_user_service:
                mock_get_trackers.return_value = []
                mock_service_instance = MagicMock()
                mock_service_instance.get_current_user_from_session.return_value = None
                mock_user_service.return_value = mock_service_instance

                # Test without admin configuration
                with patch.dict(os.environ, {}, clear=True):
                    response = client.get("/web/")
                    assert response.status_code == 200

                # Test with admin configuration
                with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
                    response = client.get("/web/")
                    assert response.status_code == 200

    def test_admin_configuration_validation(self):
        """Test admin configuration parsing and validation."""
        from trackers.auth.admin import get_admin_users

        # Test empty configuration
        with patch.dict(os.environ, {}, clear=True):
            assert get_admin_users() == []

        # Test single user
        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            assert get_admin_users() == ["admin@example.com"]

        # Test multiple users with whitespace
        with patch.dict(
            os.environ, {"ADMIN_USERS": " admin1@example.com , admin2@example.com "}
        ):
            users = get_admin_users()
            assert len(users) == 2
            assert "admin1@example.com" in users
            assert "admin2@example.com" in users

        # Test empty string handling
        with patch.dict(os.environ, {"ADMIN_USERS": ""}):
            assert get_admin_users() == []

    def test_admin_status_information(self):
        """Test admin status information function."""
        from trackers.auth.admin import get_admin_status_info

        # Test with no admin configuration
        with patch.dict(os.environ, {}, clear=True):
            with patch("trackers.auth.admin.get_current_user") as mock_get_user:
                mock_user = MagicMock()
                mock_user.email = "user@example.com"
                mock_get_user.return_value = mock_user

                status = get_admin_status_info()
                assert status["admin_system_enabled"] is False
                assert status["admin_users_configured"] == 0
                assert status["current_user_is_admin"] is False

        # Test with admin configuration
        with patch.dict(
            os.environ, {"ADMIN_USERS": "admin@example.com,admin2@example.com"}
        ):
            with patch("trackers.auth.admin.get_current_user") as mock_get_user:
                mock_user = MagicMock()
                mock_user.email = "admin@example.com"
                mock_get_user.return_value = mock_user

                status = get_admin_status_info()
                assert status["admin_system_enabled"] is True
                assert status["admin_users_configured"] == 2
                assert status["current_user_is_admin"] is True

    def test_template_context_integration(self, app):
        """Test that admin functions are properly integrated into template context."""
        with app.app_context():
            with app.test_request_context():
                # Get template context
                context = {}
                for processor in app.template_context_processors[None]:
                    try:
                        context.update(processor())
                    except Exception:
                        # Some context processors might fail in test environment
                        pass

                # Check that admin functions are available
                assert "is_admin_user" in context
                assert callable(context["is_admin_user"])


if __name__ == "__main__":
    pytest.main([__file__])
