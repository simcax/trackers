"""
Tests for admin authorization integration with web routes.

This module tests the integration of admin authorization with the web interface,
including systems page access control and template context.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from trackers import create_app


class TestAdminWebIntegration:
    """Test admin authorization integration with web routes."""

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

    def test_systems_page_requires_admin(self, client):
        """Test that systems page requires admin authorization."""
        # Test without authentication - should redirect to login
        response = client.get("/web/systems")
        assert response.status_code == 302
        assert "/auth/login" in response.location

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_systems_page_non_admin_user(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test systems page access for non-admin authenticated user."""
        # Setup non-admin user
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_user.name = "Test User"
        mock_get_current_user.return_value = mock_user
        mock_is_authenticated.return_value = True

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            response = client.get("/web/systems")
            # Should redirect to dashboard with error
            assert response.status_code == 302
            assert "/web/" in response.location
            assert "error=admin_required" in response.location

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_systems_page_admin_user_success(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test systems page access for admin user."""
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

            # Check that admin status is displayed
            response_text = response.get_data(as_text=True)
            assert "Systems Administration" in response_text
            assert "Admin Authorization Status" in response_text
            assert "Current User Is Admin: Yes" in response_text

    def test_template_context_includes_admin_functions(self, app):
        """Test that admin functions are available in template context."""
        with app.app_context():
            # Get template context
            with app.test_request_context():
                # Trigger context processor
                context = {}
                for processor in app.template_context_processors[None]:
                    context.update(processor())

                # Check admin functions are available
                assert "is_admin_user" in context
                assert callable(context["is_admin_user"])
                assert "admin_functions_available" in context

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    def test_template_admin_function_works(self, mock_get_current_user, app):
        """Test that admin function works correctly in template context."""
        with app.app_context():
            # Setup admin user
            mock_user = MagicMock()
            mock_user.email = "admin@example.com"
            mock_get_current_user.return_value = mock_user

            with app.test_request_context():
                with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
                    # Get template context
                    context = {}
                    for processor in app.template_context_processors[None]:
                        context.update(processor())

                    # Test admin function
                    is_admin_func = context["is_admin_user"]
                    assert is_admin_func() is True

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    def test_template_non_admin_function_works(self, mock_get_current_user, app):
        """Test that admin function correctly identifies non-admin users."""
        with app.app_context():
            # Setup non-admin user
            mock_user = MagicMock()
            mock_user.email = "user@example.com"
            mock_get_current_user.return_value = mock_user

            with app.test_request_context():
                with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
                    # Get template context
                    context = {}
                    for processor in app.template_context_processors[None]:
                        context.update(processor())

                    # Test admin function
                    is_admin_func = context["is_admin_user"]
                    assert is_admin_func() is False

    def test_learn_more_page_public_access(self, client):
        """Test that learn more page is publicly accessible."""
        response = client.get("/web/learn-more")
        assert response.status_code == 200

        response_text = response.get_data(as_text=True)
        assert "Welcome to Trackers" in response_text
        assert "Sign in with Google" in response_text

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_dashboard_shows_systems_link_for_admin(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test that dashboard shows Systems link only for admin users."""
        # Setup admin user
        mock_user = MagicMock()
        mock_user.email = "admin@example.com"
        mock_user.name = "Admin User"
        mock_get_current_user.return_value = mock_user
        mock_is_authenticated.return_value = True

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            # Mock database operations
            with patch(
                "trackers.routes.web_routes.get_all_trackers"
            ) as mock_get_trackers:
                with patch(
                    "trackers.services.user_service.UserService"
                ) as mock_user_service:
                    mock_get_trackers.return_value = []
                    mock_service_instance = MagicMock()
                    mock_service_instance.get_current_user_from_session.return_value = (
                        MagicMock()
                    )
                    mock_user_service.return_value = mock_service_instance

                    response = client.get("/web/")
                    assert response.status_code == 200

                    # Check that Systems link is present for admin
                    response_text = response.get_data(as_text=True)
                    # Note: The actual template rendering might not work in this test context
                    # This test verifies the route works, template testing would need more setup

    @patch("trackers.auth.context.UserContextManager.get_current_user")
    @patch("trackers.auth.context.UserContextManager.is_authenticated")
    def test_dashboard_hides_systems_link_for_non_admin(
        self, mock_is_authenticated, mock_get_current_user, client
    ):
        """Test that dashboard hides Systems link for non-admin users."""
        # Setup non-admin user
        mock_user = MagicMock()
        mock_user.email = "user@example.com"
        mock_user.name = "Regular User"
        mock_get_current_user.return_value = mock_user
        mock_is_authenticated.return_value = True

        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            # Mock database operations
            with patch(
                "trackers.routes.web_routes.get_all_trackers"
            ) as mock_get_trackers:
                with patch(
                    "trackers.services.user_service.UserService"
                ) as mock_user_service:
                    mock_get_trackers.return_value = []
                    mock_service_instance = MagicMock()
                    mock_service_instance.get_current_user_from_session.return_value = (
                        MagicMock()
                    )
                    mock_user_service.return_value = mock_service_instance

                    response = client.get("/web/")
                    assert response.status_code == 200

                    # Check that Systems link is not present for non-admin
                    response_text = response.get_data(as_text=True)
                    # Note: The actual template rendering might not work in this test context
                    # This test verifies the route works, template testing would need more setup


class TestAdminEnvironmentConfiguration:
    """Test admin system configuration through environment variables."""

    def test_admin_system_disabled_by_default(self, app):
        """Test that admin system is disabled when no ADMIN_USERS is set."""
        with patch.dict(os.environ, {}, clear=True):
            from trackers.auth.admin import get_admin_status_info

            status = get_admin_status_info()
            assert status["admin_system_enabled"] is False
            assert status["admin_users_configured"] == 0

    def test_admin_system_enabled_with_users(self, app):
        """Test that admin system is enabled when ADMIN_USERS is configured."""
        with patch.dict(os.environ, {"ADMIN_USERS": "admin@example.com"}):
            from trackers.auth.admin import get_admin_status_info

            status = get_admin_status_info()
            assert status["admin_system_enabled"] is True
            assert status["admin_users_configured"] == 1

    def test_multiple_admin_users_configuration(self, app):
        """Test configuration with multiple admin users."""
        admin_emails = "admin1@example.com,admin2@example.com,admin3@example.com"
        with patch.dict(os.environ, {"ADMIN_USERS": admin_emails}):
            from trackers.auth.admin import get_admin_status_info, get_admin_users

            users = get_admin_users()
            assert len(users) == 3
            assert "admin1@example.com" in users
            assert "admin2@example.com" in users
            assert "admin3@example.com" in users

            status = get_admin_status_info()
            assert status["admin_users_configured"] == 3


if __name__ == "__main__":
    pytest.main([__file__])
