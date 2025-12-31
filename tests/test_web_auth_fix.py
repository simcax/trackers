"""
Tests for web authentication fix.

This module tests that the web interface correctly separates API key
authentication (for API endpoints) from Google OAuth authentication
(for web interface).
"""

from unittest.mock import patch

import pytest


class TestWebAuthenticationFix:
    """Test web authentication separation."""

    def test_dashboard_shows_unauthenticated_content_without_google_oauth(self, client):
        """Test that dashboard shows unauthenticated content when no Google OAuth."""

        # Mock the Google OAuth check to return False (no authentication)
        with patch(
            "trackers.auth.decorators._has_google_auth_configured", return_value=True
        ):
            with patch(
                "trackers.auth.decorators._check_google_oauth_auth",
                return_value=(False, None),
            ):
                response = client.get("/web/")

                # Should be successful
                assert response.status_code == 200

                # Should show unauthenticated landing page content
                content = response.get_data(as_text=True)
                assert "Welcome to Trackers" in content
                assert "Sign in with Google" in content
                assert "Learn More" in content

    def test_dashboard_shows_authenticated_content_with_google_oauth(self, client):
        """Test that dashboard shows authenticated content with Google OAuth."""

        from trackers.auth.token_validator import UserInfo

        # Create mock Google user
        google_user = UserInfo(
            email="test@example.com",
            name="Test User",
            google_id="123456789",
            picture_url="https://example.com/pic.jpg",
            verified_email=True,
        )

        # Mock the Google OAuth check to return True with user info
        with patch(
            "trackers.auth.decorators._has_google_auth_configured", return_value=True
        ):
            with patch(
                "trackers.auth.decorators._check_google_oauth_auth",
                return_value=(True, google_user),
            ):
                response = client.get("/web/")

                # Should be successful
                assert response.status_code == 200

                # Should show authenticated content
                content = response.get_data(as_text=True)
                # Should show user's name in title or welcome message
                assert "Test User" in content or "Test" in content

    def test_api_key_does_not_affect_web_authentication(self, client):
        """Test that API key presence doesn't affect web authentication status."""

        # Mock API key as valid but Google OAuth as not authenticated
        with patch(
            "trackers.auth.decorators._has_api_key_auth_configured", return_value=True
        ):
            with patch(
                "trackers.auth.decorators._check_api_key_auth", return_value=True
            ):
                with patch(
                    "trackers.auth.decorators._has_google_auth_configured",
                    return_value=True,
                ):
                    with patch(
                        "trackers.auth.decorators._check_google_oauth_auth",
                        return_value=(False, None),
                    ):
                        response = client.get("/web/")

                        # Should be successful
                        assert response.status_code == 200

                        # Should still show unauthenticated content (API key ignored for web)
                        content = response.get_data(as_text=True)
                        assert "Welcome to Trackers" in content
                        assert "Sign in with Google" in content

    def test_context_processor_provides_correct_auth_status(self, client):
        """Test that the context processor provides correct authentication status."""

        # Test unauthenticated state
        with patch(
            "trackers.auth.decorators._has_google_auth_configured", return_value=True
        ):
            with patch(
                "trackers.auth.decorators._check_google_oauth_auth",
                return_value=(False, None),
            ):
                response = client.get("/web/")
                content = response.get_data(as_text=True)

                # Should not show authenticated user elements
                assert (
                    "Create New Tracker" not in content
                    or "Sign in with Google" in content
                )

    def test_login_route_redirects_to_google_oauth(self, client):
        """Test that the login route correctly redirects to Google OAuth."""

        response = client.get("/auth/login", follow_redirects=False)

        # Should be a redirect
        assert response.status_code == 302

        # Should redirect to Google OAuth
        location = response.headers.get("Location", "")
        assert "accounts.google.com" in location
        assert "oauth2" in location
        assert "client_id=" in location
        assert "redirect_uri=" in location
        assert "scope=" in location
        assert "state=" in location

    def test_login_route_does_not_redirect_to_root(self, client):
        """Test that the login route no longer incorrectly redirects to root."""

        response = client.get("/auth/login", follow_redirects=False)

        # Should be a redirect
        assert response.status_code == 302

        # Should NOT redirect to root
        location = response.headers.get("Location", "")
        assert location != "/"
        assert not location.endswith("/")

        # Should redirect to Google OAuth instead
        assert "accounts.google.com" in location


if __name__ == "__main__":
    pytest.main([__file__])
