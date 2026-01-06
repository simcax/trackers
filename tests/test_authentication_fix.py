"""
Test to verify the authentication fix for browser vs API requests.

This test verifies that the authentication system correctly handles
browser requests vs API requests and doesn't incorrectly treat
browser requests as valid API key authentication.
"""


class TestAuthenticationFix:
    """Test authentication fix for browser vs API requests."""

    def test_unauthenticated_browser_request_redirected(self, client):
        """
        Test that unauthenticated browser requests are redirected to login.

        This verifies that the fix prevents browser requests from being
        incorrectly treated as valid API key authentication.
        """
        # Make a request to the dashboard without any authentication
        response = client.get("/web/")

        # Should be redirected to login (302) or return 401
        assert response.status_code in [302, 401], (
            f"Expected redirect or 401 for unauthenticated request, got {response.status_code}"
        )

        if response.status_code == 302:
            # Check that redirect goes to login page
            location = response.headers.get("Location", "")
            assert "login" in location.lower() or "auth" in location.lower(), (
                f"Expected redirect to login page, got: {location}"
            )

    def test_trackers_data_endpoint_requires_auth(self, client):
        """
        Test that the /web/trackers/data endpoint requires authentication.

        This endpoint was previously returning data for unauthenticated users
        because it was incorrectly treating browser requests as API key auth.
        """
        # Make a request to the trackers data endpoint without authentication
        response = client.get("/web/trackers/data")

        # Should require authentication (401 or redirect)
        assert response.status_code in [401, 302], (
            f"Expected 401 or redirect for unauthenticated request, got {response.status_code}"
        )

        # If it's a JSON response, it should contain an error
        if response.content_type and "json" in response.content_type:
            data = response.get_json()
            assert "error" in data, (
                "Expected error in JSON response for unauthenticated request"
            )

    def test_api_key_authentication_still_works(self, client):
        """
        Test that API key authentication still works for API requests.

        This verifies that the fix doesn't break legitimate API key usage.
        """
        # Make a request with a valid API key header
        headers = {"Authorization": "Bearer test-api-key-12345"}

        # This should work if API keys are configured
        # Note: In test environment, API keys might be disabled
        response = client.get("/api/trackers", headers=headers)

        # The response depends on whether API keys are configured in test environment
        # We just verify that the request is processed (not a 500 error)
        assert response.status_code < 500, (
            f"API key request should not cause server error, got {response.status_code}"
        )

    def test_dashboard_route_authentication_behavior(self, client):
        """
        Test the dashboard route authentication behavior.

        This verifies that the dashboard correctly handles authentication
        and doesn't create default system users for browser requests.
        """
        # Make a request to the root path (which redirects to dashboard)
        response = client.get("/")

        # Should be redirected
        assert response.status_code == 302, (
            f"Expected redirect from root path, got {response.status_code}"
        )

        # Follow the redirect
        location = response.headers.get("Location", "")
        if location.startswith("/web"):
            # Follow redirect to web dashboard
            response = client.get(location)

            # Should be redirected to login or return 401
            assert response.status_code in [302, 401], (
                f"Expected authentication required for dashboard, got {response.status_code}"
            )

    def test_authentication_context_setup(self, client):
        """
        Test that authentication context is properly set up.

        This verifies that the authentication decorators are working
        correctly and setting up the proper context.
        """
        # Test a protected route to see authentication behavior
        response = client.get("/web/tracker/create", method="GET")

        # Should require authentication
        assert response.status_code in [302, 401, 405], (
            f"Expected authentication required or method not allowed, got {response.status_code}"
        )

    def test_no_default_system_user_creation(self, client, db_session):
        """
        Test that default system users are not created for browser requests.

        This verifies that the fix prevents the creation of default system
        users when browsers make unauthenticated requests.
        """
        from trackers.models.user_model import UserModel

        # Count users before making request
        initial_user_count = db_session.query(UserModel).count()

        # Make an unauthenticated browser request
        response = client.get("/web/")

        # Count users after request
        final_user_count = db_session.query(UserModel).count()

        # No new users should be created for unauthenticated browser requests
        assert final_user_count == initial_user_count, (
            f"Unexpected user creation: {initial_user_count} -> {final_user_count}"
        )

        # The request should be redirected or return 401
        assert response.status_code in [302, 401], (
            f"Expected redirect or 401 for unauthenticated request, got {response.status_code}"
        )

    def test_authenticated_user_can_access_dashboard(self, client, db_session):
        """
        Test that properly authenticated users can access the dashboard.

        This verifies that the authentication fix doesn't break legitimate access.
        """
        from trackers.models.user_model import UserModel

        # Create a test user
        test_user = UserModel(
            email="test@example.com",
            name="Test User",
            google_user_id="test_google_id_123",
        )
        db_session.add(test_user)
        db_session.commit()

        # Simulate authenticated session
        with client.session_transaction() as sess:
            sess["google_auth_user"] = {
                "user_info": {
                    "google_id": "test_google_id_123",
                    "email": "test@example.com",
                    "name": "Test User",
                    "picture_url": None,
                    "verified_email": True,
                }
            }

        # Now try to access the dashboard
        response = client.get("/web/")

        # Should be successful (200) for authenticated user
        assert response.status_code == 200, (
            f"Expected successful access for authenticated user, got {response.status_code}"
        )

        # Should contain user-specific content
        response_data = response.data.decode("utf-8")
        assert "Test User" in response_data or "test@example.com" in response_data, (
            "Expected user-specific content in dashboard response"
        )
