"""
Comprehensive test for web form authentication issue.

This test reproduces the production issue where adding values to existing trackers
via the web form fails with unauthorized errors, even though the web interface
should be public and only API endpoints should require authentication.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from trackers import create_app
from trackers.db import database as db_module
from trackers.db.trackerdb import create_tracker
from trackers.security.api_key_auth import init_security


class TestWebFormAuthentication:
    """Test web form authentication behavior with API key loaded."""

    @pytest.fixture
    def app_with_api_key(self):
        """Create Flask app with API key authentication enabled."""
        # Create temporary database
        db_fd, db_path = tempfile.mkstemp()

        # Set environment variables for API key authentication
        test_api_key = "test-api-key-12345678901234567890"

        with patch.dict(
            os.environ,
            {
                "API_KEYS": test_api_key,
                "DATABASE_URL": f"sqlite:///{db_path}",
                "FLASK_ENV": "testing",
            },
        ):
            # Create app with authentication
            app = create_app()
            app.config["TESTING"] = True
            app.config["DATABASE_URL"] = f"sqlite:///{db_path}"

            # Initialize security system
            init_security(app)

            with app.app_context():
                # Create a test tracker with unique name
                import uuid

                unique_name = f"Test Tracker {uuid.uuid4().hex[:8]}"

                db = db_module.SessionLocal()
                try:
                    test_tracker = create_tracker(
                        db, name=unique_name, description="Test Description"
                    )
                    db.commit()
                    app.test_tracker_id = test_tracker.id
                finally:
                    db.close()

            yield app

            # Cleanup
            os.close(db_fd)
            os.unlink(db_path)

    @pytest.fixture
    def client_with_api_key(self, app_with_api_key):
        """Create test client with API key authentication enabled."""
        return app_with_api_key.test_client()

    def test_web_dashboard_is_public(self, client_with_api_key):
        """Test that web dashboard is accessible without API key."""
        response = client_with_api_key.get("/web/")

        # Should be accessible (200) or redirect (302), not unauthorized (401)
        assert response.status_code in [200, 302], (
            f"Dashboard should be public, got {response.status_code}"
        )
        assert response.status_code != 401, (
            "Dashboard should not require authentication"
        )

    def test_web_create_tracker_is_public(self, client_with_api_key):
        """Test that web tracker creation is accessible without API key."""
        response = client_with_api_key.post(
            "/web/tracker/create",
            data={
                "name": "Test Web Tracker",
                "description": "Created via web form",
                "unit": "units",
                "goal": "test goal",
            },
        )

        # Should be successful (201) or redirect (302), not unauthorized (401)
        assert response.status_code in [200, 201, 302], (
            f"Web tracker creation should be public, got {response.status_code}"
        )
        assert response.status_code != 401, (
            "Web tracker creation should not require authentication"
        )

    def test_web_add_value_is_public(self, client_with_api_key, app_with_api_key):
        """Test that web value addition is accessible without API key."""
        tracker_id = app_with_api_key.test_tracker_id

        response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": "2024-01-15"},
        )

        # Should be successful (201) or redirect (302), not unauthorized (401)
        assert response.status_code in [200, 201, 302], (
            f"Web value addition should be public, got {response.status_code}"
        )
        assert response.status_code != 401, (
            "Web value addition should not require authentication"
        )

    def test_api_endpoints_require_authentication(
        self, client_with_api_key, app_with_api_key
    ):
        """Test that API endpoints require authentication."""
        tracker_id = app_with_api_key.test_tracker_id

        # Test API tracker creation without auth
        response = client_with_api_key.post(
            "/api/trackers", json={"name": "API Tracker", "description": "Via API"}
        )
        assert response.status_code == 401, (
            "API tracker creation should require authentication"
        )

        # Test API value addition without auth
        response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "42", "date": "2024-01-15"},
        )
        assert response.status_code == 401, (
            "API value addition should require authentication"
        )

    def test_api_endpoints_work_with_authentication(
        self, client_with_api_key, app_with_api_key
    ):
        """Test that API endpoints work with proper authentication."""
        tracker_id = app_with_api_key.test_tracker_id
        test_api_key = "test-api-key-12345678901234567890"

        headers = {"Authorization": f"Bearer {test_api_key}"}

        # Test API value addition with auth
        response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "42", "date": "2024-01-15"},
            headers=headers,
        )
        assert response.status_code in [200, 201], (
            f"API value addition with auth should work, got {response.status_code}"
        )

    def test_javascript_api_call_issue(self, client_with_api_key, app_with_api_key):
        """
        Test that reproduces the JavaScript issue where dashboard.js calls API endpoints
        instead of web endpoints, causing unauthorized errors.
        """
        tracker_id = app_with_api_key.test_tracker_id

        # This simulates what dashboard.js is currently doing - calling API endpoint without auth
        response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "42", "date": "2024-01-15"},
            headers={"X-Requested-With": "XMLHttpRequest"},  # AJAX request
        )

        # This should fail with 401 (current behavior causing the issue)
        assert response.status_code == 401, "API endpoint should require authentication"

        # The fix should be to call the web endpoint instead
        response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            json={"value": "42", "date": "2024-01-15"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )

        # This should work without authentication
        assert response.status_code in [200, 201], (
            f"Web endpoint should work without auth, got {response.status_code}"
        )

    def test_web_form_submission_simulation(
        self, client_with_api_key, app_with_api_key
    ):
        """
        Test that simulates the actual web form submission from the "Add Today's Value" button.
        This is the comprehensive test requested by the user.
        """
        tracker_id = app_with_api_key.test_tracker_id

        # First, verify the dashboard loads
        dashboard_response = client_with_api_key.get("/web/")
        assert dashboard_response.status_code == 200, "Dashboard should load"

        # Simulate the "Add Today's Value" button click - this should use web endpoint
        form_data = {"value": "123.45", "date": "2024-01-15"}

        # Test form submission (what the button should do)
        response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            data=form_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        assert response.status_code in [200, 201, 302], (
            f"Form submission should work, got {response.status_code}"
        )
        assert response.status_code != 401, (
            "Form submission should not require authentication"
        )

        # Test AJAX submission (what dashboard.js should do)
        response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            json=form_data,
            headers={
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
            },
        )

        assert response.status_code in [200, 201], (
            f"AJAX submission should work, got {response.status_code}"
        )
        assert response.status_code != 401, (
            "AJAX submission should not require authentication"
        )

    def test_route_protection_configuration(self, app_with_api_key):
        """Test that route protection is configured correctly."""
        with app_with_api_key.app_context():
            security_config = app_with_api_key.security_config

            # Web routes should not be protected
            assert not security_config.is_route_protected("/web/"), (
                "Web dashboard should not be protected"
            )
            assert not security_config.is_route_protected("/web/tracker/create"), (
                "Web tracker creation should not be protected"
            )
            assert not security_config.is_route_protected("/web/tracker/1/value"), (
                "Web value addition should not be protected"
            )

            # API routes should be protected
            assert security_config.is_route_protected("/api/trackers"), (
                "API tracker endpoints should be protected"
            )
            assert security_config.is_route_protected("/api/trackers/1/values"), (
                "API value endpoints should be protected"
            )

    def test_production_scenario_simulation(
        self, client_with_api_key, app_with_api_key
    ):
        """
        Comprehensive test that simulates the exact production scenario:
        1. API key is loaded in Flask app
        2. Creating trackers works (web interface)
        3. Adding values to existing trackers should work (web interface)
        4. API endpoints should still require authentication
        """
        # Verify API key is loaded
        assert app_with_api_key.key_validator.is_authentication_enabled(), (
            "API key authentication should be enabled"
        )

        # Step 1: Create a tracker via web interface (this works in production)
        import uuid

        unique_tracker_name = f"Production Test Tracker {uuid.uuid4().hex[:8]}"

        create_response = client_with_api_key.post(
            "/web/tracker/create",
            data={
                "name": unique_tracker_name,
                "description": "Testing production scenario",
                "unit": "points",
                "goal": "100",
            },
        )
        assert create_response.status_code in [200, 201, 302], (
            "Tracker creation should work"
        )

        # Step 2: Try to add value to existing tracker (this fails in production)
        tracker_id = app_with_api_key.test_tracker_id

        # This should work without authentication (the fix we need)
        add_value_response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "75", "date": "2024-01-15"},
        )
        assert add_value_response.status_code in [200, 201, 302], (
            f"Adding value should work, got {add_value_response.status_code}"
        )
        assert add_value_response.status_code != 401, (
            "Adding value should not require authentication"
        )

        # Step 3: Verify API endpoints still require authentication
        api_response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "75", "date": "2024-01-15"},
        )
        assert api_response.status_code == 401, (
            "API endpoints should still require authentication"
        )

        # Step 4: Verify API works with proper authentication
        test_api_key = "test-api-key-12345678901234567890"
        api_auth_response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "75", "date": "2024-01-15"},
            headers={"Authorization": f"Bearer {test_api_key}"},
        )
        assert api_auth_response.status_code in [200, 201], (
            "API should work with authentication"
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
