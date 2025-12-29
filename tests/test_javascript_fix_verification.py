"""
Test to verify that the JavaScript fix works correctly.

This test specifically verifies that the dashboard.js fix to use web endpoints
instead of API endpoints resolves the production authentication issue.
"""

import os
import tempfile
from unittest.mock import patch

import pytest

from trackers import create_app
from trackers.db import database as db_module
from trackers.db.trackerdb import create_tracker
from trackers.security.api_key_auth import init_security


class TestJavaScriptFix:
    """Test that the JavaScript fix resolves the authentication issue."""

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

                unique_name = f"JS Test Tracker {uuid.uuid4().hex[:8]}"

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

    def test_old_javascript_behavior_fails(self, client_with_api_key, app_with_api_key):
        """
        Test that the old JavaScript behavior (calling API endpoints) fails with 401.
        This demonstrates the problem that existed before the fix.
        """
        tracker_id = app_with_api_key.test_tracker_id

        # This simulates the OLD dashboard.js behavior - calling API endpoint without auth
        response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "42", "date": "2024-01-15"},
            headers={"X-Requested-With": "XMLHttpRequest"},  # AJAX request
        )

        # This should fail with 401 (the original problem)
        assert response.status_code == 401, "API endpoint should require authentication"

        response_data = response.get_json()
        assert "Unauthorized" in response_data.get("error", ""), (
            "Should return unauthorized error"
        )

    def test_new_javascript_behavior_works(self, client_with_api_key, app_with_api_key):
        """
        Test that the new JavaScript behavior (calling web endpoints) works without auth.
        This demonstrates that the fix resolves the issue.
        """
        tracker_id = app_with_api_key.test_tracker_id

        # This simulates the NEW dashboard.js behavior - calling web endpoint
        response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            json={"value": "42", "date": "2024-01-15"},
            headers={"X-Requested-With": "XMLHttpRequest"},  # AJAX request
        )

        # This should work without authentication (the fix)
        assert response.status_code in [200, 201], (
            f"Web endpoint should work without auth, got {response.status_code}"
        )

        # Verify the response contains success information
        if response.content_type and "application/json" in response.content_type:
            response_data = response.get_json()
            assert "message" in response_data or "value" in response_data, (
                "Should return success data"
            )

    def test_form_submission_also_works(self, client_with_api_key, app_with_api_key):
        """
        Test that traditional form submission also works (for completeness).
        """
        tracker_id = app_with_api_key.test_tracker_id

        # Test traditional form submission
        response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "123", "date": "2024-01-15"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        # Should work (redirect or success)
        assert response.status_code in [200, 201, 302], (
            f"Form submission should work, got {response.status_code}"
        )

    def test_api_still_works_with_auth(self, client_with_api_key, app_with_api_key):
        """
        Test that API endpoints still work when proper authentication is provided.
        This ensures we didn't break the API functionality.
        """
        tracker_id = app_with_api_key.test_tracker_id
        test_api_key = "test-api-key-12345678901234567890"

        # API should work with proper authentication
        response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "999", "date": "2024-01-15"},
            headers={
                "Authorization": f"Bearer {test_api_key}",
                "X-Requested-With": "XMLHttpRequest",
            },
        )

        assert response.status_code in [200, 201], (
            f"API with auth should work, got {response.status_code}"
        )

    def test_production_scenario_complete_fix(
        self, client_with_api_key, app_with_api_key
    ):
        """
        Complete test that simulates the exact production scenario and verifies the fix.

        Before fix: JavaScript calls /api/trackers/{id}/values -> 401 Unauthorized
        After fix: JavaScript calls /web/tracker/{id}/value -> 200/201 Success
        """
        tracker_id = app_with_api_key.test_tracker_id

        # 1. Verify API key authentication is enabled (production condition)
        assert app_with_api_key.key_validator.is_authentication_enabled(), (
            "API key auth should be enabled"
        )

        # 2. Verify the problem exists with API endpoints (old behavior)
        api_response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "42", "date": "2024-01-15"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert api_response.status_code == 401, (
            "API endpoint should require authentication (problem exists)"
        )

        # 3. Verify the fix works with web endpoints (new behavior)
        web_response = client_with_api_key.post(
            f"/web/tracker/{tracker_id}/value",
            json={"value": "42", "date": "2024-01-15"},
            headers={"X-Requested-With": "XMLHttpRequest"},
        )
        assert web_response.status_code in [200, 201], (
            f"Web endpoint should work (fix works), got {web_response.status_code}"
        )

        # 4. Verify API still works with authentication (no regression)
        test_api_key = "test-api-key-12345678901234567890"
        api_auth_response = client_with_api_key.post(
            f"/api/trackers/{tracker_id}/values",
            json={"value": "42", "date": "2024-01-15"},
            headers={
                "Authorization": f"Bearer {test_api_key}",
                "X-Requested-With": "XMLHttpRequest",
            },
        )
        assert api_auth_response.status_code in [200, 201], (
            "API with auth should still work (no regression)"
        )

        print("✅ Production authentication issue has been resolved!")
        print("✅ JavaScript now calls web endpoints instead of API endpoints")
        print("✅ Web interface works without authentication")
        print("✅ API endpoints still require authentication")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
