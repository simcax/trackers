"""
Test to verify the production fix for web form authentication.

This test demonstrates that the fix resolves the issue where:
- Creating trackers worked (because routes were public)
- Adding values to trackers failed (because @api_key_required decorator still enforced auth)

After the fix, both operations require authentication consistently.
"""

import os
from datetime import datetime

import pytest

from trackers import create_app
from trackers.db.database import SessionLocal
from trackers.db.trackerdb import create_tracker


class TestProductionFix:
    """Test the production authentication fix."""

    @pytest.fixture
    def app_with_auth(self):
        """Create Flask app with API key authentication enabled."""
        test_api_key = "production-fix-test-key-1234567890abcdef"
        os.environ["API_KEYS"] = test_api_key

        try:
            app = create_app(
                test_config={"TESTING": True, "SECRET_KEY": "test-secret-key"}
            )

            with app.app_context():
                yield app, test_api_key
        finally:
            # Clean up environment
            if "API_KEYS" in os.environ:
                del os.environ["API_KEYS"]

    def test_web_routes_now_require_authentication(self, app_with_auth):
        """Test that web routes now consistently require authentication."""
        app, api_key = app_with_auth
        client = app.test_client()

        # Verify that web routes are now protected
        with app.app_context():
            assert app.security_config.is_route_protected("/web/"), (
                "Web dashboard should be protected"
            )
            assert app.security_config.is_route_protected("/web/tracker/create"), (
                "Tracker creation should be protected"
            )
            assert app.security_config.is_route_protected("/web/tracker/1/value"), (
                "Value addition should be protected"
            )

        # Test 1: Creating tracker without auth should fail
        response = client.post(
            "/web/tracker/create",
            data={"name": "Unauthorized Tracker", "description": "This should fail"},
        )
        assert response.status_code == 401, "Creating tracker without auth should fail"

        # Test 2: Creating tracker with auth should work
        response = client.post(
            "/web/tracker/create",
            data={"name": "Authorized Tracker", "description": "This should work"},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert response.status_code in [200, 201, 302], (
            "Creating tracker with auth should work"
        )

        # Create a tracker for value testing
        db = SessionLocal()
        try:
            tracker = create_tracker(
                db, name="Test Tracker for Values", description="Test"
            )
            db.commit()
            tracker_id = tracker.id
        finally:
            db.close()

        # Test 3: Adding value without auth should fail
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": datetime.now().strftime("%Y-%m-%d")},
        )
        assert response.status_code == 401, "Adding value without auth should fail"

        # Test 4: Adding value with auth should work
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": datetime.now().strftime("%Y-%m-%d")},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert response.status_code in [200, 201, 302], (
            "Adding value with auth should work"
        )

    def test_api_routes_still_work(self, app_with_auth):
        """Test that API routes still work correctly after the fix."""
        app, api_key = app_with_auth
        client = app.test_client()

        # API routes should still require authentication
        response = client.get("/trackers")
        assert response.status_code == 401, "API without auth should fail"

        response = client.get(
            "/trackers", headers={"Authorization": f"Bearer {api_key}"}
        )
        assert response.status_code == 200, "API with auth should work"

    def test_public_routes_still_public(self, app_with_auth):
        """Test that public routes are still accessible without authentication."""
        app, api_key = app_with_auth
        client = app.test_client()

        # Health routes should still be public
        response = client.get("/health")
        assert response.status_code == 200, "Health route should be public"

        response = client.get("/hello")
        assert response.status_code == 200, "Hello route should be public"
