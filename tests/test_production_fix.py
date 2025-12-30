"""
Test to verify the production fix for web form authentication.

This test demonstrates that the fix resolves the issue where:
- Web interface should be public (no authentication required)
- API endpoints should require authentication
- The production fix ensures JavaScript uses web endpoints instead of API endpoints

After the fix, web routes are public and API routes require authentication.
"""

import os
from datetime import datetime

import pytest

from trackers import create_app
from trackers.db.database import SessionLocal
from trackers.models.tracker_model import TrackerModel


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

    def test_web_routes_are_public_after_fix(self, app_with_auth):
        """Test that web routes are public and don't require authentication (production fix)."""
        app, api_key = app_with_auth
        client = app.test_client()

        # Verify that web routes are NOT protected (they should be public)
        with app.app_context():
            assert not app.security_config.is_route_protected("/web/"), (
                "Web dashboard should be public"
            )
            assert not app.security_config.is_route_protected("/web/tracker/create"), (
                "Tracker creation should be public"
            )
            assert not app.security_config.is_route_protected("/web/tracker/1/value"), (
                "Value addition should be public"
            )

        # Test 1: Creating tracker without auth should work (public access)
        response = client.post(
            "/web/tracker/create",
            data={
                "name": "Public Tracker",
                "description": "This should work without auth",
            },
        )
        assert response.status_code in [200, 201, 302], (
            "Creating tracker without auth should work"
        )

        # Test 2: Web dashboard should be accessible without auth
        response = client.get("/web/")
        assert response.status_code == 200, (
            "Web dashboard should be accessible without auth"
        )

        # Test 3: Create a tracker for value testing
        response = client.post(
            "/web/tracker/create",
            data={"name": "Test Tracker for Values", "description": "Test"},
        )
        assert response.status_code in [200, 201, 302], "Creating tracker should work"

        # Get the tracker ID from the database for testing
        db = SessionLocal()
        try:
            tracker = (
                db.query(TrackerModel).filter_by(name="Test Tracker for Values").first()
            )
            assert tracker is not None, "Tracker should be created"
            tracker_id = tracker.id
        finally:
            db.close()

        # Test 4: Adding value without auth should work (public access)
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": datetime.now().strftime("%Y-%m-%d")},
        )
        assert response.status_code in [200, 201, 302], (
            "Adding value without auth should work"
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
