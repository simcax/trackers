"""
Test that the web interface is publicly accessible without API keys.

This test verifies that:
1. Web interface routes do not require authentication
2. API routes still require authentication
3. The production issue is resolved correctly
"""

import os
from datetime import datetime

import pytest

from trackers import create_app
from trackers.db.database import SessionLocal
from trackers.db.trackerdb import create_tracker


class TestWebPublicAccess:
    """Test that web interface is publicly accessible."""

    @pytest.fixture
    def app_with_auth(self):
        """Create Flask app with API key authentication enabled for API routes only."""
        test_api_key = "test-api-key-1234567890abcdef"
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

    def test_web_routes_are_public(self, app_with_auth):
        """Test that web routes are accessible without authentication."""
        app, api_key = app_with_auth
        client = app.test_client()

        # Verify that web routes are NOT protected
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

        # Test 1: Dashboard should be accessible without auth
        response = client.get("/web/")
        assert response.status_code == 200, (
            "Dashboard should be accessible without auth"
        )

        # Test 2: Creating tracker without auth should work
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

        # Create a tracker for value testing
        db = SessionLocal()
        try:
            import uuid

            unique_name = f"Public Test Tracker {uuid.uuid4().hex[:8]}"
            tracker = create_tracker(db, name=unique_name, description="Test")
            db.commit()
            tracker_id = tracker.id
        finally:
            db.close()

        # Test 3: Adding value without auth should work
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": datetime.now().strftime("%Y-%m-%d")},
        )
        assert response.status_code in [200, 201, 302], (
            "Adding value without auth should work"
        )

    def test_api_routes_still_require_auth(self, app_with_auth):
        """Test that API routes still require authentication."""
        app, api_key = app_with_auth
        client = app.test_client()

        # API routes should still require authentication
        response = client.get("/trackers")
        assert response.status_code == 401, "API without auth should fail"

        response = client.get(
            "/trackers", headers={"Authorization": f"Bearer {api_key}"}
        )
        assert response.status_code == 200, "API with auth should work"

    def test_production_issue_resolved(self, app_with_auth):
        """Test that the original production issue is resolved."""
        app, api_key = app_with_auth
        client = app.test_client()

        # Create a tracker (this worked in production)
        response = client.post(
            "/web/tracker/create",
            data={
                "name": "Production Test Tracker",
                "description": "Testing production fix",
            },
        )
        assert response.status_code in [200, 201, 302], "Creating tracker should work"

        # Create a tracker in database for value testing
        db = SessionLocal()
        try:
            import uuid

            unique_name = f"Production Tracker {uuid.uuid4().hex[:8]}"
            tracker = create_tracker(
                db, name=unique_name, description="Production test"
            )
            db.commit()
            tracker_id = tracker.id
        finally:
            db.close()

        # Add value to existing tracker (this failed in production, should work now)
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "100", "date": datetime.now().strftime("%Y-%m-%d")},
        )
        assert response.status_code in [200, 201, 302], (
            "Adding value should work (production issue fixed)"
        )

    def test_route_protection_configuration(self, app_with_auth):
        """Test that route protection is configured correctly."""
        app, api_key = app_with_auth

        with app.app_context():
            protected_routes = app.security_config.get_protected_routes()
            public_routes = app.security_config.get_public_routes()

            # Web routes should NOT be in protected routes
            assert "/web/*" not in protected_routes, (
                "Web routes should not be protected"
            )

            # API routes should be protected
            assert "/api/*" in protected_routes, "API routes should be protected"
            assert "/trackers/*" in protected_routes, (
                "Tracker API routes should be protected"
            )

            # Health routes should be public
            assert "/health" in public_routes or "/health/*" in public_routes, (
                "Health routes should be public"
            )
