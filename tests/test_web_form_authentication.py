"""
Test web form authentication for tracker value operations.

This test reproduces the production issue where creating trackers works
but adding values to existing trackers fails with unauthorized errors.
"""

import os
from datetime import datetime

import pytest

from trackers import create_app
from trackers.db.database import SessionLocal
from trackers.db.trackerdb import create_tracker


class TestWebFormAuthentication:
    """Test authentication for web form operations."""

    @pytest.fixture
    def app_with_api_key(self):
        """Create Flask app with API key authentication enabled."""
        # Set API key in environment before creating app
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

    @pytest.fixture
    def client_with_auth(self, app_with_api_key):
        """Create test client with authentication headers."""
        app, api_key = app_with_api_key
        client = app.test_client()

        # Set default headers for all requests
        client.environ_base["HTTP_AUTHORIZATION"] = f"Bearer {api_key}"

        return client, api_key

    def test_create_tracker_web_form_with_auth(self, client_with_auth):
        """Test creating a tracker via web form with authentication."""
        client, api_key = client_with_auth

        # Test creating tracker via web form (this should work)
        response = client.post(
            "/web/tracker/create",
            data={
                "name": "Test Tracker",
                "description": "Test Description",
                "unit": "kg",
                "goal": "100",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Should redirect to dashboard on success
        assert response.status_code in [200, 201, 302], (
            f"Expected success, got {response.status_code}: {response.get_data(as_text=True)}"
        )

        if response.status_code == 302:
            # Check redirect location contains success indicator
            location = response.headers.get("Location", "")
            assert "success" in location or "dashboard" in location

    def test_add_value_to_existing_tracker_web_form_with_auth(self, client_with_auth):
        """Test adding a value to existing tracker via web form with authentication."""
        client, api_key = client_with_auth

        # First create a tracker directly in database
        db = SessionLocal()
        try:
            tracker = create_tracker(
                db, name="Existing Tracker", description="Test tracker"
            )
            db.commit()
            tracker_id = tracker.id
        finally:
            db.close()

        # Now try to add a value to this tracker via web form
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": datetime.now().strftime("%Y-%m-%d")},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # This should work but might be failing in production
        print(f"Response status: {response.status_code}")
        print(f"Response data: {response.get_data(as_text=True)}")

        assert response.status_code in [200, 201, 302], (
            f"Expected success, got {response.status_code}: {response.get_data(as_text=True)}"
        )

        if response.status_code == 302:
            # Check redirect location contains success indicator
            location = response.headers.get("Location", "")
            assert "success" in location or "dashboard" in location

    def test_add_value_json_request_with_auth(self, client_with_auth):
        """Test adding a value via JSON request with authentication."""
        client, api_key = client_with_auth

        # First create a tracker directly in database
        db = SessionLocal()
        try:
            tracker = create_tracker(
                db, name="JSON Test Tracker", description="Test tracker"
            )
            db.commit()
            tracker_id = tracker.id
        finally:
            db.close()

        # Try adding value via JSON request
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            json={"value": "55", "date": datetime.now().strftime("%Y-%m-%d")},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        print(f"JSON Response status: {response.status_code}")
        print(f"JSON Response data: {response.get_data(as_text=True)}")

        assert response.status_code in [200, 201], (
            f"Expected success, got {response.status_code}: {response.get_data(as_text=True)}"
        )

    def test_dashboard_access_with_auth(self, client_with_auth):
        """Test accessing dashboard with authentication."""
        client, api_key = client_with_auth

        response = client.get("/web/", headers={"Authorization": f"Bearer {api_key}"})

        print(f"Dashboard response status: {response.status_code}")
        if response.status_code != 200:
            print(f"Dashboard response data: {response.get_data(as_text=True)}")

        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.get_data(as_text=True)}"
        )

    def test_authentication_system_status(self, app_with_api_key):
        """Test that authentication system is properly initialized."""
        app, api_key = app_with_api_key

        with app.app_context():
            # Check that security components are initialized
            assert hasattr(app, "security_config"), "Security config not initialized"
            assert hasattr(app, "key_validator"), "Key validator not initialized"
            assert hasattr(app, "security_logger"), "Security logger not initialized"

            # Check that authentication is enabled
            assert app.key_validator.is_authentication_enabled(), (
                "Authentication should be enabled"
            )

            # Check that our test key is valid
            assert app.key_validator.is_valid_key(api_key), (
                "Test API key should be valid"
            )

            # Check route protection configuration
            protected_routes = app.security_config.get_protected_routes()
            public_routes = app.security_config.get_public_routes()

            print(f"Protected routes: {protected_routes}")
            print(f"Public routes: {public_routes}")

            # Check if web routes are protected
            assert app.security_config.is_route_protected("/web/"), (
                "Web dashboard should be protected"
            )
            assert app.security_config.is_route_protected("/web/tracker/create"), (
                "Tracker creation should be protected"
            )
            assert app.security_config.is_route_protected("/web/tracker/1/value"), (
                "Value addition should be protected"
            )

    def test_route_protection_patterns(self, app_with_api_key):
        """Test specific route protection patterns that might be causing the issue."""
        app, api_key = app_with_api_key

        with app.app_context():
            # Test various route patterns
            test_routes = [
                "/web/",
                "/web/tracker/create",
                "/web/tracker/1/value",
                "/api/trackers",
                "/api/trackers/1/values",
                "/health",
                "/hello",
            ]

            for route in test_routes:
                is_protected = app.security_config.is_route_protected(route)
                print(f"Route {route}: {'PROTECTED' if is_protected else 'PUBLIC'}")

    def test_production_environment_route_protection(self):
        """Test route protection in production-like environment."""
        # Set production environment and API key
        test_api_key = "prod-api-key-1234567890abcdef"
        os.environ["FLASK_ENV"] = "production"
        os.environ["API_KEYS_PRODUCTION"] = test_api_key

        try:
            app = create_app(
                test_config={"TESTING": True, "SECRET_KEY": "test-secret-key"}
            )

            with app.app_context():
                # Check route protection in production
                print(f"Environment: {app.security_config.environment}")
                print(f"Protected routes: {app.security_config.get_protected_routes()}")
                print(f"Public routes: {app.security_config.get_public_routes()}")

                # Test web routes protection
                web_routes = ["/web/", "/web/tracker/create", "/web/tracker/1/value"]
                for route in web_routes:
                    is_protected = app.security_config.is_route_protected(route)
                    print(
                        f"Production route {route}: {'PROTECTED' if is_protected else 'PUBLIC'}"
                    )

                # Test with client
                client = app.test_client()

                # Try accessing without auth
                response = client.post("/web/tracker/1/value", data={"value": "42"})
                print(f"No auth response: {response.status_code}")

                # Try with auth
                response = client.post(
                    "/web/tracker/1/value",
                    data={"value": "42"},
                    headers={"Authorization": f"Bearer {test_api_key}"},
                )
                print(f"With auth response: {response.status_code}")

        finally:
            # Clean up environment
            for key in ["FLASK_ENV", "API_KEYS_PRODUCTION"]:
                if key in os.environ:
                    del os.environ[key]

    def test_web_routes_should_be_protected(self):
        """Test that demonstrates web routes should actually be protected."""
        # The current issue: web routes are public but have @api_key_required decorators
        # This creates inconsistency. Let's test what should happen.

        test_api_key = "test-api-key-1234567890abcdef"
        os.environ["API_KEYS"] = test_api_key
        # Override protected routes to include /web/*
        os.environ["PROTECTED_ROUTES"] = (
            "/api/*,/trackers/*,/tracker-values/*,/add_tracker,/web/*"
        )

        try:
            app = create_app(
                test_config={"TESTING": True, "SECRET_KEY": "test-secret-key"}
            )

            with app.app_context():
                print(f"Protected routes: {app.security_config.get_protected_routes()}")

                # Now web routes should be protected
                assert app.security_config.is_route_protected("/web/"), (
                    "Web dashboard should be protected"
                )
                assert app.security_config.is_route_protected("/web/tracker/create"), (
                    "Tracker creation should be protected"
                )
                assert app.security_config.is_route_protected("/web/tracker/1/value"), (
                    "Value addition should be protected"
                )

                client = app.test_client()

                # Create a tracker first
                db = SessionLocal()
                try:
                    import uuid

                    unique_name = f"Test Tracker {uuid.uuid4().hex[:8]}"
                    tracker = create_tracker(db, name=unique_name, description="Test")
                    db.commit()
                    tracker_id = tracker.id
                finally:
                    db.close()

                # Try without auth - should fail
                response = client.post(
                    f"/web/tracker/{tracker_id}/value", data={"value": "42"}
                )
                print(f"No auth response: {response.status_code}")
                assert response.status_code == 401, "Should require authentication"

                # Try with auth - should work
                response = client.post(
                    f"/web/tracker/{tracker_id}/value",
                    data={"value": "42"},
                    headers={"Authorization": f"Bearer {test_api_key}"},
                )
                print(f"With auth response: {response.status_code}")
                assert response.status_code in [200, 201, 302], (
                    "Should work with authentication"
                )

        finally:
            # Clean up environment
            for key in ["API_KEYS", "PROTECTED_ROUTES"]:
                if key in os.environ:
                    del os.environ[key]
