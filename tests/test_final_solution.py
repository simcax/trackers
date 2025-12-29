"""
Final test demonstrating the correct solution to the production issue.

This test shows that:
1. Web interface is publicly accessible (no authentication required)
2. API endpoints require authentication
3. Both creating trackers and adding values work without authentication in the web interface
4. The production issue is completely resolved
"""

import os
from datetime import datetime

import pytest

from trackers import create_app
from trackers.db.database import SessionLocal
from trackers.db.trackerdb import create_tracker


class TestFinalSolution:
    """Test the final solution to the production authentication issue."""

    @pytest.fixture
    def app_with_auth(self):
        """Create Flask app with proper authentication configuration."""
        test_api_key = "final-solution-test-key-1234567890abcdef"
        os.environ["API_KEYS"] = test_api_key

        try:
            app = create_app(
                test_config={"TESTING": True, "SECRET_KEY": "test-secret-key"}
            )

            with app.app_context():
                yield app, test_api_key
        finally:
            if "API_KEYS" in os.environ:
                del os.environ["API_KEYS"]

    def test_complete_solution(self, app_with_auth):
        """Test that demonstrates the complete solution works correctly."""
        app, api_key = app_with_auth
        client = app.test_client()

        print("=== Testing Final Solution ===")

        # 1. Verify configuration is correct
        with app.app_context():
            protected_routes = app.security_config.get_protected_routes()
            print(f"Protected routes: {protected_routes}")

            # Web routes should NOT be protected
            assert not app.security_config.is_route_protected("/web/"), (
                "Web routes should be public"
            )
            # API routes should be protected
            assert app.security_config.is_route_protected("/trackers"), (
                "API routes should be protected"
            )

        # 2. Test web interface works WITHOUT authentication
        print("\n--- Testing Web Interface (No Auth Required) ---")

        # Dashboard access
        response = client.get("/web/")
        print(f"Dashboard access: {response.status_code}")
        assert response.status_code == 200, "Dashboard should be accessible"

        # Create tracker (this worked in production)
        response = client.post(
            "/web/tracker/create",
            data={
                "name": "Final Test Tracker",
                "description": "Testing final solution",
            },
        )
        print(f"Create tracker: {response.status_code}")
        assert response.status_code in [200, 201, 302], "Creating tracker should work"

        # Create a tracker for value testing
        db = SessionLocal()
        try:
            import uuid

            unique_name = f"Final Tracker {uuid.uuid4().hex[:8]}"
            tracker = create_tracker(db, name=unique_name, description="Final test")
            db.commit()
            tracker_id = tracker.id
            print(f"Created tracker with ID: {tracker_id}")
        finally:
            db.close()

        # Add value to existing tracker (this failed in production, now works)
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "999", "date": datetime.now().strftime("%Y-%m-%d")},
        )
        print(f"Add value to tracker: {response.status_code}")
        assert response.status_code in [200, 201, 302], "Adding value should work"

        # 3. Test API still requires authentication
        print("\n--- Testing API (Auth Required) ---")

        # API without auth should fail
        response = client.get("/trackers")
        print(f"API without auth: {response.status_code}")
        assert response.status_code == 401, "API should require auth"

        # API with auth should work
        response = client.get(
            "/trackers", headers={"Authorization": f"Bearer {api_key}"}
        )
        print(f"API with auth: {response.status_code}")
        assert response.status_code == 200, "API with auth should work"

        print("\n=== Solution Verified: Production Issue Resolved ===")
        print("✅ Web interface is publicly accessible")
        print("✅ API endpoints require authentication")
        print("✅ Both creating trackers and adding values work in web interface")
        print("✅ No more unauthorized errors in production")

    def test_production_scenario_simulation(self, app_with_auth):
        """Simulate the exact production scenario that was failing."""
        app, api_key = app_with_auth
        client = app.test_client()

        print("\n=== Simulating Production Scenario ===")

        # Step 1: User creates a tracker (this worked in production)
        print("Step 1: Creating tracker...")
        response = client.post(
            "/web/tracker/create",
            data={
                "name": "Production Scenario Tracker",
                "description": "Simulating production usage",
            },
        )
        assert response.status_code in [200, 201, 302], "Tracker creation should work"
        print("✅ Tracker creation successful")

        # Step 2: Get the tracker ID (simulate existing tracker)
        db = SessionLocal()
        try:
            import uuid

            unique_name = f"Existing Tracker {uuid.uuid4().hex[:8]}"
            existing_tracker = create_tracker(
                db, name=unique_name, description="Existing"
            )
            db.commit()
            tracker_id = existing_tracker.id
            print(f"✅ Existing tracker ID: {tracker_id}")
        finally:
            db.close()

        # Step 3: User tries to add value to existing tracker (this failed in production)
        print("Step 3: Adding value to existing tracker...")
        response = client.post(
            f"/web/tracker/{tracker_id}/value",
            data={"value": "42", "date": datetime.now().strftime("%Y-%m-%d")},
        )

        # This should now work (was returning 401 Unauthorized in production)
        assert response.status_code in [200, 201, 302], "Value addition should work"
        print("✅ Value addition successful - Production issue resolved!")

        if response.status_code == 302:
            location = response.headers.get("Location", "")
            print(f"✅ Redirected to: {location}")
            assert "success" in location, "Should redirect to success page"
