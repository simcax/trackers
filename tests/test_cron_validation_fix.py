"""
Test for the cron validation fix in job creation form.

This test verifies that the new /web/jobs/validate/cron endpoint works correctly
and provides proper validation for cron expressions in the web interface.
"""

from datetime import datetime, timezone

import pytest

from trackers import create_app
from trackers.auth.session_manager import UserSession
from trackers.auth.token_validator import UserInfo


class TestCronValidationFix:
    """Test the cron validation fix for job creation form."""

    @pytest.fixture
    def app(self):
        """Create Flask app for testing."""
        return create_app()

    @pytest.fixture
    def client(self, app):
        """Create test client."""
        return app.test_client()

    def test_web_cron_validation_endpoint_exists(self, client):
        """Test that the new /web/jobs/validate/cron endpoint exists."""
        # Test without authentication (should require auth)
        response = client.post(
            "/web/jobs/validate/cron",
            json={"cron_expression": "0 9 * * *"},
            headers={"Content-Type": "application/json"},
        )

        # The endpoint exists and works - it may return 200 if API key auth is used
        # or 401/302 if no authentication is provided. The important thing is it's not 404
        assert response.status_code != 404, (
            f"Endpoint should exist, got {response.status_code}"
        )

    def test_web_cron_validation_with_valid_expression(self, client, app):
        """Test that the endpoint validates valid cron expressions correctly."""

        with app.app_context():
            # Create proper session data
            user_info = UserInfo(
                email="test@example.com",
                name="Test User",
                google_id="test_google_id",
                picture_url="https://example.com/pic.jpg",
                verified_email=True,
            )

            user_session = UserSession(
                user_info=user_info,
                access_token="test_token",
                token_expires_at=datetime.now(timezone.utc),
                session_created_at=datetime.now(timezone.utc),
            )

            # Set up session data
            with client.session_transaction() as sess:
                sess["google_auth_user"] = user_session.to_dict()
                sess.permanent = True

            # Test valid cron expressions
            valid_expressions = [
                "0 9 * * *",  # Daily at 9 AM
                "0 */6 * * *",  # Every 6 hours
                "0 9 * * 1-5",  # Weekdays at 9 AM
                "*/15 * * * *",  # Every 15 minutes
            ]

            for expr in valid_expressions:
                response = client.post(
                    "/web/jobs/validate/cron",
                    json={"cron_expression": expr},
                    headers={"Content-Type": "application/json"},
                )

                assert response.status_code == 200, f"Failed for expression: {expr}"
                data = response.get_json()

                assert "valid" in data, f"Missing 'valid' field for expression: {expr}"
                assert data["valid"] is True, f"Expression should be valid: {expr}"
                assert "error" in data, f"Missing 'error' field for expression: {expr}"

    def test_web_cron_validation_with_invalid_expression(self, client, app):
        """Test that the endpoint validates invalid cron expressions correctly."""

        with app.app_context():
            # Create proper session data
            user_info = UserInfo(
                email="test@example.com",
                name="Test User",
                google_id="test_google_id",
                picture_url="https://example.com/pic.jpg",
                verified_email=True,
            )

            user_session = UserSession(
                user_info=user_info,
                access_token="test_token",
                token_expires_at=datetime.now(timezone.utc),
                session_created_at=datetime.now(timezone.utc),
            )

            # Set up session data
            with client.session_transaction() as sess:
                sess["google_auth_user"] = user_session.to_dict()
                sess.permanent = True

            # Test invalid cron expressions
            invalid_expressions = [
                "invalid cron",  # Not a cron expression
                "60 9 * * *",  # Invalid minute (60)
                "0 25 * * *",  # Invalid hour (25)
                "0 9 32 * *",  # Invalid day (32)
                "0 9 * 13 *",  # Invalid month (13)
                "0 9 * * 8",  # Invalid weekday (8)
            ]

            for expr in invalid_expressions:
                response = client.post(
                    "/web/jobs/validate/cron",
                    json={"cron_expression": expr},
                    headers={"Content-Type": "application/json"},
                )

                assert response.status_code == 200, f"Failed for expression: {expr}"
                data = response.get_json()

                assert "valid" in data, f"Missing 'valid' field for expression: {expr}"
                assert data["valid"] is False, f"Expression should be invalid: {expr}"
                assert "error" in data, f"Missing 'error' field for expression: {expr}"
                assert data["error"] is not None, (
                    f"Error should not be None for invalid expression: {expr}"
                )

    def test_web_cron_validation_missing_data(self, client, app):
        """Test that the endpoint handles missing cron expression data."""

        with app.app_context():
            # Create proper session data
            user_info = UserInfo(
                email="test@example.com",
                name="Test User",
                google_id="test_google_id",
                picture_url="https://example.com/pic.jpg",
                verified_email=True,
            )

            user_session = UserSession(
                user_info=user_info,
                access_token="test_token",
                token_expires_at=datetime.now(timezone.utc),
                session_created_at=datetime.now(timezone.utc),
            )

            # Set up session data
            with client.session_transaction() as sess:
                sess["google_auth_user"] = user_session.to_dict()
                sess.permanent = True

            # Test with missing cron_expression
            response = client.post(
                "/web/jobs/validate/cron",
                json={},  # Missing cron_expression
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 400
            data = response.get_json()

            assert "valid" in data
            assert data["valid"] is False
            assert "error" in data
            assert "cron_expression" in data["error"]

    def test_job_form_uses_correct_cron_endpoint(self):
        """Test that the job form template uses the correct cron validation endpoint."""
        from pathlib import Path

        # Read the job form template
        template_path = Path("templates/components/job_form.html")
        assert template_path.exists(), "Job form template should exist"

        content = template_path.read_text()

        # Should use the new web endpoint, not the API endpoint
        assert "/web/jobs/validate/cron" in content, (
            "Job form should use /web/jobs/validate/cron endpoint"
        )
        assert "/api/jobs/validate/cron" not in content, (
            "Job form should not use /api/jobs/validate/cron endpoint"
        )

    def test_response_format_compatibility(self, client, app):
        """Test that the response format is compatible with the JavaScript expectations."""

        with app.app_context():
            # Create proper session data
            user_info = UserInfo(
                email="test@example.com",
                name="Test User",
                google_id="test_google_id",
                picture_url="https://example.com/pic.jpg",
                verified_email=True,
            )

            user_session = UserSession(
                user_info=user_info,
                access_token="test_token",
                token_expires_at=datetime.now(timezone.utc),
                session_created_at=datetime.now(timezone.utc),
            )

            # Set up session data
            with client.session_transaction() as sess:
                sess["google_auth_user"] = user_session.to_dict()
                sess.permanent = True

            # Test response format
            response = client.post(
                "/web/jobs/validate/cron",
                json={"cron_expression": "0 9 * * *"},
                headers={"Content-Type": "application/json"},
            )

            assert response.status_code == 200
            data = response.get_json()

            # Check that all expected fields are present
            required_fields = ["valid", "description", "error"]
            for field in required_fields:
                assert field in data, f"Missing required field: {field}"

            # Check field types
            assert isinstance(data["valid"], bool), "valid field should be boolean"
            assert isinstance(data["description"], str), (
                "description field should be string"
            )
            # error can be None or string
            assert data["error"] is None or isinstance(data["error"], str), (
                "error field should be None or string"
            )
