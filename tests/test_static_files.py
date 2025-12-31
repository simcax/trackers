"""
Tests for static file serving.

This module tests that static files are properly served in both
development and production environments.
"""

import pytest


class TestStaticFiles:
    """Test static file serving functionality."""

    def test_css_file_is_served(self, client):
        """Test that CSS files are properly served."""
        response = client.get("/static/css/dist/output.css")

        # Should be successful
        assert response.status_code == 200

        # Should have correct content type
        assert response.headers.get("Content-Type") == "text/css; charset=utf-8"

        # Should have content
        assert len(response.data) > 0

    def test_javascript_file_is_served(self, client):
        """Test that JavaScript files are properly served."""
        response = client.get("/static/js/dashboard.js")

        # Should be successful
        assert response.status_code == 200

        # Should have correct content type
        assert response.headers.get("Content-Type") == "text/javascript; charset=utf-8"

        # Should have content
        assert len(response.data) > 0

    def test_html_test_file_is_served(self, client):
        """Test that HTML test files are properly served."""
        response = client.get("/static/test-form.html")

        # Should be successful
        assert response.status_code == 200

        # Should have correct content type
        assert "text/html" in response.headers.get("Content-Type", "")

        # Should have content
        assert len(response.data) > 0

    def test_nonexistent_static_file_returns_404(self, client):
        """Test that nonexistent static files return 404."""
        response = client.get("/static/nonexistent.css")

        # Should return 404
        assert response.status_code == 404

    def test_static_file_path_traversal_protection(self, client):
        """Test that path traversal attacks are prevented."""
        # Try to access files outside the static directory
        response = client.get("/static/../trackers/__init__.py")

        # Should return 404 or 400, not 200
        assert response.status_code in [400, 404]

    def test_static_files_have_cache_headers(self, client):
        """Test that static files have appropriate cache headers."""
        response = client.get("/static/css/dist/output.css")

        # Should be successful
        assert response.status_code == 200

        # Should have cache control headers
        assert "Cache-Control" in response.headers

        # Should have ETag for caching
        assert "ETag" in response.headers


if __name__ == "__main__":
    pytest.main([__file__])
