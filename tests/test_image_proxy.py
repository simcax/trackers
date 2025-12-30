"""
Tests for image proxy functionality to avoid Google rate limiting.
"""

import base64
import os
import tempfile
from unittest.mock import Mock, patch

import pytest
from PIL import Image

from trackers.utils.image_utils import get_avatar_initials, get_proxied_image_url


class TestImageUtils:
    """Test image utility functions."""

    def test_get_proxied_image_url_valid_google_url(self):
        """Test proxied URL generation for valid Google image URLs."""
        google_url = "https://lh3.googleusercontent.com/a/test-image"
        proxied_url = get_proxied_image_url(google_url)

        assert proxied_url is not None
        assert proxied_url.startswith("/images/profile/")

        # Verify the encoded URL can be decoded back
        encoded_part = proxied_url.split("/images/profile/")[1]
        decoded_url = base64.urlsafe_b64decode(encoded_part.encode()).decode()
        assert decoded_url == google_url

    def test_get_proxied_image_url_invalid_url(self):
        """Test that non-Google URLs return None."""
        invalid_urls = [
            "https://example.com/image.jpg",
            "https://facebook.com/profile.jpg",
            "http://lh3.googleusercontent.com/insecure",  # HTTP not HTTPS
            None,
            "",
        ]

        for url in invalid_urls:
            assert get_proxied_image_url(url) is None

    def test_get_avatar_initials_single_name(self):
        """Test initials generation for single names."""
        assert get_avatar_initials("Alice") == "A"
        assert get_avatar_initials("bob") == "B"
        assert get_avatar_initials("X") == "X"

    def test_get_avatar_initials_full_name(self):
        """Test initials generation for full names."""
        assert get_avatar_initials("John Doe") == "JD"
        assert get_avatar_initials("Alice Bob Charlie") == "AC"  # First and last
        assert get_avatar_initials("Mary Jane Watson Smith") == "MS"

    def test_get_avatar_initials_edge_cases(self):
        """Test initials generation for edge cases."""
        assert get_avatar_initials("") == "U"
        assert get_avatar_initials(None) == "U"
        assert get_avatar_initials("   ") == "U"
        assert get_avatar_initials("  John  Doe  ") == "JD"  # Extra spaces


class TestImageProxy:
    """Test image proxy route functionality."""

    @pytest.fixture
    def mock_app(self):
        """Create a mock Flask app for testing."""
        app = Mock()
        app.logger = Mock()
        return app

    def test_cache_path_generation(self):
        """Test that cache paths are generated consistently."""
        from trackers.routes.image_routes import get_cache_path

        url1 = "https://lh3.googleusercontent.com/a/test1"
        url2 = "https://lh3.googleusercontent.com/a/test2"

        path1a = get_cache_path(url1)
        path1b = get_cache_path(url1)  # Same URL
        path2 = get_cache_path(url2)  # Different URL

        # Same URL should generate same path
        assert path1a == path1b

        # Different URLs should generate different paths
        assert path1a != path2

        # Paths should be in the expected format
        assert path1a.endswith(".jpg")
        assert "image_cache" in path1a

    def test_cache_validity_check(self):
        """Test cache validity checking."""
        from trackers.routes.image_routes import is_cache_valid

        # Non-existent file should be invalid
        assert not is_cache_valid("/nonexistent/path.jpg")

        # Create a temporary file to test with
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Fresh file should be valid
            assert is_cache_valid(tmp_path)

            # Modify file time to be very old
            old_time = 0  # Unix epoch
            os.utime(tmp_path, (old_time, old_time))

            # Old file should be invalid
            assert not is_cache_valid(tmp_path)

        finally:
            os.unlink(tmp_path)

    @patch("trackers.routes.image_routes.requests.get")
    def test_download_and_cache_image_success(self, mock_get):
        """Test successful image download and caching."""
        from trackers.routes.image_routes import download_and_cache_image

        # Create a simple test image
        test_image = Image.new("RGB", (100, 100), color="red")

        # Mock the HTTP response
        mock_response = Mock()
        mock_response.headers = {"content-type": "image/jpeg"}
        mock_response.raise_for_status = Mock()

        # Convert image to bytes for mock response
        from io import BytesIO

        img_bytes = BytesIO()
        test_image.save(img_bytes, "JPEG")
        mock_response.content = img_bytes.getvalue()

        mock_get.return_value = mock_response

        # Test download and cache
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            cache_path = tmp.name

        try:
            os.unlink(cache_path)  # Remove the empty file

            result = download_and_cache_image(
                "https://lh3.googleusercontent.com/a/test", cache_path
            )

            assert result is True
            assert os.path.exists(cache_path)

            # Verify the cached image can be opened
            with Image.open(cache_path) as cached_img:
                assert cached_img.size[0] <= 200  # Should be resized
                assert cached_img.size[1] <= 200

        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    @patch("trackers.routes.image_routes.requests.get")
    def test_download_and_cache_image_failure(self, mock_get):
        """Test image download failure handling."""
        from trackers.routes.image_routes import download_and_cache_image

        # Mock HTTP error
        mock_get.side_effect = Exception("Network error")

        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            cache_path = tmp.name

        try:
            os.unlink(cache_path)  # Remove the empty file

            result = download_and_cache_image(
                "https://lh3.googleusercontent.com/a/test", cache_path
            )

            assert result is False
            assert not os.path.exists(cache_path)

        finally:
            if os.path.exists(cache_path):
                os.unlink(cache_path)

    def test_default_avatar_generation(self):
        """Test default avatar generation."""
        from trackers.routes.image_routes import generate_default_avatar

        with patch("trackers.routes.image_routes.send_file") as mock_send:
            mock_send.return_value = Mock()

            response = generate_default_avatar(100)

            # Should call send_file with image data
            mock_send.assert_called_once()
            call_args = mock_send.call_args

            # First argument should be BytesIO object
            assert hasattr(call_args[0][0], "read")

            # Should specify JPEG mimetype
            assert call_args[1]["mimetype"] == "image/jpeg"
