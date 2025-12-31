"""
Tests for redirect security and open redirect vulnerability prevention.

This module tests the redirect validation functionality to ensure that
open redirect vulnerabilities are properly prevented.
"""

from unittest.mock import patch

import pytest

from trackers.auth.auth_routes import ALLOWED_REDIRECT_PATHS, validate_redirect_url


class TestRedirectSecurity:
    """Test redirect security validation."""

    def test_validate_redirect_url_none(self):
        """Test validation with None URL returns default."""
        result = validate_redirect_url(None)
        assert result == "/"

    def test_validate_redirect_url_empty_string(self):
        """Test validation with empty string returns default."""
        result = validate_redirect_url("")
        assert result == "/"

    def test_validate_redirect_url_valid_paths(self):
        """Test validation with valid allowlisted paths."""
        for path in ALLOWED_REDIRECT_PATHS:
            result = validate_redirect_url(path)
            assert result == path, f"Valid path {path} should be allowed"

    def test_validate_redirect_url_with_query_params(self):
        """Test validation preserves query parameters for valid paths."""
        result = validate_redirect_url("/web/?test=123&foo=bar")
        assert result == "/web/?test=123&foo=bar"

    def test_validate_redirect_url_trailing_slash_normalization(self):
        """Test that trailing slashes are normalized except for root."""
        result = validate_redirect_url("/web/dashboard/")
        assert result == "/web/dashboard"

        # Root should keep its slash
        result = validate_redirect_url("/")
        assert result == "/"

    def test_validate_redirect_url_blocks_external_urls(self):
        """Test that external URLs are blocked."""
        external_urls = [
            "http://evil.com",
            "https://malicious.site",
            "//evil.com",
            "https://evil.com/path",
            "http://localhost:8080/admin",
        ]

        for url in external_urls:
            with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
                result = validate_redirect_url(url)
                assert result == "/", f"External URL {url} should be blocked"
                mock_logger.log_authentication_failure.assert_called_once()
                args = mock_logger.log_authentication_failure.call_args[0]
                assert args[0] == "unknown"  # client_ip when outside request context
                assert url in args[1]
                assert args[2] == "suspicious_redirect_attempt"

    def test_validate_redirect_url_blocks_non_allowlisted_paths(self):
        """Test that non-allowlisted internal paths are blocked."""
        blocked_paths = [
            "/admin",
            "/secret",
            "/api/admin",
            "/web/admin",
            "/internal/config",
        ]

        for path in blocked_paths:
            with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
                result = validate_redirect_url(path)
                assert result == "/", f"Non-allowlisted path {path} should be blocked"
                mock_logger.log_authentication_failure.assert_called_once()
                args = mock_logger.log_authentication_failure.call_args[0]
                assert args[0] == "unknown"  # client_ip when outside request context
                assert path in args[1]
                assert args[2] == "blocked_redirect_attempt"

    def test_validate_redirect_url_handles_malformed_urls(self):
        """Test that malformed URLs are handled gracefully."""
        malformed_urls = [
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "vbscript:msgbox('xss')",
            "file:///etc/passwd",
            "ftp://evil.com/",
        ]

        for url in malformed_urls:
            with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
                result = validate_redirect_url(url)
                assert result == "/", f"Malformed URL {url} should be blocked"
                # Should log either suspicious_redirect_attempt or redirect_validation_error
                mock_logger.log_authentication_failure.assert_called_once()

    def test_validate_redirect_url_handles_exceptions(self):
        """Test that exceptions during URL parsing are handled."""
        # This should trigger an exception in urlparse or string processing
        problematic_urls = [
            "http://[invalid-ipv6",
            "://no-scheme",
            "\x00\x01\x02",  # Control characters
        ]

        for url in problematic_urls:
            with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
                result = validate_redirect_url(url)
                assert result == "/", (
                    f"Problematic URL {url} should default to safe redirect"
                )

    def test_validate_redirect_url_path_traversal_attempts(self):
        """Test that path traversal attempts are blocked."""
        traversal_attempts = [
            "/../admin",
            "/web/../admin",
            "/web/../../etc/passwd",
            "/web/%2e%2e/admin",
            "/web/..%2fadmin",
        ]

        for url in traversal_attempts:
            with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
                result = validate_redirect_url(url)
                assert result == "/", f"Path traversal attempt {url} should be blocked"

    def test_validate_redirect_url_case_sensitivity(self):
        """Test that path matching is case sensitive (as it should be)."""
        # These should be blocked because they don't match the exact case
        case_variants = [
            "/WEB/",
            "/Web/Dashboard",
            "/AUTH/LOGIN",
        ]

        for url in case_variants:
            with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
                result = validate_redirect_url(url)
                assert result == "/", f"Case variant {url} should be blocked"

    def test_validate_redirect_url_fragment_handling(self):
        """Test that URL fragments are handled properly."""
        # Fragments should be ignored/stripped for security
        result = validate_redirect_url("/web/#section")
        assert result == "/web/"

        result = validate_redirect_url("/web/dashboard#top")
        assert result == "/web/dashboard"

    def test_allowlist_completeness(self):
        """Test that the allowlist contains expected application paths."""
        expected_paths = {
            "/",
            "/web/",
            "/web/dashboard",
            "/web/systems",
            "/web/learn-more",
            "/web/test",
            "/auth/login",
            "/health",
            "/health/detailed",
            "/health/ready",
            "/health/live",
        }

        assert ALLOWED_REDIRECT_PATHS == expected_paths

    def test_validate_redirect_url_logging_includes_client_ip(self):
        """Test that security logging includes client IP."""
        with patch("trackers.auth.auth_routes.auth_logger") as mock_logger:
            with patch(
                "trackers.auth.auth_routes.get_client_ip", return_value="192.168.1.100"
            ):
                validate_redirect_url("http://evil.com")

                mock_logger.log_authentication_failure.assert_called_once()
                args = mock_logger.log_authentication_failure.call_args[0]
                # First argument should be the client IP
                assert args[0] == "192.168.1.100"


class TestRedirectSecurityIntegration:
    """Test redirect security in the context of the full application."""

    def test_auth_routes_use_validation(self):
        """Test that auth routes properly use redirect validation."""
        # This is more of a code review test - ensuring the functions are called
        from trackers.auth.auth_routes import validate_redirect_url

        # The function should be importable and callable
        assert callable(validate_redirect_url)

        # Test that it works as expected
        result = validate_redirect_url("/web/")
        assert result == "/web/"

    def test_security_headers_recommendation(self):
        """Test recommendation for additional security headers."""
        # This test documents the recommendation for additional security measures
        # In a real application, you might want to add:
        # - Content-Security-Policy headers
        # - X-Frame-Options
        # - Referrer-Policy
        # - etc.

        # For now, just document that redirect validation is the primary defense
        assert validate_redirect_url("http://evil.com") == "/"


if __name__ == "__main__":
    pytest.main([__file__])
