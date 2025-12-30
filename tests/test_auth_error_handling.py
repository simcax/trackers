"""
Tests for comprehensive error handling and logging in Google OAuth authentication.

Requirements: 7.1, 7.2, 7.3, 7.4
"""

from unittest.mock import Mock, patch

import pytest
import requests
from flask import Flask

from trackers.auth.error_handling import (
    AuthError,
    AuthLogger,
    NetworkError,
    NetworkRetryHandler,
    OAuthConfigError,
    RateLimiter,
    RateLimitError,
    TokenExchangeError,
    create_error_response,
    get_client_ip,
    with_error_handling,
)


@pytest.fixture
def app():
    """Create a Flask app for testing."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    return app


class TestAuthErrors:
    """Test authentication error classes."""

    def test_auth_error_base_class(self):
        """Test base AuthError class functionality."""
        error = AuthError(
            message="Test error",
            error_code="test_error",
            status_code=400,
            details={"key": "value"},
        )

        assert error.message == "Test error"
        assert error.error_code == "test_error"
        assert error.status_code == 400
        assert error.details == {"key": "value"}
        assert "authentication error occurred" in error.user_message.lower()

    def test_oauth_config_error(self):
        """Test OAuth configuration error."""
        error = OAuthConfigError(
            message="Missing config", missing_config=["client_id", "client_secret"]
        )

        assert error.error_code == "oauth_config_error"
        assert error.status_code == 500
        assert error.details["missing_config"] == ["client_id", "client_secret"]
        assert "not properly configured" in error.user_message

    def test_token_exchange_error(self):
        """Test token exchange error."""
        error = TokenExchangeError(
            message="Token exchange failed", google_error="invalid_grant"
        )

        assert error.error_code == "token_exchange_failed"
        assert error.status_code == 400
        assert error.details["google_error"] == "invalid_grant"
        assert "unable to complete authentication" in error.user_message.lower()

    def test_rate_limit_error(self):
        """Test rate limiting error."""
        error = RateLimitError(message="Too many attempts", retry_after=300)

        assert error.error_code == "rate_limit_exceeded"
        assert error.status_code == 429
        assert error.details["retry_after_seconds"] == 300
        assert "too many authentication attempts" in error.user_message.lower()


class TestAuthLogger:
    """Test authentication logging functionality."""

    def test_auth_logger_initialization(self):
        """Test AuthLogger initialization."""
        logger = AuthLogger()
        assert logger.logger.name == "trackers.auth"

    def test_log_oauth_initiation(self):
        """Test OAuth initiation logging."""
        logger = AuthLogger()

        with patch.object(logger.logger, "info") as mock_info:
            logger.log_oauth_initiation("192.168.1.1", "/dashboard")

            mock_info.assert_called_once()
            call_args = mock_info.call_args
            assert "OAuth login initiated" in call_args[0][0]
            assert call_args[1]["extra"]["user_ip"] == "192.168.1.1"
            assert call_args[1]["extra"]["redirect_uri"] == "/dashboard"

    def test_log_authentication_failure(self):
        """Test authentication failure logging."""
        logger = AuthLogger()

        with patch.object(logger.logger, "error") as mock_error:
            logger.log_authentication_failure(
                "192.168.1.1", "Invalid token", "token_invalid"
            )

            mock_error.assert_called_once()
            call_args = mock_error.call_args
            assert "Authentication failed: Invalid token" in call_args[0][0]
            assert call_args[1]["extra"]["error_code"] == "token_invalid"

    def test_log_rate_limit_violation(self):
        """Test rate limit violation logging."""
        logger = AuthLogger()

        with patch.object(logger.logger, "warning") as mock_warning:
            logger.log_rate_limit_violation("192.168.1.1", 5)

            mock_warning.assert_called_once()
            call_args = mock_warning.call_args
            assert "Rate limit exceeded" in call_args[0][0]
            assert call_args[1]["extra"]["attempt_count"] == 5


class TestNetworkRetryHandler:
    """Test network retry logic with exponential backoff."""

    def test_successful_request_no_retry(self):
        """Test successful request doesn't trigger retry."""
        handler = NetworkRetryHandler(max_retries=3, base_delay=0.1)

        mock_func = Mock(return_value="success")
        result = handler.retry_with_backoff(mock_func, "arg1", key="value")

        assert result == "success"
        assert mock_func.call_count == 1
        mock_func.assert_called_with("arg1", key="value")

    def test_retry_on_network_error(self):
        """Test retry logic on network errors."""
        handler = NetworkRetryHandler(max_retries=2, base_delay=0.01)

        mock_func = Mock(
            side_effect=[
                requests.RequestException("Network error"),
                requests.RequestException("Network error"),
                "success",
            ]
        )

        with patch("time.sleep") as mock_sleep:
            result = handler.retry_with_backoff(mock_func)

        assert result == "success"
        assert mock_func.call_count == 3
        assert mock_sleep.call_count == 2

        # Check exponential backoff delays
        sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
        assert sleep_calls[0] == 0.01  # First retry: base_delay * 2^0
        assert sleep_calls[1] == 0.02  # Second retry: base_delay * 2^1

    def test_max_retries_exceeded(self):
        """Test behavior when max retries are exceeded."""
        handler = NetworkRetryHandler(max_retries=2, base_delay=0.01)

        mock_func = Mock(side_effect=requests.RequestException("Persistent error"))

        with patch("time.sleep"):
            with pytest.raises(NetworkError) as exc_info:
                handler.retry_with_backoff(mock_func)

        assert "failed after 2 retries" in str(exc_info.value)
        assert mock_func.call_count == 3  # Initial + 2 retries

    def test_non_network_error_no_retry(self):
        """Test that non-network errors are not retried."""
        handler = NetworkRetryHandler(max_retries=3, base_delay=0.01)

        mock_func = Mock(side_effect=ValueError("Not a network error"))

        with pytest.raises(ValueError):
            handler.retry_with_backoff(mock_func)

        assert mock_func.call_count == 1  # No retries for non-network errors


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_initialization(self):
        """Test RateLimiter initialization."""
        limiter = RateLimiter(max_attempts=5, window_minutes=15, lockout_minutes=30)

        assert limiter.max_attempts == 5
        assert limiter.window_minutes == 15
        assert limiter.lockout_minutes == 30

    def test_no_rate_limiting_initially(self):
        """Test that new IPs are not rate limited initially."""
        limiter = RateLimiter(max_attempts=3, window_minutes=15)

        is_limited, retry_after = limiter.is_rate_limited("192.168.1.1")

        assert not is_limited
        assert retry_after is None

    def test_rate_limiting_after_max_attempts(self):
        """Test rate limiting after exceeding max attempts."""
        limiter = RateLimiter(max_attempts=2, window_minutes=15, lockout_minutes=5)

        # Record failed attempts
        limiter.record_attempt("192.168.1.1", success=False)
        limiter.record_attempt("192.168.1.1", success=False)

        # Should not be limited yet (at max, not over)
        is_limited, retry_after = limiter.is_rate_limited("192.168.1.1")
        assert not is_limited

        # One more attempt should trigger rate limiting
        limiter.record_attempt("192.168.1.1", success=False)
        is_limited, retry_after = limiter.is_rate_limited("192.168.1.1")

        assert is_limited
        assert retry_after is not None
        assert retry_after > 0

    def test_successful_attempt_clears_rate_limiting(self):
        """Test that successful attempts clear rate limiting."""
        limiter = RateLimiter(max_attempts=2, window_minutes=15)

        # Record failed attempts
        limiter.record_attempt("192.168.1.1", success=False)
        limiter.record_attempt("192.168.1.1", success=False)

        # Record successful attempt
        limiter.record_attempt("192.168.1.1", success=True)

        # Should not be rate limited
        is_limited, retry_after = limiter.is_rate_limited("192.168.1.1")
        assert not is_limited

    def test_different_ips_independent_rate_limiting(self):
        """Test that different IPs have independent rate limiting."""
        limiter = RateLimiter(max_attempts=2, window_minutes=15)

        # Exceed limit for first IP
        limiter.record_attempt("192.168.1.1", success=False)
        limiter.record_attempt("192.168.1.1", success=False)
        limiter.record_attempt("192.168.1.1", success=False)

        # First IP should be limited
        is_limited_1, _ = limiter.is_rate_limited("192.168.1.1")
        assert is_limited_1

        # Second IP should not be limited
        is_limited_2, _ = limiter.is_rate_limited("192.168.1.2")
        assert not is_limited_2


class TestErrorResponseCreation:
    """Test error response creation."""

    def test_create_error_response_basic(self):
        """Test basic error response creation."""
        error = AuthError("Test error", "test_error", 400)
        response, status_code = create_error_response(error)

        assert status_code == 400
        assert response["error"]["code"] == "test_error"
        assert response["error"]["message"] == error.user_message
        assert response["error"]["status_code"] == 400
        assert "timestamp" in response["error"]

    def test_create_error_response_with_retry_after(self):
        """Test error response with retry after information."""
        error = RateLimitError("Too many attempts", retry_after=300)
        response, status_code = create_error_response(error)

        assert status_code == 429
        assert response["error"]["retry_after"] == 300
        assert "suggestion" in response["error"]

    def test_create_error_response_with_suggestions(self):
        """Test error response includes helpful suggestions."""
        error = OAuthConfigError("Missing config")
        response, status_code = create_error_response(error)

        assert "suggestion" in response["error"]
        assert "administrator" in response["error"]["suggestion"].lower()


class TestErrorHandlingDecorator:
    """Test error handling decorator."""

    def test_with_error_handling_success(self):
        """Test decorator doesn't interfere with successful execution."""

        @with_error_handling()
        def test_func(x, y):
            return x + y

        result = test_func(2, 3)
        assert result == 5

    def test_with_error_handling_auth_error_passthrough(self):
        """Test decorator passes through AuthError instances."""

        @with_error_handling()
        def test_func():
            raise TokenExchangeError("Token failed")

        with pytest.raises(TokenExchangeError):
            test_func()

    def test_with_error_handling_network_error_conversion(self):
        """Test decorator converts network errors to NetworkError."""

        @with_error_handling()
        def test_func():
            raise requests.RequestException("Network failed")

        with pytest.raises(NetworkError) as exc_info:
            test_func()

        assert "Network error" in str(exc_info.value)

    def test_with_error_handling_unexpected_error_conversion(self):
        """Test decorator converts unexpected errors to AuthError."""

        @with_error_handling()
        def test_func():
            raise ValueError("Unexpected error")

        with pytest.raises(AuthError) as exc_info:
            test_func()

        assert "Unexpected error in authentication" in str(exc_info.value)


class TestClientIPExtraction:
    """Test client IP address extraction."""

    def test_get_client_ip_with_forwarded_header(self, app):
        """Test IP extraction with X-Forwarded-For header."""
        with app.test_request_context(
            "/",
            headers={"X-Forwarded-For": "203.0.113.1, 192.168.1.1"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        ):
            ip = get_client_ip()
            assert ip == "203.0.113.1"  # First IP from forwarded header

    def test_get_client_ip_with_real_ip_header(self, app):
        """Test IP extraction with X-Real-IP header."""
        with app.test_request_context(
            "/",
            headers={"X-Real-IP": "203.0.113.2"},
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
        ):
            ip = get_client_ip()
            assert ip == "203.0.113.2"

    def test_get_client_ip_fallback_to_remote_addr(self, app):
        """Test IP extraction falls back to remote_addr."""
        with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
            ip = get_client_ip()
            assert ip == "10.0.0.1"

    def test_get_client_ip_unknown_fallback(self, app):
        """Test IP extraction with unknown fallback."""
        with app.test_request_context("/"):
            ip = get_client_ip()
            assert ip == "unknown"
