"""
Comprehensive error handling and logging for Google OAuth authentication.

This module provides centralized error handling, detailed logging, network retry logic,
and rate limiting for the Google OAuth 2.0 authentication system.

Requirements: 7.1, 7.2, 7.3, 7.4
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Optional, Tuple

import requests
from flask import request

# Configure logging for authentication
auth_logger = logging.getLogger("trackers.auth")
auth_logger.setLevel(logging.INFO)

# Create file handler for authentication logs
auth_handler = logging.FileHandler("auth_errors.log")
auth_handler.setLevel(logging.INFO)

# Create formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
auth_handler.setFormatter(formatter)
auth_logger.addHandler(auth_handler)


class AuthError(Exception):
    """Base exception class for authentication-related errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "auth_error",
        status_code: int = 500,
        details: Optional[Dict] = None,
        user_message: Optional[str] = None,
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.status_code = status_code
        self.details = details or {}
        self.user_message = user_message or self._get_user_friendly_message()

    def _get_user_friendly_message(self) -> str:
        """Generate user-friendly error message based on error code."""
        user_messages = {
            "oauth_config_error": "Authentication service is not properly configured. Please contact support.",
            "oauth_state_invalid": "Authentication request has expired or is invalid. Please try logging in again.",
            "oauth_code_invalid": "Authentication failed. Please try logging in again.",
            "token_exchange_failed": "Unable to complete authentication with Google. Please try again.",
            "token_validation_failed": "Authentication token is invalid. Please try logging in again.",
            "network_error": "Unable to connect to authentication service. Please check your internet connection and try again.",
            "rate_limit_exceeded": "Too many authentication attempts. Please wait a few minutes before trying again.",
            "session_expired": "Your session has expired. Please log in again.",
            "user_info_extraction_failed": "Unable to retrieve user information. Please try logging in again.",
        }
        return user_messages.get(
            self.error_code, "An authentication error occurred. Please try again."
        )


class OAuthConfigError(AuthError):
    """Exception for OAuth configuration errors."""

    def __init__(self, message: str, missing_config: Optional[list] = None):
        details = {"missing_config": missing_config} if missing_config else {}
        super().__init__(
            message=message,
            error_code="oauth_config_error",
            status_code=500,
            details=details,
        )


class OAuthStateError(AuthError):
    """Exception for OAuth state validation errors."""

    def __init__(self, message: str):
        super().__init__(
            message=message, error_code="oauth_state_invalid", status_code=400
        )


class TokenExchangeError(AuthError):
    """Exception for token exchange failures."""

    def __init__(self, message: str, google_error: Optional[str] = None):
        details = {"google_error": google_error} if google_error else {}
        super().__init__(
            message=message,
            error_code="token_exchange_failed",
            status_code=400,
            details=details,
        )


class TokenValidationError(AuthError):
    """Exception for token validation failures."""

    def __init__(self, message: str, token_error: Optional[str] = None):
        details = {"token_error": token_error} if token_error else {}
        super().__init__(
            message=message,
            error_code="token_validation_failed",
            status_code=400,
            details=details,
        )


class NetworkError(AuthError):
    """Exception for network-related errors."""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        details = {"original_error": str(original_error)} if original_error else {}
        super().__init__(
            message=message,
            error_code="network_error",
            status_code=503,
            details=details,
        )


class RateLimitError(AuthError):
    """Exception for rate limiting violations."""

    def __init__(self, message: str, retry_after: Optional[int] = None):
        details = {"retry_after_seconds": retry_after} if retry_after else {}
        super().__init__(
            message=message,
            error_code="rate_limit_exceeded",
            status_code=429,
            details=details,
        )


class AuthLogger:
    """Centralized logging for authentication events and errors."""

    def __init__(self, logger_name: str = "trackers.auth"):
        self.logger = logging.getLogger(logger_name)

    def log_oauth_initiation(self, user_ip: str, redirect_uri: Optional[str] = None):
        """Log OAuth flow initiation."""
        self.logger.info(
            "OAuth login initiated",
            extra={
                "event": "oauth_initiation",
                "user_ip": user_ip,
                "redirect_uri": redirect_uri,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_oauth_callback(
        self, user_ip: str, success: bool, error: Optional[str] = None
    ):
        """Log OAuth callback processing."""
        level = logging.INFO if success else logging.WARNING
        self.logger.log(
            level,
            f"OAuth callback processed - {'success' if success else 'failed'}",
            extra={
                "event": "oauth_callback",
                "user_ip": user_ip,
                "success": success,
                "error": error,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_token_exchange(
        self, user_ip: str, success: bool, error: Optional[str] = None
    ):
        """Log token exchange attempts."""
        level = logging.INFO if success else logging.ERROR
        self.logger.log(
            level,
            f"Token exchange - {'success' if success else 'failed'}",
            extra={
                "event": "token_exchange",
                "user_ip": user_ip,
                "success": success,
                "error": error,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_authentication_success(self, user_email: str, user_ip: str):
        """Log successful authentication."""
        self.logger.info(
            f"User authenticated successfully: {user_email}",
            extra={
                "event": "authentication_success",
                "user_email": user_email,
                "user_ip": user_ip,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_authentication_failure(self, user_ip: str, error: str, error_code: str):
        """Log authentication failures."""
        self.logger.error(
            f"Authentication failed: {error}",
            extra={
                "event": "authentication_failure",
                "user_ip": user_ip,
                "error": error,
                "error_code": error_code,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_logout(self, user_email: str, user_ip: str):
        """Log user logout."""
        self.logger.info(
            f"User logged out: {user_email}",
            extra={
                "event": "logout",
                "user_email": user_email,
                "user_ip": user_ip,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_rate_limit_violation(self, user_ip: str, attempt_count: int):
        """Log rate limit violations."""
        self.logger.warning(
            f"Rate limit exceeded for IP {user_ip}: {attempt_count} attempts",
            extra={
                "event": "rate_limit_violation",
                "user_ip": user_ip,
                "attempt_count": attempt_count,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_security_event(self, event_type: str, message: str, user_ip: str):
        """Log security-related events."""
        self.logger.warning(
            f"Security event [{event_type}]: {message}",
            extra={
                "event": "security_event",
                "event_type": event_type,
                "user_ip": user_ip,
                "security_message": message,  # Changed from "message" to avoid conflict
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_network_error(self, endpoint: str, error: str, retry_count: int):
        """Log network errors and retry attempts."""
        self.logger.error(
            f"Network error accessing {endpoint}: {error} (retry {retry_count})",
            extra={
                "event": "network_error",
                "endpoint": endpoint,
                "error": error,
                "retry_count": retry_count,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )


class NetworkRetryHandler:
    """Handles network retry logic with exponential backoff."""

    def __init__(
        self, max_retries: int = 3, base_delay: float = 1.0, max_delay: float = 30.0
    ):
        """
        Initialize retry handler.

        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Base delay in seconds for exponential backoff
            max_delay: Maximum delay between retries
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.logger = AuthLogger()

    def retry_with_backoff(self, func, *args, **kwargs):
        """
        Execute function with exponential backoff retry logic.

        Args:
            func: Function to execute
            *args: Function arguments
            **kwargs: Function keyword arguments

        Returns:
            Function result

        Raises:
            NetworkError: If all retry attempts fail

        Requirements: 7.3 - Network retry logic with exponential backoff
        """
        last_exception = None

        for attempt in range(self.max_retries + 1):
            try:
                return func(*args, **kwargs)
            except requests.RequestException as e:
                last_exception = e

                if attempt == self.max_retries:
                    # Final attempt failed
                    self.logger.log_network_error(
                        endpoint=getattr(e.request, "url", "unknown")
                        if hasattr(e, "request")
                        else "unknown",
                        error=str(e),
                        retry_count=attempt,
                    )
                    raise NetworkError(
                        f"Network request failed after {self.max_retries} retries: {str(e)}",
                        original_error=e,
                    )

                # Calculate delay with exponential backoff
                delay = min(self.base_delay * (2**attempt), self.max_delay)

                self.logger.log_network_error(
                    endpoint=getattr(e.request, "url", "unknown")
                    if hasattr(e, "request")
                    else "unknown",
                    error=str(e),
                    retry_count=attempt,
                )

                time.sleep(delay)
            except Exception as e:
                # Non-network errors should not be retried
                raise e

        # This should never be reached, but just in case
        raise NetworkError(
            "Unexpected error in retry logic", original_error=last_exception
        )


class RateLimiter:
    """Rate limiter for authentication attempts."""

    def __init__(
        self, max_attempts: int = 5, window_minutes: int = 15, lockout_minutes: int = 30
    ):
        """
        Initialize rate limiter.

        Args:
            max_attempts: Maximum attempts allowed in the time window
            window_minutes: Time window for counting attempts
            lockout_minutes: Lockout duration after exceeding max attempts
        """
        self.max_attempts = max_attempts
        self.window_minutes = window_minutes
        self.lockout_minutes = lockout_minutes
        self.attempts = defaultdict(list)  # IP -> list of attempt timestamps
        self.lockouts = {}  # IP -> lockout expiry timestamp
        self.logger = AuthLogger()

    def is_rate_limited(self, ip_address: str) -> Tuple[bool, Optional[int]]:
        """
        Check if IP address is rate limited.

        Args:
            ip_address: Client IP address

        Returns:
            Tuple of (is_limited, retry_after_seconds)

        Requirements: 7.4 - Rate limiting for repeated authentication failures
        """
        current_time = datetime.utcnow()

        # Check if IP is currently locked out
        if ip_address in self.lockouts:
            lockout_expiry = self.lockouts[ip_address]
            if current_time < lockout_expiry:
                retry_after = int((lockout_expiry - current_time).total_seconds())
                return True, retry_after
            else:
                # Lockout has expired, remove it
                del self.lockouts[ip_address]

        # Clean up old attempts outside the window
        window_start = current_time - timedelta(minutes=self.window_minutes)
        if ip_address in self.attempts:
            self.attempts[ip_address] = [
                attempt_time
                for attempt_time in self.attempts[ip_address]
                if attempt_time > window_start
            ]

        # Check if current attempts exceed the limit
        attempt_count = len(self.attempts.get(ip_address, []))
        if attempt_count > self.max_attempts:
            # Apply lockout
            lockout_expiry = current_time + timedelta(minutes=self.lockout_minutes)
            self.lockouts[ip_address] = lockout_expiry

            self.logger.log_rate_limit_violation(ip_address, attempt_count)

            retry_after = int(timedelta(minutes=self.lockout_minutes).total_seconds())
            return True, retry_after

        return False, None

    def record_attempt(self, ip_address: str, success: bool = False):
        """
        Record an authentication attempt.

        Args:
            ip_address: Client IP address
            success: Whether the attempt was successful
        """
        current_time = datetime.utcnow()

        if success:
            # Clear attempts on successful authentication
            if ip_address in self.attempts:
                del self.attempts[ip_address]
            if ip_address in self.lockouts:
                del self.lockouts[ip_address]
        else:
            # Record failed attempt
            self.attempts[ip_address].append(current_time)


def get_client_ip() -> str:
    """Get client IP address from request."""
    # Check for forwarded IP first (for reverse proxies)
    forwarded_ip = request.headers.get("X-Forwarded-For")
    if forwarded_ip:
        # X-Forwarded-For can contain multiple IPs, take the first one
        return forwarded_ip.split(",")[0].strip()

    # Check for real IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to remote address
    return request.remote_addr or "unknown"


def create_error_response(error: AuthError) -> Tuple[Dict, int]:
    """
    Create standardized error response for authentication errors.

    Args:
        error: Authentication error instance

    Returns:
        Tuple of (response_dict, status_code)

    Requirements: 7.2 - User-friendly error messages for common scenarios
    """
    response = {
        "error": {
            "code": error.error_code,
            "message": error.user_message,
            "timestamp": datetime.utcnow().isoformat(),
            "status_code": error.status_code,
        }
    }

    # Add retry information for rate limit errors
    if isinstance(error, RateLimitError) and "retry_after_seconds" in error.details:
        response["error"]["retry_after"] = error.details["retry_after_seconds"]

    # Add helpful suggestions based on error type
    suggestions = {
        "oauth_config_error": "Please contact system administrator to configure OAuth credentials.",
        "oauth_state_invalid": "Clear your browser cookies and try logging in again.",
        "oauth_code_invalid": "Return to the login page and try again.",
        "token_exchange_failed": "Check your internet connection and try again.",
        "token_validation_failed": "Clear your browser cookies and try logging in again.",
        "network_error": "Check your internet connection. If the problem persists, try again later.",
        "rate_limit_exceeded": "Wait a few minutes before attempting to log in again.",
        "session_expired": "Please log in again to continue.",
        "user_info_extraction_failed": "Try logging in again. If the problem persists, contact support.",
    }

    if error.error_code in suggestions:
        response["error"]["suggestion"] = suggestions[error.error_code]

    return response, error.status_code


def with_error_handling(logger: Optional[AuthLogger] = None):
    """
    Decorator to add comprehensive error handling to authentication methods.

    Args:
        logger: Optional logger instance

    Requirements: 7.1, 7.2 - Detailed error logging and user-friendly messages
    """
    if logger is None:
        logger = AuthLogger()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except AuthError:
                # Re-raise authentication errors as-is
                raise
            except requests.RequestException as e:
                # Convert network errors to AuthError
                raise NetworkError(
                    f"Network error in {func.__name__}: {str(e)}", original_error=e
                )
            except Exception as e:
                # Log unexpected errors and convert to generic AuthError
                logger.logger.error(
                    f"Unexpected error in {func.__name__}: {str(e)}", exc_info=True
                )
                raise AuthError(
                    f"Unexpected error in authentication: {str(e)}",
                    error_code="auth_error",
                )

        return wrapper

    return decorator


def with_rate_limiting(rate_limiter: RateLimiter):
    """
    Decorator to add rate limiting to authentication endpoints.

    Args:
        rate_limiter: Rate limiter instance

    Requirements: 7.4 - Rate limiting for repeated authentication failures
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = get_client_ip()

            # Check if rate limited
            is_limited, retry_after = rate_limiter.is_rate_limited(client_ip)
            if is_limited:
                raise RateLimitError(
                    f"Too many authentication attempts from {client_ip}",
                    retry_after=retry_after,
                )

            try:
                result = func(*args, **kwargs)
                # Record successful attempt
                rate_limiter.record_attempt(client_ip, success=True)
                return result
            except AuthError as e:
                # Record failed attempt
                rate_limiter.record_attempt(client_ip, success=False)
                raise e

        return wrapper

    return decorator


# Global instances for use across the authentication system
auth_logger = AuthLogger()
network_retry_handler = NetworkRetryHandler()
rate_limiter = RateLimiter()
