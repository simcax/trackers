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


# Email/Password Authentication Errors
class EmailPasswordAuthError(AuthError):
    """Base class for email/password authentication errors."""

    def __init__(
        self,
        message: str,
        error_code: str = "email_password_auth_error",
        status_code: int = 400,
        details: Optional[Dict] = None,
        user_message: Optional[str] = None,
    ):
        super().__init__(message, error_code, status_code, details, user_message)


class PasswordValidationError(EmailPasswordAuthError):
    """Password doesn't meet security requirements."""

    def __init__(self, validation_errors: list):
        message = f"Password validation failed: {', '.join(validation_errors)}"
        user_message = "Password does not meet security requirements. " + "; ".join(
            validation_errors
        )
        super().__init__(
            message=message,
            error_code="password_validation_failed",
            status_code=400,
            details={"validation_errors": validation_errors},
            user_message=user_message,
        )


class InvalidCredentialsError(EmailPasswordAuthError):
    """Invalid email/password combination - secure error that doesn't reveal user existence."""

    def __init__(self, message: str = "Invalid email or password"):
        # Always use generic message to prevent user enumeration
        generic_message = (
            "Invalid email or password. Please check your credentials and try again."
        )
        super().__init__(
            message=message,
            error_code="invalid_credentials",
            status_code=401,
            user_message=generic_message,
        )


class AccountLockedError(EmailPasswordAuthError):
    """Account temporarily locked due to failed attempts."""

    def __init__(self, locked_until: datetime, remaining_minutes: Optional[int] = None):
        if remaining_minutes is None:
            remaining_minutes = max(
                1, int((locked_until - datetime.utcnow()).total_seconds() / 60)
            )

        message = f"Account locked until {locked_until.isoformat()}"
        user_message = f"Account is temporarily locked due to too many failed login attempts. Please try again in {remaining_minutes} minutes."
        super().__init__(
            message=message,
            error_code="account_locked",
            status_code=423,
            details={
                "locked_until": locked_until.isoformat(),
                "retry_after_minutes": remaining_minutes,
            },
            user_message=user_message,
        )


class DuplicateEmailError(EmailPasswordAuthError):
    """Email already registered - secure error that doesn't reveal existing accounts."""

    def __init__(self, email: str):
        message = f"Email already registered: {email}"
        # Generic message to prevent user enumeration
        user_message = "If this email is not already registered, an account will be created. If it is already registered, please try logging in instead."
        super().__init__(
            message=message,
            error_code="duplicate_email",
            status_code=409,
            details={"email": email},
            user_message=user_message,
        )


class EmailPasswordRateLimitError(EmailPasswordAuthError):
    """Rate limiting specific to email/password authentication."""

    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        attempt_type: str = "authentication",
    ):
        details = (
            {"retry_after_seconds": retry_after, "attempt_type": attempt_type}
            if retry_after
            else {"attempt_type": attempt_type}
        )

        if attempt_type == "registration":
            user_message = "Too many registration attempts. Please wait a few minutes before trying again."
        elif attempt_type == "password_change":
            user_message = "Too many password change attempts. Please wait a few minutes before trying again."
        else:
            user_message = "Too many authentication attempts. Please wait a few minutes before trying again."

        super().__init__(
            message=message,
            error_code="email_password_rate_limit_exceeded",
            status_code=429,
            details=details,
            user_message=user_message,
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

    # Email/Password Authentication Logging Methods
    def log_email_password_registration(
        self, user_email: str, user_ip: str, success: bool, error: Optional[str] = None
    ):
        """Log email/password registration attempts."""
        level = logging.INFO if success else logging.WARNING
        status = "success" if success else "failed"

        log_data = {
            "event": "email_password_registration",
            "user_email": user_email
            if success
            else "[REDACTED]",  # Only log email on success
            "user_ip": user_ip,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if error and not success:
            log_data["error"] = error

        self.logger.log(
            level,
            f"Email/password registration {status}: {user_email if success else 'email redacted'}",
            extra=log_data,
        )

    def log_email_password_login(
        self, user_email: str, user_ip: str, success: bool, error: Optional[str] = None
    ):
        """Log email/password login attempts."""
        level = logging.INFO if success else logging.WARNING
        status = "success" if success else "failed"

        log_data = {
            "event": "email_password_login",
            "user_email": user_email
            if success
            else "[REDACTED]",  # Only log email on success
            "user_ip": user_ip,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if error and not success:
            log_data["error"] = error

        self.logger.log(
            level,
            f"Email/password login {status}: {user_email if success else 'email redacted'}",
            extra=log_data,
        )

    def log_password_change(
        self, user_email: str, user_ip: str, success: bool, error: Optional[str] = None
    ):
        """Log password change attempts."""
        level = logging.INFO if success else logging.WARNING
        status = "success" if success else "failed"

        log_data = {
            "event": "password_change",
            "user_email": user_email,
            "user_ip": user_ip,
            "success": success,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if error and not success:
            log_data["error"] = error

        self.logger.log(
            level,
            f"Password change {status}: {user_email}",
            extra=log_data,
        )

    def log_account_lockout(
        self,
        user_email: str,
        user_ip: str,
        failed_attempts: int,
        lockout_duration_minutes: int,
    ):
        """Log account lockout events."""
        self.logger.warning(
            f"Account locked due to {failed_attempts} failed attempts: {user_email}",
            extra={
                "event": "account_lockout",
                "user_email": user_email,
                "user_ip": user_ip,
                "failed_attempts": failed_attempts,
                "lockout_duration_minutes": lockout_duration_minutes,
                "timestamp": datetime.utcnow().isoformat(),
            },
        )

    def log_suspicious_activity(
        self,
        activity_type: str,
        user_email: str,
        user_ip: str,
        details: Optional[Dict] = None,
    ):
        """Log suspicious authentication activity."""
        log_data = {
            "event": "suspicious_activity",
            "activity_type": activity_type,
            "user_email": user_email,
            "user_ip": user_ip,
            "timestamp": datetime.utcnow().isoformat(),
        }

        if details:
            log_data["details"] = details

        self.logger.warning(
            f"Suspicious activity [{activity_type}]: {user_email} from {user_ip}",
            extra=log_data,
        )

    def log_email_password_rate_limit(
        self,
        user_ip: str,
        attempt_type: str,
        attempt_count: int,
        retry_after_seconds: int,
    ):
        """Log email/password specific rate limit violations."""
        self.logger.warning(
            f"Email/password rate limit exceeded for {attempt_type} from IP {user_ip}: {attempt_count} attempts",
            extra={
                "event": "email_password_rate_limit_violation",
                "user_ip": user_ip,
                "attempt_type": attempt_type,
                "attempt_count": attempt_count,
                "retry_after_seconds": retry_after_seconds,
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


class EmailPasswordRateLimiter:
    """Enhanced rate limiter specifically for email/password authentication with multiple attempt types."""

    def __init__(
        self,
        login_max_attempts: int = 5,
        login_window_minutes: int = 15,
        login_lockout_minutes: int = 30,
        registration_max_attempts: int = 3,
        registration_window_minutes: int = 60,
        registration_lockout_minutes: int = 60,
        password_change_max_attempts: int = 3,
        password_change_window_minutes: int = 30,
        password_change_lockout_minutes: int = 30,
    ):
        """
        Initialize email/password rate limiter with different limits for different operations.

        Args:
            login_max_attempts: Maximum login attempts allowed in the time window
            login_window_minutes: Time window for counting login attempts
            login_lockout_minutes: Lockout duration after exceeding max login attempts
            registration_max_attempts: Maximum registration attempts allowed in the time window
            registration_window_minutes: Time window for counting registration attempts
            registration_lockout_minutes: Lockout duration after exceeding max registration attempts
            password_change_max_attempts: Maximum password change attempts allowed in the time window
            password_change_window_minutes: Time window for counting password change attempts
            password_change_lockout_minutes: Lockout duration after exceeding max password change attempts
        """
        self.limits = {
            "login": {
                "max_attempts": login_max_attempts,
                "window_minutes": login_window_minutes,
                "lockout_minutes": login_lockout_minutes,
            },
            "registration": {
                "max_attempts": registration_max_attempts,
                "window_minutes": registration_window_minutes,
                "lockout_minutes": registration_lockout_minutes,
            },
            "password_change": {
                "max_attempts": password_change_max_attempts,
                "window_minutes": password_change_window_minutes,
                "lockout_minutes": password_change_lockout_minutes,
            },
        }

        # Separate tracking for each attempt type
        self.attempts = defaultdict(
            lambda: defaultdict(list)
        )  # attempt_type -> IP -> list of timestamps
        self.lockouts = defaultdict(
            dict
        )  # attempt_type -> IP -> lockout expiry timestamp
        self.logger = AuthLogger()

    def is_rate_limited(
        self, ip_address: str, attempt_type: str = "login"
    ) -> Tuple[bool, Optional[int]]:
        """
        Check if IP address is rate limited for a specific attempt type.

        Args:
            ip_address: Client IP address
            attempt_type: Type of attempt ('login', 'registration', 'password_change')

        Returns:
            Tuple of (is_limited, retry_after_seconds)
        """
        if attempt_type not in self.limits:
            attempt_type = "login"  # Default to login limits

        current_time = datetime.utcnow()
        limits = self.limits[attempt_type]

        # Check if IP is currently locked out for this attempt type
        if ip_address in self.lockouts[attempt_type]:
            lockout_expiry = self.lockouts[attempt_type][ip_address]
            if current_time < lockout_expiry:
                retry_after = int((lockout_expiry - current_time).total_seconds())
                return True, retry_after
            else:
                # Lockout has expired, remove it
                del self.lockouts[attempt_type][ip_address]

        # Clean up old attempts outside the window
        window_start = current_time - timedelta(minutes=limits["window_minutes"])
        if ip_address in self.attempts[attempt_type]:
            self.attempts[attempt_type][ip_address] = [
                attempt_time
                for attempt_time in self.attempts[attempt_type][ip_address]
                if attempt_time > window_start
            ]

        # Check if current attempts exceed the limit
        attempt_count = len(self.attempts[attempt_type].get(ip_address, []))
        if attempt_count >= limits["max_attempts"]:
            # Apply lockout
            lockout_expiry = current_time + timedelta(minutes=limits["lockout_minutes"])
            self.lockouts[attempt_type][ip_address] = lockout_expiry

            self.logger.log_email_password_rate_limit(
                ip_address, attempt_type, attempt_count, limits["lockout_minutes"] * 60
            )

            retry_after = int(
                timedelta(minutes=limits["lockout_minutes"]).total_seconds()
            )
            return True, retry_after

        return False, None

    def record_attempt(
        self, ip_address: str, attempt_type: str = "login", success: bool = False
    ):
        """
        Record an authentication attempt for a specific type.

        Args:
            ip_address: Client IP address
            attempt_type: Type of attempt ('login', 'registration', 'password_change')
            success: Whether the attempt was successful
        """
        if attempt_type not in self.limits:
            attempt_type = "login"  # Default to login limits

        current_time = datetime.utcnow()

        if success:
            # Clear attempts on successful authentication for this attempt type
            if ip_address in self.attempts[attempt_type]:
                del self.attempts[attempt_type][ip_address]
            if ip_address in self.lockouts[attempt_type]:
                del self.lockouts[attempt_type][ip_address]
        else:
            # Record failed attempt
            self.attempts[attempt_type][ip_address].append(current_time)

    def get_attempt_count(self, ip_address: str, attempt_type: str = "login") -> int:
        """
        Get current attempt count for an IP and attempt type.

        Args:
            ip_address: Client IP address
            attempt_type: Type of attempt ('login', 'registration', 'password_change')

        Returns:
            Current attempt count within the time window
        """
        if attempt_type not in self.limits:
            attempt_type = "login"

        current_time = datetime.utcnow()
        limits = self.limits[attempt_type]
        window_start = current_time - timedelta(minutes=limits["window_minutes"])

        if ip_address not in self.attempts[attempt_type]:
            return 0

        # Count attempts within the window
        valid_attempts = [
            attempt_time
            for attempt_time in self.attempts[attempt_type][ip_address]
            if attempt_time > window_start
        ]

        return len(valid_attempts)


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


def create_secure_email_password_error_response(
    error: EmailPasswordAuthError,
) -> Tuple[Dict, int]:
    """
    Create secure error response for email/password authentication that prevents user enumeration.

    This function ensures that error messages don't reveal whether a user account exists,
    preventing attackers from enumerating valid email addresses.

    Args:
        error: Email/password authentication error instance

    Returns:
        Tuple of (response_dict, status_code)

    Requirements: 8.4 - Secure error messages that don't reveal user existence
    """
    # Map internal error codes to secure user messages
    secure_messages = {
        "invalid_credentials": "Invalid email or password. Please check your credentials and try again.",
        "duplicate_email": "Thank you for your registration request. If this email is not already in use, your account will be created. If it is already in use, please try logging in instead.",
        "password_validation_failed": error.user_message,  # Password validation errors are safe to show
        "account_locked": error.user_message,  # Account lockout messages are safe to show
        "email_password_rate_limit_exceeded": error.user_message,  # Rate limit messages are safe to show
        "missing_email": "Email and password are required.",
        "missing_password": "Email and password are required.",
        "missing_name": "Name is required for registration.",
        "missing_new_password": "Current password and new password are required.",
        "invalid_current_password": "Current password is incorrect.",
    }

    # Use secure message or fall back to generic message
    secure_message = secure_messages.get(
        error.error_code, "An error occurred during authentication. Please try again."
    )

    response = {
        "error": {
            "code": "authentication_error",  # Generic code for security
            "message": secure_message,
            "timestamp": datetime.utcnow().isoformat(),
            "status_code": error.status_code,
        }
    }

    # Add retry information for rate limit and account lockout errors
    if error.error_code in ["email_password_rate_limit_exceeded", "account_locked"]:
        if "retry_after_seconds" in error.details:
            response["error"]["retry_after"] = error.details["retry_after_seconds"]
        elif "retry_after_minutes" in error.details:
            response["error"]["retry_after"] = error.details["retry_after_minutes"] * 60

    # Add helpful suggestions for specific error types
    suggestions = {
        "password_validation_failed": "Please ensure your password meets all security requirements.",
        "account_locked": "Your account has been temporarily locked for security. Please wait before trying again.",
        "email_password_rate_limit_exceeded": "Please wait before making additional attempts.",
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


def with_email_password_rate_limiting(
    rate_limiter: "EmailPasswordRateLimiter", attempt_type: str = "login"
):
    """
    Decorator to add email/password specific rate limiting to authentication endpoints.

    Args:
        rate_limiter: EmailPasswordRateLimiter instance
        attempt_type: Type of attempt ('login', 'registration', 'password_change')

    Requirements: 8.1, 8.2 - Rate limiting for login and registration attempts
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = get_client_ip()

            # Check if rate limited for this attempt type
            is_limited, retry_after = rate_limiter.is_rate_limited(
                client_ip, attempt_type
            )
            if is_limited:
                from trackers.auth.error_handling import EmailPasswordRateLimitError

                raise EmailPasswordRateLimitError(
                    f"Too many {attempt_type} attempts from {client_ip}",
                    retry_after=retry_after,
                    attempt_type=attempt_type,
                )

            try:
                result = func(*args, **kwargs)
                # Record successful attempt
                rate_limiter.record_attempt(client_ip, attempt_type, success=True)
                return result
            except Exception as e:
                # Record failed attempt for any exception
                rate_limiter.record_attempt(client_ip, attempt_type, success=False)
                raise e

        return wrapper

    return decorator


def with_email_password_security_logging(logger: Optional[AuthLogger] = None):
    """
    Decorator to add comprehensive security logging to email/password authentication methods.

    Args:
        logger: Optional logger instance

    Requirements: 8.3, 8.5 - Authentication event logging
    """
    if logger is None:
        logger = AuthLogger()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            client_ip = get_client_ip()
            start_time = datetime.utcnow()

            # Determine operation type from function name
            operation_type = "unknown"
            if "register" in func.__name__.lower():
                operation_type = "registration"
            elif (
                "authenticate" in func.__name__.lower()
                or "login" in func.__name__.lower()
            ):
                operation_type = "login"
            elif (
                "password" in func.__name__.lower()
                and "change" in func.__name__.lower()
            ):
                operation_type = "password_change"

            try:
                result = func(*args, **kwargs)

                # Extract user email from result or arguments for logging
                user_email = "unknown"
                if (
                    hasattr(result, "user_info")
                    and result.user_info
                    and result.user_info.email
                ):
                    user_email = result.user_info.email
                elif (
                    hasattr(result, "user_model")
                    and result.user_model
                    and result.user_model.email
                ):
                    user_email = result.user_model.email
                elif len(args) > 0 and isinstance(args[0], str) and "@" in args[0]:
                    user_email = args[0]  # First argument might be email

                # Log successful operation
                if operation_type == "registration":
                    logger.log_email_password_registration(user_email, client_ip, True)
                elif operation_type == "login":
                    logger.log_email_password_login(user_email, client_ip, True)
                elif operation_type == "password_change":
                    logger.log_password_change(user_email, client_ip, True)
                else:
                    logger.log_security_event(
                        f"email_password_{operation_type}",
                        f"Successful {operation_type}",
                        client_ip,
                    )

                return result

            except Exception as e:
                # Extract user email from arguments for failed attempt logging
                user_email = "unknown"
                if len(args) > 0 and isinstance(args[0], str) and "@" in args[0]:
                    user_email = args[0]  # First argument might be email

                error_message = str(e)

                # Log failed operation
                if operation_type == "registration":
                    logger.log_email_password_registration(
                        user_email, client_ip, False, error_message
                    )
                elif operation_type == "login":
                    logger.log_email_password_login(
                        user_email, client_ip, False, error_message
                    )
                elif operation_type == "password_change":
                    logger.log_password_change(
                        user_email, client_ip, False, error_message
                    )
                else:
                    logger.log_security_event(
                        f"email_password_{operation_type}_failed",
                        f"Failed {operation_type}: {error_message}",
                        client_ip,
                    )

                # Log suspicious activity for certain error patterns
                if any(
                    pattern in error_message.lower()
                    for pattern in ["brute force", "enumeration", "suspicious"]
                ):
                    logger.log_suspicious_activity(
                        f"{operation_type}_attack",
                        user_email,
                        client_ip,
                        {"error": error_message},
                    )

                raise e

        return wrapper

    return decorator


# Global instances for use across the authentication system
auth_logger = AuthLogger()
network_retry_handler = NetworkRetryHandler()
rate_limiter = RateLimiter()
email_password_rate_limiter = EmailPasswordRateLimiter()
