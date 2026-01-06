"""
Secure Job Provider with Security Features.

This module provides a secure base class for job providers with built-in
security features including HTTPS enforcement, secure HTTP requests,
comprehensive error handling, and resilience features.

Requirements: 5.2, 6.2, 6.3, 6.4, 6.5, 8.4, 8.5
"""

import logging
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .base_job_provider import BaseJobProvider
from .error_handling import (
    ErrorCategory,
    ErrorSeverity,
    RateLimitHandler,
    RetryConfig,
    StructuredErrorLogger,
)

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Exception raised for security-related errors."""

    pass


class SecureJobProvider(BaseJobProvider):
    """
    Base class with security features for all job providers.

    This class extends BaseJobProvider with security-focused functionality:
    - HTTPS enforcement for all external requests
    - Secure HTTP client with proper timeouts and retries
    - Security headers and user agent
    - Request/response logging for security monitoring
    - Rate limiting and retry logic with exponential backoff
    - Comprehensive error handling and failure isolation

    Requirements: 5.2, 6.2, 6.3, 6.4, 6.5, 8.4, 8.5
    """

    def __init__(self, job_config):
        """
        Initialize secure job provider.

        Args:
            job_config: JobModel instance containing job configuration

        Requirements: 6.2, 6.3, 6.4, 8.4, 8.5
        """
        # Security configuration (set before calling super().__init__)
        self.max_response_size = 10 * 1024 * 1024  # 10MB
        self.default_timeout = 30
        self.max_retries = 3
        self.retry_backoff_factor = 1.0

        super().__init__(job_config)

        # Initialize error handling and resilience components
        self.retry_config = RetryConfig(
            max_retries=self.max_retries,
            base_delay=1.0,
            max_delay=60.0,
            backoff_factor=2.0,
            jitter=True,
        )
        self.rate_limit_handler = RateLimitHandler(max_wait_time=300)
        self.error_logger = StructuredErrorLogger(f"{self.__class__.__name__}.errors")

        # Initialize secure HTTP session
        self.session = self._create_secure_session()

        # Security logging
        self.security_logger = logging.getLogger(f"{self.__class__.__name__}.security")

    def _create_secure_session(self) -> requests.Session:
        """
        Create a secure HTTP session with proper configuration.

        Returns:
            Configured requests.Session with security features

        Requirements: 6.3, 6.4, 8.4, 8.5
        """
        session = requests.Session()

        # Configure retry strategy with exponential backoff
        retry_strategy = Retry(
            total=self.max_retries,
            backoff_factor=self.retry_backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST"],
            raise_on_status=False,  # Handle status codes manually
        )

        # Mount adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)

        # Set default headers
        session.headers.update(
            {
                "User-Agent": "TrackerApp-JobScheduler/1.0",
                "Accept": "application/json",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        return session

    def _make_secure_request(
        self, method: str, url: str, **kwargs
    ) -> requests.Response:
        """
        Make a secure HTTP request with validation, retry logic, and comprehensive error handling.

        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            **kwargs: Additional request parameters

        Returns:
            HTTP response object

        Raises:
            SecurityError: If security validation fails
            requests.RequestException: If request fails after all retries

        Requirements: 6.2, 6.3, 6.4, 6.5, 8.4, 8.5
        """
        # Security validation
        self._validate_request_security(url, **kwargs)

        # Set default timeout if not provided
        kwargs.setdefault("timeout", self.default_timeout)

        # Check if URL is currently rate limited
        if self.rate_limit_handler.is_rate_limited(url):
            raise requests.RequestException(f"URL {url} is currently rate limited")

        # Log request for security monitoring
        self._log_request_start(method, url)

        start_time = time.time()

        try:
            # Make the request
            response = self.session.request(method, url, **kwargs)

            # Handle rate limiting
            if response.status_code == 429:
                wait_time = self.rate_limit_handler.handle_rate_limit(response, url)
                if wait_time:
                    # Log rate limit handling
                    self.error_logger.log_error(
                        self.error_logger.create_error_details(
                            exception=requests.RequestException(
                                f"Rate limited, waiting {wait_time}s"
                            ),
                            category=ErrorCategory.RATE_LIMIT,
                            severity=ErrorSeverity.MEDIUM,
                            job_id=self.job_config.id,
                            url=url,
                            http_status=429,
                            context={"wait_time": wait_time},
                        )
                    )
                    time.sleep(wait_time)
                    # Retry the request after waiting
                    response = self.session.request(method, url, **kwargs)

            # Validate response
            self._validate_response_security(response)

            # Log successful request
            duration = time.time() - start_time
            self._log_request_success(method, url, response.status_code, duration)

            return response

        except requests.RequestException as e:
            # Log failed request with structured error details
            duration = time.time() - start_time
            self._log_request_failure(method, url, str(e), duration)

            # Create structured error details
            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.MEDIUM,
                job_id=self.job_config.id,
                url=url,
                http_status=getattr(getattr(e, "response", None), "status_code", None),
                context={"duration": duration, "method": method},
            )
            self.error_logger.log_error(error_details)
            raise
        except SecurityError as e:
            # Log security violation with high severity
            duration = time.time() - start_time
            self._log_security_violation(method, url, str(e), duration)

            # Create structured error details for security violation
            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.SECURITY,
                severity=ErrorSeverity.CRITICAL,
                job_id=self.job_config.id,
                url=url,
                context={"duration": duration, "method": method},
            )
            self.error_logger.log_error(error_details)
            raise

    def _validate_request_security(self, url: str, **kwargs) -> None:
        """
        Validate request security requirements.

        Args:
            url: Request URL
            **kwargs: Request parameters

        Raises:
            SecurityError: If security validation fails

        Requirements: 8.4, 8.5
        """
        # Enforce HTTPS
        if not url.startswith("https://"):
            raise SecurityError("Only HTTPS URLs are allowed for external API calls")

        # Validate URL format
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            if not parsed.netloc:
                raise SecurityError("Invalid URL format")
        except Exception as e:
            raise SecurityError(f"URL validation failed: {e}")

        # Check for suspicious headers
        headers = kwargs.get("headers", {})
        if isinstance(headers, dict):
            for key, value in headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    raise SecurityError("Header keys and values must be strings")

                # Check for potentially dangerous headers
                key_lower = key.lower()
                if key_lower in ["host", "content-length", "transfer-encoding"]:
                    raise SecurityError(f"Header '{key}' is not allowed")

        # Validate timeout
        timeout = kwargs.get("timeout", self.default_timeout)
        if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 300:
            raise SecurityError("Timeout must be between 1 and 300 seconds")

    def _validate_response_security(self, response: requests.Response) -> None:
        """
        Validate response security requirements.

        Args:
            response: HTTP response object

        Raises:
            SecurityError: If security validation fails

        Requirements: 8.4, 8.5
        """
        # Check response size
        content_length = response.headers.get("content-length")
        if content_length and int(content_length) > self.max_response_size:
            raise SecurityError(f"Response too large: {content_length} bytes")

        # Check for suspicious content types
        content_type = response.headers.get("content-type", "").lower()
        allowed_types = [
            "application/json",
            "text/plain",
            "text/html",
            "application/xml",
        ]

        if content_type and not any(
            allowed in content_type for allowed in allowed_types
        ):
            self.security_logger.warning(f"Unexpected content type: {content_type}")

    def _get_secure_credential(self, field_name: str) -> Optional[str]:
        """
        Safely retrieve and decrypt credential from configuration.

        Args:
            field_name: Name of the credential field

        Returns:
            Decrypted credential value or None if not found

        Requirements: 8.4, 8.5
        """
        try:
            credential = super()._get_secure_credential(field_name)
            if credential:
                self.security_logger.debug(f"Retrieved credential: {field_name}")
            return credential
        except Exception as e:
            self.security_logger.error(
                f"Failed to retrieve credential {field_name}: {e}"
            )
            return None

    def _handle_rate_limit(self, response: requests.Response) -> None:
        """
        Handle rate limiting from API responses.

        Args:
            response: HTTP response that may contain rate limit headers

        Requirements: 6.3, 6.4
        """
        if response.status_code == 429:  # Too Many Requests
            # Use the centralized rate limit handler
            url = response.url
            wait_time = self.rate_limit_handler.handle_rate_limit(response, url)

            if wait_time:
                self.logger.info(f"Rate limited, waiting {wait_time} seconds")

                # Log rate limit event with structured error details
                error_details = self.error_logger.create_error_details(
                    exception=requests.RequestException(
                        f"Rate limited, waiting {wait_time}s"
                    ),
                    category=ErrorCategory.RATE_LIMIT,
                    severity=ErrorSeverity.MEDIUM,
                    job_id=self.job_config.id,
                    url=url,
                    http_status=429,
                    context={
                        "wait_time": wait_time,
                        "retry_after": response.headers.get("retry-after"),
                    },
                )
                self.error_logger.log_error(error_details)

                time.sleep(wait_time)
            else:
                self.logger.warning("Rate limited but cannot determine wait time")

                # Log rate limit without wait time
                error_details = self.error_logger.create_error_details(
                    exception=requests.RequestException(
                        "Rate limited without retry information"
                    ),
                    category=ErrorCategory.RATE_LIMIT,
                    severity=ErrorSeverity.HIGH,
                    job_id=self.job_config.id,
                    url=url,
                    http_status=429,
                    context={"headers": dict(response.headers)},
                )
                self.error_logger.log_error(error_details)

    def _log_request_start(self, method: str, url: str) -> None:
        """
        Log the start of an HTTP request.

        Args:
            method: HTTP method
            url: Request URL

        Requirements: 8.5
        """
        # Don't log full URL to avoid exposing sensitive data
        from urllib.parse import urlparse

        parsed = urlparse(url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        self.security_logger.info(
            f"Starting {method} request to {safe_url} for job {self.job_config.id}"
        )

    def _log_request_success(
        self, method: str, url: str, status_code: int, duration: float
    ) -> None:
        """
        Log successful HTTP request.

        Args:
            method: HTTP method
            url: Request URL
            status_code: HTTP status code
            duration: Request duration in seconds

        Requirements: 8.5
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        self.security_logger.info(
            f"Request completed: {method} {safe_url} -> {status_code} "
            f"({duration:.2f}s) for job {self.job_config.id}"
        )

    def _log_request_failure(
        self, method: str, url: str, error: str, duration: float
    ) -> None:
        """
        Log failed HTTP request.

        Args:
            method: HTTP method
            url: Request URL
            error: Error message
            duration: Request duration in seconds

        Requirements: 8.5
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        safe_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        self.security_logger.error(
            f"Request failed: {method} {safe_url} -> {error} "
            f"({duration:.2f}s) for job {self.job_config.id}"
        )

    def _log_security_violation(
        self, method: str, url: str, violation: str, duration: float
    ) -> None:
        """
        Log security violation.

        Args:
            method: HTTP method
            url: Request URL (may be unsafe)
            violation: Security violation description
            duration: Request duration in seconds

        Requirements: 8.5
        """
        # Be careful not to log potentially malicious URLs
        safe_url = url[:100] + "..." if len(url) > 100 else url

        self.security_logger.error(
            f"SECURITY VIOLATION: {method} {safe_url} -> {violation} "
            f"({duration:.2f}s) for job {self.job_config.id}"
        )

    def get_security_info(self) -> Dict[str, Any]:
        """
        Get information about security configuration.

        Returns:
            Dictionary with security configuration details

        Requirements: 6.2, 6.3, 6.4, 8.4, 8.5
        """
        return {
            "https_enforced": True,
            "max_response_size": self.max_response_size,
            "default_timeout": self.default_timeout,
            "max_retries": self.max_retries,
            "retry_backoff_factor": self.retry_backoff_factor,
            "security_headers": dict(self.session.headers),
            "encryption_enabled": self.encryptor.validate_encryption_key(),
            "retry_config": {
                "max_retries": self.retry_config.max_retries,
                "base_delay": self.retry_config.base_delay,
                "max_delay": self.retry_config.max_delay,
                "backoff_factor": self.retry_config.backoff_factor,
                "jitter": self.retry_config.jitter,
            },
            "rate_limit_handler": {
                "max_wait_time": self.rate_limit_handler.max_wait_time,
                "cached_limits": len(self.rate_limit_handler.rate_limit_cache),
            },
        }
