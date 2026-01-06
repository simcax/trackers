"""
Comprehensive Error Handling and Resilience for Job Providers.

This module provides enhanced error handling, retry logic, rate limiting,
and failure isolation for the automated job scheduling system.

Requirements: 6.2, 6.3, 6.4, 6.5
"""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Type

import requests
from requests.exceptions import (
    ConnectionError,
    HTTPError,
    ReadTimeout,
    Timeout,
)

logger = logging.getLogger(__name__)


class ErrorSeverity(Enum):
    """Error severity levels for structured logging."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Categories of errors for better classification."""

    NETWORK = "network"
    API = "api"
    AUTHENTICATION = "authentication"
    RATE_LIMIT = "rate_limit"
    CONFIGURATION = "configuration"
    DATA_EXTRACTION = "data_extraction"
    SECURITY = "security"
    SYSTEM = "system"


@dataclass
class ErrorDetails:
    """
    Structured error information for comprehensive logging.

    Requirements: 6.2
    """

    category: ErrorCategory
    severity: ErrorSeverity
    message: str
    exception_type: str
    timestamp: datetime
    job_id: Optional[int] = None
    url: Optional[str] = None
    http_status: Optional[int] = None
    retry_attempt: Optional[int] = None
    context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert error details to dictionary for logging."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "message": self.message,
            "exception_type": self.exception_type,
            "timestamp": self.timestamp.isoformat(),
            "job_id": self.job_id,
            "url": self._safe_url(self.url) if self.url else None,
            "http_status": self.http_status,
            "retry_attempt": self.retry_attempt,
            "context": self.context or {},
        }

    def _safe_url(self, url: str) -> str:
        """Return safe URL for logging (removes query parameters)."""
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return url[:100] + "..." if len(url) > 100 else url


class RetryConfig:
    """
    Configuration for retry logic with exponential backoff.

    Requirements: 6.3, 6.4
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        jitter: bool = True,
        retryable_status_codes: Optional[List[int]] = None,
        retryable_exceptions: Optional[List[Type[Exception]]] = None,
    ):
        """
        Initialize retry configuration.

        Args:
            max_retries: Maximum number of retry attempts
            base_delay: Base delay in seconds for first retry
            max_delay: Maximum delay in seconds between retries
            backoff_factor: Exponential backoff multiplier
            jitter: Whether to add random jitter to delays
            retryable_status_codes: HTTP status codes that should trigger retries
            retryable_exceptions: Exception types that should trigger retries
        """
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter

        # Default retryable status codes (server errors and rate limiting)
        self.retryable_status_codes = retryable_status_codes or [
            429,  # Too Many Requests
            500,  # Internal Server Error
            502,  # Bad Gateway
            503,  # Service Unavailable
            504,  # Gateway Timeout
        ]

        # Default retryable exceptions (network and timeout errors)
        self.retryable_exceptions = retryable_exceptions or [
            ConnectionError,
            Timeout,
            ReadTimeout,
        ]

    def calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for retry attempt with exponential backoff.

        Args:
            attempt: Current retry attempt number (0-based)

        Returns:
            Delay in seconds before next retry

        Requirements: 6.3
        """
        if attempt < 0:
            return 0.0

        # Calculate exponential backoff delay
        delay = self.base_delay * (self.backoff_factor**attempt)

        # Cap at maximum delay
        delay = min(delay, self.max_delay)

        # Add jitter to prevent thundering herd
        if self.jitter:
            import random

            jitter_factor = random.uniform(0.5, 1.5)
            delay *= jitter_factor

        return delay

    def should_retry(
        self, exception: Exception, response: Optional[requests.Response] = None
    ) -> bool:
        """
        Determine if an error should trigger a retry.

        Args:
            exception: Exception that occurred
            response: HTTP response (if available)

        Returns:
            True if the error should trigger a retry

        Requirements: 6.3, 6.4
        """
        # Check if exception type is retryable
        if any(
            isinstance(exception, exc_type) for exc_type in self.retryable_exceptions
        ):
            return True

        # Check HTTP status codes
        if response and response.status_code in self.retryable_status_codes:
            return True

        # Check for specific HTTP errors
        if isinstance(exception, HTTPError) and hasattr(exception, "response"):
            status_code = exception.response.status_code
            return status_code in self.retryable_status_codes

        return False


class RateLimitHandler:
    """
    Handler for API rate limiting with retry-after support.

    Requirements: 6.3, 6.4
    """

    def __init__(self, max_wait_time: int = 300):
        """
        Initialize rate limit handler.

        Args:
            max_wait_time: Maximum time to wait for rate limit (seconds)
        """
        self.max_wait_time = max_wait_time
        self.rate_limit_cache: Dict[str, datetime] = {}

    def handle_rate_limit(
        self, response: requests.Response, url: str
    ) -> Optional[float]:
        """
        Handle rate limiting from API response.

        Args:
            response: HTTP response with rate limit information
            url: Request URL for caching

        Returns:
            Wait time in seconds, or None if rate limit cannot be handled

        Requirements: 6.3, 6.4
        """
        if response.status_code != 429:
            return None

        # Check for Retry-After header
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                wait_time = int(retry_after)
                if wait_time <= self.max_wait_time:
                    logger.info(f"Rate limited, waiting {wait_time} seconds")
                    self._cache_rate_limit(url, wait_time)
                    return wait_time
                else:
                    logger.warning(
                        f"Rate limit wait time too long: {wait_time}s (max: {self.max_wait_time}s)"
                    )
                    return None
            except ValueError:
                logger.warning(f"Invalid retry-after header: {retry_after}")

        # Check for X-RateLimit headers
        reset_time = self._parse_rate_limit_headers(response)
        if reset_time:
            wait_time = max(
                0, (reset_time - datetime.now(timezone.utc)).total_seconds()
            )
            if wait_time <= self.max_wait_time:
                logger.info(
                    f"Rate limited, waiting {wait_time:.1f} seconds until reset"
                )
                self._cache_rate_limit(url, wait_time)
                return wait_time

        # Default rate limit handling
        default_wait = min(60, self.max_wait_time)  # Default to 1 minute
        logger.info(f"Rate limited, using default wait time: {default_wait}s")
        self._cache_rate_limit(url, default_wait)
        return default_wait

    def _parse_rate_limit_headers(
        self, response: requests.Response
    ) -> Optional[datetime]:
        """
        Parse rate limit headers to determine reset time.

        Args:
            response: HTTP response with rate limit headers

        Returns:
            Reset time as datetime, or None if not available
        """
        # Try X-RateLimit-Reset (Unix timestamp)
        reset_header = response.headers.get("x-ratelimit-reset")
        if reset_header:
            try:
                reset_timestamp = int(reset_header)
                return datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
            except ValueError:
                pass

        # Try X-Rate-Limit-Reset (Unix timestamp)
        reset_header = response.headers.get("x-rate-limit-reset")
        if reset_header:
            try:
                reset_timestamp = int(reset_header)
                return datetime.fromtimestamp(reset_timestamp, tz=timezone.utc)
            except ValueError:
                pass

        return None

    def _cache_rate_limit(self, url: str, wait_time: float) -> None:
        """
        Cache rate limit information for URL.

        Args:
            url: Request URL
            wait_time: Wait time in seconds
        """
        from urllib.parse import urlparse

        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            reset_time = datetime.now(timezone.utc).timestamp() + wait_time
            self.rate_limit_cache[domain] = datetime.fromtimestamp(
                reset_time, tz=timezone.utc
            )
        except Exception as e:
            logger.warning(f"Failed to cache rate limit for {url}: {e}")

    def is_rate_limited(self, url: str) -> bool:
        """
        Check if URL is currently rate limited.

        Args:
            url: Request URL to check

        Returns:
            True if URL is currently rate limited
        """
        try:
            from urllib.parse import urlparse

            parsed = urlparse(url)
            domain = parsed.netloc

            if domain in self.rate_limit_cache:
                reset_time = self.rate_limit_cache[domain]
                if datetime.now(timezone.utc) < reset_time:
                    return True
                else:
                    # Rate limit expired, remove from cache
                    del self.rate_limit_cache[domain]

            return False
        except Exception:
            return False


class JobFailureIsolation:
    """
    Isolation mechanism to prevent job failures from crashing the scheduler.

    Requirements: 6.5
    """

    def __init__(self, max_consecutive_failures: int = 5):
        """
        Initialize failure isolation.

        Args:
            max_consecutive_failures: Max consecutive failures before isolation
        """
        self.max_consecutive_failures = max_consecutive_failures
        self.failure_counts: Dict[int, int] = {}
        self.isolated_jobs: Dict[int, datetime] = {}
        self.isolation_duration = 300  # 5 minutes

    def record_failure(self, job_id: int) -> bool:
        """
        Record a job failure and check if job should be isolated.

        Args:
            job_id: ID of the job that failed

        Returns:
            True if job should be isolated, False otherwise

        Requirements: 6.5
        """
        self.failure_counts[job_id] = self.failure_counts.get(job_id, 0) + 1

        if self.failure_counts[job_id] >= self.max_consecutive_failures:
            self.isolate_job(job_id)
            return True

        return False

    def record_success(self, job_id: int) -> None:
        """
        Record a job success and reset failure count.

        Args:
            job_id: ID of the job that succeeded

        Requirements: 6.5
        """
        self.failure_counts.pop(job_id, None)
        self.isolated_jobs.pop(job_id, None)

    def isolate_job(self, job_id: int) -> None:
        """
        Isolate a job temporarily to prevent scheduler crashes.

        Args:
            job_id: ID of the job to isolate

        Requirements: 6.5
        """
        isolation_time = datetime.now(timezone.utc)
        self.isolated_jobs[job_id] = isolation_time

        logger.warning(
            f"Job {job_id} isolated due to {self.failure_counts.get(job_id, 0)} "
            f"consecutive failures. Will retry after {self.isolation_duration}s"
        )

    def is_job_isolated(self, job_id: int) -> bool:
        """
        Check if a job is currently isolated.

        Args:
            job_id: ID of the job to check

        Returns:
            True if job is isolated, False otherwise

        Requirements: 6.5
        """
        if job_id not in self.isolated_jobs:
            return False

        isolation_time = self.isolated_jobs[job_id]
        elapsed = (datetime.now(timezone.utc) - isolation_time).total_seconds()

        if elapsed >= self.isolation_duration:
            # Isolation period expired, remove from isolation
            self.isolated_jobs.pop(job_id, None)
            self.failure_counts.pop(job_id, None)
            logger.info(f"Job {job_id} isolation period expired, re-enabling")
            return False

        return True

    def get_isolation_status(self, job_id: int) -> Dict[str, Any]:
        """
        Get isolation status for a job.

        Args:
            job_id: ID of the job

        Returns:
            Dictionary with isolation status information

        Requirements: 6.5
        """
        failure_count = self.failure_counts.get(job_id, 0)
        is_isolated = self.is_job_isolated(job_id)

        status = {
            "job_id": job_id,
            "failure_count": failure_count,
            "is_isolated": is_isolated,
            "max_consecutive_failures": self.max_consecutive_failures,
        }

        if is_isolated and job_id in self.isolated_jobs:
            isolation_time = self.isolated_jobs[job_id]
            elapsed = (datetime.now(timezone.utc) - isolation_time).total_seconds()
            remaining = max(0, self.isolation_duration - elapsed)

            status.update(
                {
                    "isolation_time": isolation_time.isoformat(),
                    "isolation_duration": self.isolation_duration,
                    "time_remaining": remaining,
                }
            )

        return status


class StructuredErrorLogger:
    """
    Structured error logging with categorization and severity levels.

    Requirements: 6.2
    """

    def __init__(self, logger_name: str = "job_error_handler"):
        """
        Initialize structured error logger.

        Args:
            logger_name: Name of the logger to use
        """
        self.logger = logging.getLogger(logger_name)

    def log_error(self, error_details: ErrorDetails) -> None:
        """
        Log structured error information.

        Args:
            error_details: Structured error details

        Requirements: 6.2
        """
        error_dict = error_details.to_dict()

        # Choose log level based on severity
        if error_details.severity == ErrorSeverity.CRITICAL:
            self.logger.critical(
                "Job execution error", extra={"error_details": error_dict}
            )
        elif error_details.severity == ErrorSeverity.HIGH:
            self.logger.error(
                "Job execution error", extra={"error_details": error_dict}
            )
        elif error_details.severity == ErrorSeverity.MEDIUM:
            self.logger.warning(
                "Job execution error", extra={"error_details": error_dict}
            )
        else:
            self.logger.info("Job execution error", extra={"error_details": error_dict})

    def create_error_details(
        self,
        exception: Exception,
        category: ErrorCategory,
        severity: ErrorSeverity,
        job_id: Optional[int] = None,
        url: Optional[str] = None,
        http_status: Optional[int] = None,
        retry_attempt: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> ErrorDetails:
        """
        Create structured error details from exception.

        Args:
            exception: Exception that occurred
            category: Error category
            severity: Error severity
            job_id: ID of the job (if applicable)
            url: Request URL (if applicable)
            http_status: HTTP status code (if applicable)
            retry_attempt: Current retry attempt (if applicable)
            context: Additional context information

        Returns:
            Structured error details

        Requirements: 6.2
        """
        return ErrorDetails(
            category=category,
            severity=severity,
            message=str(exception),
            exception_type=type(exception).__name__,
            timestamp=datetime.now(timezone.utc),
            job_id=job_id,
            url=url,
            http_status=http_status,
            retry_attempt=retry_attempt,
            context=context,
        )


def with_retry_and_error_handling(
    retry_config: Optional[RetryConfig] = None,
    rate_limit_handler: Optional[RateLimitHandler] = None,
    error_logger: Optional[StructuredErrorLogger] = None,
    job_id: Optional[int] = None,
):
    """
    Decorator for adding comprehensive error handling and retry logic.

    Args:
        retry_config: Retry configuration
        rate_limit_handler: Rate limit handler
        error_logger: Structured error logger
        job_id: Job ID for logging context

    Returns:
        Decorator function

    Requirements: 6.2, 6.3, 6.4
    """

    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            # Initialize default handlers if not provided
            nonlocal retry_config, rate_limit_handler, error_logger

            if retry_config is None:
                retry_config = RetryConfig()
            if rate_limit_handler is None:
                rate_limit_handler = RateLimitHandler()
            if error_logger is None:
                error_logger = StructuredErrorLogger()

            last_exception = None
            last_response = None

            for attempt in range(retry_config.max_retries + 1):
                try:
                    # Execute the function
                    result = func(*args, **kwargs)
                    return result

                except Exception as e:
                    last_exception = e
                    last_response = getattr(e, "response", None)

                    # Determine error category and severity
                    category, severity = _categorize_error(e)

                    # Create structured error details
                    error_details = error_logger.create_error_details(
                        exception=e,
                        category=category,
                        severity=severity,
                        job_id=job_id,
                        retry_attempt=attempt,
                        context={"function": func.__name__, "args_count": len(args)},
                    )

                    # Log the error
                    error_logger.log_error(error_details)

                    # Check if we should retry
                    if attempt < retry_config.max_retries and retry_config.should_retry(
                        e, last_response
                    ):
                        # Handle rate limiting
                        if (
                            last_response
                            and last_response.status_code == 429
                            and hasattr(kwargs, "get")
                        ):
                            url = kwargs.get("url", "unknown")
                            wait_time = rate_limit_handler.handle_rate_limit(
                                last_response, url
                            )
                            if wait_time:
                                time.sleep(wait_time)
                                continue

                        # Calculate retry delay
                        delay = retry_config.calculate_delay(attempt)
                        logger.info(
                            f"Retrying in {delay:.1f}s (attempt {attempt + 1}/{retry_config.max_retries + 1})"
                        )
                        time.sleep(delay)
                    else:
                        # No more retries, re-raise the exception
                        break

            # All retries exhausted, re-raise the last exception
            raise last_exception

        return wrapper

    return decorator


def _categorize_error(exception: Exception) -> tuple[ErrorCategory, ErrorSeverity]:
    """
    Categorize an exception and determine its severity.

    Args:
        exception: Exception to categorize

    Returns:
        Tuple of (category, severity)

    Requirements: 6.2
    """
    # Network-related errors
    if isinstance(exception, (ConnectionError, Timeout, ReadTimeout)):
        return ErrorCategory.NETWORK, ErrorSeverity.MEDIUM

    # HTTP errors
    if isinstance(exception, HTTPError):
        status_code = getattr(exception.response, "status_code", 0)
        if status_code == 401:
            return ErrorCategory.AUTHENTICATION, ErrorSeverity.HIGH
        elif status_code == 429:
            return ErrorCategory.RATE_LIMIT, ErrorSeverity.MEDIUM
        elif 400 <= status_code < 500:
            return ErrorCategory.API, ErrorSeverity.MEDIUM
        elif 500 <= status_code < 600:
            return ErrorCategory.API, ErrorSeverity.HIGH

    # Configuration errors
    if "config" in str(exception).lower() or "validation" in str(exception).lower():
        return ErrorCategory.CONFIGURATION, ErrorSeverity.HIGH

    # Security errors
    if "security" in str(exception).lower() or "https" in str(exception).lower():
        return ErrorCategory.SECURITY, ErrorSeverity.CRITICAL

    # Default to system error
    return ErrorCategory.SYSTEM, ErrorSeverity.MEDIUM
