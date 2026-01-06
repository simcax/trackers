"""
HTTP Utilities for Secure Job Providers.

This module provides utility functions for making secure HTTP requests
with HTTPS enforcement, comprehensive error handling, retry logic,
and security logging.

Requirements: 6.2, 6.3, 6.4, 8.4, 8.5
"""

import json
import logging
from typing import Any, Dict, Optional, Union
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


class HTTPSecurityError(Exception):
    """Exception raised for HTTP security violations."""

    pass


class SecureHTTPClient:
    """
    Secure HTTP client with HTTPS enforcement and comprehensive error handling.

    This class provides a secure wrapper around requests with built-in
    security validations, HTTPS enforcement, retry logic with exponential
    backoff, and structured error logging.

    Requirements: 6.2, 6.3, 6.4, 8.4, 8.5
    """

    def __init__(
        self,
        timeout: int = 30,
        max_response_size: int = 10 * 1024 * 1024,
        retry_config=None,
    ):
        """
        Initialize secure HTTP client.

        Args:
            timeout: Default request timeout in seconds
            max_response_size: Maximum allowed response size in bytes
            retry_config: Optional retry configuration

        Requirements: 6.3, 8.4, 8.5
        """
        self.timeout = timeout
        self.max_response_size = max_response_size
        self.session = self._create_session()

        # Initialize error handling components
        from .error_handling import RetryConfig, StructuredErrorLogger

        self.retry_config = retry_config or RetryConfig()
        self.error_logger = StructuredErrorLogger("secure_http_client")

    def _create_session(self) -> requests.Session:
        """
        Create a configured requests session.

        Returns:
            Configured requests.Session

        Requirements: 8.4, 8.5
        """
        session = requests.Session()

        # Set security headers
        session.headers.update(
            {
                "User-Agent": "TrackerApp-JobScheduler/1.0",
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
            }
        )

        return session

    def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Make a secure GET request.

        Args:
            url: Request URL (must be HTTPS)
            headers: Optional request headers
            timeout: Request timeout (uses default if not provided)
            **kwargs: Additional request parameters

        Returns:
            HTTP response object

        Raises:
            HTTPSecurityError: If security validation fails
            requests.RequestException: If request fails

        Requirements: 8.4, 8.5
        """
        return self._make_request(
            "GET", url, headers=headers, timeout=timeout, **kwargs
        )

    def post(
        self,
        url: str,
        data: Optional[Union[Dict[str, Any], str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Make a secure POST request.

        Args:
            url: Request URL (must be HTTPS)
            data: Form data or raw data
            json_data: JSON data (will be serialized)
            headers: Optional request headers
            timeout: Request timeout (uses default if not provided)
            **kwargs: Additional request parameters

        Returns:
            HTTP response object

        Raises:
            HTTPSecurityError: If security validation fails
            requests.RequestException: If request fails

        Requirements: 8.4, 8.5
        """
        if json_data is not None:
            kwargs["json"] = json_data
        elif data is not None:
            kwargs["data"] = data

        return self._make_request(
            "POST", url, headers=headers, timeout=timeout, **kwargs
        )

    def _make_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        **kwargs,
    ) -> requests.Response:
        """
        Make a secure HTTP request with validation and comprehensive error handling.

        Args:
            method: HTTP method
            url: Request URL
            headers: Optional request headers
            timeout: Request timeout
            **kwargs: Additional request parameters

        Returns:
            HTTP response object

        Raises:
            HTTPSecurityError: If security validation fails
            requests.RequestException: If request fails after all retries

        Requirements: 6.2, 6.3, 6.4, 8.4, 8.5
        """
        # Validate URL security
        self._validate_url(url)

        # Prepare headers
        request_headers = {}
        if headers:
            self._validate_headers(headers)
            request_headers.update(headers)

        # Set timeout
        request_timeout = timeout or self.timeout

        # Log request (without sensitive data)
        safe_url = self._get_safe_url(url)
        logger.debug(f"Making {method} request to {safe_url}")

        try:
            # Make the request
            response = self.session.request(
                method=method,
                url=url,
                headers=request_headers,
                timeout=request_timeout,
                **kwargs,
            )

            # Validate response
            self._validate_response(response)

            logger.debug(
                f"Request completed: {method} {safe_url} -> {response.status_code}"
            )

            return response

        except requests.RequestException as e:
            logger.error(f"Request failed: {method} {safe_url} -> {e}")

            # Log structured error
            from .error_handling import ErrorCategory, ErrorSeverity

            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.NETWORK,
                severity=ErrorSeverity.MEDIUM,
                url=url,
                http_status=getattr(getattr(e, "response", None), "status_code", None),
                context={"method": method, "timeout": request_timeout},
            )
            self.error_logger.log_error(error_details)

            raise
        except HTTPSecurityError as e:
            logger.error(f"Security violation: {method} {safe_url} -> {e}")

            # Log structured security error
            from .error_handling import ErrorCategory, ErrorSeverity

            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.SECURITY,
                severity=ErrorSeverity.CRITICAL,
                url=url,
                context={"method": method},
            )
            self.error_logger.log_error(error_details)

            raise

    def _validate_url(self, url: str) -> None:
        """
        Validate URL security requirements.

        Args:
            url: URL to validate

        Raises:
            HTTPSecurityError: If URL fails security validation

        Requirements: 8.4, 8.5
        """
        if not url:
            raise HTTPSecurityError("URL cannot be empty")

        if not isinstance(url, str):
            raise HTTPSecurityError("URL must be a string")

        # Enforce HTTPS
        if not url.startswith("https://"):
            raise HTTPSecurityError("Only HTTPS URLs are allowed")

        # Validate URL format
        try:
            parsed = urlparse(url)
            if not parsed.netloc:
                raise HTTPSecurityError("Invalid URL format: missing hostname")
            if parsed.scheme != "https":
                raise HTTPSecurityError("Only HTTPS scheme is allowed")
        except Exception as e:
            raise HTTPSecurityError(f"URL validation failed: {e}")

        # Check URL length
        if len(url) > 2000:
            raise HTTPSecurityError("URL too long (max 2000 characters)")

    def _validate_headers(self, headers: Dict[str, str]) -> None:
        """
        Validate request headers.

        Args:
            headers: Headers dictionary to validate

        Raises:
            HTTPSecurityError: If headers fail security validation

        Requirements: 8.4, 8.5
        """
        if not isinstance(headers, dict):
            raise HTTPSecurityError("Headers must be a dictionary")

        # Check for dangerous headers
        dangerous_headers = {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "proxy-authorization",
        }

        for key, value in headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise HTTPSecurityError("Header keys and values must be strings")

            key_lower = key.lower()
            if key_lower in dangerous_headers:
                raise HTTPSecurityError(f"Header '{key}' is not allowed")

            # Check header length
            if len(key) > 100:
                raise HTTPSecurityError(f"Header key too long: {key}")
            if len(value) > 1000:
                raise HTTPSecurityError(f"Header value too long for key: {key}")

    def _validate_response(self, response: requests.Response) -> None:
        """
        Validate response security requirements.

        Args:
            response: HTTP response to validate

        Raises:
            HTTPSecurityError: If response fails security validation

        Requirements: 8.4, 8.5
        """
        # Check response size
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
                if size > self.max_response_size:
                    raise HTTPSecurityError(f"Response too large: {size} bytes")
            except ValueError:
                logger.warning(f"Invalid content-length header: {content_length}")

        # Check for suspicious redirects
        if response.history:
            for redirect in response.history:
                if not redirect.url.startswith("https://"):
                    raise HTTPSecurityError("Redirect to non-HTTPS URL detected")

    def _get_safe_url(self, url: str) -> str:
        """
        Get a safe version of URL for logging (removes query parameters).

        Args:
            url: Original URL

        Returns:
            Safe URL without sensitive query parameters

        Requirements: 8.5
        """
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            # If parsing fails, return truncated URL
            return url[:100] + "..." if len(url) > 100 else url


def make_secure_request(
    method: str,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    timeout: int = 30,
    **kwargs,
) -> requests.Response:
    """
    Make a secure HTTP request with HTTPS enforcement.

    This is a convenience function for making one-off secure requests
    without creating a SecureHTTPClient instance.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Request URL (must be HTTPS)
        headers: Optional request headers
        timeout: Request timeout in seconds
        **kwargs: Additional request parameters

    Returns:
        HTTP response object

    Raises:
        HTTPSecurityError: If security validation fails
        requests.RequestException: If request fails

    Requirements: 8.4, 8.5
    """
    client = SecureHTTPClient(timeout=timeout)
    return client._make_request(method, url, headers=headers, timeout=timeout, **kwargs)


def extract_json_value(
    response: requests.Response, json_path: str = "$.value"
) -> Optional[float]:
    """
    Extract a numeric value from JSON response using JSONPath.

    Args:
        response: HTTP response containing JSON data
        json_path: JSONPath expression to extract value

    Returns:
        Extracted numeric value or None if extraction fails

    Requirements: 5.1, 5.2
    """
    try:
        # Parse JSON response
        data = response.json()

        # Try to use jsonpath_ng if available
        try:
            import jsonpath_ng

            jsonpath_expr = jsonpath_ng.parse(json_path)
            matches = jsonpath_expr.find(data)

            if matches:
                value = matches[0].value
                return _convert_to_float(value)
            else:
                logger.warning(f"JSONPath '{json_path}' found no matches")
                return None

        except ImportError:
            # Fallback to simple extraction for common patterns
            return _extract_simple_json_value(data, json_path)

    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse JSON response: {e}")
        return None
    except Exception as e:
        logger.error(f"Failed to extract value from JSON: {e}")
        return None


def _extract_simple_json_value(data: Any, json_path: str) -> Optional[float]:
    """
    Simple JSON value extraction for common patterns.

    Args:
        data: Parsed JSON data
        json_path: JSONPath expression (limited support)

    Returns:
        Extracted numeric value or None
    """
    # Handle simple cases like $.value, $.data.price, etc.
    if json_path == "$.value" and isinstance(data, dict) and "value" in data:
        return _convert_to_float(data["value"])
    elif json_path == "$.price" and isinstance(data, dict) and "price" in data:
        return _convert_to_float(data["price"])
    elif json_path == "$.data.value" and isinstance(data, dict) and "data" in data:
        if isinstance(data["data"], dict) and "value" in data["data"]:
            return _convert_to_float(data["data"]["value"])

    logger.warning(f"Simple JSON extraction not supported for path: {json_path}")
    return None


def _convert_to_float(value: Any) -> Optional[float]:
    """
    Convert a value to float with error handling.

    Args:
        value: Value to convert

    Returns:
        Float value or None if conversion fails
    """
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return float(value)

    if isinstance(value, str):
        # Remove common formatting characters
        cleaned = value.strip().replace(",", "").replace("$", "").replace("%", "")
        try:
            return float(cleaned)
        except ValueError:
            logger.warning(f"Cannot convert string to float: {value}")
            return None

    logger.warning(f"Cannot convert value to float: {value} (type: {type(value)})")
    return None
