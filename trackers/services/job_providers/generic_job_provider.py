"""
Generic HTTP Job Provider for Automated Job Scheduling.

This module provides a job provider for fetching data from arbitrary HTTP APIs
with configurable requests, JSONPath-based data extraction, and support for
GET/POST methods with custom headers and authentication.

Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
"""

import json
import logging
from typing import Any, Dict, List, Optional

import requests

from .http_utils import extract_json_value
from .secure_job_provider import SecureJobProvider

logger = logging.getLogger(__name__)


class GenericAPIError(Exception):
    """Exception raised for generic API-related errors."""

    pass


class GenericJobProvider(SecureJobProvider):
    """
    Job provider for fetching data from arbitrary HTTP APIs.

    This provider supports configurable HTTP requests with GET/POST methods,
    custom headers, authentication, and JSONPath-based data extraction from
    API responses. It includes comprehensive error handling and security features.

    Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
    """

    def __init__(self, job_config):
        """
        Initialize generic HTTP job provider.

        Args:
            job_config: JobModel instance containing generic job configuration

        Requirements: 4.1, 4.2
        """
        super().__init__(job_config)

        # Extract HTTP-specific configuration
        self.url = self.config.get("url", "").strip()
        self.method = self.config.get("method", "GET").upper()
        self.headers = self.config.get("headers", {})
        self.json_path = self.config.get("json_path", "$.value")
        self.timeout = self.config.get("timeout", 30)
        self.retry_count = self.config.get("retry_count", 3)

        # Request body configuration
        self.request_data = self.config.get("data")
        self.request_json = self.config.get("json")
        self.request_params = self.config.get("params", {})

        # Authentication configuration
        self.auth_type = self.config.get("auth_type", "none").lower()
        self.auth_config = self.config.get("auth", {})

        # Response configuration
        self.expected_status_codes = self.config.get("expected_status_codes", [200])
        if not isinstance(self.expected_status_codes, list):
            self.expected_status_codes = [200]

        self.logger.info(
            f"Initialized generic HTTP job provider for {self.method} {self.url}"
        )

    def validate_config(self) -> List[str]:
        """
        Validate generic HTTP job configuration.

        Returns:
            List of validation error messages (empty if valid)

        Requirements: 4.1, 4.4
        """
        errors = []

        # Validate URL
        if not self.url:
            errors.append("URL is required for generic HTTP jobs")
        elif not self.url.startswith("https://"):
            errors.append("Only HTTPS URLs are allowed for security")
        elif len(self.url) > 2000:
            errors.append("URL too long (max 2000 characters)")
        else:
            try:
                from urllib.parse import urlparse

                parsed = urlparse(self.url)
                if not parsed.netloc:
                    errors.append("Invalid URL format: missing hostname")
            except Exception:
                errors.append("Invalid URL format")

        # Validate HTTP method
        if self.method not in ["GET", "POST"]:
            errors.append("HTTP method must be GET or POST")

        # Validate headers
        if self.headers and not isinstance(self.headers, dict):
            errors.append("Headers must be a dictionary")
        elif self.headers:
            for key, value in self.headers.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    errors.append("Header keys and values must be strings")
                elif len(key) > 100:
                    errors.append(f"Header key too long: {key}")
                elif len(value) > 1000:
                    errors.append(f"Header value too long for key: {key}")

        # Validate JSONPath expression
        json_path_errors = self._validate_json_path(self.json_path)
        errors.extend(json_path_errors)

        # Validate timeout
        if (
            not isinstance(self.timeout, (int, float))
            or self.timeout <= 0
            or self.timeout > 300
        ):
            errors.append("Timeout must be a positive number between 1 and 300 seconds")

        # Validate retry count
        if (
            not isinstance(self.retry_count, int)
            or self.retry_count < 0
            or self.retry_count > 10
        ):
            errors.append("Retry count must be an integer between 0 and 10")

        # Validate authentication configuration
        auth_errors = self._validate_auth_config()
        errors.extend(auth_errors)

        # Validate expected status codes
        if not isinstance(self.expected_status_codes, list):
            errors.append("Expected status codes must be a list")
        else:
            for code in self.expected_status_codes:
                if not isinstance(code, int) or code < 100 or code > 599:
                    errors.append(f"Invalid HTTP status code: {code}")

        # Validate request data for POST requests
        if self.method == "POST":
            if self.request_data is not None and self.request_json is not None:
                errors.append("Cannot specify both 'data' and 'json' for POST request")

        return errors

    def _validate_json_path(self, json_path: str) -> List[str]:
        """
        Validate JSONPath expression.

        Args:
            json_path: JSONPath expression to validate

        Returns:
            List of validation error messages

        Requirements: 4.3
        """
        errors = []

        if not json_path:
            errors.append("JSONPath expression is required")
            return errors

        try:
            import jsonpath_ng

            try:
                jsonpath_ng.parse(json_path)
            except Exception as e:
                errors.append(f"Invalid JSONPath expression: {e}")
        except ImportError:
            # Basic validation if jsonpath_ng is not available
            if not json_path.startswith("$"):
                errors.append("JSONPath expression should start with '$'")
            elif len(json_path) > 200:
                errors.append("JSONPath expression too long")

        return errors

    def _validate_auth_config(self) -> List[str]:
        """
        Validate authentication configuration.

        Returns:
            List of validation error messages

        Requirements: 4.4, 4.5
        """
        errors = []

        if self.auth_type not in ["none", "bearer", "basic", "api_key", "custom"]:
            errors.append(
                "Authentication type must be one of: none, bearer, basic, api_key, custom"
            )
            return errors

        if self.auth_type == "bearer":
            token = self.auth_config.get("token") or self._get_secure_credential(
                "bearer_token"
            )
            if not token:
                errors.append("Bearer token is required for bearer authentication")

        elif self.auth_type == "basic":
            username = self.auth_config.get("username") or self._get_secure_credential(
                "username"
            )
            password = self.auth_config.get("password") or self._get_secure_credential(
                "password"
            )
            if not username or not password:
                errors.append(
                    "Username and password are required for basic authentication"
                )

        elif self.auth_type == "api_key":
            api_key = self.auth_config.get("api_key") or self._get_secure_credential(
                "api_key"
            )
            header_name = self.auth_config.get("header_name", "X-API-Key")
            if not api_key:
                errors.append("API key is required for API key authentication")
            if not header_name:
                errors.append("Header name is required for API key authentication")

        elif self.auth_type == "custom":
            if not isinstance(self.auth_config, dict) or not self.auth_config:
                errors.append("Custom authentication configuration is required")

        return errors

    async def fetch_data(self) -> Optional[float]:
        """
        Fetch data from the configured HTTP API endpoint.

        Returns:
            Extracted numeric value from API response, or None if failed

        Requirements: 4.1, 4.2, 4.3, 4.4, 4.5
        """
        try:
            # Prepare request headers with authentication
            request_headers = self._prepare_headers()

            # Prepare request parameters
            request_kwargs = {
                "headers": request_headers,
                "timeout": self.timeout,
                "params": self.request_params,
            }

            # Add request body for POST requests
            if self.method == "POST":
                if self.request_json is not None:
                    request_kwargs["json"] = self.request_json
                elif self.request_data is not None:
                    request_kwargs["data"] = self.request_data

            # Make the HTTP request with retries
            response = await self._make_request_with_retries(
                self.method, self.url, **request_kwargs
            )

            # Validate response status
            if response.status_code not in self.expected_status_codes:
                raise GenericAPIError(
                    f"Unexpected status code: {response.status_code}. "
                    f"Expected: {self.expected_status_codes}"
                )

            # Extract numeric value from response
            value = self._extract_value_from_response(response)

            if value is not None:
                self.logger.info(
                    f"Generic HTTP job extracted value: {value} from {self.method} {self.url}"
                )
                return value
            else:
                raise GenericAPIError("Failed to extract numeric value from response")

        except GenericAPIError as e:
            self.logger.error(f"Generic API error for {self.url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error fetching data from {self.url}: {e}")
            return None

    def _prepare_headers(self) -> Dict[str, str]:
        """
        Prepare request headers including authentication.

        Returns:
            Dictionary of request headers

        Requirements: 4.4, 4.5
        """
        headers = {}

        # Add configured headers
        if self.headers:
            headers.update(self.headers)

        # Add authentication headers
        if self.auth_type == "bearer":
            token = self.auth_config.get("token") or self._get_secure_credential(
                "bearer_token"
            )
            if token:
                headers["Authorization"] = f"Bearer {token}"

        elif self.auth_type == "basic":
            username = self.auth_config.get("username") or self._get_secure_credential(
                "username"
            )
            password = self.auth_config.get("password") or self._get_secure_credential(
                "password"
            )
            if username and password:
                import base64

                credentials = base64.b64encode(
                    f"{username}:{password}".encode()
                ).decode()
                headers["Authorization"] = f"Basic {credentials}"

        elif self.auth_type == "api_key":
            api_key = self.auth_config.get("api_key") or self._get_secure_credential(
                "api_key"
            )
            header_name = self.auth_config.get("header_name", "X-API-Key")
            if api_key and header_name:
                headers[header_name] = api_key

        elif self.auth_type == "custom":
            # Add custom authentication headers
            for key, value in self.auth_config.items():
                if isinstance(key, str) and isinstance(value, str):
                    # Check if value is a credential reference
                    if value.startswith("${") and value.endswith("}"):
                        credential_name = value[2:-1]
                        credential_value = self._get_secure_credential(credential_name)
                        if credential_value:
                            headers[key] = credential_value
                    else:
                        headers[key] = value

        # Ensure Content-Type for POST requests with JSON data
        if self.method == "POST" and self.request_json is not None:
            headers.setdefault("Content-Type", "application/json")

        return headers

    async def _make_request_with_retries(
        self, method: str, url: str, **kwargs
    ) -> requests.Response:
        """
        Make HTTP request with comprehensive retry logic and error handling.

        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Request parameters

        Returns:
            HTTP response object

        Raises:
            GenericAPIError: If all retry attempts fail

        Requirements: 4.2, 4.5, 6.2, 6.3, 6.4
        """
        last_exception = None

        for attempt in range(self.retry_count + 1):
            try:
                self.logger.debug(
                    f"Making {method} request to {url} (attempt {attempt + 1}/{self.retry_count + 1})"
                )

                response = self._make_secure_request(method, url, **kwargs)

                # Handle rate limiting with enhanced error logging
                if response.status_code == 429:
                    wait_time = self.rate_limit_handler.handle_rate_limit(response, url)
                    if wait_time and attempt < self.retry_count:
                        # Log rate limit with structured error details
                        from .error_handling import ErrorCategory, ErrorSeverity

                        error_details = self.error_logger.create_error_details(
                            exception=GenericAPIError(
                                f"Rate limited, waiting {wait_time}s"
                            ),
                            category=ErrorCategory.RATE_LIMIT,
                            severity=ErrorSeverity.MEDIUM,
                            job_id=self.job_config.id,
                            url=url,
                            http_status=429,
                            retry_attempt=attempt,
                            context={
                                "wait_time": wait_time,
                                "retry_after": response.headers.get("retry-after"),
                            },
                        )
                        self.error_logger.log_error(error_details)

                        time.sleep(wait_time)
                        continue
                    else:
                        raise GenericAPIError("Rate limit exceeded after all retries")

                return response

            except requests.RequestException as e:
                last_exception = e
                self.logger.warning(f"Request attempt {attempt + 1} failed: {e}")

                # Log structured error for network failures
                from .error_handling import ErrorCategory, ErrorSeverity

                error_details = self.error_logger.create_error_details(
                    exception=e,
                    category=ErrorCategory.NETWORK,
                    severity=ErrorSeverity.MEDIUM,
                    job_id=self.job_config.id,
                    url=url,
                    retry_attempt=attempt,
                    context={
                        "method": method,
                        "max_retries": self.retry_count,
                        "timeout": kwargs.get("timeout", self.timeout),
                    },
                )
                self.error_logger.log_error(error_details)

                if attempt < self.retry_count:
                    # Exponential backoff with jitter
                    wait_time = (2**attempt) * self.retry_backoff_factor
                    # Add jitter to prevent thundering herd
                    import random

                    jitter = random.uniform(0.5, 1.5)
                    wait_time *= jitter

                    self.logger.info(f"Retrying in {wait_time:.1f} seconds...")
                    time.sleep(wait_time)
                else:
                    break

        # All retries failed - log final failure
        from .error_handling import ErrorCategory, ErrorSeverity

        final_error = GenericAPIError(
            f"All {self.retry_count + 1} request attempts failed: {last_exception}"
        )

        error_details = self.error_logger.create_error_details(
            exception=final_error,
            category=ErrorCategory.NETWORK,
            severity=ErrorSeverity.HIGH,
            job_id=self.job_config.id,
            url=url,
            context={
                "method": method,
                "total_attempts": self.retry_count + 1,
                "final_exception": str(last_exception),
                "exception_type": type(last_exception).__name__
                if last_exception
                else "Unknown",
            },
        )
        self.error_logger.log_error(error_details)

        raise final_error

    def _extract_value_from_response(
        self, response: requests.Response
    ) -> Optional[float]:
        """
        Extract numeric value from HTTP response using JSONPath.

        Args:
            response: HTTP response object

        Returns:
            Extracted numeric value or None if extraction fails

        Requirements: 4.3
        """
        try:
            # Check if response contains JSON
            content_type = response.headers.get("content-type", "").lower()
            if (
                "application/json" not in content_type
                and "text/json" not in content_type
            ):
                # Try to parse as JSON anyway (some APIs don't set proper content-type)
                try:
                    response.json()
                except json.JSONDecodeError:
                    raise GenericAPIError(
                        f"Response is not JSON (content-type: {content_type})"
                    )

            # Use the HTTP utils function for JSON value extraction
            value = extract_json_value(response, self.json_path)

            if value is None:
                # Log response for debugging (truncated)
                response_text = (
                    response.text[:500] + "..."
                    if len(response.text) > 500
                    else response.text
                )
                self.logger.warning(
                    f"Failed to extract value using JSONPath '{self.json_path}' "
                    f"from response: {response_text}"
                )

            return value

        except json.JSONDecodeError as e:
            raise GenericAPIError(f"Invalid JSON response: {e}")
        except Exception as e:
            raise GenericAPIError(f"Failed to extract value from response: {e}")

    def get_request_info(self) -> Dict[str, Any]:
        """
        Get information about the HTTP request configuration.

        Returns:
            Dictionary with request configuration details

        Requirements: 4.1
        """
        # Prepare safe headers (without sensitive data)
        safe_headers = {}
        for key, value in self.headers.items():
            if key.lower() in ["authorization", "x-api-key", "api-key"]:
                safe_headers[key] = "[REDACTED]"
            else:
                safe_headers[key] = value

        return {
            "url": self.url,
            "method": self.method,
            "headers": safe_headers,
            "json_path": self.json_path,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "auth_type": self.auth_type,
            "expected_status_codes": self.expected_status_codes,
            "has_request_data": self.request_data is not None,
            "has_request_json": self.request_json is not None,
            "has_request_params": bool(self.request_params),
        }

    def get_supported_auth_types(self) -> List[Dict[str, Any]]:
        """
        Get list of supported authentication types.

        Returns:
            List of authentication type information

        Requirements: 4.4, 4.5
        """
        return [
            {
                "type": "none",
                "name": "No Authentication",
                "description": "No authentication headers added",
                "required_fields": [],
            },
            {
                "type": "bearer",
                "name": "Bearer Token",
                "description": "Authorization: Bearer <token>",
                "required_fields": ["token"],
            },
            {
                "type": "basic",
                "name": "Basic Authentication",
                "description": "Authorization: Basic <base64(username:password)>",
                "required_fields": ["username", "password"],
            },
            {
                "type": "api_key",
                "name": "API Key",
                "description": "Custom header with API key",
                "required_fields": ["api_key"],
                "optional_fields": ["header_name"],
            },
            {
                "type": "custom",
                "name": "Custom Headers",
                "description": "Custom authentication headers",
                "required_fields": [],
            },
        ]

    def test_connection(self) -> Dict[str, Any]:
        """
        Test the HTTP connection without extracting data.

        Returns:
            Dictionary with connection test results

        Requirements: 4.1, 4.2
        """
        try:
            # Prepare headers
            headers = self._prepare_headers()

            # Make a simple request (HEAD if supported, otherwise GET)
            test_method = "HEAD" if self.method == "GET" else self.method

            response = self._make_secure_request(
                test_method,
                self.url,
                headers=headers,
                timeout=min(self.timeout, 10),  # Shorter timeout for testing
            )

            return {
                "success": True,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
                "content_type": response.headers.get("content-type"),
                "content_length": response.headers.get("content-length"),
                "server": response.headers.get("server"),
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
            }
