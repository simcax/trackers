"""
Job Configuration Validation and Sanitization.

This module provides comprehensive validation and sanitization of job
configuration data to ensure security and correctness.

Requirements: 5.1, 5.4, 8.4, 8.5
"""

import os
import re
import urllib.parse
from typing import Any, Dict, List

try:
    import jsonpath_ng

    JSONPATH_AVAILABLE = True
except ImportError:
    JSONPATH_AVAILABLE = False

try:
    from croniter import croniter

    CRONITER_AVAILABLE = True
except ImportError:
    CRONITER_AVAILABLE = False


class JobConfigValidator:
    """
    Validates and sanitizes job configuration data.

    This class provides comprehensive validation for different job types
    and sanitizes input data to prevent injection attacks and ensure
    data integrity.

    Requirements: 5.1, 5.4, 8.4, 8.5
    """

    def __init__(self):
        """Initialize validator with configuration patterns."""
        self.stock_providers = {
            "alpha_vantage": {
                "name": "Alpha Vantage",
                "requires_api_key": True,
                "supported_markets": ["US", "GLOBAL"],
            },
            "yahoo_finance": {
                "name": "Yahoo Finance",
                "requires_api_key": False,
                "supported_markets": ["US", "GLOBAL"],
            },
            "iex_cloud": {
                "name": "IEX Cloud",
                "requires_api_key": True,
                "supported_markets": ["US"],
            },
        }

        self.allowed_http_methods = ["GET", "POST"]
        self.max_field_length = 1000
        self.max_url_length = 2000

    def resolve_environment_variables(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Resolve environment variables in configuration values.

        Supports ${VAR_NAME} syntax for environment variable substitution.

        Args:
            config: Configuration dictionary that may contain environment variable references

        Returns:
            Configuration with environment variables resolved

        Requirements: 5.1, 5.4
        """
        resolved_config = {}

        for key, value in config.items():
            if (
                isinstance(value, str)
                and value.startswith("${")
                and value.endswith("}")
            ):
                # Extract environment variable name
                env_var_name = value[2:-1]  # Remove ${ and }
                env_value = os.getenv(env_var_name)

                if env_value is not None:
                    resolved_config[key] = env_value
                else:
                    # Keep original value if environment variable not found
                    resolved_config[key] = value
            elif isinstance(value, dict):
                # Recursively resolve nested dictionaries
                resolved_config[key] = self.resolve_environment_variables(value)
            else:
                resolved_config[key] = value

        return resolved_config

    def get_api_key_for_provider(self, provider: str) -> str:
        """
        Get API key for a specific provider from environment variables.

        Args:
            provider: Provider name (e.g., 'alpha_vantage', 'yahoo_finance')

        Returns:
            API key from environment or empty string if not found

        Requirements: 5.1, 5.4
        """
        # Map provider names to environment variable names
        env_var_mapping = {
            "alpha_vantage": "ALPHA_VANTAGE_API_KEY",
            "yahoo_finance": "YAHOO_FINANCE_API_KEY",
            "iex_cloud": "IEX_CLOUD_API_KEY",
        }

        env_var_name = env_var_mapping.get(provider.lower())
        if env_var_name:
            return os.getenv(env_var_name, "")

        return ""

    def validate_job_config(self, job_type: str, config: Dict[str, Any]) -> List[str]:
        """
        Validate job configuration based on job type.

        Args:
            job_type: Type of job ('stock', 'generic')
            config: Job configuration dictionary

        Returns:
            List of validation error messages (empty if valid)

        Requirements: 5.1, 5.4
        """
        if job_type == "stock":
            return self.validate_stock_config(config)
        elif job_type == "generic":
            return self.validate_generic_config(config)
        else:
            return [f"Unknown job type: {job_type}"]

    def validate_stock_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate stock job configuration.

        Args:
            config: Stock job configuration dictionary

        Returns:
            List of validation error messages

        Requirements: 5.1, 5.4
        """
        errors = []

        # Validate stock symbol
        symbol = config.get("symbol", "").strip().upper()
        if not symbol:
            errors.append("Stock symbol is required")
        elif not re.match(r"^[A-Z0-9.-]{1,15}$", symbol):
            errors.append(
                "Stock symbol must be 1-15 characters containing only letters, numbers, hyphens, and dots"
            )

        # Validate provider
        provider = config.get("provider", "").lower()
        if not provider:
            errors.append("Stock provider is required")
        elif provider not in self.stock_providers:
            available = ", ".join(self.stock_providers.keys())
            errors.append(f"Provider must be one of: {available}")
        else:
            # Check if API key is required for this provider
            provider_info = self.stock_providers[provider]
            if provider_info["requires_api_key"]:
                api_key = config.get("api_key", "")

                # If no API key provided, try to get from environment
                if not api_key:
                    env_api_key = self.get_api_key_for_provider(provider)
                    if not env_api_key:
                        errors.append(
                            f"API key is required for {provider_info['name']}. "
                            f"Set ALPHA_VANTAGE_API_KEY environment variable or provide api_key in config."
                        )
                elif len(api_key) < 8 and not api_key.startswith("${"):
                    errors.append("API key appears to be too short")

        # Validate market (optional)
        market = config.get("market", "US").upper()
        if provider in self.stock_providers:
            supported_markets = self.stock_providers[provider]["supported_markets"]
            if market not in supported_markets:
                errors.append(f"Market '{market}' not supported by {provider}")

        return errors

    def validate_generic_config(self, config: Dict[str, Any]) -> List[str]:
        """
        Validate generic HTTP job configuration.

        Args:
            config: Generic job configuration dictionary

        Returns:
            List of validation error messages

        Requirements: 5.1, 5.4, 8.4, 8.5
        """
        errors = []

        # Validate URL
        url = config.get("url", "").strip()
        if not url:
            errors.append("URL is required for generic jobs")
        elif len(url) > self.max_url_length:
            errors.append(f"URL too long (max {self.max_url_length} characters)")
        elif not url.startswith("https://"):
            errors.append("Only HTTPS URLs are allowed for security")
        else:
            try:
                parsed = urllib.parse.urlparse(url)
                if not parsed.netloc:
                    errors.append("Invalid URL format")
                elif parsed.scheme != "https":
                    errors.append("Only HTTPS URLs are allowed")
            except Exception:
                errors.append("Invalid URL format")

        # Validate HTTP method
        method = config.get("method", "GET").upper()
        if method not in self.allowed_http_methods:
            errors.append(
                f"HTTP method must be one of: {', '.join(self.allowed_http_methods)}"
            )

        # Validate JSON path
        json_path = config.get("json_path", "$.value")
        if JSONPATH_AVAILABLE:
            try:
                jsonpath_ng.parse(json_path)
            except Exception as e:
                errors.append(f"Invalid JSONPath expression: {e}")
        else:
            # Basic validation if jsonpath_ng is not available
            if not json_path.startswith("$"):
                errors.append("JSONPath expression should start with '$'")

        # Validate headers
        headers = config.get("headers", {})
        if headers is not None:
            if not isinstance(headers, dict):
                errors.append("Headers must be a dictionary")
            else:
                for key, value in headers.items():
                    if not isinstance(key, str) or not isinstance(value, str):
                        errors.append("Header keys and values must be strings")
                    elif len(key) > 100:
                        errors.append(f"Header key too long: {key}")
                    elif len(value) > self.max_field_length:
                        errors.append(f"Header value too long for key: {key}")

        # Validate timeout
        timeout = config.get("timeout", 30)
        if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 300:
            errors.append("Timeout must be a positive number between 1 and 300 seconds")

        # Validate retry count
        retry_count = config.get("retry_count", 3)
        if not isinstance(retry_count, int) or retry_count < 0 or retry_count > 10:
            errors.append("Retry count must be an integer between 0 and 10")

        return errors

    def validate_cron_schedule(self, cron_expression: str) -> List[str]:
        """
        Validate cron schedule expression.

        Args:
            cron_expression: Cron expression string

        Returns:
            List of validation error messages

        Requirements: 5.1, 5.4
        """
        errors = []

        if not cron_expression or not cron_expression.strip():
            errors.append("Cron schedule is required")
            return errors

        cron_expression = cron_expression.strip()

        # Basic format validation
        parts = cron_expression.split()
        if len(parts) != 5:
            errors.append(
                "Cron expression must have exactly 5 parts (minute hour day month weekday)"
            )
            return errors

        # Use croniter for validation if available
        if CRONITER_AVAILABLE:
            try:
                croniter(cron_expression)
            except Exception as e:
                errors.append(f"Invalid cron expression: {e}")
        else:
            # Basic validation without croniter
            for i, part in enumerate(parts):
                if not re.match(r"^[\d\*\-\,\/]+$", part):
                    field_names = ["minute", "hour", "day", "month", "weekday"]
                    errors.append(
                        f"Invalid characters in {field_names[i]} field: {part}"
                    )

        return errors

    def validate_cron_schedule_detailed(self, cron_expression: str) -> Dict[str, Any]:
        """
        Validate cron schedule expression with detailed feedback.

        Args:
            cron_expression: Cron expression string

        Returns:
            Dictionary with detailed validation results

        Requirements: 5.1, 5.4
        """
        from trackers.services.job_providers.job_config_testing import (
            CronExpressionValidator,
        )

        cron_validator = CronExpressionValidator()
        return cron_validator.validate_cron_expression(cron_expression)

    def sanitize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize configuration data to prevent injection attacks.

        Args:
            config: Configuration dictionary to sanitize

        Returns:
            Sanitized configuration dictionary

        Requirements: 8.4, 8.5
        """
        sanitized = {}

        for key, value in config.items():
            sanitized_key = self._sanitize_string(str(key))[:100]  # Limit key length

            if isinstance(value, str):
                sanitized[sanitized_key] = self._sanitize_string(value)
            elif isinstance(value, dict):
                sanitized[sanitized_key] = self.sanitize_config(value)
            elif isinstance(value, list):
                sanitized[sanitized_key] = [
                    self._sanitize_string(str(item)) if isinstance(item, str) else item
                    for item in value[:10]  # Limit list length
                ]
            elif isinstance(value, (int, float, bool)):
                sanitized[sanitized_key] = value
            elif value is None:
                sanitized[sanitized_key] = None
            else:
                # Convert other types to string and sanitize
                sanitized[sanitized_key] = self._sanitize_string(str(value))

        return sanitized

    def _sanitize_string(self, value: str) -> str:
        """
        Sanitize a string value to prevent injection attacks.

        Args:
            value: String value to sanitize

        Returns:
            Sanitized string value

        Requirements: 8.4, 8.5
        """
        if not isinstance(value, str):
            value = str(value)

        # Remove null bytes and control characters (except tab, newline, carriage return)
        sanitized = "".join(
            char for char in value if ord(char) >= 32 or char in "\t\n\r"
        )

        # Limit length to prevent DoS
        sanitized = sanitized[: self.max_field_length]

        # Remove leading/trailing whitespace
        sanitized = sanitized.strip()

        return sanitized

    def get_validation_info(self) -> Dict[str, Any]:
        """
        Get information about validation capabilities and requirements.

        Returns:
            Dictionary with validation information

        Requirements: 5.1
        """
        return {
            "supported_job_types": ["stock", "generic"],
            "stock_providers": list(self.stock_providers.keys()),
            "http_methods": self.allowed_http_methods,
            "max_field_length": self.max_field_length,
            "max_url_length": self.max_url_length,
            "jsonpath_available": JSONPATH_AVAILABLE,
            "croniter_available": CRONITER_AVAILABLE,
            "security_features": [
                "HTTPS enforcement",
                "Input sanitization",
                "Length limits",
                "Character filtering",
            ],
        }
