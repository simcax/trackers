"""
Job Configuration Testing and Validation Utilities.

This module provides utilities for testing job configurations, validating
cron expressions, and creating mock API responses for testing job providers.

Requirements: 5.1, 5.4, 10.1, 10.2
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock

try:
    from croniter import croniter

    CRONITER_AVAILABLE = True
except ImportError:
    CRONITER_AVAILABLE = False

from trackers.models.job_model import JobModel
from trackers.services.job_providers.job_config_validator import JobConfigValidator

logger = logging.getLogger(__name__)


class CronExpressionValidator:
    """
    Enhanced cron expression validation with detailed error messages.

    Requirements: 5.1, 5.4
    """

    def __init__(self):
        """Initialize cron validator with field definitions."""
        self.field_names = ["minute", "hour", "day", "month", "weekday"]
        self.field_ranges = {
            "minute": (0, 59),
            "hour": (0, 23),
            "day": (1, 31),
            "month": (1, 12),
            "weekday": (0, 7),  # 0 and 7 both represent Sunday
        }

    def validate_cron_expression(self, cron_expression: str) -> Dict[str, Any]:
        """
        Validate cron expression with detailed error reporting.

        Args:
            cron_expression: Cron expression string to validate

        Returns:
            Dict containing validation results with errors and suggestions

        Requirements: 5.1, 5.4
        """
        result = {
            "is_valid": False,
            "errors": [],
            "warnings": [],
            "suggestions": [],
            "next_runs": [],
            "human_readable": None,
        }

        if not cron_expression or not cron_expression.strip():
            result["errors"].append("Cron expression is required")
            result["suggestions"].append("Example: '0 9 * * *' (daily at 9:00 AM)")
            return result

        cron_expression = cron_expression.strip()

        # Basic format validation
        parts = cron_expression.split()
        if len(parts) != 5:
            result["errors"].append(
                f"Cron expression must have exactly 5 parts (minute hour day month weekday), "
                f"found {len(parts)} parts"
            )
            result["suggestions"].extend(
                [
                    "Format: 'minute hour day month weekday'",
                    "Example: '0 9 * * *' (daily at 9:00 AM)",
                    "Example: '*/15 * * * *' (every 15 minutes)",
                    "Example: '0 0 1 * *' (monthly on the 1st at midnight)",
                ]
            )
            return result

        # Validate each field
        field_errors = self._validate_cron_fields(parts)
        result["errors"].extend(field_errors)

        # Use croniter for advanced validation if available
        if CRONITER_AVAILABLE:
            try:
                cron = croniter(cron_expression)
                result["is_valid"] = len(result["errors"]) == 0

                if result["is_valid"]:
                    # Generate next few run times
                    result["next_runs"] = self._get_next_runs(cron, count=5)
                    result["human_readable"] = self._get_human_readable_description(
                        cron_expression
                    )

                    # Add warnings for potentially problematic schedules
                    warnings = self._check_for_warnings(cron_expression, parts)
                    result["warnings"].extend(warnings)

            except Exception as e:
                result["errors"].append(f"Invalid cron expression: {str(e)}")
                result["suggestions"].extend(self._get_error_suggestions(str(e)))
        else:
            # Basic validation without croniter
            if len(result["errors"]) == 0:
                result["is_valid"] = True
                result["warnings"].append(
                    "Advanced cron validation not available. Install 'croniter' for better validation."
                )

        return result

    def _validate_cron_fields(self, parts: List[str]) -> List[str]:
        """
        Validate individual cron fields.

        Args:
            parts: List of cron expression parts

        Returns:
            List of validation errors
        """
        errors = []

        for i, part in enumerate(parts):
            field_name = self.field_names[i]
            field_min, field_max = self.field_ranges[field_name]

            # Check for valid characters
            if not self._is_valid_cron_field(part):
                errors.append(
                    f"Invalid characters in {field_name} field: '{part}'. "
                    f"Use numbers, *, -, /, and , only"
                )
                continue

            # Validate numeric ranges
            field_errors = self._validate_field_ranges(
                part, field_name, field_min, field_max
            )
            errors.extend(field_errors)

        return errors

    def _is_valid_cron_field(self, field: str) -> bool:
        """Check if field contains only valid cron characters."""
        import re

        return bool(re.match(r"^[\d\*\-\,\/]+$", field))

    def _validate_field_ranges(
        self, field: str, field_name: str, min_val: int, max_val: int
    ) -> List[str]:
        """Validate numeric ranges in a cron field."""
        errors = []

        if field == "*":
            return errors

        # Handle comma-separated values
        for part in field.split(","):
            part = part.strip()

            # Handle ranges (e.g., "1-5")
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    start_val = int(start)
                    end_val = int(end)

                    if start_val < min_val or start_val > max_val:
                        errors.append(
                            f"{field_name} range start {start_val} is out of range "
                            f"({min_val}-{max_val})"
                        )
                    if end_val < min_val or end_val > max_val:
                        errors.append(
                            f"{field_name} range end {end_val} is out of range "
                            f"({min_val}-{max_val})"
                        )
                    if start_val > end_val:
                        errors.append(
                            f"{field_name} range start {start_val} is greater than end {end_val}"
                        )
                except ValueError:
                    errors.append(
                        f"Invalid range format in {field_name} field: '{part}'"
                    )

            # Handle step values (e.g., "*/5" or "1-10/2")
            elif "/" in part:
                try:
                    base, step = part.split("/", 1)
                    step_val = int(step)

                    if step_val <= 0:
                        errors.append(
                            f"{field_name} step value must be positive: {step_val}"
                        )
                    elif step_val > (max_val - min_val + 1):
                        errors.append(
                            f"{field_name} step value {step_val} is too large for range "
                            f"({min_val}-{max_val})"
                        )

                    # Validate base part if not "*"
                    if base != "*":
                        base_errors = self._validate_field_ranges(
                            base, field_name, min_val, max_val
                        )
                        errors.extend(base_errors)

                except ValueError:
                    errors.append(
                        f"Invalid step format in {field_name} field: '{part}'"
                    )

            # Handle single numeric values
            else:
                try:
                    val = int(part)
                    if val < min_val or val > max_val:
                        errors.append(
                            f"{field_name} value {val} is out of range ({min_val}-{max_val})"
                        )
                except ValueError:
                    errors.append(
                        f"Invalid numeric value in {field_name} field: '{part}'"
                    )

        return errors

    def _get_next_runs(self, cron: "croniter", count: int = 5) -> List[str]:
        """Get next few execution times."""
        next_runs = []
        for _ in range(count):
            next_run = cron.get_next(datetime)
            next_runs.append(next_run.isoformat())
        return next_runs

    def _get_human_readable_description(self, cron_expression: str) -> str:
        """Generate human-readable description of cron expression."""
        parts = cron_expression.split()
        minute, hour, day, month, weekday = parts

        descriptions = []

        # Time description
        if minute == "0" and hour != "*":
            if hour.isdigit():
                descriptions.append(f"at {hour}:00")
            else:
                descriptions.append(f"at hour {hour}")
        elif minute != "*" or hour != "*":
            time_desc = f"at {hour if hour != '*' else 'every hour'}:{minute if minute != '*' else 'every minute'}"
            descriptions.append(time_desc)

        # Frequency description
        if day == "*" and month == "*" and weekday == "*":
            descriptions.append("every day")
        elif day != "*" and month == "*" and weekday == "*":
            descriptions.append(f"on day {day} of every month")
        elif day == "*" and month != "*" and weekday == "*":
            descriptions.append(f"every day in month {month}")
        elif day == "*" and month == "*" and weekday != "*":
            weekday_names = [
                "Sunday",
                "Monday",
                "Tuesday",
                "Wednesday",
                "Thursday",
                "Friday",
                "Saturday",
            ]
            if weekday.isdigit() and 0 <= int(weekday) <= 6:
                descriptions.append(f"every {weekday_names[int(weekday)]}")
            else:
                descriptions.append(f"on weekday {weekday}")

        return " ".join(descriptions) if descriptions else "complex schedule"

    def _check_for_warnings(self, cron_expression: str, parts: List[str]) -> List[str]:
        """Check for potentially problematic cron schedules."""
        warnings = []
        minute, hour, day, month, weekday = parts

        # Very frequent executions
        if minute.startswith("*/") and int(minute.split("/")[1]) < 5:
            warnings.append(
                "Very frequent execution (less than 5 minutes). "
                "Consider if this is necessary to avoid API rate limits."
            )

        # Executions during typical maintenance hours
        if hour.isdigit() and 2 <= int(hour) <= 4:
            warnings.append(
                "Scheduled during typical maintenance hours (2-4 AM). "
                "External APIs might be less reliable during this time."
            )

        # Complex expressions that might be hard to understand
        complexity_score = sum(
            1 for part in parts if any(char in part for char in [",", "-", "/"])
        )
        if complexity_score >= 3:
            warnings.append(
                "Complex cron expression. Consider simplifying for better maintainability."
            )

        return warnings

    def _get_error_suggestions(self, error_message: str) -> List[str]:
        """Get suggestions based on error message."""
        suggestions = []

        if "minute" in error_message.lower():
            suggestions.extend(
                [
                    "Minutes: 0-59, or * for every minute",
                    "Examples: 0 (top of hour), 30 (half past), */15 (every 15 minutes)",
                ]
            )
        if "hour" in error_message.lower():
            suggestions.extend(
                [
                    "Hours: 0-23 (24-hour format), or * for every hour",
                    "Examples: 9 (9 AM), 14 (2 PM), */2 (every 2 hours)",
                ]
            )
        if "day" in error_message.lower():
            suggestions.extend(
                [
                    "Day of month: 1-31, or * for every day",
                    "Examples: 1 (1st of month), 15 (15th), */7 (every 7 days)",
                ]
            )
        if "month" in error_message.lower():
            suggestions.extend(
                [
                    "Month: 1-12, or * for every month",
                    "Examples: 1 (January), 6 (June), */3 (every 3 months)",
                ]
            )
        if "weekday" in error_message.lower():
            suggestions.extend(
                [
                    "Weekday: 0-7 (0 and 7 = Sunday), or * for every day",
                    "Examples: 1 (Monday), 5 (Friday), 1-5 (weekdays)",
                ]
            )

        return suggestions


class MockAPIProvider:
    """
    Mock external APIs for testing job providers.

    Requirements: 10.1, 10.2
    """

    def __init__(self):
        """Initialize mock API provider."""
        self.stock_responses = {}
        self.generic_responses = {}
        self.default_responses = {}

    def setup_stock_api_mock(
        self,
        symbol: str,
        price: float,
        provider: str = "alpha_vantage",
        status_code: int = 200,
        additional_data: Optional[Dict] = None,
    ) -> None:
        """
        Set up mock response for stock API.

        Args:
            symbol: Stock symbol (e.g., "AAPL")
            price: Stock price to return
            provider: API provider name
            status_code: HTTP status code to return
            additional_data: Additional data to include in response

        Requirements: 10.1, 10.2
        """
        key = f"{provider}_{symbol}"

        if provider == "alpha_vantage":
            response_data = {
                "Global Quote": {
                    "01. symbol": symbol,
                    "05. price": str(price),
                    "07. latest trading day": datetime.now().strftime("%Y-%m-%d"),
                    "09. change": "0.00",
                    "10. change percent": "0.00%",
                }
            }
        elif provider == "yahoo_finance":
            response_data = {
                "chart": {
                    "result": [
                        {
                            "meta": {"regularMarketPrice": price, "symbol": symbol},
                            "timestamp": [int(datetime.now().timestamp())],
                            "indicators": {"quote": [{"close": [price]}]},
                        }
                    ]
                }
            }
        else:
            # Generic stock response format
            response_data = {
                "symbol": symbol,
                "price": price,
                "timestamp": datetime.now().isoformat(),
            }

        if additional_data:
            response_data.update(additional_data)

        self.stock_responses[key] = {
            "status_code": status_code,
            "json": response_data,
            "headers": {"Content-Type": "application/json"},
        }

    def setup_generic_api_mock(
        self,
        url: str,
        response_data: Union[Dict, List, str, float, int],
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Set up mock response for generic HTTP API.

        Args:
            url: API endpoint URL
            response_data: Data to return in response
            status_code: HTTP status code to return
            headers: HTTP headers to return

        Requirements: 10.1, 10.2
        """
        self.generic_responses[url] = {
            "status_code": status_code,
            "json": response_data
            if isinstance(response_data, dict)
            else {"value": response_data},
            "text": json.dumps(response_data)
            if not isinstance(response_data, str)
            else response_data,
            "headers": headers or {"Content-Type": "application/json"},
        }

    def simulate_rate_limit(self, url_or_symbol: str, retry_after: int = 60) -> None:
        """
        Simulate API rate limiting.

        Args:
            url_or_symbol: URL or stock symbol to apply rate limit to
            retry_after: Seconds to wait before retry

        Requirements: 10.1, 10.2
        """
        response_data = {
            "error": "Rate limit exceeded",
            "message": f"Too many requests. Try again in {retry_after} seconds.",
            "retry_after": retry_after,
        }

        mock_response = {
            "status_code": 429,
            "json": response_data,
            "headers": {
                "Content-Type": "application/json",
                "Retry-After": str(retry_after),
            },
        }

        # Apply to both stock and generic responses
        if "_" in url_or_symbol:  # Likely a stock key
            self.stock_responses[url_or_symbol] = mock_response
        else:  # Likely a URL
            self.generic_responses[url_or_symbol] = mock_response

    def simulate_network_error(
        self, url_or_symbol: str, error_type: str = "timeout"
    ) -> None:
        """
        Simulate network errors.

        Args:
            url_or_symbol: URL or stock symbol to apply error to
            error_type: Type of error ("timeout", "connection", "dns")

        Requirements: 10.1, 10.2
        """
        error_responses = {
            "timeout": {"status_code": 408, "error": "Request timeout"},
            "connection": {"status_code": 503, "error": "Connection failed"},
            "dns": {"status_code": 502, "error": "DNS resolution failed"},
        }

        error_config = error_responses.get(error_type, error_responses["timeout"])

        mock_response = {
            "status_code": error_config["status_code"],
            "json": {"error": error_config["error"]},
            "headers": {"Content-Type": "application/json"},
            "raise_exception": True,
            "exception_type": error_type,
        }

        # Apply to both stock and generic responses
        if "_" in url_or_symbol:  # Likely a stock key
            self.stock_responses[url_or_symbol] = mock_response
        else:  # Likely a URL
            self.generic_responses[url_or_symbol] = mock_response

    def get_mock_response(self, url_or_key: str) -> Optional[Dict]:
        """
        Get mock response for URL or stock key.

        Args:
            url_or_key: URL or stock API key

        Returns:
            Mock response configuration or None

        Requirements: 10.1, 10.2
        """
        # Check stock responses first
        if url_or_key in self.stock_responses:
            return self.stock_responses[url_or_key]

        # Check generic responses
        if url_or_key in self.generic_responses:
            return self.generic_responses[url_or_key]

        # Check default responses
        return self.default_responses.get(url_or_key)

    def clear_mocks(self) -> None:
        """Clear all mock responses."""
        self.stock_responses.clear()
        self.generic_responses.clear()
        self.default_responses.clear()


class JobConfigurationTester:
    """
    Test job configurations without scheduling them.

    Requirements: 5.1, 5.4, 10.1, 10.2
    """

    def __init__(self, mock_api_provider: Optional[MockAPIProvider] = None):
        """
        Initialize job configuration tester.

        Args:
            mock_api_provider: Optional mock API provider for testing
        """
        self.validator = JobConfigValidator()
        self.cron_validator = CronExpressionValidator()
        self.mock_api = mock_api_provider or MockAPIProvider()

    def test_job_configuration(
        self,
        job_type: str,
        config: Dict[str, Any],
        cron_schedule: str,
        use_mocks: bool = True,
    ) -> Dict[str, Any]:
        """
        Test a complete job configuration without scheduling.

        Args:
            job_type: Type of job ("stock" or "generic")
            config: Job configuration dictionary
            cron_schedule: Cron schedule expression
            use_mocks: Whether to use mock APIs for testing

        Returns:
            Comprehensive test results

        Requirements: 5.1, 5.4, 10.1, 10.2
        """
        test_results = {
            "overall_valid": False,
            "config_validation": {},
            "cron_validation": {},
            "execution_test": {},
            "recommendations": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Test configuration validation
        test_results["config_validation"] = self._test_config_validation(
            job_type, config
        )

        # Test cron schedule validation
        test_results["cron_validation"] = self.cron_validator.validate_cron_expression(
            cron_schedule
        )

        # Test job execution if configuration is valid
        if (
            test_results["config_validation"]["is_valid"]
            and test_results["cron_validation"]["is_valid"]
        ):
            test_results["execution_test"] = self._test_job_execution(
                job_type, config, use_mocks
            )

        # Generate overall validity and recommendations
        test_results["overall_valid"] = (
            test_results["config_validation"]["is_valid"]
            and test_results["cron_validation"]["is_valid"]
            and test_results["execution_test"].get("success", False)
        )

        test_results["recommendations"] = self._generate_recommendations(test_results)

        return test_results

    def _test_config_validation(
        self, job_type: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Test job configuration validation."""
        # Resolve environment variables
        resolved_config = self.validator.resolve_environment_variables(config)

        # Sanitize configuration
        sanitized_config = self.validator.sanitize_config(resolved_config)

        # Validate configuration
        validation_errors = self.validator.validate_job_config(
            job_type, sanitized_config
        )

        return {
            "is_valid": len(validation_errors) == 0,
            "errors": validation_errors,
            "resolved_config": resolved_config,
            "sanitized_config": sanitized_config,
            "changes_made": resolved_config != config,
        }

    def _test_job_execution(
        self, job_type: str, config: Dict[str, Any], use_mocks: bool
    ) -> Dict[str, Any]:
        """Test job execution simulation."""
        execution_result = {
            "success": False,
            "error_message": None,
            "execution_time": 0.0,
            "mock_used": use_mocks,
            "response_preview": None,
        }

        try:
            if use_mocks:
                # Set up appropriate mocks
                if job_type == "stock":
                    symbol = config.get("symbol", "TEST")
                    provider = config.get("provider", "alpha_vantage")
                    self.mock_api.setup_stock_api_mock(symbol, 150.00, provider)

                elif job_type == "generic":
                    url = config.get("url", "https://api.example.com/test")
                    self.mock_api.setup_generic_api_mock(url, {"value": 42.0})

            # Create a mock job model for testing
            mock_job = self._create_mock_job_model(job_type, config)

            # Simulate job execution
            start_time = datetime.now(timezone.utc)

            # This would normally create and execute a job provider
            # For testing, we simulate the execution
            if job_type == "stock":
                execution_result.update(self._simulate_stock_execution(config))
            elif job_type == "generic":
                execution_result.update(self._simulate_generic_execution(config))

            execution_result["execution_time"] = (
                datetime.now(timezone.utc) - start_time
            ).total_seconds()

        except Exception as e:
            execution_result["error_message"] = str(e)

        return execution_result

    def _simulate_stock_execution(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate stock job execution."""
        symbol = config.get("symbol", "TEST")
        provider = config.get("provider", "alpha_vantage")

        # Check if we have a mock response
        mock_key = f"{provider}_{symbol}"
        mock_response = self.mock_api.get_mock_response(mock_key)

        if mock_response:
            if mock_response.get("raise_exception"):
                return {
                    "success": False,
                    "error_message": f"Network error: {mock_response['json']['error']}",
                }
            else:
                return {
                    "success": True,
                    "value": 150.00,  # Mock price
                    "response_preview": mock_response["json"],
                }
        else:
            return {
                "success": False,
                "error_message": "No mock response configured for stock API",
            }

    def _simulate_generic_execution(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate generic job execution."""
        url = config.get("url", "https://api.example.com/test")

        # Check if we have a mock response
        mock_response = self.mock_api.get_mock_response(url)

        if mock_response:
            if mock_response.get("raise_exception"):
                return {
                    "success": False,
                    "error_message": f"Network error: {mock_response['json']['error']}",
                }
            else:
                return {
                    "success": True,
                    "value": 42.0,  # Mock value
                    "response_preview": mock_response["json"],
                }
        else:
            return {
                "success": False,
                "error_message": "No mock response configured for generic API",
            }

    def _create_mock_job_model(self, job_type: str, config: Dict[str, Any]) -> Mock:
        """Create a mock JobModel for testing."""
        mock_job = Mock(spec=JobModel)
        mock_job.id = 999  # Test job ID
        mock_job.name = "Test Job"
        mock_job.job_type = job_type
        mock_job.config = json.dumps(config)
        mock_job.is_active = True
        mock_job.user_id = 1
        mock_job.tracker_id = 1
        return mock_job

    def _generate_recommendations(self, test_results: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on test results."""
        recommendations = []

        # Configuration recommendations
        if not test_results["config_validation"]["is_valid"]:
            recommendations.append("Fix configuration errors before creating the job")

        # Cron schedule recommendations
        cron_warnings = test_results["cron_validation"].get("warnings", [])
        if cron_warnings:
            recommendations.extend(
                [f"Cron schedule warning: {warning}" for warning in cron_warnings]
            )

        # Execution recommendations
        if not test_results["execution_test"].get("success", False):
            recommendations.append(
                "Test job execution failed. Verify API credentials and endpoints."
            )

        # Performance recommendations
        execution_time = test_results["execution_test"].get("execution_time", 0)
        if execution_time > 30:
            recommendations.append(
                f"Job execution took {execution_time:.1f}s. Consider optimizing for better performance."
            )

        if not recommendations:
            recommendations.append("Job configuration looks good! Ready to create.")

        return recommendations


class JobConfigurationExamples:
    """
    Provides example job configurations and templates.

    Requirements: 10.1, 10.2
    """

    @staticmethod
    def get_stock_job_examples() -> Dict[str, Dict[str, Any]]:
        """
        Get example stock job configurations.

        Returns:
            Dictionary of example configurations

        Requirements: 10.1, 10.2
        """
        return {
            "alpha_vantage_daily": {
                "name": "Daily Apple Stock Price",
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",
                    "provider": "alpha_vantage",
                    "api_key": "${ALPHA_VANTAGE_API_KEY}",
                    "market": "US",
                },
                "cron_schedule": "0 9 * * 1-5",  # Weekdays at 9 AM
                "description": "Fetch Apple stock price daily during market hours",
            },
            "yahoo_finance_hourly": {
                "name": "Hourly Tesla Stock Price",
                "job_type": "stock",
                "config": {
                    "symbol": "TSLA",
                    "provider": "yahoo_finance",
                    "market": "US",
                },
                "cron_schedule": "0 9-16 * * 1-5",  # Every hour during market hours
                "description": "Fetch Tesla stock price hourly during trading hours",
            },
            "crypto_tracking": {
                "name": "Bitcoin Price Tracking",
                "job_type": "stock",
                "config": {
                    "symbol": "BTC-USD",
                    "provider": "yahoo_finance",
                    "market": "CRYPTO",
                },
                "cron_schedule": "*/30 * * * *",  # Every 30 minutes
                "description": "Track Bitcoin price every 30 minutes",
            },
        }

    @staticmethod
    def get_generic_job_examples() -> Dict[str, Dict[str, Any]]:
        """
        Get example generic job configurations.

        Returns:
            Dictionary of example configurations

        Requirements: 10.1, 10.2
        """
        return {
            "weather_api": {
                "name": "Daily Weather Temperature",
                "job_type": "generic",
                "config": {
                    "url": "https://api.openweathermap.org/data/2.5/weather",
                    "method": "GET",
                    "headers": {"Accept": "application/json"},
                    "params": {
                        "q": "New York",
                        "appid": "${OPENWEATHER_API_KEY}",
                        "units": "metric",
                    },
                    "json_path": "$.main.temp",
                    "timeout": 30,
                    "retry_count": 3,
                },
                "cron_schedule": "0 8 * * *",  # Daily at 8 AM
                "description": "Fetch daily temperature for New York",
            },
            "api_with_auth": {
                "name": "Custom API with Authentication",
                "job_type": "generic",
                "config": {
                    "url": "https://api.example.com/metrics/daily",
                    "method": "GET",
                    "headers": {
                        "Authorization": "Bearer ${API_TOKEN}",
                        "Content-Type": "application/json",
                    },
                    "json_path": "$.data.value",
                    "timeout": 45,
                    "retry_count": 2,
                    "expected_status_codes": [200, 202],
                },
                "cron_schedule": "0 0 * * *",  # Daily at midnight
                "description": "Fetch daily metrics from custom API with bearer token auth",
            },
            "post_request": {
                "name": "POST Request with Data",
                "job_type": "generic",
                "config": {
                    "url": "https://api.example.com/calculate",
                    "method": "POST",
                    "headers": {
                        "Content-Type": "application/json",
                        "X-API-Key": "${CUSTOM_API_KEY}",
                    },
                    "data": {"metric": "daily_average", "period": "24h"},
                    "json_path": "$.result.average",
                    "timeout": 60,
                    "retry_count": 3,
                },
                "cron_schedule": "0 1 * * *",  # Daily at 1 AM
                "description": "POST request to calculate daily averages",
            },
        }

    @staticmethod
    def get_cron_schedule_examples() -> Dict[str, str]:
        """
        Get example cron schedule expressions with descriptions.

        Returns:
            Dictionary mapping cron expressions to descriptions

        Requirements: 10.1, 10.2
        """
        return {
            "0 9 * * *": "Daily at 9:00 AM",
            "0 9 * * 1-5": "Weekdays at 9:00 AM",
            "0 0 1 * *": "Monthly on the 1st at midnight",
            "0 0 * * 0": "Weekly on Sunday at midnight",
            "*/15 * * * *": "Every 15 minutes",
            "0 */2 * * *": "Every 2 hours",
            "0 9,17 * * 1-5": "Weekdays at 9 AM and 5 PM",
            "0 0 1,15 * *": "Twice monthly (1st and 15th) at midnight",
            "0 8-17 * * 1-5": "Every hour from 8 AM to 5 PM on weekdays",
            "*/30 9-17 * * 1-5": "Every 30 minutes during business hours",
        }

    @staticmethod
    def get_configuration_template(job_type: str) -> Dict[str, Any]:
        """
        Get a configuration template for a job type.

        Args:
            job_type: Type of job ("stock" or "generic")

        Returns:
            Configuration template

        Requirements: 10.1, 10.2
        """
        if job_type == "stock":
            return {
                "name": "My Stock Job",
                "job_type": "stock",
                "config": {
                    "symbol": "AAPL",  # Stock symbol to track
                    "provider": "alpha_vantage",  # API provider
                    "api_key": "${ALPHA_VANTAGE_API_KEY}",  # Environment variable
                    "market": "US",  # Market type
                },
                "cron_schedule": "0 9 * * 1-5",  # Weekdays at 9 AM
                "is_active": True,
                "description": "Template for stock price tracking job",
            }
        elif job_type == "generic":
            return {
                "name": "My Generic API Job",
                "job_type": "generic",
                "config": {
                    "url": "https://api.example.com/data",  # API endpoint
                    "method": "GET",  # HTTP method
                    "headers": {  # HTTP headers
                        "Accept": "application/json",
                        "Authorization": "Bearer ${API_TOKEN}",
                    },
                    "json_path": "$.value",  # JSONPath to extract value
                    "timeout": 30,  # Request timeout in seconds
                    "retry_count": 3,  # Number of retries on failure
                },
                "cron_schedule": "0 0 * * *",  # Daily at midnight
                "is_active": True,
                "description": "Template for generic HTTP API job",
            }
        else:
            raise ValueError(f"Unknown job type: {job_type}")
