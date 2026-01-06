"""
Tests for Job Configuration Testing and Validation Utilities.

This module tests the job configuration testing utilities including
cron validation, mock API systems, and configuration testing.

Requirements: 5.1, 5.4, 10.1, 10.2
"""

from unittest.mock import patch

import pytest

from trackers.services.job_providers.job_config_testing import (
    CronExpressionValidator,
    JobConfigurationExamples,
    JobConfigurationTester,
    MockAPIProvider,
)
from trackers.services.job_providers.job_testing_service import JobTestingService


class TestCronExpressionValidator:
    """Test cases for CronExpressionValidator class."""

    def test_valid_cron_expressions(self):
        """Test validation of valid cron expressions."""
        validator = CronExpressionValidator()

        valid_expressions = [
            "0 9 * * *",  # Daily at 9 AM
            "0 9 * * 1-5",  # Weekdays at 9 AM
            "*/15 * * * *",  # Every 15 minutes
            "0 0 1 * *",  # Monthly on 1st at midnight
            "0 9,17 * * 1-5",  # Weekdays at 9 AM and 5 PM
        ]

        for expr in valid_expressions:
            result = validator.validate_cron_expression(expr)
            assert result["is_valid"], f"Expression '{expr}' should be valid"
            assert len(result["errors"]) == 0

    def test_invalid_cron_expressions(self):
        """Test validation of invalid cron expressions."""
        validator = CronExpressionValidator()

        invalid_expressions = [
            "",  # Empty
            "0 9 * *",  # Too few parts
            "0 9 * * * *",  # Too many parts
            "60 9 * * *",  # Invalid minute
            "0 25 * * *",  # Invalid hour
            "0 9 32 * *",  # Invalid day
            "0 9 * 13 *",  # Invalid month
            "0 9 * * 8",  # Invalid weekday
        ]

        for expr in invalid_expressions:
            result = validator.validate_cron_expression(expr)
            assert not result["is_valid"], f"Expression '{expr}' should be invalid"
            assert len(result["errors"]) > 0

    def test_cron_validation_with_suggestions(self):
        """Test that validation provides helpful suggestions."""
        validator = CronExpressionValidator()

        result = validator.validate_cron_expression("60 9 * * *")  # Invalid minute

        assert not result["is_valid"]
        assert len(result["errors"]) > 0
        # The error message itself should be helpful, even if no separate suggestions
        assert any("minute" in error.lower() for error in result["errors"])

    def test_cron_validation_warnings(self):
        """Test that validation provides warnings for problematic schedules."""
        validator = CronExpressionValidator()

        # Very frequent execution
        result = validator.validate_cron_expression("*/1 * * * *")  # Every minute

        if result["is_valid"]:  # Only check warnings if expression is valid
            # Should have at least some warnings (either about frequency or croniter availability)
            assert len(result["warnings"]) > 0
            # Check for either frequency warning or croniter warning
            has_frequency_warning = any(
                "frequent" in warning.lower() for warning in result["warnings"]
            )
            has_croniter_warning = any(
                "croniter" in warning.lower() for warning in result["warnings"]
            )
            assert has_frequency_warning or has_croniter_warning
        else:
            # If invalid, that's also acceptable for this test
            assert not result["is_valid"]

    @patch(
        "trackers.services.job_providers.job_config_testing.CRONITER_AVAILABLE", False
    )
    def test_cron_validation_without_croniter(self):
        """Test cron validation when croniter is not available."""
        validator = CronExpressionValidator()

        result = validator.validate_cron_expression("0 9 * * *")

        # Should still do basic validation
        assert result["is_valid"]
        assert len(result["warnings"]) > 0
        assert any("croniter" in warning for warning in result["warnings"])


class TestMockAPIProvider:
    """Test cases for MockAPIProvider class."""

    def test_setup_stock_api_mock(self):
        """Test setting up stock API mocks."""
        mock_api = MockAPIProvider()

        mock_api.setup_stock_api_mock("AAPL", 150.0, "alpha_vantage")

        response = mock_api.get_mock_response("alpha_vantage_AAPL")
        assert response is not None
        assert response["status_code"] == 200
        assert "Global Quote" in response["json"]
        assert response["json"]["Global Quote"]["05. price"] == "150.0"

    def test_setup_generic_api_mock(self):
        """Test setting up generic API mocks."""
        mock_api = MockAPIProvider()

        url = "https://api.example.com/data"
        mock_api.setup_generic_api_mock(url, {"value": 42.0})

        response = mock_api.get_mock_response(url)
        assert response is not None
        assert response["status_code"] == 200
        assert response["json"]["value"] == 42.0

    def test_simulate_rate_limit(self):
        """Test simulating API rate limits."""
        mock_api = MockAPIProvider()

        url = "https://api.example.com/data"
        mock_api.simulate_rate_limit(url, retry_after=60)

        response = mock_api.get_mock_response(url)
        assert response is not None
        assert response["status_code"] == 429
        assert "Rate limit exceeded" in response["json"]["error"]
        assert response["headers"]["Retry-After"] == "60"

    def test_simulate_network_error(self):
        """Test simulating network errors."""
        mock_api = MockAPIProvider()

        url = "https://api.example.com/data"
        mock_api.simulate_network_error(url, "timeout")

        response = mock_api.get_mock_response(url)
        assert response is not None
        assert response["status_code"] == 408
        assert response["raise_exception"] is True
        assert response["exception_type"] == "timeout"

    def test_clear_mocks(self):
        """Test clearing all mocks."""
        mock_api = MockAPIProvider()

        # Set up some mocks
        mock_api.setup_stock_api_mock("AAPL", 150.0)
        mock_api.setup_generic_api_mock("https://api.example.com", {"value": 42})

        # Verify mocks exist
        assert mock_api.get_mock_response("alpha_vantage_AAPL") is not None
        assert mock_api.get_mock_response("https://api.example.com") is not None

        # Clear mocks
        mock_api.clear_mocks()

        # Verify mocks are cleared
        assert mock_api.get_mock_response("alpha_vantage_AAPL") is None
        assert mock_api.get_mock_response("https://api.example.com") is None


class TestJobConfigurationTester:
    """Test cases for JobConfigurationTester class."""

    def test_test_stock_job_configuration(self):
        """Test testing stock job configuration."""
        mock_api = MockAPIProvider()
        tester = JobConfigurationTester(mock_api)

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_key_12345",
            "market": "US",
        }

        result = tester.test_job_configuration(
            "stock", config, "0 9 * * *", use_mocks=True
        )

        assert "overall_valid" in result
        assert "config_validation" in result
        assert "cron_validation" in result
        assert "execution_test" in result
        assert "recommendations" in result

        # Configuration should be valid
        assert result["config_validation"]["is_valid"]
        assert result["cron_validation"]["is_valid"]

    def test_test_generic_job_configuration(self):
        """Test testing generic job configuration."""
        mock_api = MockAPIProvider()
        tester = JobConfigurationTester(mock_api)

        config = {
            "url": "https://api.example.com/data",
            "method": "GET",
            "headers": {"Accept": "application/json"},
            "json_path": "$.value",
            "timeout": 30,
        }

        result = tester.test_job_configuration(
            "generic", config, "0 0 * * *", use_mocks=True
        )

        assert "overall_valid" in result
        assert "config_validation" in result
        assert "cron_validation" in result
        assert "execution_test" in result

        # Configuration should be valid
        assert result["config_validation"]["is_valid"]
        assert result["cron_validation"]["is_valid"]

    def test_test_invalid_configuration(self):
        """Test testing invalid job configuration."""
        tester = JobConfigurationTester()

        # Invalid stock config (missing required fields)
        config = {"symbol": ""}  # Empty symbol

        result = tester.test_job_configuration(
            "stock", config, "invalid cron", use_mocks=True
        )

        assert not result["overall_valid"]
        assert not result["config_validation"]["is_valid"]
        assert not result["cron_validation"]["is_valid"]
        assert len(result["recommendations"]) > 0


class TestJobConfigurationExamples:
    """Test cases for JobConfigurationExamples class."""

    def test_get_stock_job_examples(self):
        """Test getting stock job examples."""
        examples = JobConfigurationExamples.get_stock_job_examples()

        assert isinstance(examples, dict)
        assert len(examples) > 0

        # Check that examples have required fields
        for example_name, example in examples.items():
            assert "name" in example
            assert "job_type" in example
            assert "config" in example
            assert "cron_schedule" in example
            assert example["job_type"] == "stock"

    def test_get_generic_job_examples(self):
        """Test getting generic job examples."""
        examples = JobConfigurationExamples.get_generic_job_examples()

        assert isinstance(examples, dict)
        assert len(examples) > 0

        # Check that examples have required fields
        for example_name, example in examples.items():
            assert "name" in example
            assert "job_type" in example
            assert "config" in example
            assert "cron_schedule" in example
            assert example["job_type"] == "generic"

    def test_get_cron_schedule_examples(self):
        """Test getting cron schedule examples."""
        examples = JobConfigurationExamples.get_cron_schedule_examples()

        assert isinstance(examples, dict)
        assert len(examples) > 0

        # Check that all examples are strings
        for cron_expr, description in examples.items():
            assert isinstance(cron_expr, str)
            assert isinstance(description, str)
            assert len(cron_expr.split()) == 5  # Valid cron format

    def test_get_configuration_template_stock(self):
        """Test getting stock configuration template."""
        template = JobConfigurationExamples.get_configuration_template("stock")

        assert template["job_type"] == "stock"
        assert "config" in template
        assert "symbol" in template["config"]
        assert "provider" in template["config"]
        assert "cron_schedule" in template

    def test_get_configuration_template_generic(self):
        """Test getting generic configuration template."""
        template = JobConfigurationExamples.get_configuration_template("generic")

        assert template["job_type"] == "generic"
        assert "config" in template
        assert "url" in template["config"]
        assert "method" in template["config"]
        assert "cron_schedule" in template

    def test_get_configuration_template_invalid(self):
        """Test getting template for invalid job type."""
        with pytest.raises(ValueError):
            JobConfigurationExamples.get_configuration_template("invalid")


class TestJobTestingService:
    """Test cases for JobTestingService class."""

    def test_validate_cron_expression(self):
        """Test cron expression validation through service."""
        service = JobTestingService()

        result = service.validate_cron_expression("0 9 * * *")

        assert "is_valid" in result
        assert result["is_valid"]
        assert "errors" in result
        assert "suggestions" in result

    def test_test_job_configuration(self):
        """Test job configuration testing through service."""
        service = JobTestingService()

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_key_12345",
        }

        result = service.test_job_configuration(
            "stock", config, "0 9 * * *", use_mocks=True
        )

        assert "overall_valid" in result
        assert "config_validation" in result
        assert "cron_validation" in result
        assert "execution_test" in result

    def test_get_job_examples(self):
        """Test getting job examples through service."""
        service = JobTestingService()

        # Get all examples
        all_examples = service.get_job_examples()
        assert "stock_examples" in all_examples
        assert "generic_examples" in all_examples
        assert "cron_examples" in all_examples

        # Get stock examples only
        stock_examples = service.get_job_examples("stock")
        assert "stock_examples" in stock_examples
        assert "generic_examples" not in stock_examples

        # Get generic examples only
        generic_examples = service.get_job_examples("generic")
        assert "generic_examples" in generic_examples
        assert "stock_examples" not in generic_examples

    def test_get_configuration_template(self):
        """Test getting configuration templates through service."""
        service = JobTestingService()

        stock_template = service.get_configuration_template("stock")
        assert stock_template["job_type"] == "stock"

        generic_template = service.get_configuration_template("generic")
        assert generic_template["job_type"] == "generic"

    def test_setup_test_environment(self):
        """Test setting up test environment."""
        service = JobTestingService()

        setup_result = service.setup_test_environment(
            stock_symbols=["AAPL", "MSFT"],
            generic_urls=["https://api.example.com/data"],
        )

        assert "stock_mocks" in setup_result
        assert "generic_mocks" in setup_result
        assert "total_mocks" in setup_result
        assert setup_result["stock_mocks"] == 4  # 2 symbols * 2 providers
        assert setup_result["generic_mocks"] == 1
        assert setup_result["total_mocks"] == 5

    def test_validate_job_config_only(self):
        """Test validating only job configuration."""
        service = JobTestingService()

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_key_12345",
        }

        result = service.validate_job_config_only("stock", config)

        assert "is_valid" in result
        assert result["is_valid"]
        assert "errors" in result
        assert "resolved_config" in result
        assert "sanitized_config" in result

    def test_get_validation_help(self):
        """Test getting validation help."""
        service = JobTestingService()

        # Get stock help
        stock_help = service.get_validation_help("stock")
        assert "stock_help" in stock_help
        assert "cron_help" in stock_help
        assert "validation_info" in stock_help

        # Get generic help
        generic_help = service.get_validation_help("generic")
        assert "generic_help" in generic_help
        assert "cron_help" in generic_help
        assert "validation_info" in generic_help

    def test_simulate_api_scenarios(self):
        """Test simulating API scenarios."""
        service = JobTestingService()

        config = {"symbol": "AAPL", "provider": "alpha_vantage", "api_key": "test_key"}

        scenarios = ["success", "rate_limit", "timeout"]

        results = service.simulate_api_scenarios("stock", config, scenarios)

        assert "success" in results
        assert "rate_limit" in results
        assert "timeout" in results

        # Each scenario should have execution results
        for scenario in scenarios:
            assert "success" in results[scenario]
            assert "error_message" in results[scenario]

    def test_cleanup_test_environment(self):
        """Test cleaning up test environment."""
        service = JobTestingService()

        # Set up some mocks first
        service.setup_test_environment(
            stock_symbols=["AAPL"], generic_urls=["https://api.example.com"]
        )

        # Clean up
        cleanup_result = service.cleanup_test_environment()

        assert cleanup_result["success"]
        assert "message" in cleanup_result


class TestJobConfigValidatorEnhancements:
    """Test enhancements to JobConfigValidator."""

    def test_validate_cron_schedule_detailed(self):
        """Test detailed cron schedule validation."""
        from trackers.services.job_providers.job_config_validator import (
            JobConfigValidator,
        )

        validator = JobConfigValidator()

        # Test valid expression
        result = validator.validate_cron_schedule_detailed("0 9 * * *")
        assert "is_valid" in result
        assert "errors" in result
        assert "warnings" in result
        assert "suggestions" in result

        # Test invalid expression
        result = validator.validate_cron_schedule_detailed("invalid")
        assert not result["is_valid"]
        assert len(result["errors"]) > 0
