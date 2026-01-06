"""
Job Testing Service for comprehensive job configuration testing.

This module provides a service layer for testing job configurations
without scheduling them, including validation, mock execution, and
detailed reporting.

Requirements: 5.1, 5.4, 10.1, 10.2
"""

import logging
from typing import Any, Dict, List, Optional

from trackers.services.job_providers.job_config_testing import (
    CronExpressionValidator,
    JobConfigurationExamples,
    JobConfigurationTester,
    MockAPIProvider,
)
from trackers.services.job_providers.job_config_validator import JobConfigValidator

logger = logging.getLogger(__name__)


class JobTestingService:
    """
    Service for testing job configurations and providing examples.

    This service provides a high-level interface for testing job configurations,
    validating cron expressions, and providing configuration examples and templates.

    Requirements: 5.1, 5.4, 10.1, 10.2
    """

    def __init__(self):
        """Initialize job testing service."""
        self.validator = JobConfigValidator()
        self.cron_validator = CronExpressionValidator()
        self.mock_api = MockAPIProvider()
        self.tester = JobConfigurationTester(self.mock_api)
        self.examples = JobConfigurationExamples()

    def validate_cron_expression(self, cron_expression: str) -> Dict[str, Any]:
        """
        Validate cron expression with detailed feedback.

        Args:
            cron_expression: Cron expression to validate

        Returns:
            Detailed validation results with errors and suggestions

        Requirements: 5.1, 5.4
        """
        try:
            return self.cron_validator.validate_cron_expression(cron_expression)
        except Exception as e:
            logger.error(
                f"Error validating cron expression '{cron_expression}': {str(e)}"
            )
            return {
                "is_valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "warnings": [],
                "suggestions": ["Please check the cron expression format"],
                "next_runs": [],
                "human_readable": None,
            }

    def test_job_configuration(
        self,
        job_type: str,
        config: Dict[str, Any],
        cron_schedule: str,
        use_mocks: bool = True,
    ) -> Dict[str, Any]:
        """
        Test complete job configuration without scheduling.

        Args:
            job_type: Type of job ("stock" or "generic")
            config: Job configuration dictionary
            cron_schedule: Cron schedule expression
            use_mocks: Whether to use mock APIs for testing

        Returns:
            Comprehensive test results

        Requirements: 5.1, 5.4, 10.1, 10.2
        """
        try:
            return self.tester.test_job_configuration(
                job_type, config, cron_schedule, use_mocks
            )
        except Exception as e:
            logger.error(f"Error testing job configuration: {str(e)}")
            return {
                "overall_valid": False,
                "config_validation": {
                    "is_valid": False,
                    "errors": [f"Testing error: {str(e)}"],
                },
                "cron_validation": {"is_valid": False, "errors": []},
                "execution_test": {"success": False, "error_message": str(e)},
                "recommendations": ["Fix configuration errors and try again"],
                "timestamp": None,
            }

    def get_job_examples(self, job_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Get job configuration examples.

        Args:
            job_type: Optional job type filter ("stock" or "generic")

        Returns:
            Dictionary of example configurations

        Requirements: 10.1, 10.2
        """
        try:
            if job_type == "stock":
                return {"stock_examples": self.examples.get_stock_job_examples()}
            elif job_type == "generic":
                return {"generic_examples": self.examples.get_generic_job_examples()}
            else:
                return {
                    "stock_examples": self.examples.get_stock_job_examples(),
                    "generic_examples": self.examples.get_generic_job_examples(),
                    "cron_examples": self.examples.get_cron_schedule_examples(),
                }
        except Exception as e:
            logger.error(f"Error getting job examples: {str(e)}")
            return {"error": f"Failed to get examples: {str(e)}"}

    def get_configuration_template(self, job_type: str) -> Dict[str, Any]:
        """
        Get configuration template for job type.

        Args:
            job_type: Type of job ("stock" or "generic")

        Returns:
            Configuration template

        Requirements: 10.1, 10.2
        """
        try:
            return self.examples.get_configuration_template(job_type)
        except Exception as e:
            logger.error(
                f"Error getting configuration template for {job_type}: {str(e)}"
            )
            return {"error": f"Failed to get template: {str(e)}"}

    def setup_test_environment(
        self,
        stock_symbols: Optional[List[str]] = None,
        generic_urls: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Set up test environment with mock API responses.

        Args:
            stock_symbols: List of stock symbols to mock
            generic_urls: List of generic URLs to mock

        Returns:
            Summary of mock setup

        Requirements: 10.1, 10.2
        """
        setup_summary = {"stock_mocks": 0, "generic_mocks": 0, "total_mocks": 0}

        try:
            # Clear existing mocks
            self.mock_api.clear_mocks()

            # Set up stock API mocks
            if stock_symbols:
                for symbol in stock_symbols:
                    # Set up mocks for different providers
                    self.mock_api.setup_stock_api_mock(symbol, 100.0, "alpha_vantage")
                    self.mock_api.setup_stock_api_mock(symbol, 100.0, "yahoo_finance")
                    setup_summary["stock_mocks"] += 2

            # Set up generic API mocks
            if generic_urls:
                for url in generic_urls:
                    self.mock_api.setup_generic_api_mock(url, {"value": 42.0})
                    setup_summary["generic_mocks"] += 1

            setup_summary["total_mocks"] = (
                setup_summary["stock_mocks"] + setup_summary["generic_mocks"]
            )

            logger.info(
                f"Set up test environment with {setup_summary['total_mocks']} mocks"
            )

        except Exception as e:
            logger.error(f"Error setting up test environment: {str(e)}")
            setup_summary["error"] = str(e)

        return setup_summary

    def validate_job_config_only(
        self, job_type: str, config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate only the job configuration (no cron or execution test).

        Args:
            job_type: Type of job ("stock" or "generic")
            config: Job configuration dictionary

        Returns:
            Configuration validation results

        Requirements: 5.1, 5.4
        """
        try:
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
                "validation_info": self.validator.get_validation_info(),
            }

        except Exception as e:
            logger.error(f"Error validating job config: {str(e)}")
            return {
                "is_valid": False,
                "errors": [f"Validation error: {str(e)}"],
                "resolved_config": config,
                "sanitized_config": config,
                "changes_made": False,
            }

    def get_cron_examples(self) -> Dict[str, str]:
        """
        Get cron schedule examples with descriptions.

        Returns:
            Dictionary of cron expressions and descriptions

        Requirements: 10.1, 10.2
        """
        try:
            return self.examples.get_cron_schedule_examples()
        except Exception as e:
            logger.error(f"Error getting cron examples: {str(e)}")
            return {"error": f"Failed to get cron examples: {str(e)}"}

    def simulate_api_scenarios(
        self, job_type: str, config: Dict[str, Any], scenarios: List[str]
    ) -> Dict[str, Any]:
        """
        Simulate different API scenarios for testing.

        Args:
            job_type: Type of job ("stock" or "generic")
            config: Job configuration
            scenarios: List of scenarios to test ("success", "rate_limit", "timeout", etc.)

        Returns:
            Results of scenario testing

        Requirements: 10.1, 10.2
        """
        scenario_results = {}

        try:
            for scenario in scenarios:
                # Set up scenario-specific mocks
                if job_type == "stock":
                    symbol = config.get("symbol", "TEST")
                    provider = config.get("provider", "alpha_vantage")

                    if scenario == "success":
                        self.mock_api.setup_stock_api_mock(symbol, 150.0, provider)
                    elif scenario == "rate_limit":
                        self.mock_api.simulate_rate_limit(f"{provider}_{symbol}")
                    elif scenario == "timeout":
                        self.mock_api.simulate_network_error(
                            f"{provider}_{symbol}", "timeout"
                        )
                    elif scenario == "connection_error":
                        self.mock_api.simulate_network_error(
                            f"{provider}_{symbol}", "connection"
                        )

                elif job_type == "generic":
                    url = config.get("url", "https://api.example.com/test")

                    if scenario == "success":
                        self.mock_api.setup_generic_api_mock(url, {"value": 42.0})
                    elif scenario == "rate_limit":
                        self.mock_api.simulate_rate_limit(url)
                    elif scenario == "timeout":
                        self.mock_api.simulate_network_error(url, "timeout")
                    elif scenario == "connection_error":
                        self.mock_api.simulate_network_error(url, "connection")

                # Test the scenario
                test_result = self.tester._test_job_execution(job_type, config, True)
                scenario_results[scenario] = test_result

        except Exception as e:
            logger.error(f"Error simulating API scenarios: {str(e)}")
            scenario_results["error"] = str(e)

        return scenario_results

    def get_validation_help(self, job_type: str) -> Dict[str, Any]:
        """
        Get validation help and guidance for job type.

        Args:
            job_type: Type of job ("stock" or "generic")

        Returns:
            Validation help information

        Requirements: 5.1, 5.4, 10.1, 10.2
        """
        help_info = {
            "job_type": job_type,
            "validation_info": self.validator.get_validation_info(),
            "cron_help": {
                "format": "minute hour day month weekday",
                "examples": self.get_cron_examples(),
                "special_characters": {
                    "*": "Any value",
                    ",": "Value list separator (e.g., 1,3,5)",
                    "-": "Range of values (e.g., 1-5)",
                    "/": "Step values (e.g., */15 for every 15 minutes)",
                },
            },
        }

        if job_type == "stock":
            help_info["stock_help"] = {
                "required_fields": ["symbol", "provider"],
                "optional_fields": ["api_key", "market"],
                "supported_providers": list(self.validator.stock_providers.keys()),
                "symbol_format": "1-10 alphanumeric characters (e.g., AAPL, MSFT)",
                "api_key_note": "Can be provided in config or via environment variables",
            }
        elif job_type == "generic":
            help_info["generic_help"] = {
                "required_fields": ["url"],
                "optional_fields": [
                    "method",
                    "headers",
                    "json_path",
                    "timeout",
                    "retry_count",
                ],
                "supported_methods": ["GET", "POST"],
                "url_requirements": "Must use HTTPS for security",
                "json_path_format": "JSONPath expression (e.g., $.data.value)",
                "timeout_range": "1-300 seconds",
                "retry_range": "0-10 attempts",
            }

        return help_info

    def cleanup_test_environment(self) -> Dict[str, Any]:
        """
        Clean up test environment and mocks.

        Returns:
            Cleanup summary

        Requirements: 10.1, 10.2
        """
        try:
            self.mock_api.clear_mocks()
            return {
                "success": True,
                "message": "Test environment cleaned up successfully",
            }
        except Exception as e:
            logger.error(f"Error cleaning up test environment: {str(e)}")
            return {"success": False, "error": str(e)}
