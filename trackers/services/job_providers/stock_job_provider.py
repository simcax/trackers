"""
Stock Job Provider for Automated Job Scheduling.

This module provides a job provider for fetching stock prices from financial APIs
like Alpha Vantage, Yahoo Finance, and IEX Cloud.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
"""

import json
import logging
from typing import Dict, List, Optional

import requests

from .secure_job_provider import SecureJobProvider

logger = logging.getLogger(__name__)


class StockAPIError(Exception):
    """Exception raised for stock API-related errors."""

    pass


class StockJobProvider(SecureJobProvider):
    """
    Job provider for fetching stock prices from financial APIs.

    This provider supports multiple stock data APIs including Alpha Vantage,
    Yahoo Finance, and IEX Cloud. It handles API key management, stock symbol
    validation, and price data extraction with comprehensive error handling.

    Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
    """

    def __init__(self, job_config):
        """
        Initialize stock job provider.

        Args:
            job_config: JobModel instance containing stock job configuration

        Requirements: 3.1, 3.2
        """
        super().__init__(job_config)

        # Extract stock-specific configuration
        self.symbol = self.config.get("symbol", "").upper().strip()
        self.provider = self.config.get("provider", "alpha_vantage").lower()
        self.market = self.config.get("market", "US").upper()

        # Get API key (from config or environment)
        self.api_key = self._get_api_key()

        # Provider-specific configuration
        self.provider_configs = {
            "alpha_vantage": {
                "name": "Alpha Vantage",
                "base_url": "https://www.alphavantage.co/query",
                "requires_api_key": True,
                "rate_limit": 5,  # requests per minute for free tier
            },
            "yahoo_finance": {
                "name": "Yahoo Finance",
                "base_url": "https://query1.finance.yahoo.com/v8/finance/chart",
                "requires_api_key": False,
                "rate_limit": 2000,  # requests per hour
            },
            "iex_cloud": {
                "name": "IEX Cloud",
                "base_url": "https://cloud.iexapis.com/stable/stock",
                "requires_api_key": True,
                "rate_limit": 100,  # requests per second for paid tier
            },
        }

        self.logger.info(
            f"Initialized stock job provider for {self.symbol} using {self.provider}"
        )

    def _get_api_key(self) -> Optional[str]:
        """
        Get API key from configuration or environment variables.

        Returns:
            API key string or None if not found/required

        Requirements: 3.1, 3.2
        """
        # First try to get from job configuration
        api_key = self._get_secure_credential("api_key")
        if api_key:
            return api_key

        # If not in config, try environment variables
        from .job_config_validator import JobConfigValidator

        validator = JobConfigValidator()
        env_api_key = validator.get_api_key_for_provider(self.provider)
        if env_api_key:
            return env_api_key

        return None

    def validate_config(self) -> List[str]:
        """
        Validate stock job configuration.

        Returns:
            List of validation error messages (empty if valid)

        Requirements: 3.1, 3.4
        """
        errors = []

        # Validate stock symbol
        if not self.symbol:
            errors.append("Stock symbol is required")
        elif not self._is_valid_symbol(self.symbol):
            errors.append(
                f"Invalid stock symbol '{self.symbol}'. Must be 1-15 characters containing only letters, numbers, hyphens, and dots."
            )

        # Validate provider
        if self.provider not in self.provider_configs:
            available = ", ".join(self.provider_configs.keys())
            errors.append(
                f"Unsupported provider '{self.provider}'. Available: {available}"
            )
            return errors  # Can't validate further without valid provider

        provider_config = self.provider_configs[self.provider]

        # Validate API key if required
        if provider_config["requires_api_key"]:
            if not self.api_key:
                errors.append(
                    f"API key is required for {provider_config['name']}. "
                    f"Set environment variable or provide in job configuration."
                )
            elif len(self.api_key) < 8:
                errors.append("API key appears to be too short")

        # Validate market (basic validation)
        if self.market not in ["US", "GLOBAL"]:
            errors.append(f"Unsupported market '{self.market}'. Supported: US, GLOBAL")

        return errors

    def _is_valid_symbol(self, symbol: str) -> bool:
        """
        Validate stock symbol format.

        Args:
            symbol: Stock symbol to validate

        Returns:
            True if symbol is valid, False otherwise

        Requirements: 3.1
        """
        import re

        # Stock symbols can contain:
        # - Letters (A-Z)
        # - Numbers (0-9)
        # - Hyphens (-) for international stocks
        # - Dots (.) for exchange suffixes
        # - Length: 1-15 characters to accommodate international formats
        return bool(re.match(r"^[A-Z0-9.-]{1,15}$", symbol))

    async def fetch_data(self) -> Optional[float]:
        """
        Fetch current stock price from the configured API.

        Returns:
            JobExecutionResult with detailed error information, or float for success

        Requirements: 3.2, 3.3, 3.4, 3.5, 6.2
        """
        try:
            if self.provider == "alpha_vantage":
                return await self._fetch_alpha_vantage_price()
            elif self.provider == "yahoo_finance":
                return await self._fetch_yahoo_finance_price()
            elif self.provider == "iex_cloud":
                return await self._fetch_iex_cloud_price()
            else:
                error_msg = f"Unsupported stock data provider: {self.provider}"
                self.logger.error(error_msg)

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    error_category="configuration",
                    error_details={
                        "provider": self.provider,
                        "supported_providers": list(self.provider_configs.keys()),
                        "symbol": self.symbol,
                    },
                )

        except StockAPIError as e:
            error_msg = f"Stock API error for {self.symbol}: {str(e)}"
            self.logger.error(error_msg)

            # Log structured error for API failures
            from .error_handling import ErrorCategory, ErrorSeverity

            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.API,
                severity=ErrorSeverity.MEDIUM,
                job_id=self.job_config.id,
                context={
                    "provider": self.provider,
                    "symbol": self.symbol,
                    "market": self.market,
                },
            )
            self.error_logger.log_error(error_details)

            # Return detailed error information
            from .base_job_provider import JobExecutionResult

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                error_category="api",
                error_details={
                    "provider": self.provider,
                    "symbol": self.symbol,
                    "market": self.market,
                    "api_error": str(e),
                    "error_type": "StockAPIError",
                },
            )

        except Exception as e:
            error_msg = f"Unexpected error fetching {self.symbol} price: {str(e)}"
            self.logger.error(error_msg, exc_info=True)

            # Log structured error for unexpected failures
            from .error_handling import ErrorCategory, ErrorSeverity

            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.SYSTEM,
                severity=ErrorSeverity.HIGH,
                job_id=self.job_config.id,
                context={
                    "provider": self.provider,
                    "symbol": self.symbol,
                    "operation": "fetch_data",
                },
            )
            self.error_logger.log_error(error_details)

            # Return detailed error information
            from .base_job_provider import JobExecutionResult

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                error_category="system",
                error_details={
                    "provider": self.provider,
                    "symbol": self.symbol,
                    "exception_type": type(e).__name__,
                    "operation": "fetch_data",
                    "traceback": str(e),
                },
            )

    async def _fetch_alpha_vantage_price(self) -> Optional[float]:
        """
        Fetch stock price from Alpha Vantage API.

        Returns:
            Current stock price, JobExecutionResult with detailed errors, or None if failed

        Requirements: 3.2, 3.3, 3.4, 3.5
        """
        if not self.api_key:
            error_msg = "Alpha Vantage API key is required but not configured"

            from .base_job_provider import JobExecutionResult

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                error_category="configuration",
                error_details={
                    "provider": "alpha_vantage",
                    "symbol": self.symbol,
                    "missing_credential": "api_key",
                    "solution": "Configure API key in job configuration or environment variables",
                },
            )

        url = self.provider_configs["alpha_vantage"]["base_url"]
        params = {
            "function": "GLOBAL_QUOTE",
            "symbol": self.symbol,
            "apikey": self.api_key,
        }

        response = None
        response_text = None

        try:
            self.logger.debug(f"Fetching Alpha Vantage data for {self.symbol}")

            response = self._make_secure_request("GET", url, params=params)
            response_text = response.text[
                :1000
            ]  # Capture first 1000 chars for debugging

            # Handle rate limiting
            if response.status_code == 429:
                self._handle_rate_limit(response)
                error_msg = "Rate limit exceeded for Alpha Vantage API"

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="rate_limit",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "retry_after": response.headers.get("retry-after"),
                        "rate_limit_info": response.headers.get(
                            "x-ratelimit-remaining"
                        ),
                    },
                    api_response=response_text,
                )

            response.raise_for_status()

            # Parse response
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                error_msg = "Invalid JSON response from Alpha Vantage API"

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="api_response",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "json_error": str(e),
                        "content_type": response.headers.get("content-type"),
                    },
                    api_response=response_text,
                )

            # Check for API errors
            if "Error Message" in data:
                error_msg = f"Alpha Vantage API error: {data['Error Message']}"

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="api_error",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "api_error_message": data["Error Message"],
                        "possible_causes": [
                            "Invalid stock symbol",
                            "Symbol not found",
                            "Market closed",
                            "API service issue",
                        ],
                    },
                    api_response=json.dumps(data, indent=2)[:500],
                )

            if "Note" in data:
                # API call frequency limit
                error_msg = f"Alpha Vantage rate limit: {data['Note']}"

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="rate_limit",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "rate_limit_note": data["Note"],
                        "solution": "Wait before making another request or upgrade API plan",
                    },
                    api_response=json.dumps(data, indent=2)[:500],
                )

            # Extract price from Global Quote
            global_quote = data.get("Global Quote", {})
            if not global_quote:
                error_msg = "No Global Quote data in Alpha Vantage response"

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="api_response",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "available_keys": list(data.keys()),
                        "expected_key": "Global Quote",
                        "possible_causes": [
                            "Invalid symbol format",
                            "Symbol not found on exchange",
                            "API response format changed",
                        ],
                    },
                    api_response=json.dumps(data, indent=2)[:500],
                )

            # Alpha Vantage returns price in "05. price" field
            price_str = global_quote.get("05. price")
            if not price_str:
                error_msg = "Price field not found in Alpha Vantage response"

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="api_response",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "available_fields": list(global_quote.keys()),
                        "expected_field": "05. price",
                        "global_quote_data": global_quote,
                    },
                    api_response=json.dumps(data, indent=2)[:500],
                )

            try:
                price = float(price_str)
                self.logger.info(f"Alpha Vantage price for {self.symbol}: ${price}")
                return price
            except (ValueError, TypeError) as e:
                error_msg = (
                    f"Invalid price format in Alpha Vantage response: '{price_str}'"
                )

                from .base_job_provider import JobExecutionResult

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    http_status=response.status_code,
                    response_size=len(response_text) if response_text else 0,
                    error_category="data_parsing",
                    error_details={
                        "provider": "alpha_vantage",
                        "symbol": self.symbol,
                        "price_string": price_str,
                        "parsing_error": str(e),
                        "price_field": "05. price",
                    },
                    api_response=json.dumps(global_quote, indent=2)[:300],
                )

        except requests.RequestException as e:
            error_msg = f"Alpha Vantage API request failed: {str(e)}"

            from .base_job_provider import JobExecutionResult

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                http_status=getattr(response, "status_code", None)
                if response
                else None,
                response_size=len(response_text) if response_text else 0,
                error_category="network",
                error_details={
                    "provider": "alpha_vantage",
                    "symbol": self.symbol,
                    "request_url": url,
                    "request_error": str(e),
                    "error_type": type(e).__name__,
                    "possible_causes": [
                        "Network connectivity issue",
                        "API service unavailable",
                        "DNS resolution failure",
                        "Timeout",
                    ],
                },
                api_response=response_text if response_text else None,
            )
        except Exception as e:
            error_msg = f"Unexpected error in Alpha Vantage API call: {str(e)}"

            from .base_job_provider import JobExecutionResult

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                http_status=getattr(response, "status_code", None)
                if response
                else None,
                response_size=len(response_text) if response_text else 0,
                error_category="system",
                error_details={
                    "provider": "alpha_vantage",
                    "symbol": self.symbol,
                    "exception_type": type(e).__name__,
                    "traceback": str(e),
                },
                api_response=response_text if response_text else None,
            )

    async def _fetch_yahoo_finance_price(self) -> Optional[float]:
        """
        Fetch stock price from Yahoo Finance API.

        Returns:
            Current stock price or None if failed

        Requirements: 3.2, 3.3, 3.4, 3.5
        """
        base_url = self.provider_configs["yahoo_finance"]["base_url"]
        url = f"{base_url}/{self.symbol}"

        params = {
            "interval": "1d",
            "range": "1d",
            "includePrePost": "false",
        }

        try:
            self.logger.debug(f"Fetching Yahoo Finance data for {self.symbol}")

            response = self._make_secure_request("GET", url, params=params)

            # Handle rate limiting
            if response.status_code == 429:
                self._handle_rate_limit(response)
                raise StockAPIError("Rate limit exceeded for Yahoo Finance API")

            response.raise_for_status()

            # Parse response
            data = response.json()

            # Check for errors
            if "chart" not in data:
                raise StockAPIError("No chart data in Yahoo Finance response")

            chart = data["chart"]
            if "error" in chart and chart["error"]:
                raise StockAPIError(f"Yahoo Finance error: {chart['error']}")

            results = chart.get("result", [])
            if not results:
                raise StockAPIError("No results in Yahoo Finance response")

            result = results[0]
            meta = result.get("meta", {})

            # Get current price from meta data
            current_price = meta.get("regularMarketPrice")
            if current_price is None:
                # Try previous close as fallback
                current_price = meta.get("previousClose")

            if current_price is None:
                raise StockAPIError("Price not found in Yahoo Finance response")

            price = float(current_price)
            self.logger.info(f"Yahoo Finance price for {self.symbol}: ${price}")

            return price

        except requests.RequestException as e:
            raise StockAPIError(f"Yahoo Finance API request failed: {e}")
        except (ValueError, KeyError) as e:
            raise StockAPIError(f"Failed to parse Yahoo Finance response: {e}")
        except json.JSONDecodeError as e:
            raise StockAPIError(f"Invalid JSON response from Yahoo Finance: {e}")

    async def _fetch_iex_cloud_price(self) -> Optional[float]:
        """
        Fetch stock price from IEX Cloud API.

        Returns:
            Current stock price or None if failed

        Requirements: 3.2, 3.3, 3.4, 3.5
        """
        if not self.api_key:
            raise StockAPIError("IEX Cloud API key is required")

        base_url = self.provider_configs["iex_cloud"]["base_url"]
        url = f"{base_url}/{self.symbol}/quote"

        params = {
            "token": self.api_key,
        }

        try:
            self.logger.debug(f"Fetching IEX Cloud data for {self.symbol}")

            response = self._make_secure_request("GET", url, params=params)

            # Handle rate limiting
            if response.status_code == 429:
                self._handle_rate_limit(response)
                raise StockAPIError("Rate limit exceeded for IEX Cloud API")

            response.raise_for_status()

            # Parse response
            data = response.json()

            # Check for errors
            if isinstance(data, dict) and "error" in data:
                raise StockAPIError(f"IEX Cloud error: {data['error']}")

            # Extract current price
            current_price = data.get("latestPrice")
            if current_price is None:
                # Try close price as fallback
                current_price = data.get("close")

            if current_price is None:
                raise StockAPIError("Price not found in IEX Cloud response")

            price = float(current_price)
            self.logger.info(f"IEX Cloud price for {self.symbol}: ${price}")

            return price

        except requests.RequestException as e:
            raise StockAPIError(f"IEX Cloud API request failed: {e}")
        except (ValueError, KeyError) as e:
            raise StockAPIError(f"Failed to parse IEX Cloud response: {e}")
        except json.JSONDecodeError as e:
            raise StockAPIError(f"Invalid JSON response from IEX Cloud: {e}")

    def get_provider_info(self) -> Dict[str, any]:
        """
        Get information about the current stock provider configuration.

        Returns:
            Dictionary with provider information

        Requirements: 3.1
        """
        provider_config = self.provider_configs.get(self.provider, {})

        return {
            "provider": self.provider,
            "provider_name": provider_config.get("name", "Unknown"),
            "symbol": self.symbol,
            "market": self.market,
            "requires_api_key": provider_config.get("requires_api_key", False),
            "has_api_key": bool(self.api_key),
            "rate_limit": provider_config.get("rate_limit", "Unknown"),
            "base_url": provider_config.get("base_url", "Unknown"),
        }

    def get_supported_providers(self) -> List[Dict[str, any]]:
        """
        Get list of supported stock data providers.

        Returns:
            List of provider information dictionaries

        Requirements: 3.5
        """
        return [
            {
                "id": provider_id,
                "name": config["name"],
                "requires_api_key": config["requires_api_key"],
                "rate_limit": config["rate_limit"],
            }
            for provider_id, config in self.provider_configs.items()
        ]
