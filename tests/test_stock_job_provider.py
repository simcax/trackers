"""
Tests for StockJobProvider.

This module tests the stock job provider functionality including
API integration, validation, and error handling.

Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
"""

import json
from unittest.mock import Mock, patch

from trackers.models.job_model import JobModel
from trackers.services.job_providers.stock_job_provider import (
    StockJobProvider,
)


class TestStockJobProvider:
    """Test cases for StockJobProvider class."""

    def create_mock_job_config(self, config_dict):
        """Create a mock JobModel with encrypted configuration."""
        job_config = Mock(spec=JobModel)
        job_config.id = 1
        job_config.name = "Test Stock Job"
        job_config.job_type = "stock"
        job_config.tracker_id = 1
        job_config.user_id = 1
        job_config.is_active = True
        job_config.cron_schedule = "0 9 * * *"
        job_config.config = json.dumps(config_dict)
        return job_config

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_stock_job_provider_initialization(self, mock_encryption):
        """
        Test StockJobProvider initialization with valid configuration.

        Requirements: 3.1, 3.2
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        assert provider.symbol == "AAPL"
        assert provider.provider == "alpha_vantage"
        assert provider.market == "US"
        assert provider.api_key == "test_api_key"

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_valid(self, mock_encryption):
        """
        Test configuration validation with valid stock configuration.

        Requirements: 3.1, 3.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_12345",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_12345",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        errors = provider.validate_config()
        assert errors == []

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_international_symbol(self, mock_encryption):
        """
        Test configuration validation with international stock symbol like NOVO-B.CPH.

        Requirements: 3.1, 3.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "NOVO-B.CPH",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_12345",
            "market": "GLOBAL",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "NOVO-B.CPH",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_12345",
            "market": "GLOBAL",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        errors = provider.validate_config()
        # Should have no errors for international symbol
        symbol_errors = [error for error in errors if "Invalid stock symbol" in error]
        assert len(symbol_errors) == 0

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_invalid_symbol(self, mock_encryption):
        """
        Test configuration validation with international stock symbol like NOVO-B.CPH.

        Requirements: 3.1, 3.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "NOVO-B.CPH",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_12345",
            "market": "GLOBAL",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "NOVO-B.CPH",
            "provider": "alpha_vantage",
            "api_key": "test_api_key_12345",
            "market": "GLOBAL",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        errors = provider.validate_config()
        # Should have no errors for international symbol
        symbol_errors = [error for error in errors if "Invalid stock symbol" in error]
        assert len(symbol_errors) == 0
        """
        Test configuration validation with invalid stock symbol.

        Requirements: 3.1, 3.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "INVALID_SYMBOL_TOO_LONG",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "INVALID_SYMBOL_TOO_LONG",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any("Invalid stock symbol" in error for error in errors)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_missing_api_key(self, mock_encryption):
        """
        Test configuration validation with missing API key.

        Requirements: 3.1, 3.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "market": "US",
        }
        mock_encryptor.get_secure_credential.return_value = None
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)

        with patch.object(StockJobProvider, "_get_api_key", return_value=None):
            provider = StockJobProvider(job_config)

            errors = provider.validate_config()
            assert len(errors) > 0
            assert any("API key is required" in error for error in errors)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_validate_config_unsupported_provider(self, mock_encryption):
        """
        Test configuration validation with unsupported provider.

        Requirements: 3.1, 3.4
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "unsupported_provider",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "unsupported_provider",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        errors = provider.validate_config()
        assert len(errors) > 0
        assert any("Unsupported provider" in error for error in errors)

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_fetch_alpha_vantage_price_success(self, mock_encryption):
        """
        Test successful Alpha Vantage price fetching.

        Requirements: 3.2, 3.3, 3.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        # Mock HTTP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = (
            '{"Global Quote": {"01. symbol": "AAPL", "05. price": "150.25"}}'
        )
        mock_response.json.return_value = {
            "Global Quote": {
                "01. symbol": "AAPL",
                "05. price": "150.25",
                "07. latest trading day": "2024-01-04",
            }
        }
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {}

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        # Mock the secure request method
        with patch.object(provider, "_make_secure_request", return_value=mock_response):
            import asyncio

            price = asyncio.run(provider._fetch_alpha_vantage_price())

        assert price == 150.25

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_fetch_alpha_vantage_price_api_error(self, mock_encryption):
        """
        Test Alpha Vantage API error handling.

        Requirements: 3.4, 3.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "INVALID",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        # Mock HTTP response with API error
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = '{"Error Message": "Invalid API call"}'
        mock_response.json.return_value = {
            "Error Message": "Invalid API call. Please retry or visit the documentation."
        }
        mock_response.raise_for_status.return_value = None
        mock_response.headers = {}

        config = {
            "symbol": "INVALID",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        # Mock the secure request method
        with patch.object(provider, "_make_secure_request", return_value=mock_response):
            import asyncio

            result = asyncio.run(provider._fetch_alpha_vantage_price())

            # Should return JobExecutionResult with error details
            from trackers.services.job_providers.base_job_provider import (
                JobExecutionResult,
            )

            assert isinstance(result, JobExecutionResult)
            assert result.success is False
            assert "Alpha Vantage API error" in result.error_message

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_get_provider_info(self, mock_encryption):
        """
        Test getting provider information.

        Requirements: 3.1
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        info = provider.get_provider_info()

        assert info["provider"] == "alpha_vantage"
        assert info["provider_name"] == "Alpha Vantage"
        assert info["symbol"] == "AAPL"
        assert info["market"] == "US"
        assert info["requires_api_key"] is True
        assert info["has_api_key"] is True

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_get_supported_providers(self, mock_encryption):
        """
        Test getting list of supported providers.

        Requirements: 3.5
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        providers = provider.get_supported_providers()

        assert len(providers) == 3
        provider_ids = [p["id"] for p in providers]
        assert "alpha_vantage" in provider_ids
        assert "yahoo_finance" in provider_ids
        assert "iex_cloud" in provider_ids

        # Check Alpha Vantage provider details
        alpha_vantage = next(p for p in providers if p["id"] == "alpha_vantage")
        assert alpha_vantage["name"] == "Alpha Vantage"
        assert alpha_vantage["requires_api_key"] is True

    @patch("trackers.security.job_config_encryption.JobConfigEncryption")
    def test_is_valid_symbol(self, mock_encryption):
        """
        Test stock symbol validation.

        Requirements: 3.1
        """
        # Mock encryption
        mock_encryptor = Mock()
        mock_encryptor.decrypt_config.return_value = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }
        mock_encryption.return_value = mock_encryptor

        config = {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_api_key",
            "market": "US",
        }

        job_config = self.create_mock_job_config(config)
        provider = StockJobProvider(job_config)

        # Valid US symbols
        assert provider._is_valid_symbol("AAPL") is True
        assert provider._is_valid_symbol("MSFT") is True
        assert provider._is_valid_symbol("GOOGL") is True
        assert provider._is_valid_symbol("BRK") is True  # Valid short symbol

        # Valid international symbols
        assert provider._is_valid_symbol("NOVO-B.CPH") is True  # Danish stock
        assert provider._is_valid_symbol("SAP.DE") is True  # German stock
        assert provider._is_valid_symbol("ASML.AS") is True  # Dutch stock
        assert provider._is_valid_symbol("NESN.SW") is True  # Swiss stock
        assert provider._is_valid_symbol("7203.T") is True  # Japanese stock

        # Valid symbols with numbers
        assert provider._is_valid_symbol("BRK.A") is True  # Berkshire Hathaway Class A
        assert provider._is_valid_symbol("BRK.B") is True  # Berkshire Hathaway Class B

        # Invalid symbols
        assert (
            provider._is_valid_symbol("TOOLONGSTOCKSYMBOL") is False
        )  # Too long (16+ chars)
        assert provider._is_valid_symbol("") is False  # Empty
        assert provider._is_valid_symbol("aapl") is False  # Lowercase
        assert provider._is_valid_symbol("AAPL@") is False  # Invalid character
        assert provider._is_valid_symbol("AAPL_TEST") is False  # Underscore not allowed
