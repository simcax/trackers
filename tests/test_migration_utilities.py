"""
Unit tests for migration utilities.

Tests configuration loading and validation, utility functions for edge cases,
and migration status reporting functionality.

Requirements: All requirements (supporting functionality)
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from trackers.db.migration import MigrationResult, MigrationStatus
from trackers.db.migration_config import MigrationConfig
from trackers.db.migration_utils import (
    format_migration_report,
    get_migration_status_report,
    trigger_manual_migration,
    validate_migration_environment,
)


class TestMigrationConfig:
    """Test migration configuration loading and validation."""

    def test_default_configuration(self):
        """Test default configuration values."""
        config = MigrationConfig()

        assert config.enabled is True
        assert config.timeout_seconds == 30
        assert config.lock_timeout_seconds == 30
        assert config.enable_logging is True
        assert config.log_level == "INFO"
        assert config.skip_validation is False
        assert config.concurrent_safety is True

    def test_configuration_from_environment(self):
        """Test configuration loading from environment variables."""
        env_vars = {
            "MIGRATION_ENABLED": "false",
            "MIGRATION_TIMEOUT": "60",
            "MIGRATION_LOCK_TIMEOUT": "45",
            "MIGRATION_LOGGING": "false",
            "MIGRATION_LOG_LEVEL": "DEBUG",
            "MIGRATION_SKIP_VALIDATION": "true",
            "MIGRATION_CONCURRENT_SAFETY": "false",
        }

        with patch.dict(os.environ, env_vars):
            config = MigrationConfig.from_environment()

            assert config.enabled is False
            assert config.timeout_seconds == 60
            assert config.lock_timeout_seconds == 45
            assert config.enable_logging is False
            assert config.log_level == "DEBUG"
            assert config.skip_validation is True
            assert config.concurrent_safety is False

    def test_boolean_parsing_variations(self):
        """Test various boolean value formats."""
        test_cases = [
            ("true", True),
            ("True", True),
            ("TRUE", True),
            ("1", True),
            ("yes", True),
            ("on", True),
            ("false", False),
            ("False", False),
            ("FALSE", False),
            ("0", False),
            ("no", False),
            ("off", False),
            ("invalid", False),  # Default fallback
        ]

        for env_value, expected in test_cases:
            with patch.dict(os.environ, {"MIGRATION_ENABLED": env_value}):
                config = MigrationConfig.from_environment()
                assert config.enabled == expected

    def test_integer_parsing_with_invalid_values(self):
        """Test integer parsing with invalid values falls back to defaults."""
        with patch.dict(os.environ, {"MIGRATION_TIMEOUT": "invalid"}):
            config = MigrationConfig.from_environment()
            assert config.timeout_seconds == 30  # Default value

        with patch.dict(os.environ, {"MIGRATION_LOCK_TIMEOUT": "not_a_number"}):
            config = MigrationConfig.from_environment()
            assert config.lock_timeout_seconds == 30  # Default value

    def test_configuration_validation_success(self):
        """Test successful configuration validation."""
        config = MigrationConfig(
            timeout_seconds=60, lock_timeout_seconds=45, log_level="DEBUG"
        )

        # Should not raise any exception
        config.validate()

    def test_configuration_validation_invalid_timeout(self):
        """Test configuration validation with invalid timeout values."""
        config = MigrationConfig(timeout_seconds=0)

        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            config.validate()

        config = MigrationConfig(timeout_seconds=-10)

        with pytest.raises(ValueError, match="timeout_seconds must be positive"):
            config.validate()

    def test_configuration_validation_invalid_lock_timeout(self):
        """Test configuration validation with invalid lock timeout values."""
        config = MigrationConfig(lock_timeout_seconds=0)

        with pytest.raises(ValueError, match="lock_timeout_seconds must be positive"):
            config.validate()

        config = MigrationConfig(lock_timeout_seconds=-5)

        with pytest.raises(ValueError, match="lock_timeout_seconds must be positive"):
            config.validate()

    def test_configuration_validation_invalid_log_level(self):
        """Test configuration validation with invalid log level."""
        config = MigrationConfig(log_level="INVALID")

        with pytest.raises(ValueError, match="log_level must be one of"):
            config.validate()

    def test_configuration_validation_valid_log_levels(self):
        """Test configuration validation with all valid log levels."""
        valid_levels = ["DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"]

        for level in valid_levels:
            config = MigrationConfig(log_level=level)
            # Should not raise any exception
            config.validate()


class TestMigrationUtilities:
    """Test migration utility functions."""

    def test_trigger_manual_migration_success(self):
        """Test successful manual migration trigger."""
        # Create mock objects
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_logger = MagicMock()

        # Create expected result
        expected_result = MigrationResult(
            success=True,
            tables_created=["test_table"],
            errors=[],
            duration_seconds=1.5,
            message="Migration completed successfully",
        )

        # Mock the MigrationEngine
        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_instance = mock_migration_engine.return_value
            mock_instance.run_migration.return_value = expected_result

            # Test the function
            result = trigger_manual_migration(
                mock_engine, mock_metadata, logger=mock_logger
            )

            # Verify results
            assert result == expected_result
            mock_migration_engine.assert_called_once_with(
                engine=mock_engine,
                metadata=mock_metadata,
                logger=mock_logger,
                timeout_seconds=30,  # Default timeout
            )
            mock_instance.run_migration.assert_called_once()

    def test_trigger_manual_migration_with_custom_config(self):
        """Test manual migration trigger with custom configuration."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_logger = MagicMock()

        # Create custom config
        custom_config = MigrationConfig(enabled=True, timeout_seconds=60)

        expected_result = MigrationResult(
            success=True,
            tables_created=[],
            errors=[],
            duration_seconds=0.1,
            message="No tables needed creation",
        )

        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_instance = mock_migration_engine.return_value
            mock_instance.run_migration.return_value = expected_result

            result = trigger_manual_migration(
                mock_engine, mock_metadata, config=custom_config, logger=mock_logger
            )

            assert result == expected_result
            mock_migration_engine.assert_called_once_with(
                engine=mock_engine,
                metadata=mock_metadata,
                logger=mock_logger,
                timeout_seconds=60,  # Custom timeout
            )

    def test_trigger_manual_migration_disabled(self):
        """Test manual migration trigger when migration is disabled."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_logger = MagicMock()

        # Create disabled config
        disabled_config = MigrationConfig(enabled=False)

        result = trigger_manual_migration(
            mock_engine, mock_metadata, config=disabled_config, logger=mock_logger
        )

        assert result.success is True
        assert result.tables_created == []
        assert result.errors == []
        assert result.message == "Migration disabled by configuration"
        mock_logger.info.assert_called_with("Migration is disabled by configuration")

    def test_trigger_manual_migration_failure(self):
        """Test manual migration trigger with failure."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_logger = MagicMock()

        # Create failure result
        failure_result = MigrationResult(
            success=False,
            tables_created=[],
            errors=["Database connection failed"],
            duration_seconds=0.5,
            message="Migration failed due to database error",
        )

        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_instance = mock_migration_engine.return_value
            mock_instance.run_migration.return_value = failure_result

            result = trigger_manual_migration(
                mock_engine, mock_metadata, logger=mock_logger
            )

            assert result == failure_result
            mock_logger.error.assert_called_with(
                f"Manual migration failed: {failure_result.message}"
            )

    def test_get_migration_status_report_success(self):
        """Test successful migration status report generation."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_metadata.tables.keys.return_value = ["table1", "table2", "table3"]
        mock_logger = MagicMock()

        # Create mock status
        mock_status = MigrationStatus(
            database_exists=True,
            tables_exist=["table1", "table2"],
            missing_tables=["table3"],
            migration_needed=True,
            connection_healthy=True,
        )

        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_instance = mock_migration_engine.return_value
            mock_instance.get_migration_status.return_value = mock_status

            # Mock the imported migration_config
            mock_config = MagicMock()
            mock_config.enabled = True
            mock_config.timeout_seconds = 30
            mock_config.lock_timeout_seconds = 30
            mock_config.enable_logging = True
            mock_config.log_level = "INFO"
            mock_config.skip_validation = False
            mock_config.concurrent_safety = True

            with patch("trackers.db.migration_utils.migration_config", mock_config):
                report = get_migration_status_report(
                    mock_engine, mock_metadata, mock_logger
                )

                # Verify report structure
                assert "migration_status" in report
                assert "configuration" in report
                assert "database_info" in report
                assert "health" in report
                assert "health_message" in report

                # Verify migration status
                migration_status = report["migration_status"]
                assert migration_status["database_exists"] is True
                assert migration_status["connection_healthy"] is True
                assert migration_status["migration_needed"] is True
                assert migration_status["existing_tables"] == ["table1", "table2"]
                assert migration_status["missing_tables"] == ["table3"]
                assert migration_status["total_expected_tables"] == 3
                assert migration_status["total_existing_tables"] == 2

                # Verify health assessment
                assert report["health"] == "needs_migration"
                assert "needs 1 tables created" in report["health_message"]

    def test_get_migration_status_report_healthy(self):
        """Test migration status report when database is healthy."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_metadata.tables.keys.return_value = ["table1", "table2"]

        # Create healthy status
        mock_status = MigrationStatus(
            database_exists=True,
            tables_exist=["table1", "table2"],
            missing_tables=[],
            migration_needed=False,
            connection_healthy=True,
        )

        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_instance = mock_migration_engine.return_value
            mock_instance.get_migration_status.return_value = mock_status

            mock_config = MagicMock()
            mock_config.enabled = True

            with patch("trackers.db.migration_utils.migration_config", mock_config):
                report = get_migration_status_report(mock_engine, mock_metadata)

                assert report["health"] == "healthy"
                assert report["health_message"] == "Database is healthy and up to date"

    def test_get_migration_status_report_unhealthy(self):
        """Test migration status report when database is unhealthy."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()

        # Create unhealthy status
        mock_status = MigrationStatus(
            database_exists=False,
            tables_exist=[],
            missing_tables=["table1", "table2"],
            migration_needed=True,
            connection_healthy=False,
        )

        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_instance = mock_migration_engine.return_value
            mock_instance.get_migration_status.return_value = mock_status

            mock_config = MagicMock()
            mock_config.enabled = True

            with patch("trackers.db.migration_utils.migration_config", mock_config):
                report = get_migration_status_report(mock_engine, mock_metadata)

                assert report["health"] == "unhealthy"
                assert report["health_message"] == "Database connection is not healthy"

    def test_get_migration_status_report_error(self):
        """Test migration status report when an error occurs."""
        mock_engine = MagicMock()
        mock_metadata = MagicMock()
        mock_logger = MagicMock()

        with patch(
            "trackers.db.migration_utils.MigrationEngine"
        ) as mock_migration_engine:
            mock_migration_engine.side_effect = Exception("Test error")

            report = get_migration_status_report(
                mock_engine, mock_metadata, mock_logger
            )

            assert "error" in report
            assert report["health"] == "error"
            assert "Failed to assess migration status" in report["health_message"]
            mock_logger.error.assert_called_once()


class TestEnvironmentValidation:
    """Test environment validation functionality."""

    def test_validate_migration_environment_success(self):
        """Test successful environment validation."""
        env_vars = {
            "POSTGRESQL_ADDON_HOST": "localhost",
            "POSTGRESQL_ADDON_USER": "user",
            "POSTGRESQL_ADDON_PASSWORD": "password",
            "POSTGRESQL_ADDON_DB": "database",
            "MIGRATION_ENABLED": "true",
            "MIGRATION_TIMEOUT": "30",
        }

        with patch.dict(os.environ, env_vars):
            mock_config = MagicMock()
            mock_config.enabled = True
            mock_config.timeout_seconds = 30
            mock_config.lock_timeout_seconds = 30
            mock_config.enable_logging = True
            mock_config.log_level = "INFO"
            mock_config.skip_validation = False
            mock_config.concurrent_safety = True
            mock_config.validate.return_value = None  # No exception

            with patch("trackers.db.migration_utils.migration_config", mock_config):
                result = validate_migration_environment()

                assert result["valid"] is True
                assert result["configuration"] == "valid"
                assert len(result["errors"]) == 0

    def test_validate_migration_environment_missing_db_vars(self):
        """Test environment validation with missing database variables."""
        # Clear all database environment variables
        env_vars = {}

        with patch.dict(os.environ, env_vars, clear=True):
            mock_config = MagicMock()
            mock_config.validate.return_value = None

            with patch("trackers.db.migration_utils.migration_config", mock_config):
                result = validate_migration_environment()

                assert result["valid"] is False
                assert any(
                    "Missing database environment variables" in error
                    for error in result["errors"]
                )

    def test_validate_migration_environment_config_error(self):
        """Test environment validation with configuration error."""
        mock_config = MagicMock()
        mock_config.validate.side_effect = ValueError("Invalid configuration")

        with patch("trackers.db.migration_utils.migration_config", mock_config):
            result = validate_migration_environment()

            assert result["valid"] is False
            assert any(
                "Configuration validation failed" in error for error in result["errors"]
            )

    def test_validate_migration_environment_warnings(self):
        """Test environment validation generates appropriate warnings."""
        mock_config = MagicMock()
        mock_config.enabled = False
        mock_config.timeout_seconds = 15
        mock_config.skip_validation = True
        mock_config.concurrent_safety = False
        mock_config.validate.return_value = None

        with patch("trackers.db.migration_utils.migration_config", mock_config):
            result = validate_migration_environment()

            warnings = result["warnings"]
            assert any("Migration is disabled" in warning for warning in warnings)
            assert any(
                "timeout is less than 30 seconds" in warning for warning in warnings
            )
            assert any("validation is disabled" in warning for warning in warnings)
            assert any(
                "Concurrent migration safety is disabled" in warning
                for warning in warnings
            )

    def test_validate_migration_environment_exception(self):
        """Test environment validation handles exceptions gracefully."""
        mock_config = MagicMock()
        mock_config.validate.side_effect = Exception("Unexpected error")

        with patch("trackers.db.migration_utils.migration_config", mock_config):
            result = validate_migration_environment()

            assert result["valid"] is False
            assert any(
                "Environment validation failed" in error for error in result["errors"]
            )


class TestReportFormatting:
    """Test migration report formatting functionality."""

    def test_format_migration_report_success(self):
        """Test formatting a successful migration report."""
        report = {
            "health": "healthy",
            "health_message": "Database is healthy and up to date",
            "migration_status": {
                "connection_healthy": True,
                "migration_needed": False,
                "total_existing_tables": 4,
                "total_expected_tables": 4,
                "missing_tables": [],
            },
            "configuration": {
                "enabled": True,
                "timeout_seconds": 30,
                "lock_timeout_seconds": 30,
                "enable_logging": True,
                "log_level": "INFO",
                "concurrent_safety": True,
            },
            "database_info": {
                "engine_url": "postgresql://user:***@localhost/db",
                "expected_tables": ["table1", "table2", "table3", "table4"],
            },
        }

        formatted = format_migration_report(report)

        assert "Migration Status Report" in formatted
        assert "Health: HEALTHY" in formatted
        assert "Database is healthy and up to date" in formatted
        assert "Connection Healthy: True" in formatted
        assert "Migration Needed: False" in formatted
        assert "Existing Tables: 4" in formatted
        assert "Expected Tables: 4" in formatted
        assert "Enabled: True" in formatted
        assert "Timeout: 30s" in formatted
        assert "table1, table2, table3, table4" in formatted

    def test_format_migration_report_needs_migration(self):
        """Test formatting a report that needs migration."""
        report = {
            "health": "needs_migration",
            "health_message": "Database needs 2 tables created",
            "migration_status": {
                "connection_healthy": True,
                "migration_needed": True,
                "total_existing_tables": 2,
                "total_expected_tables": 4,
                "missing_tables": ["table3", "table4"],
            },
            "configuration": {
                "enabled": True,
                "timeout_seconds": 60,
                "lock_timeout_seconds": 45,
                "enable_logging": True,
                "log_level": "DEBUG",
                "concurrent_safety": True,
            },
            "database_info": {
                "engine_url": "postgresql://user:***@localhost/db",
                "expected_tables": ["table1", "table2", "table3", "table4"],
            },
        }

        formatted = format_migration_report(report)

        assert "Health: NEEDS_MIGRATION" in formatted
        assert "Database needs 2 tables created" in formatted
        assert "Missing Tables: table3, table4" in formatted
        assert "Timeout: 60s" in formatted
        assert "Log Level: DEBUG" in formatted

    def test_format_migration_report_error(self):
        """Test formatting an error report."""
        report = {
            "error": "Database connection failed",
            "health": "error",
            "health_message": "Failed to assess migration status",
        }

        formatted = format_migration_report(report)

        assert "Migration Status Report - ERROR" in formatted
        assert "Error: Database connection failed" in formatted

    def test_format_migration_report_minimal(self):
        """Test formatting a minimal report with missing sections."""
        report = {"health": "unknown", "health_message": "Status unknown"}

        formatted = format_migration_report(report)

        assert "Migration Status Report" in formatted
        assert "Health: UNKNOWN" in formatted
        assert "Status unknown" in formatted
        # Should handle missing sections gracefully
        assert "=" in formatted  # Should still have proper formatting
