"""
Migration configuration system for controlling migration behavior.

This module provides configuration options for migration behavior including
enable/disable settings, timeout configurations, and other migration parameters.
Supports both environment variables and programmatic configuration.

Requirements: All requirements (supporting functionality)
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class MigrationConfig:
    """
    Configuration settings for database migration behavior.

    Attributes:
        enabled: Whether automatic migration is enabled (default: True)
        timeout_seconds: Timeout for migration operations (default: 30)
        lock_timeout_seconds: Timeout for acquiring migration lock (default: 30)
        enable_logging: Whether to enable detailed migration logging (default: True)
        log_level: Logging level for migration operations (default: "INFO")
        skip_validation: Whether to skip post-migration validation (default: False)
        concurrent_safety: Whether to enable concurrent migration safety (default: True)
    """

    enabled: bool = True
    timeout_seconds: int = 30
    lock_timeout_seconds: int = 30
    enable_logging: bool = True
    log_level: str = "INFO"
    skip_validation: bool = False
    concurrent_safety: bool = True

    @classmethod
    def from_environment(cls) -> "MigrationConfig":
        """
        Create configuration from environment variables.

        Environment variables:
            MIGRATION_ENABLED: Enable/disable migration (true/false, default: true)
            MIGRATION_TIMEOUT: Migration timeout in seconds (default: 30)
            MIGRATION_LOCK_TIMEOUT: Lock timeout in seconds (default: 30)
            MIGRATION_LOGGING: Enable detailed logging (true/false, default: true)
            MIGRATION_LOG_LEVEL: Log level (DEBUG/INFO/WARN/ERROR, default: INFO)
            MIGRATION_SKIP_VALIDATION: Skip validation (true/false, default: false)
            MIGRATION_CONCURRENT_SAFETY: Enable concurrent safety (true/false, default: true)

        Returns:
            MigrationConfig instance with values from environment
        """

        def parse_bool(value: Optional[str], default: bool) -> bool:
            """Parse boolean from string with default fallback."""
            if value is None:
                return default
            return value.lower() in ("true", "1", "yes", "on")

        def parse_int(value: Optional[str], default: int) -> int:
            """Parse integer from string with default fallback."""
            if value is None:
                return default
            try:
                return int(value)
            except ValueError:
                return default

        return cls(
            enabled=parse_bool(os.getenv("MIGRATION_ENABLED"), True),
            timeout_seconds=parse_int(os.getenv("MIGRATION_TIMEOUT"), 30),
            lock_timeout_seconds=parse_int(os.getenv("MIGRATION_LOCK_TIMEOUT"), 30),
            enable_logging=parse_bool(os.getenv("MIGRATION_LOGGING"), True),
            log_level=os.getenv("MIGRATION_LOG_LEVEL", "INFO").upper(),
            skip_validation=parse_bool(os.getenv("MIGRATION_SKIP_VALIDATION"), False),
            concurrent_safety=parse_bool(
                os.getenv("MIGRATION_CONCURRENT_SAFETY"), True
            ),
        )

    def validate(self) -> None:
        """
        Validate configuration values.

        Raises:
            ValueError: If any configuration value is invalid
        """
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        if self.lock_timeout_seconds <= 0:
            raise ValueError("lock_timeout_seconds must be positive")

        valid_log_levels = {"DEBUG", "INFO", "WARN", "WARNING", "ERROR", "CRITICAL"}
        if self.log_level not in valid_log_levels:
            raise ValueError(f"log_level must be one of {valid_log_levels}")


# Global configuration instance
migration_config = MigrationConfig.from_environment()
