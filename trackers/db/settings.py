"""
Database configuration settings module.

This module manages database connection parameters and provides
environment-specific database URLs for both regular and test databases.
Supports both Clever Cloud PostgreSQL addon variables and local development variables.
"""

import os
from typing import Optional


class Settings:
    """Database configuration settings loaded from environment variables."""

    db_host: str
    db_user: str
    db_password: str
    db_name: str
    db_port: str
    db_url: str
    ssl_mode: str

    def __init__(self) -> None:
        """
        Initialize settings by loading from environment variables.

        Raises:
            ValueError: If any required environment variable is missing.
        """
        self._load_from_env()
        self.db_url = self._construct_db_url()

    def _load_from_env(self) -> None:
        """
        Load database configuration from environment variables.

        Supports two sets of environment variables:
        1. Clever Cloud PostgreSQL addon variables (production):
           - POSTGRESQL_ADDON_HOST: PostgreSQL server host
           - POSTGRESQL_ADDON_USER: Database username
           - POSTGRESQL_ADDON_PASSWORD: Database password
           - POSTGRESQL_ADDON_DB: Database name
           - POSTGRESQL_ADDON_PORT: Database port

        2. Local development variables (fallback):
           - DB_HOST: PostgreSQL server host
           - DB_USER: Database username
           - DB_PASSWORD: Database password
           - DB_NAME: Database name
           - DB_PORT: Database port (optional, defaults to 5432)

        Raises:
            ValueError: If any required environment variable is missing.

        Requirements: 6.1, 6.4 - Clear error messages with helpful suggestions
        """
        missing_vars = []

        # Try Clever Cloud variables first, then fall back to local development variables
        self.db_host = os.getenv("POSTGRESQL_ADDON_HOST") or os.getenv("DB_HOST", "")
        if not self.db_host:
            missing_vars.append("POSTGRESQL_ADDON_HOST or DB_HOST")

        self.db_user = os.getenv("POSTGRESQL_ADDON_USER") or os.getenv("DB_USER", "")
        if not self.db_user:
            missing_vars.append("POSTGRESQL_ADDON_USER or DB_USER")

        self.db_password = os.getenv("POSTGRESQL_ADDON_PASSWORD") or os.getenv(
            "DB_PASSWORD", ""
        )
        if not self.db_password:
            missing_vars.append("POSTGRESQL_ADDON_PASSWORD or DB_PASSWORD")

        self.db_name = os.getenv("POSTGRESQL_ADDON_DB") or os.getenv("DB_NAME", "")
        if not self.db_name:
            missing_vars.append("POSTGRESQL_ADDON_DB or DB_NAME")

        # Port is optional, defaults to 5432
        self.db_port = os.getenv("POSTGRESQL_ADDON_PORT") or os.getenv(
            "DB_PORT", "5432"
        )

        # SSL mode configuration (optional)
        # Values: disable, allow, prefer, require, verify-ca, verify-full
        # Default: auto-detect based on environment
        self.ssl_mode = os.getenv("DB_SSL_MODE", "auto")

        # Raise error if any variables are missing with helpful message
        if missing_vars:
            error_msg = (
                f"\n{'=' * 60}\n"
                f"MISSING REQUIRED ENVIRONMENT VARIABLES\n"
                f"{'=' * 60}\n"
                f"Missing variables: {', '.join(missing_vars)}\n"
                f"\n"
                f"Required environment variables:\n"
                f"\n"
                f"For Clever Cloud deployment:\n"
                f"  POSTGRESQL_ADDON_HOST     - PostgreSQL server host\n"
                f"  POSTGRESQL_ADDON_USER     - Database username\n"
                f"  POSTGRESQL_ADDON_PASSWORD - Database password\n"
                f"  POSTGRESQL_ADDON_DB       - Database name\n"
                f"  POSTGRESQL_ADDON_PORT     - Database port (optional, defaults to 5432)\n"
                f"\n"
                f"For local development:\n"
                f"  DB_HOST     - PostgreSQL server host (e.g., localhost, 127.0.0.1)\n"
                f"  DB_USER     - Database username\n"
                f"  DB_PASSWORD - Database password\n"
                f"  DB_NAME     - Database name\n"
                f"  DB_PORT     - Database port (optional, defaults to 5432)\n"
                f"\n"
                f"How to fix:\n"
                f"  1. For local development, create a .env file in the project root\n"
                f"  2. Add the missing variables:\n"
                f"     DB_HOST=localhost\n"
                f"     DB_USER=your_username\n"
                f"     DB_PASSWORD=your_password\n"
                f"     DB_NAME=your_database\n"
                f"     DB_PORT=5432\n"
                f"  3. Or set them in your shell:\n"
                f"     export DB_HOST=localhost\n"
                f"     export DB_USER=your_username\n"
                f"     export DB_PASSWORD=your_password\n"
                f"     export DB_NAME=your_database\n"
                f"  4. For Clever Cloud, the PostgreSQL addon variables are set automatically\n"
                f"{'=' * 60}\n"
            )
            raise ValueError(error_msg)

    def _construct_db_url(self) -> str:
        """
        Construct PostgreSQL connection URL from settings.

        Returns:
            str: PostgreSQL connection string in format:
                 postgresql://user:password@host:port/database
        """
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"

    def get_test_db_url(self, test_db_name: Optional[str] = None) -> str:
        """
        Generate test database URL.

        Args:
            test_db_name: Optional custom test database name.
                         If not provided, uses {db_name}_test format.

        Returns:
            str: PostgreSQL connection string for test database.
        """
        if test_db_name is None:
            test_db_name = f"{self.db_name}_test"

        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{test_db_name}"


# Global settings instance
settings = Settings()
