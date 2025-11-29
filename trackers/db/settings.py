"""
Database configuration settings module.

This module manages database connection parameters and provides
environment-specific database URLs for both regular and test databases.
"""

import os
from typing import Optional


class Settings:
    """Database configuration settings loaded from environment variables."""

    db_host: str
    db_user: str
    db_password: str
    db_name: str
    db_url: str

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

        Required environment variables:
        - DB_HOST: PostgreSQL server host
        - DB_USER: Database username
        - DB_PASSWORD: Database password
        - DB_NAME: Database name

        Raises:
            ValueError: If any required environment variable is missing.

        Requirements: 6.1, 6.4 - Clear error messages with helpful suggestions
        """
        missing_vars = []

        # Load each required environment variable
        self.db_host = os.getenv("DB_HOST", "")
        if not self.db_host:
            missing_vars.append("DB_HOST")

        self.db_user = os.getenv("DB_USER", "")
        if not self.db_user:
            missing_vars.append("DB_USER")

        self.db_password = os.getenv("DB_PASSWORD", "")
        if not self.db_password:
            missing_vars.append("DB_PASSWORD")

        self.db_name = os.getenv("DB_NAME", "")
        if not self.db_name:
            missing_vars.append("DB_NAME")

        # Raise error if any variables are missing with helpful message
        if missing_vars:
            error_msg = (
                f"\n{'=' * 60}\n"
                f"MISSING REQUIRED ENVIRONMENT VARIABLES\n"
                f"{'=' * 60}\n"
                f"Missing variables: {', '.join(missing_vars)}\n"
                f"\n"
                f"Required environment variables:\n"
                f"  DB_HOST     - PostgreSQL server host (e.g., localhost, 127.0.0.1)\n"
                f"  DB_USER     - Database username\n"
                f"  DB_PASSWORD - Database password\n"
                f"  DB_NAME     - Database name\n"
                f"\n"
                f"How to fix:\n"
                f"  1. Create a .env file in the project root\n"
                f"  2. Add the missing variables:\n"
                f"     DB_HOST=localhost\n"
                f"     DB_USER=your_username\n"
                f"     DB_PASSWORD=your_password\n"
                f"     DB_NAME=your_database\n"
                f"  3. Or set them in your shell:\n"
                f"     export DB_HOST=localhost\n"
                f"     export DB_USER=your_username\n"
                f"     export DB_PASSWORD=your_password\n"
                f"     export DB_NAME=your_database\n"
                f"{'=' * 60}\n"
            )
            raise ValueError(error_msg)

    def _construct_db_url(self) -> str:
        """
        Construct PostgreSQL connection URL from settings.

        Returns:
            str: PostgreSQL connection string in format:
                 postgresql://user:password@host/database
        """
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}/{self.db_name}"

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

        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}/{test_db_name}"


# Global settings instance
settings = Settings()
