"""
Email/Password Authentication Database Migration.

This module provides migration functionality to extend the existing users table
with password-related fields for email/password authentication support.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

import logging
from typing import Optional

from sqlalchemy import (
    inspect,
    text,
)
from sqlalchemy.engine import Engine


class EmailPasswordMigrationError(Exception):
    """Exception raised during email/password migration operations."""

    pass


class EmailPasswordMigration:
    """
    Handles database migration for email/password authentication features.

    This class provides methods to safely extend the existing users table
    with password-related fields while maintaining backward compatibility.

    Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
    """

    def __init__(self, engine: Engine, logger: Optional[logging.Logger] = None):
        self.engine = engine
        self.logger = logger or logging.getLogger(__name__)

    def is_migration_needed(self) -> bool:
        """
        Check if email/password migration is needed.

        Returns:
            True if migration is needed, False if already applied

        Requirements: 7.2 - Backward compatibility check
        """
        try:
            inspector = inspect(self.engine)

            # Check if users table exists
            if "users" not in inspector.get_table_names():
                self.logger.info("Users table does not exist - migration not needed")
                return False

            # Check if password-related columns already exist
            columns = inspector.get_columns("users")
            column_names = [col["name"] for col in columns]

            password_columns = [
                "password_hash",
                "email_verified",
                "password_changed_at",
                "failed_login_attempts",
                "locked_until",
                "auth_methods",
            ]

            missing_columns = [
                col for col in password_columns if col not in column_names
            ]

            if missing_columns:
                self.logger.info(
                    f"Email/password migration needed - missing columns: {missing_columns}"
                )
                return True
            else:
                self.logger.info("Email/password migration already applied")
                return False

        except Exception as e:
            self.logger.error(f"Failed to check migration status: {e}")
            # Assume migration is needed if we can't determine
            return True

    def get_migration_status(self) -> dict:
        """
        Get detailed migration status information.

        Returns:
            Dictionary with migration status details

        Requirements: 7.1 - Database schema extension analysis
        """
        try:
            inspector = inspect(self.engine)
            status = {
                "users_table_exists": False,
                "google_user_id_nullable": False,
                "password_columns_exist": {},
                "indexes_exist": {},
                "migration_needed": True,
                "errors": [],
            }

            # Check if users table exists
            table_names = inspector.get_table_names()
            status["users_table_exists"] = "users" in table_names

            if not status["users_table_exists"]:
                status["errors"].append("Users table does not exist")
                return status

            # Check existing columns
            columns = inspector.get_columns("users")
            column_info = {col["name"]: col for col in columns}

            # Check if google_user_id is nullable (requirement for backward compatibility)
            if "google_user_id" in column_info:
                status["google_user_id_nullable"] = column_info["google_user_id"].get(
                    "nullable", False
                )

            # Check password-related columns
            password_columns = [
                "password_hash",
                "email_verified",
                "password_changed_at",
                "failed_login_attempts",
                "locked_until",
                "auth_methods",
            ]

            for col in password_columns:
                status["password_columns_exist"][col] = col in column_info

            # Check indexes
            indexes = inspector.get_indexes("users")
            index_names = [idx["name"] for idx in indexes]

            expected_indexes = [
                "idx_users_password_hash",
                "idx_users_email_verified",
                "idx_users_failed_attempts",
                "idx_users_locked_until",
            ]

            for idx in expected_indexes:
                status["indexes_exist"][idx] = idx in index_names

            # Determine if migration is needed
            all_columns_exist = all(status["password_columns_exist"].values())
            status["migration_needed"] = not all_columns_exist

            return status

        except Exception as e:
            self.logger.error(f"Failed to get migration status: {e}")
            return {
                "migration_needed": True,
                "errors": [f"Status check failed: {e}"],
            }

    def apply_migration(self) -> bool:
        """
        Apply the email/password authentication migration.

        This method safely extends the users table with password-related fields
        while maintaining backward compatibility with existing data.

        Returns:
            True if migration was successful, False otherwise

        Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
        """
        try:
            self.logger.info("Starting email/password authentication migration")

            # Check if migration is needed
            if not self.is_migration_needed():
                self.logger.info("Migration not needed - already applied")
                return True

            # Apply migration steps
            success = True
            success &= self._make_google_user_id_nullable()
            success &= self._add_password_columns()
            success &= self._add_indexes()
            success &= self._validate_migration()

            if success:
                self.logger.info(
                    "Email/password authentication migration completed successfully"
                )
            else:
                self.logger.error("Email/password authentication migration failed")

            return success

        except Exception as e:
            self.logger.error(f"Migration failed with exception: {e}")
            return False

    def _make_google_user_id_nullable(self) -> bool:
        """
        Make google_user_id column nullable for backward compatibility.

        This allows users to exist with only email/password authentication.

        Returns:
            True if successful, False otherwise

        Requirements: 7.2 - Backward compatibility
        """
        try:
            self.logger.info("Making google_user_id column nullable")

            with self.engine.connect() as conn:
                # Check current nullable status
                result = conn.execute(
                    text("""
                    SELECT is_nullable 
                    FROM information_schema.columns 
                    WHERE table_name = 'users' AND column_name = 'google_user_id'
                """)
                )
                row = result.fetchone()

                if row and row[0] == "YES":
                    self.logger.info("google_user_id is already nullable")
                    return True

                # Make column nullable
                conn.execute(
                    text("ALTER TABLE users ALTER COLUMN google_user_id DROP NOT NULL")
                )
                conn.commit()

                self.logger.info("✓ Made google_user_id column nullable")
                return True

        except Exception as e:
            self.logger.error(f"Failed to make google_user_id nullable: {e}")
            return False

    def _add_password_columns(self) -> bool:
        """
        Add password-related columns to the users table.

        Returns:
            True if successful, False otherwise

        Requirements: 7.1 - Database schema extension
        """
        try:
            self.logger.info("Adding password-related columns")

            with self.engine.connect() as conn:
                # Define columns to add
                columns_to_add = [
                    ("password_hash", "VARCHAR(255) NULL"),
                    ("email_verified", "BOOLEAN DEFAULT FALSE NOT NULL"),
                    ("password_changed_at", "TIMESTAMP NULL"),
                    ("failed_login_attempts", "INTEGER DEFAULT 0 NOT NULL"),
                    ("locked_until", "TIMESTAMP NULL"),
                    ("auth_methods", "VARCHAR(100) DEFAULT '' NOT NULL"),
                ]

                # Check which columns already exist
                existing_columns = []
                result = conn.execute(
                    text("""
                    SELECT column_name 
                    FROM information_schema.columns 
                    WHERE table_name = 'users'
                """)
                )
                existing_columns = [row[0] for row in result.fetchall()]

                # Add missing columns
                for column_name, column_def in columns_to_add:
                    if column_name not in existing_columns:
                        try:
                            conn.execute(
                                text(
                                    f"ALTER TABLE users ADD COLUMN {column_name} {column_def}"
                                )
                            )
                            self.logger.info(f"✓ Added column: {column_name}")
                        except Exception as e:
                            self.logger.error(
                                f"Failed to add column {column_name}: {e}"
                            )
                            return False
                    else:
                        self.logger.info(f"Column {column_name} already exists")

                conn.commit()
                self.logger.info("✓ All password-related columns added")
                return True

        except Exception as e:
            self.logger.error(f"Failed to add password columns: {e}")
            return False

    def _add_indexes(self) -> bool:
        """
        Add performance indexes for password-related columns.

        Returns:
            True if successful, False otherwise

        Requirements: 7.5 - Index email and password-related fields
        """
        try:
            self.logger.info("Adding indexes for password-related columns")

            with self.engine.connect() as conn:
                # Define indexes to create
                indexes_to_create = [
                    ("idx_users_password_hash", "password_hash"),
                    ("idx_users_email_verified", "email_verified"),
                    ("idx_users_failed_attempts", "failed_login_attempts"),
                    ("idx_users_locked_until", "locked_until"),
                ]

                # Check which indexes already exist
                existing_indexes = []
                result = conn.execute(
                    text("""
                    SELECT indexname 
                    FROM pg_indexes 
                    WHERE tablename = 'users'
                """)
                )
                existing_indexes = [row[0] for row in result.fetchall()]

                # Create missing indexes
                for index_name, column_name in indexes_to_create:
                    if index_name not in existing_indexes:
                        try:
                            conn.execute(
                                text(
                                    f"CREATE INDEX {index_name} ON users({column_name})"
                                )
                            )
                            self.logger.info(f"✓ Created index: {index_name}")
                        except Exception as e:
                            self.logger.error(
                                f"Failed to create index {index_name}: {e}"
                            )
                            return False
                    else:
                        self.logger.info(f"Index {index_name} already exists")

                conn.commit()
                self.logger.info("✓ All indexes created")
                return True

        except Exception as e:
            self.logger.error(f"Failed to add indexes: {e}")
            return False

    def _validate_migration(self) -> bool:
        """
        Validate that the migration was applied correctly.

        Returns:
            True if validation passes, False otherwise

        Requirements: 7.4 - Migration validation
        """
        try:
            self.logger.info("Validating migration")

            status = self.get_migration_status()

            if status.get("errors"):
                self.logger.error(f"Migration validation errors: {status['errors']}")
                return False

            # Check all required columns exist
            password_columns = status.get("password_columns_exist", {})
            missing_columns = [
                col for col, exists in password_columns.items() if not exists
            ]

            if missing_columns:
                self.logger.error(
                    f"Migration validation failed - missing columns: {missing_columns}"
                )
                return False

            # Check google_user_id is nullable
            if not status.get("google_user_id_nullable", False):
                self.logger.error(
                    "Migration validation failed - google_user_id is not nullable"
                )
                return False

            self.logger.info("✓ Migration validation passed")
            return True

        except Exception as e:
            self.logger.error(f"Migration validation failed: {e}")
            return False

    def rollback_migration(self) -> bool:
        """
        Rollback the email/password authentication migration.

        This method removes the password-related columns and indexes.
        Use with caution as this will delete data.

        Returns:
            True if rollback was successful, False otherwise

        Requirements: 7.3 - Migration rollback capability
        """
        try:
            self.logger.warning(
                "Starting email/password authentication migration rollback"
            )
            self.logger.warning("This will delete all password-related data!")

            with self.engine.connect() as conn:
                # Drop indexes first
                indexes_to_drop = [
                    "idx_users_password_hash",
                    "idx_users_email_verified",
                    "idx_users_failed_attempts",
                    "idx_users_locked_until",
                ]

                for index_name in indexes_to_drop:
                    try:
                        conn.execute(text(f"DROP INDEX IF EXISTS {index_name}"))
                        self.logger.info(f"✓ Dropped index: {index_name}")
                    except Exception as e:
                        self.logger.warning(f"Failed to drop index {index_name}: {e}")

                # Drop columns
                columns_to_drop = [
                    "password_hash",
                    "email_verified",
                    "password_changed_at",
                    "failed_login_attempts",
                    "locked_until",
                    "auth_methods",
                ]

                for column_name in columns_to_drop:
                    try:
                        conn.execute(
                            text(
                                f"ALTER TABLE users DROP COLUMN IF EXISTS {column_name}"
                            )
                        )
                        self.logger.info(f"✓ Dropped column: {column_name}")
                    except Exception as e:
                        self.logger.warning(f"Failed to drop column {column_name}: {e}")

                # Make google_user_id NOT NULL again (if there are no NULL values)
                try:
                    # Check if there are any NULL values
                    result = conn.execute(
                        text("SELECT COUNT(*) FROM users WHERE google_user_id IS NULL")
                    )
                    null_count = result.scalar()

                    if null_count == 0:
                        conn.execute(
                            text(
                                "ALTER TABLE users ALTER COLUMN google_user_id SET NOT NULL"
                            )
                        )
                        self.logger.info("✓ Made google_user_id NOT NULL")
                    else:
                        self.logger.warning(
                            f"Cannot make google_user_id NOT NULL - {null_count} rows have NULL values"
                        )
                except Exception as e:
                    self.logger.warning(f"Failed to make google_user_id NOT NULL: {e}")

                conn.commit()

            self.logger.info(
                "Email/password authentication migration rollback completed"
            )
            return True

        except Exception as e:
            self.logger.error(f"Migration rollback failed: {e}")
            return False


def run_email_password_migration(
    engine: Engine, logger: Optional[logging.Logger] = None
) -> bool:
    """
    Convenience function to run the email/password authentication migration.

    Args:
        engine: SQLAlchemy engine
        logger: Optional logger instance

    Returns:
        True if migration was successful, False otherwise

    Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
    """
    migration = EmailPasswordMigration(engine, logger)
    return migration.apply_migration()


def check_email_password_migration_status(
    engine: Engine, logger: Optional[logging.Logger] = None
) -> dict:
    """
    Check the status of email/password authentication migration.

    Args:
        engine: SQLAlchemy engine
        logger: Optional logger instance

    Returns:
        Dictionary with migration status information

    Requirements: 7.1, 7.2
    """
    migration = EmailPasswordMigration(engine, logger)
    return migration.get_migration_status()
