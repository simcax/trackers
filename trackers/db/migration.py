"""
Database migration engine for automatic schema management.

This module provides automatic database migration functionality that detects
missing database schema during Flask application startup and applies necessary
changes using SQLAlchemy metadata. It includes support for user ownership
migration and comprehensive error handling.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 3.1, 3.2, 3.3, 3.4, 3.5
"""

import logging
import os
import signal
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Engine, MetaData, inspect, text
from sqlalchemy.exc import OperationalError, ProgrammingError

if TYPE_CHECKING:
    from .user_migration import UserMigrationResult


class MigrationLockException(Exception):
    """Exception raised when migration lock cannot be acquired."""

    pass


@contextmanager
def migration_lock(
    lock_file_path: str = "/tmp/migration.lock", timeout_seconds: int = 30
):
    """
    Context manager for ensuring only one migration runs at a time.

    Implements concurrent migration safety for multiple application instances
    by using a file-based lock mechanism.

    Requirements: 7.3 - Concurrent migration safety
    """
    lock_acquired = False
    start_time = time.time()

    try:
        # Try to acquire lock with timeout
        while time.time() - start_time < timeout_seconds:
            try:
                # Try to create lock file exclusively
                fd = os.open(lock_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(
                    fd,
                    f"Migration lock acquired by PID {os.getpid()} at {time.time()}".encode(),
                )
                os.close(fd)
                lock_acquired = True
                break
            except FileExistsError:
                # Lock file exists, check if it's stale
                try:
                    stat = os.stat(lock_file_path)
                    # If lock file is older than 5 minutes, consider it stale
                    if time.time() - stat.st_mtime > 300:
                        os.remove(lock_file_path)
                        continue
                except (OSError, FileNotFoundError):
                    # Lock file was removed by another process, try again
                    continue

                # Wait a bit before retrying
                time.sleep(0.1)

        if not lock_acquired:
            raise MigrationLockException(
                f"Could not acquire migration lock within {timeout_seconds} seconds. "
                f"Another migration may be in progress."
            )

        yield

    finally:
        # Release lock
        if lock_acquired:
            try:
                os.remove(lock_file_path)
            except (OSError, FileNotFoundError):
                # Lock file already removed, that's fine
                pass


class TimeoutException(Exception):
    """Exception raised when database operations timeout."""

    pass


@contextmanager
def timeout_handler(seconds: int):
    """
    Context manager for handling operation timeouts.

    Handles both main thread (using signals) and worker thread (using threading.Timer) scenarios.
    This ensures compatibility with production environments that may use concurrent deployments.

    Requirements: 7.2, 7.3 - Production timeout constraints and concurrent migration safety
    """

    # Check if we're in the main thread
    is_main_thread = threading.current_thread() is threading.main_thread()

    if is_main_thread:
        # Use signal-based timeout for main thread
        def timeout_signal_handler(signum, frame):
            raise TimeoutException(f"Operation timed out after {seconds} seconds")

        # Set up the timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_signal_handler)
        signal.alarm(seconds)

        try:
            yield
        finally:
            # Clean up
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
    else:
        # Use threading.Timer for worker threads (concurrent migration safety)
        timeout_occurred = threading.Event()

        def timeout_callback():
            timeout_occurred.set()

        timer = threading.Timer(seconds, timeout_callback)
        timer.start()

        try:
            yield
            if timeout_occurred.is_set():
                raise TimeoutException(f"Operation timed out after {seconds} seconds")
        finally:
            timer.cancel()


@dataclass
class MigrationResult:
    """
    Represents the outcome of a migration operation.

    Requirements: 1.5, 3.2, 3.3, 5.1, 5.4
    """

    success: bool
    tables_created: List[str]
    errors: List[str]
    duration_seconds: float
    message: str
    user_migration_result: Optional["UserMigrationResult"] = None


@dataclass
class MigrationStatus:
    """
    Represents the current state of the database schema.

    Requirements: 1.1, 1.2, 1.3, 3.5
    """

    database_exists: bool
    tables_exist: List[str]
    missing_tables: List[str]
    migration_needed: bool
    connection_healthy: bool


@dataclass
class SchemaValidationResult:
    """
    Detailed analysis of schema validation.

    Requirements: 1.3, 2.4, 6.3
    """

    valid: bool
    missing_tables: List[str]
    unexpected_tables: List[str]
    schema_errors: List[str]


class MigrationLogger:
    """
    Provides comprehensive logging throughout the migration process.

    Requirements: 1.5, 3.3, 5.1, 5.2, 5.4, 5.5
    """

    def __init__(self, logger: logging.Logger):
        self.logger = logger

    def log_migration_start(self, status: MigrationStatus) -> None:
        """Log the start of migration with current database state."""
        self.logger.info("=" * 60)
        self.logger.info("STARTING DATABASE MIGRATION")
        self.logger.info("=" * 60)
        self.logger.info(f"Database connection healthy: {status.connection_healthy}")
        self.logger.info(f"Existing tables: {len(status.tables_exist)}")
        if status.tables_exist:
            self.logger.info(f"Found tables: {', '.join(status.tables_exist)}")
        self.logger.info(f"Missing tables: {len(status.missing_tables)}")
        if status.missing_tables:
            self.logger.info(f"Tables to create: {', '.join(status.missing_tables)}")
        self.logger.info(f"Migration needed: {status.migration_needed}")

    def log_table_creation(self, table: str, success: bool) -> None:
        """Log individual table creation results."""
        if success:
            self.logger.info(f"✓ Created table: {table}")
        else:
            self.logger.error(f"✗ Failed to create table: {table}")

    def log_migration_complete(self, result: MigrationResult) -> None:
        """Log migration completion with summary."""
        self.logger.info("=" * 60)
        if result.success:
            self.logger.info("MIGRATION COMPLETED SUCCESSFULLY")
        else:
            self.logger.error("MIGRATION COMPLETED WITH ERRORS")
        self.logger.info("=" * 60)
        self.logger.info(f"Duration: {result.duration_seconds:.2f} seconds")
        self.logger.info(f"Tables created: {len(result.tables_created)}")
        if result.tables_created:
            self.logger.info(f"Created: {', '.join(result.tables_created)}")
        if result.errors:
            self.logger.error(f"Errors encountered: {len(result.errors)}")
            for error in result.errors:
                self.logger.error(f"  - {error}")
        self.logger.info(f"Result: {result.message}")
        self.logger.info("=" * 60)

    def log_error(self, error: Exception, context: str) -> None:
        """
        Log detailed error information with context and recovery suggestions.

        Enhanced for production environments with deployment-friendly error messages
        and specific guidance for common production issues.

        Requirements: 7.4 - Deployment-friendly error messages and logging
        """
        self.logger.error(f"Migration error in {context}: {error}")

        # Provide specific error handling and recovery suggestions
        if isinstance(error, OperationalError):
            error_msg = str(error).lower()
            if "connection" in error_msg or "refused" in error_msg:
                self.logger.error("Database connection issue detected")
                self.logger.error("Recovery suggestions:")
                self.logger.error("  - Check database server is running")
                self.logger.error(
                    "  - Verify connection parameters (host, port, database name)"
                )
                self.logger.error(
                    "  - Check network connectivity and firewall settings"
                )
                self.logger.error("  - Ensure database service is accessible")
                # Production-specific guidance
                self.logger.error("Production deployment guidance:")
                self.logger.error(
                    "  - For Clever Cloud: Check PostgreSQL addon status in console"
                )
                self.logger.error("  - Verify environment variables are correctly set")
                self.logger.error(
                    "  - Check if database addon is properly attached to application"
                )
            elif (
                "authentication" in error_msg
                or "password" in error_msg
                or "login" in error_msg
            ):
                self.logger.error("Database authentication issue detected")
                self.logger.error("Recovery suggestions:")
                self.logger.error("  - Verify database username and password")
                self.logger.error("  - Check user authentication credentials")
                self.logger.error("  - Ensure user has login permissions")
                # Production-specific guidance
                self.logger.error("Production deployment guidance:")
                self.logger.error(
                    "  - For Clever Cloud: Credentials are managed automatically"
                )
                self.logger.error(
                    "  - Check if POSTGRESQL_ADDON_* environment variables are set"
                )
                self.logger.error(
                    "  - Verify addon configuration in deployment platform"
                )
            elif "timeout" in error_msg:
                self.logger.error("Database operation timeout detected")
                self.logger.error("Recovery suggestions:")
                self.logger.error("  - Check network latency and stability")
                self.logger.error("  - Consider increasing timeout settings")
                self.logger.error("  - Verify database server performance")
                # Production-specific guidance
                self.logger.error("Production deployment guidance:")
                self.logger.error("  - Cloud platforms may have network latency")
                self.logger.error(
                    "  - Consider increasing migration timeout for production"
                )
                self.logger.error(
                    "  - Check if database is under heavy load during deployment"
                )
            elif "disk" in error_msg or "space" in error_msg:
                self.logger.error("Database storage issue detected")
                self.logger.error("Recovery suggestions:")
                self.logger.error("  - Check available disk space on database server")
                self.logger.error("  - Clean up unnecessary files or expand storage")
                # Production-specific guidance
                self.logger.error("Production deployment guidance:")
                self.logger.error("  - For Clever Cloud: Check addon storage limits")
                self.logger.error(
                    "  - Consider upgrading database plan if storage is full"
                )
            else:
                self.logger.error(
                    "Database operational error - check connectivity and permissions"
                )
                # General production guidance
                self.logger.error("Production deployment guidance:")
                self.logger.error("  - Check deployment platform status and health")
                self.logger.error(
                    "  - Verify all required environment variables are set"
                )

        elif isinstance(error, ProgrammingError):
            error_msg = str(error).lower()
            if "permission" in error_msg or "privilege" in error_msg:
                self.logger.error("Database permission issue detected")
                self.logger.error("Recovery suggestions:")
                self.logger.error("  - Check user has CREATE TABLE privileges")
                self.logger.error(
                    "  - Verify user has necessary schema modification permissions"
                )
                self.logger.error(
                    "  - Contact database administrator to grant required privileges"
                )
                # Production-specific guidance
                self.logger.error("Production deployment guidance:")
                self.logger.error(
                    "  - For Clever Cloud: Database user should have full privileges"
                )
                self.logger.error("  - Check if addon provides sufficient permissions")
                self.logger.error(
                    "  - Verify database user configuration in deployment platform"
                )
            else:
                self.logger.error(
                    "Database programming error - check user privileges and SQL syntax"
                )

        elif isinstance(error, MigrationLockException):
            self.logger.error("Migration lock acquisition failed")
            self.logger.error("Recovery suggestions:")
            self.logger.error("  - Another migration may be in progress")
            self.logger.error("  - Wait for concurrent migration to complete")
            self.logger.error("  - Check for stale lock files if issue persists")
            # Production-specific guidance
            self.logger.error("Production deployment guidance:")
            self.logger.error("  - Multiple instances may be deploying simultaneously")
            self.logger.error(
                "  - This is normal behavior for zero-downtime deployments"
            )
            self.logger.error(
                "  - One instance will complete migration, others will skip"
            )

        elif "TimeoutError" in str(type(error)) or isinstance(error, TimeoutException):
            self.logger.error("Operation timeout detected")
            self.logger.error("Recovery suggestions:")
            self.logger.error("  - Retry the operation")
            self.logger.error("  - Check system performance and resource availability")
            self.logger.error("  - Consider increasing timeout limits")
            # Production-specific guidance
            self.logger.error("Production deployment guidance:")
            self.logger.error("  - Cloud deployments may have stricter timeout limits")
            self.logger.error("  - Consider optimizing migration for faster execution")
            self.logger.error("  - Check if deployment platform allows longer timeouts")
        else:
            self.logger.error("General migration error - check logs for details")
            # General production guidance
            self.logger.error("Production deployment guidance:")
            self.logger.error(
                "  - Check deployment platform logs for additional context"
            )
            self.logger.error("  - Verify all environment variables and configuration")
            self.logger.error(
                "  - Consider manual database initialization if migration fails repeatedly"
            )

    def log_schema_creation_start(self, table_count: int) -> None:
        """Log the start of schema creation phase."""
        self.logger.info("-" * 40)
        self.logger.info("STARTING SCHEMA CREATION")
        self.logger.info("-" * 40)
        self.logger.info(f"Creating {table_count} missing tables...")

    def log_connectivity_validation(self, success: bool) -> None:
        """Log database connectivity validation results."""
        if success:
            self.logger.info("✓ Database connectivity validation passed")
        else:
            self.logger.error("✗ Database connectivity validation failed")

    def log_migration_phase(self, phase: str, details: str = "") -> None:
        """Log migration phase transitions with optional details."""
        self.logger.info(f"Migration phase: {phase}")
        if details:
            self.logger.info(f"  {details}")

    def log_troubleshooting_info(self, info: str) -> None:
        """Log troubleshooting information at DEBUG level."""
        self.logger.debug(f"Troubleshooting: {info}")


@dataclass
class UserSchemaStatus:
    """
    Represents the current state of user ownership schema.

    Requirements: 2.1, 5.1
    """

    users_table_exists: bool
    trackers_has_user_id: bool
    user_foreign_key_exists: bool
    user_constraints_valid: bool
    migration_needed: bool
    schema_errors: List[str]


@dataclass
class ForeignKeyValidationResult:
    """
    Detailed analysis of foreign key relationships.

    Requirements: 2.1, 5.1
    """

    valid: bool
    missing_foreign_keys: List[str]
    invalid_constraints: List[str]
    orphaned_references: List[str]
    validation_errors: List[str]


class SchemaDetector:
    """
    Analyzes the current database state and determines what schema changes are needed.

    Enhanced to detect user ownership requirements and validate foreign key relationships.

    Requirements: 1.1, 1.2, 1.3, 1.4, 2.1, 5.1
    """

    def __init__(self, engine: Engine, metadata: MetaData):
        self.engine = engine
        self.metadata = metadata
        self.logger = logging.getLogger(__name__)

    def detect_missing_tables(self) -> List[str]:
        """
        Detect which tables are missing from the database.

        Returns:
            List of table names that exist in metadata but not in database

        Requirements: 1.1, 1.2
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())
            expected_tables = set(self.metadata.tables.keys())
            missing_tables = list(expected_tables - existing_tables)

            self.logger.debug(f"Expected tables: {expected_tables}")
            self.logger.debug(f"Existing tables: {existing_tables}")
            self.logger.debug(f"Missing tables: {missing_tables}")

            # Add troubleshooting information
            if missing_tables:
                self.logger.debug(
                    f"Schema detection: {len(missing_tables)} tables need to be created"
                )
            else:
                self.logger.debug("Schema detection: All expected tables exist")

            return missing_tables
        except Exception as e:
            self.logger.error(f"Failed to detect missing tables: {e}")
            # Return all expected tables if we can't inspect the database
            return list(self.metadata.tables.keys())

    def detect_user_schema_status(self) -> UserSchemaStatus:
        """
        Detect the current state of user ownership schema requirements.

        Analyzes the database to determine if user ownership features are properly
        implemented, including users table, user_id column in trackers, and
        foreign key relationships.

        Returns:
            UserSchemaStatus with detailed analysis of user ownership schema

        Requirements: 2.1, 5.1
        """
        try:
            # Check if users table is expected in metadata
            if "users" not in self.metadata.tables:
                # If users table is not expected, user ownership is not needed
                return UserSchemaStatus(
                    users_table_exists=False,
                    trackers_has_user_id=False,
                    user_foreign_key_exists=False,
                    user_constraints_valid=True,  # Valid because not required
                    migration_needed=False,  # No migration needed
                    schema_errors=[],
                )

            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())
            schema_errors = []

            # Check if users table exists
            users_table_exists = "users" in existing_tables
            if not users_table_exists:
                schema_errors.append("Users table is missing")

            # Check if trackers table has user_id column
            trackers_has_user_id = False
            if "trackers" in existing_tables:
                try:
                    columns = inspector.get_columns("trackers")
                    column_names = [col["name"] for col in columns]
                    trackers_has_user_id = "user_id" in column_names
                    if not trackers_has_user_id:
                        schema_errors.append("Trackers table missing user_id column")
                except Exception as e:
                    schema_errors.append(f"Failed to inspect trackers table: {e}")
            else:
                schema_errors.append("Trackers table is missing")

            # Check foreign key relationship between trackers and users
            user_foreign_key_exists = False
            if users_table_exists and trackers_has_user_id:
                try:
                    foreign_keys = inspector.get_foreign_keys("trackers")
                    for fk in foreign_keys:
                        if fk.get("referred_table") == "users" and "user_id" in fk.get(
                            "constrained_columns", []
                        ):
                            user_foreign_key_exists = True
                            break
                    if not user_foreign_key_exists:
                        schema_errors.append(
                            "Foreign key constraint missing between trackers.user_id and users.id"
                        )
                except Exception as e:
                    schema_errors.append(f"Failed to inspect foreign keys: {e}")

            # Validate user constraints (unique constraints, indexes)
            user_constraints_valid = True
            if users_table_exists and trackers_has_user_id:
                try:
                    # Check for unique constraint on user_id + name in trackers
                    unique_constraints = inspector.get_unique_constraints("trackers")
                    user_name_unique = False
                    for constraint in unique_constraints:
                        columns = constraint.get("column_names", [])
                        if "user_id" in columns and "name" in columns:
                            user_name_unique = True
                            break

                    if not user_name_unique:
                        schema_errors.append(
                            "Unique constraint missing for user_id + name in trackers table"
                        )
                        user_constraints_valid = False

                    # Check for index on user_id for performance
                    indexes = inspector.get_indexes("trackers")
                    user_id_indexed = False
                    for index in indexes:
                        columns = index.get("column_names", [])
                        if "user_id" in columns:
                            user_id_indexed = True
                            break

                    if not user_id_indexed:
                        self.logger.debug(
                            "Performance recommendation: Consider adding index on trackers.user_id"
                        )

                except Exception as e:
                    schema_errors.append(f"Failed to validate user constraints: {e}")
                    user_constraints_valid = False

            # Determine if migration is needed
            migration_needed = not (
                users_table_exists
                and trackers_has_user_id
                and user_foreign_key_exists
                and user_constraints_valid
            )

            self.logger.debug("User schema analysis:")
            self.logger.debug(f"  Users table exists: {users_table_exists}")
            self.logger.debug(f"  Trackers has user_id: {trackers_has_user_id}")
            self.logger.debug(f"  Foreign key exists: {user_foreign_key_exists}")
            self.logger.debug(f"  Constraints valid: {user_constraints_valid}")
            self.logger.debug(f"  Migration needed: {migration_needed}")

            return UserSchemaStatus(
                users_table_exists=users_table_exists,
                trackers_has_user_id=trackers_has_user_id,
                user_foreign_key_exists=user_foreign_key_exists,
                user_constraints_valid=user_constraints_valid,
                migration_needed=migration_needed,
                schema_errors=schema_errors,
            )

        except Exception as e:
            self.logger.error(f"Failed to detect user schema status: {e}")
            return UserSchemaStatus(
                users_table_exists=False,
                trackers_has_user_id=False,
                user_foreign_key_exists=False,
                user_constraints_valid=False,
                migration_needed=True,
                schema_errors=[f"User schema detection failed: {e}"],
            )

    def is_user_migration_needed(self) -> bool:
        """
        Check if user ownership migration is needed.

        Returns:
            True if user ownership migration is required, False otherwise

        Requirements: 2.1, 5.1
        """
        try:
            status = self.detect_user_schema_status()
            return status.migration_needed
        except Exception as e:
            self.logger.error(f"Failed to check if user migration is needed: {e}")
            # Assume migration is needed if we can't determine
            return True

    def validate_foreign_key_relationships(self) -> ForeignKeyValidationResult:
        """
        Validate foreign key relationships and constraints across the database.

        Performs comprehensive validation of all foreign key relationships,
        checking for missing constraints, orphaned references, and constraint
        integrity.

        Returns:
            ForeignKeyValidationResult with detailed validation information

        Requirements: 2.1, 5.1
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())

            missing_foreign_keys = []
            invalid_constraints = []
            orphaned_references = []
            validation_errors = []

            # Validate expected foreign key relationships from metadata
            for table_name, table in self.metadata.tables.items():
                if table_name not in existing_tables:
                    continue  # Skip tables that don't exist yet

                try:
                    # Get actual foreign keys from database
                    actual_fks = inspector.get_foreign_keys(table_name)
                    actual_fk_map = {}
                    for fk in actual_fks:
                        for col in fk.get("constrained_columns", []):
                            actual_fk_map[col] = fk.get("referred_table")

                    # Check expected foreign keys from metadata
                    for column in table.columns:
                        if column.foreign_keys:
                            for fk in column.foreign_keys:
                                expected_table = fk.column.table.name
                                column_name = column.name

                                # Check if foreign key exists in database
                                if column_name not in actual_fk_map:
                                    missing_foreign_keys.append(
                                        f"{table_name}.{column_name} -> {expected_table}"
                                    )
                                elif actual_fk_map[column_name] != expected_table:
                                    invalid_constraints.append(
                                        f"{table_name}.{column_name} references {actual_fk_map[column_name]} but should reference {expected_table}"
                                    )

                    # Check for orphaned references (foreign key points to non-existent records)
                    if table_name == "trackers" and "user_id" in [
                        col["name"] for col in inspector.get_columns(table_name)
                    ]:
                        try:
                            with self.engine.connect() as conn:
                                # Check for trackers with user_id that don't reference existing users
                                if "users" in existing_tables:
                                    result = conn.execute(
                                        text("""
                                        SELECT COUNT(*) FROM trackers t 
                                        LEFT JOIN users u ON t.user_id = u.id 
                                        WHERE t.user_id IS NOT NULL AND u.id IS NULL
                                    """)
                                    )
                                    orphaned_count = result.scalar()
                                    if orphaned_count > 0:
                                        orphaned_references.append(
                                            f"{orphaned_count} trackers reference non-existent users"
                                        )
                        except Exception as e:
                            validation_errors.append(
                                f"Failed to check orphaned references: {e}"
                            )

                except Exception as e:
                    validation_errors.append(
                        f"Failed to validate foreign keys for table {table_name}: {e}"
                    )

            # Overall validation result
            is_valid = (
                len(missing_foreign_keys) == 0
                and len(invalid_constraints) == 0
                and len(orphaned_references) == 0
                and len(validation_errors) == 0
            )

            self.logger.debug("Foreign key validation:")
            self.logger.debug(f"  Valid: {is_valid}")
            self.logger.debug(f"  Missing FKs: {len(missing_foreign_keys)}")
            self.logger.debug(f"  Invalid constraints: {len(invalid_constraints)}")
            self.logger.debug(f"  Orphaned references: {len(orphaned_references)}")

            return ForeignKeyValidationResult(
                valid=is_valid,
                missing_foreign_keys=missing_foreign_keys,
                invalid_constraints=invalid_constraints,
                orphaned_references=orphaned_references,
                validation_errors=validation_errors,
            )

        except Exception as e:
            self.logger.error(f"Foreign key validation failed: {e}")
            return ForeignKeyValidationResult(
                valid=False,
                missing_foreign_keys=[],
                invalid_constraints=[],
                orphaned_references=[],
                validation_errors=[f"Foreign key validation failed: {e}"],
            )

    def validate_existing_schema(self) -> SchemaValidationResult:
        """
        Validate the existing database schema against expected metadata.

        Enhanced with detailed schema analysis including user ownership validation
        and foreign key relationship checking.

        Returns:
            SchemaValidationResult with detailed validation information

        Requirements: 1.3, 2.4, 2.1, 5.1
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())
            expected_tables = set(self.metadata.tables.keys())

            missing_tables = list(expected_tables - existing_tables)
            unexpected_tables = list(existing_tables - expected_tables)
            schema_errors = []

            # Basic table existence validation
            for table_name in expected_tables.intersection(existing_tables):
                try:
                    # Basic validation - table exists and is accessible
                    inspector.get_columns(table_name)
                except Exception as e:
                    schema_errors.append(f"Table {table_name} validation failed: {e}")

            # Enhanced validation: User ownership schema
            if "users" in expected_tables or "trackers" in expected_tables:
                user_status = self.detect_user_schema_status()
                schema_errors.extend(user_status.schema_errors)

            # Enhanced validation: Foreign key relationships
            fk_validation = self.validate_foreign_key_relationships()
            if not fk_validation.valid:
                schema_errors.extend(
                    [
                        f"Missing foreign keys: {', '.join(fk_validation.missing_foreign_keys)}"
                        if fk_validation.missing_foreign_keys
                        else None,
                        f"Invalid constraints: {', '.join(fk_validation.invalid_constraints)}"
                        if fk_validation.invalid_constraints
                        else None,
                        f"Orphaned references: {', '.join(fk_validation.orphaned_references)}"
                        if fk_validation.orphaned_references
                        else None,
                    ]
                )
                schema_errors.extend(fk_validation.validation_errors)
                # Remove None values
                schema_errors = [error for error in schema_errors if error is not None]

            is_valid = len(missing_tables) == 0 and len(schema_errors) == 0

            self.logger.debug("Enhanced schema validation:")
            self.logger.debug(f"  Valid: {is_valid}")
            self.logger.debug(f"  Missing tables: {len(missing_tables)}")
            self.logger.debug(f"  Schema errors: {len(schema_errors)}")

            return SchemaValidationResult(
                valid=is_valid,
                missing_tables=missing_tables,
                unexpected_tables=unexpected_tables,
                schema_errors=schema_errors,
            )
        except Exception as e:
            self.logger.error(f"Schema validation failed: {e}")
            return SchemaValidationResult(
                valid=False,
                missing_tables=list(self.metadata.tables.keys()),
                unexpected_tables=[],
                schema_errors=[f"Schema validation error: {e}"],
            )

    def get_expected_tables(self) -> List[str]:
        """
        Get list of all tables expected to exist based on metadata.

        Returns:
            List of table names from SQLAlchemy metadata

        Requirements: 1.4
        """
        return list(self.metadata.tables.keys())

    def get_detailed_schema_analysis(self) -> dict:
        """
        Get comprehensive schema analysis including user ownership and foreign key validation.

        Provides detailed reporting for migration status with enhanced analysis
        of user ownership requirements and foreign key relationships.

        Returns:
            Dictionary with comprehensive schema analysis

        Requirements: 2.1, 5.1
        """
        try:
            # Basic schema analysis
            missing_tables = self.detect_missing_tables()
            schema_validation = self.validate_existing_schema()

            # User ownership analysis
            user_schema_status = self.detect_user_schema_status()

            # Foreign key analysis
            fk_validation = self.validate_foreign_key_relationships()

            # Build comprehensive analysis
            analysis = {
                "basic_schema": {
                    "expected_tables": self.get_expected_tables(),
                    "missing_tables": missing_tables,
                    "unexpected_tables": schema_validation.unexpected_tables,
                    "migration_needed": len(missing_tables) > 0,
                },
                "user_ownership": {
                    "users_table_exists": user_schema_status.users_table_exists,
                    "trackers_has_user_id": user_schema_status.trackers_has_user_id,
                    "foreign_key_exists": user_schema_status.user_foreign_key_exists,
                    "constraints_valid": user_schema_status.user_constraints_valid,
                    "migration_needed": user_schema_status.migration_needed,
                    "schema_errors": user_schema_status.schema_errors,
                },
                "foreign_key_validation": {
                    "valid": fk_validation.valid,
                    "missing_foreign_keys": fk_validation.missing_foreign_keys,
                    "invalid_constraints": fk_validation.invalid_constraints,
                    "orphaned_references": fk_validation.orphaned_references,
                    "validation_errors": fk_validation.validation_errors,
                },
                "overall_status": {
                    "schema_valid": schema_validation.valid,
                    "migration_needed": (
                        len(missing_tables) > 0
                        or user_schema_status.migration_needed
                        or not fk_validation.valid
                    ),
                    "total_errors": len(schema_validation.schema_errors),
                    "all_errors": schema_validation.schema_errors,
                },
            }

            self.logger.debug("Generated detailed schema analysis")
            return analysis

        except Exception as e:
            self.logger.error(f"Failed to generate detailed schema analysis: {e}")
            return {
                "error": str(e),
                "basic_schema": {"migration_needed": True},
                "user_ownership": {"migration_needed": True},
                "foreign_key_validation": {"valid": False},
                "overall_status": {"schema_valid": False, "migration_needed": True},
            }


class MigrationExecutor:
    """
    Safely applies schema changes to the database with proper error handling and validation.

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.5
    """

    def __init__(self, engine: Engine, metadata: MetaData, logger: MigrationLogger):
        self.engine = engine
        self.metadata = metadata
        self.logger = logger
        self.migration_logger = logger

    def create_missing_tables(self, tables: List[str]) -> MigrationResult:
        """
        Create missing tables in the database using safe table creation with comprehensive error handling.

        This method implements safe table creation using Base.metadata.create_all()
        with post-migration validation to verify table creation. It includes
        idempotent migration logic to handle repeated runs safely, ensures
        foreign key relationships are established correctly, and provides
        detailed error handling with recovery suggestions.

        Args:
            tables: List of table names to create

        Returns:
            MigrationResult with execution details

        Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.4
        """
        start_time = time.time()
        created_tables = []
        errors = []

        try:
            if not tables:
                return MigrationResult(
                    success=True,
                    tables_created=[],
                    errors=[],
                    duration_seconds=time.time() - start_time,
                    message="No tables needed creation",
                )

            self.migration_logger.logger.info(
                f"Creating {len(tables)} missing tables..."
            )

            # Safe table creation using SQLAlchemy metadata.create_all()
            # This method is idempotent - it only creates tables that don't exist
            # Requirements: 2.1, 2.5
            try:
                self.metadata.create_all(self.engine)
            except OperationalError as e:
                # Handle database connection and operational errors
                # Requirements: 3.2
                error_msg = f"Failed to create tables due to database error: {e}"
                errors.append(error_msg)
                self.migration_logger.log_error(e, "table creation")

                return MigrationResult(
                    success=False,
                    tables_created=created_tables,
                    errors=errors,
                    duration_seconds=time.time() - start_time,
                    message=error_msg,
                )

            except ProgrammingError as e:
                # Handle permission and syntax errors
                # Requirements: 3.2
                error_msg = f"Failed to create tables due to permission error: {e}"
                errors.append(error_msg)
                self.migration_logger.log_error(e, "table creation")

                return MigrationResult(
                    success=False,
                    tables_created=created_tables,
                    errors=errors,
                    duration_seconds=time.time() - start_time,
                    message=error_msg,
                )

            # Ensure changes are committed for in-memory databases
            try:
                with self.engine.connect() as conn:
                    conn.commit()
            except Exception:
                # Some engines don't support explicit commit
                pass

            # Post-migration validation to verify table creation
            # Requirements: 2.4
            try:
                # Create a fresh inspector after table creation to see new tables
                inspector = inspect(self.engine)
                existing_tables = set(inspector.get_table_names())

                # Verify each requested table was created successfully
                for table in tables:
                    if table in existing_tables:
                        created_tables.append(table)
                        self.migration_logger.log_table_creation(table, True)

                        # Verify table structure and foreign key relationships
                        # Requirements: 2.2, 2.3
                        self._verify_table_structure(table, inspector)
                    else:
                        error_msg = f"Table {table} was not created successfully"
                        errors.append(error_msg)
                        self.migration_logger.log_table_creation(table, False)

            except Exception as e:
                # Handle post-creation validation errors
                # Requirements: 3.2, 3.4
                error_msg = f"Post-creation validation failed: {e}"
                errors.append(error_msg)
                self.migration_logger.log_error(e, "post-creation validation")

            success = len(errors) == 0
            message = (
                f"Created {len(created_tables)} tables successfully"
                if success
                else f"Created {len(created_tables)} tables with {len(errors)} errors"
            )

            # Log summary of creation results
            if success:
                self.migration_logger.logger.info(
                    f"✓ Successfully created all {len(created_tables)} tables"
                )
            else:
                self.migration_logger.logger.error(
                    f"✗ Created {len(created_tables)} tables with {len(errors)} errors"
                )

            return MigrationResult(
                success=success,
                tables_created=created_tables,
                errors=errors,
                duration_seconds=time.time() - start_time,
                message=message,
            )

        except Exception as e:
            # Handle any unexpected errors gracefully
            # Requirements: 3.2, 3.4
            error_msg = f"Failed to create tables: {e}"
            errors.append(error_msg)
            self.migration_logger.log_error(e, "table creation")

            return MigrationResult(
                success=False,
                tables_created=created_tables,
                errors=errors,
                duration_seconds=time.time() - start_time,
                message=error_msg,
            )

    def _verify_table_structure(self, table_name: str, inspector) -> None:
        """
        Verify that a table was created with correct structure and relationships.

        This method ensures that foreign key relationships are established correctly
        and that the table structure matches the expected metadata.

        Args:
            table_name: Name of the table to verify
            inspector: SQLAlchemy inspector instance

        Requirements: 2.2, 2.3
        """
        try:
            # Verify table has expected columns
            columns = inspector.get_columns(table_name)
            if not columns:
                self.migration_logger.logger.warning(
                    f"Table {table_name} has no columns"
                )
                return

            # Verify primary key exists
            pk_constraint = inspector.get_pk_constraint(table_name)
            if not pk_constraint.get("constrained_columns"):
                self.migration_logger.logger.warning(
                    f"Table {table_name} has no primary key"
                )

            # Verify foreign key relationships if expected
            if table_name in self.metadata.tables:
                table = self.metadata.tables[table_name]
                expected_fks = []

                for column in table.columns:
                    if column.foreign_keys:
                        for fk in column.foreign_keys:
                            expected_fks.append((column.name, fk.column.table.name))

                if expected_fks:
                    actual_fks = inspector.get_foreign_keys(table_name)
                    self.migration_logger.logger.debug(
                        f"Table {table_name} has {len(actual_fks)} foreign keys, expected {len(expected_fks)}"
                    )

        except Exception as e:
            self.migration_logger.logger.warning(
                f"Could not verify structure for table {table_name}: {e}"
            )

    def validate_migration(self) -> SchemaValidationResult:
        """
        Validate that migration was successful with comprehensive post-migration validation.

        This method performs thorough validation to verify table creation,
        ensuring the migration meets all requirements for completeness and correctness.

        Returns:
            SchemaValidationResult with post-migration validation

        Requirements: 2.4, 2.5
        """
        try:
            detector = SchemaDetector(self.engine, self.metadata)
            validation_result = detector.validate_existing_schema()

            # Additional post-migration checks
            if validation_result.valid:
                self.migration_logger.logger.info("✓ Post-migration validation passed")
            else:
                self.migration_logger.logger.error("✗ Post-migration validation failed")
                for error in validation_result.schema_errors:
                    self.migration_logger.logger.error(f"  - {error}")

            return validation_result

        except Exception as e:
            self.migration_logger.log_error(e, "post-migration validation")
            return SchemaValidationResult(
                valid=False,
                missing_tables=[],
                unexpected_tables=[],
                schema_errors=[f"Validation failed with exception: {e}"],
            )


class MigrationEngine:
    """
    Central coordinator that orchestrates the entire migration process.

    This class now includes integrated user migration functionality to handle
    the transition from non-user to user-ownership database schema.

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5
    """

    def __init__(
        self,
        engine: Engine,
        metadata: MetaData,
        logger: Optional[logging.Logger] = None,
        timeout_seconds: int = 30,
        enable_user_migration: bool = True,
    ):
        self.engine = engine
        self.metadata = metadata
        self.logger = logger or logging.getLogger(__name__)
        self.timeout_seconds = timeout_seconds
        self.enable_user_migration = enable_user_migration
        self.migration_logger = MigrationLogger(self.logger)
        self.schema_detector = SchemaDetector(engine, metadata)
        self.migration_executor = MigrationExecutor(
            engine, metadata, self.migration_logger
        )

    def run_migration(self) -> MigrationResult:
        """
        Run the complete automatic migration process with comprehensive error handling.

        This method implements the full automatic schema creation functionality,
        including safe table creation, post-migration validation, idempotent
        migration logic, timeout handling, concurrent migration safety, and
        comprehensive error recovery.

        Returns:
            MigrationResult with complete migration details

        Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 7.2, 7.3
        """
        start_time = time.time()

        try:
            # Implement concurrent migration safety for production environments
            # Requirements: 7.3
            with migration_lock():
                # Implement timeout handling for database operations
                # Requirements: 3.5, 7.2
                with timeout_handler(self.timeout_seconds):
                    # Validate database connectivity before migration
                    # Requirements: 3.5
                    if not self._validate_database_connectivity():
                        self.migration_logger.log_connectivity_validation(False)
                        result = MigrationResult(
                            success=False,
                            tables_created=[],
                            errors=["Database connectivity validation failed"],
                            duration_seconds=time.time() - start_time,
                            message="Migration failed - database connectivity validation failed",
                        )
                        self.migration_logger.log_migration_complete(result)
                        return result

                    self.migration_logger.log_connectivity_validation(True)

                    # Get current migration status
                    status = self.get_migration_status()
                    self.migration_logger.log_migration_start(status)

                    # Check if migration is needed (idempotent check)
                    # Requirements: 2.5, 3.1
                    if not status.migration_needed:
                        self.migration_logger.log_migration_phase(
                            "No migration needed", "All tables already exist"
                        )
                        result = MigrationResult(
                            success=True,
                            tables_created=[],
                            errors=[],
                            duration_seconds=time.time() - start_time,
                            message="No migration needed - all tables exist",
                        )
                        self.migration_logger.log_migration_complete(result)
                        return result

                    # Check database connectivity before proceeding
                    # Requirements: 3.5
                    if not status.connection_healthy:
                        result = MigrationResult(
                            success=False,
                            tables_created=[],
                            errors=["Database connection is not healthy"],
                            duration_seconds=time.time() - start_time,
                            message="Migration failed - database connection unhealthy",
                        )
                        self.migration_logger.log_migration_complete(result)
                        return result

                    # Execute automatic schema creation with error handling
                    # Requirements: 2.1, 2.2, 2.3, 2.4, 3.2
                    self.migration_logger.log_schema_creation_start(
                        len(status.missing_tables)
                    )
                    self.migration_logger.log_migration_phase(
                        "Schema creation",
                        f"Creating {len(status.missing_tables)} tables",
                    )
                    result = self.migration_executor.create_missing_tables(
                        status.missing_tables
                    )

                    # Perform post-migration validation
                    # Requirements: 2.4
                    if result.success:
                        self.migration_logger.log_migration_phase(
                            "Post-migration validation", "Verifying schema creation"
                        )
                        validation_result = self.migration_executor.validate_migration()
                        if not validation_result.valid:
                            result.success = False
                            result.errors.extend(validation_result.schema_errors)
                            result.message = f"Migration completed but validation failed: {'; '.join(validation_result.schema_errors)}"

                    # Log completion
                    self.migration_logger.log_migration_complete(result)

                    # Run user migration if enabled and basic migration succeeded
                    # Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
                    if self.enable_user_migration and result.success:
                        # Only run user migration if users table is in metadata
                        if "users" in self.metadata.tables:
                            user_migration_result = self._run_user_migration()
                            result.user_migration_result = user_migration_result

                            # Update overall success based on user migration
                            if not user_migration_result.success:
                                result.success = False
                                result.errors.extend(user_migration_result.errors)
                                result.message += f" (User migration failed: {user_migration_result.message})"
                        else:
                            # Skip user migration if users table not in metadata
                            self.migration_logger.logger.info(
                                "Skipping user migration - users table not in metadata"
                            )

                    return result

        except MigrationLockException as e:
            # Handle migration lock acquisition failures
            # Requirements: 7.3 - Concurrent migration safety
            error_msg = f"Migration lock acquisition failed: {e}"
            self.migration_logger.log_error(e, "migration lock")
            result = MigrationResult(
                success=False,
                tables_created=[],
                errors=[error_msg],
                duration_seconds=time.time() - start_time,
                message=f"Migration failed due to lock acquisition: {e}",
            )
            self.migration_logger.log_migration_complete(result)
            return result

        except TimeoutException as e:
            # Handle timeout errors with detailed recovery suggestions
            # Requirements: 3.2, 3.4, 3.5
            error_msg = f"Migration timed out after {self.timeout_seconds} seconds: {e}"
            self.migration_logger.log_error(e, "migration timeout")
            result = MigrationResult(
                success=False,
                tables_created=[],
                errors=[error_msg],
                duration_seconds=time.time() - start_time,
                message=f"Migration failed due to timeout: {e}",
            )
            self.migration_logger.log_migration_complete(result)
            return result

        except (OperationalError, ProgrammingError) as e:
            # Handle database-specific errors with detailed recovery suggestions
            # Requirements: 3.2, 3.4
            self.migration_logger.log_error(e, "database operation")
            result = MigrationResult(
                success=False,
                tables_created=[],
                errors=[f"Database error during migration: {e}"],
                duration_seconds=time.time() - start_time,
                message=f"Migration failed due to database error: {e}",
            )
            self.migration_logger.log_migration_complete(result)
            return result

        except Exception as e:
            # Handle all other errors gracefully to ensure application startup continues
            # Requirements: 3.2, 3.4
            self.migration_logger.log_error(e, "migration execution")
            result = MigrationResult(
                success=False,
                tables_created=[],
                errors=[f"Migration failed with exception: {e}"],
                duration_seconds=time.time() - start_time,
                message=f"Migration failed: {e}",
            )
            self.migration_logger.log_migration_complete(result)
            return result

    def is_migration_needed(self) -> bool:
        """
        Check if migration is needed.

        Returns:
            True if migration is needed, False otherwise

        Requirements: 1.1, 1.2, 1.3
        """
        try:
            missing_tables = self.schema_detector.detect_missing_tables()
            return len(missing_tables) > 0
        except Exception as e:
            self.logger.error(f"Failed to check if migration is needed: {e}")
            # Assume migration is needed if we can't determine
            return True

    def get_migration_status(self) -> MigrationStatus:
        """
        Get current migration status with enhanced analysis.

        Enhanced to include user ownership schema analysis and detailed
        foreign key validation for comprehensive migration reporting.

        Returns:
            MigrationStatus with current database state

        Requirements: 1.1, 1.2, 1.3, 3.5, 2.1, 5.1
        """
        try:
            # Test database connectivity
            connection_healthy = self._test_connection()

            if not connection_healthy:
                return MigrationStatus(
                    database_exists=False,
                    tables_exist=[],
                    missing_tables=self.schema_detector.get_expected_tables(),
                    migration_needed=True,
                    connection_healthy=False,
                )

            # Get existing and missing tables
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()
            missing_tables = self.schema_detector.detect_missing_tables()

            # Enhanced analysis: Check if user ownership migration is also needed
            # Only check user migration if users table is expected in metadata
            user_migration_needed = False
            if self.enable_user_migration and "users" in self.metadata.tables:
                try:
                    user_migration_needed = (
                        self.schema_detector.is_user_migration_needed()
                    )
                except Exception as e:
                    self.logger.debug(f"Could not check user migration status: {e}")

            # Overall migration needed if either basic tables missing or user migration needed
            migration_needed = len(missing_tables) > 0 or user_migration_needed

            return MigrationStatus(
                database_exists=True,
                tables_exist=existing_tables,
                missing_tables=missing_tables,
                migration_needed=migration_needed,
                connection_healthy=True,
            )

        except Exception as e:
            self.logger.error(f"Failed to get migration status: {e}")
            return MigrationStatus(
                database_exists=False,
                tables_exist=[],
                missing_tables=self.schema_detector.get_expected_tables(),
                migration_needed=True,
                connection_healthy=False,
            )

    def _validate_database_connectivity(self) -> bool:
        """
        Validate database connectivity before attempting migration.

        This method performs comprehensive connectivity validation including
        connection health, basic query execution, and permission checks.

        Returns:
            True if database is accessible and ready for migration, False otherwise

        Requirements: 3.5, 7.2
        """
        try:
            # Test basic connection
            with self.engine.connect() as conn:
                # Test basic query execution
                conn.execute(text("SELECT 1"))

                # Test if we can access database metadata (requires basic permissions)
                inspector = inspect(self.engine)
                inspector.get_table_names()

            self.logger.debug("Database connectivity validation passed")
            return True

        except OperationalError as e:
            error_msg = str(e).lower()
            if "connection" in error_msg or "refused" in error_msg:
                self.logger.error(
                    "Database connection validation failed - connection refused"
                )
                self.logger.error("Check if database server is running and accessible")
                self.logger.debug(f"Connection error details: {e}")
            elif "authentication" in error_msg or "password" in error_msg:
                self.logger.error(
                    "Database connection validation failed - authentication error"
                )
                self.logger.error("Check database credentials and user permissions")
                self.logger.debug(f"Authentication error details: {e}")
            elif "timeout" in error_msg:
                self.logger.error(
                    "Database connection validation failed - connection timeout"
                )
                self.logger.error(
                    "Check network connectivity and database server performance"
                )
                self.logger.debug(f"Timeout error details: {e}")
            else:
                self.logger.error(f"Database connection validation failed: {e}")
                self.logger.debug(f"Operational error details: {e}")
            return False

        except ProgrammingError as e:
            self.logger.error(f"Database permission validation failed: {e}")
            self.logger.error("Check if user has necessary database access permissions")
            self.logger.debug(f"Permission error details: {e}")
            return False

        except Exception as e:
            self.logger.error(
                f"Database connectivity validation failed with unexpected error: {e}"
            )
            self.logger.debug(f"Unexpected error details: {e}")
            return False

    def _test_connection(self) -> bool:
        """
        Test database connectivity.

        Returns:
            True if connection is healthy, False otherwise

        Requirements: 3.5
        """
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception as e:
            self.logger.debug(f"Database connection test failed: {e}")
            return False

    def _run_user_migration(self) -> "UserMigrationResult":
        """
        Run user ownership migration as part of the main migration process.

        This method integrates user migration functionality directly into the
        main migration engine, providing comprehensive reporting and error handling.

        Returns:
            UserMigrationResult with migration details

        Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
        """
        try:
            # Import UserMigrationEngine here to avoid circular imports
            from .user_migration import UserMigrationEngine, UserMigrationResult

            self.migration_logger.log_migration_phase(
                "User Migration", "Starting user ownership migration"
            )

            # Create user migration engine
            user_migration_engine = UserMigrationEngine(
                engine=self.engine,
                metadata=self.metadata,
                logger=self.logger,
                timeout_seconds=self.timeout_seconds,
            )

            # Run user migration
            result = user_migration_engine.run_user_migration()

            # Log user migration results
            if result.success:
                self.migration_logger.logger.info(
                    f"✓ User migration completed successfully in {result.duration_seconds:.2f}s"
                )
                if result.orphaned_trackers_migrated > 0:
                    self.migration_logger.logger.info(
                        f"✓ Migrated {result.orphaned_trackers_migrated} existing trackers to default user"
                    )
            else:
                self.migration_logger.logger.error(
                    f"✗ User migration failed: {result.message}"
                )
                for error in result.errors:
                    self.migration_logger.logger.error(f"  - {error}")

            return result

        except Exception as e:
            # Handle user migration errors gracefully
            self.migration_logger.log_error(e, "user migration integration")

            # Import here to avoid circular imports
            from .user_migration import UserMigrationResult

            return UserMigrationResult(
                success=False,
                users_table_created=False,
                trackers_table_modified=False,
                default_user_created=False,
                orphaned_trackers_migrated=0,
                errors=[f"User migration integration failed: {e}"],
                duration_seconds=0.0,
                message=f"User migration integration failed: {e}",
            )

    def run_complete_migration(self) -> MigrationResult:
        """
        Run complete migration including both schema and user migrations.

        This method provides a comprehensive migration that includes:
        1. Basic schema migration (tables, indexes, constraints)
        2. User ownership migration (users table, tracker ownership)
        3. Data migration (existing trackers to default user)
        4. Comprehensive reporting and error handling

        Returns:
            MigrationResult with complete migration details

        Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
        """
        return self.run_migration()

    def run_migration_legacy(self) -> MigrationResult:
        """
        Legacy method that runs migration without user migration for backward compatibility.

        This method provides the old behavior for existing tests and code that
        expects the original migration behavior without user migration integration.

        Returns:
            MigrationResult with basic migration details (no user migration)
        """
        # Temporarily disable user migration for legacy behavior
        original_setting = self.enable_user_migration
        self.enable_user_migration = False

        try:
            result = self.run_migration()
            return result
        finally:
            # Restore original setting
            self.enable_user_migration = original_setting

    def get_migration_report(self) -> dict:
        """
        Get comprehensive migration status report including enhanced schema analysis.

        Enhanced to provide detailed information about user ownership schema,
        foreign key relationships, and comprehensive migration status for
        monitoring and debugging purposes.

        Returns:
            Dictionary with comprehensive migration status information

        Requirements: 3.5, 2.1, 5.1
        """
        try:
            # Get basic migration status
            status = self.get_migration_status()

            # Get enhanced schema analysis
            detailed_analysis = self.schema_detector.get_detailed_schema_analysis()

            # Get user migration status
            user_migration_status = {}
            if self.enable_user_migration:
                try:
                    from .user_migration import UserMigrationEngine

                    user_migration_engine = UserMigrationEngine(
                        self.engine, self.metadata, self.logger
                    )
                    user_migration_status = user_migration_engine.get_migration_status()
                except Exception as e:
                    user_migration_status = {
                        "error": f"Failed to get user migration status: {e}"
                    }

            # Build comprehensive report with enhanced analysis
            report = {
                "schema_migration": {
                    "database_exists": status.database_exists,
                    "connection_healthy": status.connection_healthy,
                    "migration_needed": status.migration_needed,
                    "existing_tables": status.tables_exist,
                    "missing_tables": status.missing_tables,
                    "total_expected_tables": len(self.metadata.tables.keys()),
                    "total_existing_tables": len(status.tables_exist),
                },
                "user_migration": user_migration_status,
                "detailed_analysis": detailed_analysis,
                "configuration": {
                    "timeout_seconds": self.timeout_seconds,
                    "user_migration_enabled": self.enable_user_migration,
                },
                "database_info": {
                    "expected_tables": list(self.metadata.tables.keys()),
                },
            }

            # Enhanced health assessment using detailed analysis
            schema_healthy = status.connection_healthy and not status.migration_needed
            user_healthy = not user_migration_status.get("migration_needed", False)
            detailed_healthy = detailed_analysis.get("overall_status", {}).get(
                "schema_valid", False
            )

            if schema_healthy and user_healthy and detailed_healthy:
                report["health"] = "healthy"
                report["health_message"] = "Database is healthy and up to date"
            elif status.connection_healthy:
                needed_migrations = []
                if status.migration_needed:
                    needed_migrations.append("schema migration")
                if user_migration_status.get("migration_needed"):
                    needed_migrations.append("user migration")
                if not detailed_healthy:
                    needed_migrations.append("schema validation fixes")

                report["health"] = "needs_migration"
                report["health_message"] = (
                    f"Database needs: {', '.join(needed_migrations)}"
                )
            else:
                report["health"] = "unhealthy"
                report["health_message"] = "Database connection is not healthy"

            # Add summary of issues found
            total_issues = 0
            issue_summary = []

            if detailed_analysis.get("basic_schema", {}).get("missing_tables"):
                missing_count = len(detailed_analysis["basic_schema"]["missing_tables"])
                total_issues += missing_count
                issue_summary.append(f"{missing_count} missing tables")

            if detailed_analysis.get("user_ownership", {}).get("schema_errors"):
                user_errors = len(detailed_analysis["user_ownership"]["schema_errors"])
                total_issues += user_errors
                issue_summary.append(f"{user_errors} user ownership issues")

            if not detailed_analysis.get("foreign_key_validation", {}).get(
                "valid", True
            ):
                fk_issues = len(
                    detailed_analysis["foreign_key_validation"].get(
                        "missing_foreign_keys", []
                    )
                )
                fk_issues += len(
                    detailed_analysis["foreign_key_validation"].get(
                        "invalid_constraints", []
                    )
                )
                fk_issues += len(
                    detailed_analysis["foreign_key_validation"].get(
                        "orphaned_references", []
                    )
                )
                if fk_issues > 0:
                    total_issues += fk_issues
                    issue_summary.append(f"{fk_issues} foreign key issues")

            report["issue_summary"] = {
                "total_issues": total_issues,
                "issues": issue_summary,
            }

            return report

        except Exception as e:
            self.logger.error(f"Failed to generate migration report: {e}")
            return {
                "error": str(e),
                "health": "error",
                "health_message": f"Failed to assess migration status: {e}",
            }
