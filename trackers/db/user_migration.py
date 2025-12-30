"""
User Migration System for User Ownership Feature.

This module provides migration functionality to add user support to the existing
tracker database schema. It handles creating the users table, modifying the
trackers table to include user ownership, and migrating existing data with
comprehensive backup and safety features.

Requirements: 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 7.1, 7.2, 7.3
"""

import logging
import time
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy import Engine, MetaData, inspect, text

from .migration import MigrationLogger, migration_lock, timeout_handler


@dataclass
class BackupResult:
    """
    Represents the outcome of a data backup operation.

    Requirements: 2.2, 3.1
    """

    success: bool
    backup_file_path: Optional[str]
    records_backed_up: int
    errors: List[str]
    message: str


@dataclass
class UserMigrationResult:
    """
    Represents the outcome of a user migration operation.

    Requirements: 2.2, 2.3, 2.4, 2.5, 3.2, 3.3, 7.3
    """

    success: bool
    users_table_created: bool
    trackers_table_modified: bool
    default_user_created: bool
    orphaned_trackers_migrated: int
    backup_result: Optional[BackupResult]
    errors: List[str]
    duration_seconds: float
    message: str


class UserMigrationEngine:
    """
    Handles migration from non-user to user-ownership database schema with comprehensive
    backup and safety features.

    This class provides functionality to:
    1. Create backup of existing tracker data before migration
    2. Create the users table
    3. Add user_id column to trackers table with proper constraints
    4. Create a default user for existing trackers
    5. Migrate existing trackers to default user with atomic operations
    6. Update constraints and indexes safely

    Requirements: 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 7.1, 7.2, 7.3
    """

    def __init__(
        self,
        engine: Engine,
        metadata: MetaData,
        logger: Optional[logging.Logger] = None,
        timeout_seconds: int = 60,
        backup_directory: Optional[str] = None,
    ):
        self.engine = engine
        self.metadata = metadata
        self.logger = logger or logging.getLogger(__name__)
        self.timeout_seconds = timeout_seconds
        self.backup_directory = backup_directory or tempfile.gettempdir()
        self.migration_logger = MigrationLogger(self.logger)

    def run_user_migration(self) -> UserMigrationResult:
        """
        Run the complete user ownership migration process with comprehensive backup and safety features.

        This method implements the full migration from a non-user database
        to a user-ownership database, including safe schema modifications,
        data preservation with backup, and comprehensive error handling.

        Returns:
            UserMigrationResult with complete migration details

        Requirements: 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 7.1, 7.2, 7.3
        """
        start_time = time.time()
        result = UserMigrationResult(
            success=False,
            users_table_created=False,
            trackers_table_modified=False,
            default_user_created=False,
            orphaned_trackers_migrated=0,
            backup_result=None,
            errors=[],
            duration_seconds=0,
            message="",
        )

        try:
            # Implement concurrent migration safety
            # Requirements: 7.3
            with migration_lock():
                # Implement timeout handling
                # Requirements: 7.2
                with timeout_handler(self.timeout_seconds):
                    self.migration_logger.logger.info("=" * 60)
                    self.migration_logger.logger.info(
                        "STARTING SAFE USER OWNERSHIP MIGRATION"
                    )
                    self.migration_logger.logger.info("=" * 60)

                    # Check if migration is needed
                    if not self._is_user_migration_needed():
                        result.success = True
                        result.message = (
                            "User migration not needed - users table already exists"
                        )
                        self.migration_logger.logger.info(result.message)
                        return result

                    # Step 1: Create backup of existing tracker data
                    # Requirements: 2.2, 3.1
                    self.migration_logger.logger.info(
                        "Step 1: Creating backup of existing tracker data..."
                    )
                    backup_result = self.backup_tracker_data()
                    result.backup_result = backup_result

                    if backup_result.success:
                        self.migration_logger.logger.info(
                            f"✓ Backup created successfully: {backup_result.records_backed_up} records backed up"
                        )
                        if backup_result.backup_file_path:
                            self.migration_logger.logger.info(
                                f"✓ Backup file: {backup_result.backup_file_path}"
                            )
                    else:
                        error_msg = f"Failed to create backup: {backup_result.message}"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")
                        # Continue with migration even if backup fails, but log the risk
                        self.migration_logger.logger.warning(
                            "⚠ Continuing migration without backup - data loss risk exists"
                        )

                    # Step 2: Create users table
                    # Requirements: 3.1
                    self.migration_logger.logger.info("Step 2: Creating users table...")
                    if self._create_users_table():
                        result.users_table_created = True
                        self.migration_logger.logger.info(
                            "✓ Users table created successfully"
                        )
                    else:
                        error_msg = "Failed to create users table"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 3: Create default user for existing trackers
                    # Requirements: 2.4, 3.3, 7.1
                    self.migration_logger.logger.info(
                        "Step 3: Creating default user..."
                    )
                    default_user_id = self._create_default_user()
                    if default_user_id:
                        result.default_user_created = True
                        self.migration_logger.logger.info(
                            f"✓ Default user created with ID: {default_user_id}"
                        )
                    else:
                        error_msg = "Failed to create default user"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 4: Safely modify trackers table to add user_id column
                    # Requirements: 2.3, 3.2
                    self.migration_logger.logger.info(
                        "Step 4: Safely modifying trackers table..."
                    )
                    if self._safe_modify_trackers_table(default_user_id):
                        result.trackers_table_modified = True
                        self.migration_logger.logger.info(
                            "✓ Trackers table modified safely"
                        )
                    else:
                        error_msg = "Failed to safely modify trackers table"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 5: Migrate existing trackers to default user with atomic operations
                    # Requirements: 2.5, 7.1, 7.3
                    self.migration_logger.logger.info(
                        "Step 5: Migrating existing trackers with atomic operations..."
                    )
                    migrated_count = self._atomic_migrate_orphaned_trackers(
                        default_user_id
                    )
                    result.orphaned_trackers_migrated = migrated_count
                    if migrated_count >= 0:
                        self.migration_logger.logger.info(
                            f"✓ Atomically migrated {migrated_count} existing trackers"
                        )
                    else:
                        error_msg = "Failed to migrate existing trackers"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 6: Update constraints and indexes safely
                    # Requirements: 2.3, 3.2
                    self.migration_logger.logger.info(
                        "Step 6: Updating constraints and indexes safely..."
                    )
                    if self._safe_update_constraints_and_indexes():
                        self.migration_logger.logger.info(
                            "✓ Constraints and indexes updated safely"
                        )
                    else:
                        error_msg = "Failed to update constraints and indexes safely"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 7: Validate data integrity after migration
                    # Requirements: 2.4, 3.5
                    self.migration_logger.logger.info(
                        "Step 7: Validating data integrity..."
                    )
                    if self._validate_data_integrity():
                        self.migration_logger.logger.info(
                            "✓ Data integrity validation passed"
                        )
                    else:
                        error_msg = "Data integrity validation failed"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Determine overall success
                    result.success = len(result.errors) == 0
                    result.duration_seconds = time.time() - start_time

                    if result.success:
                        result.message = f"Safe user migration completed successfully in {result.duration_seconds:.2f}s"
                        self.migration_logger.logger.info("=" * 60)
                        self.migration_logger.logger.info(
                            "SAFE USER MIGRATION COMPLETED SUCCESSFULLY"
                        )
                        self.migration_logger.logger.info("=" * 60)
                    else:
                        result.message = f"Safe user migration completed with {len(result.errors)} errors"
                        self.migration_logger.logger.error("=" * 60)
                        self.migration_logger.logger.error(
                            "SAFE USER MIGRATION COMPLETED WITH ERRORS"
                        )
                        self.migration_logger.logger.error("=" * 60)
                        for error in result.errors:
                            self.migration_logger.logger.error(f"  - {error}")

                    return result

        except Exception as e:
            # Handle any unexpected errors gracefully
            # Requirements: 3.4, 3.5
            error_msg = f"Safe user migration failed with exception: {e}"
            result.errors.append(error_msg)
            result.duration_seconds = time.time() - start_time
            result.message = error_msg
            self.migration_logger.log_error(e, "safe user migration")
            return result

    def backup_tracker_data(self) -> BackupResult:
        """
        Create a backup of existing tracker data before migration.

        This method creates a comprehensive backup of all tracker data including
        related items, logs, and tracker values to ensure data can be recovered
        if migration fails.

        Returns:
            BackupResult with backup operation details

        Requirements: 2.2, 3.1
        """
        try:
            # Check if trackers table exists
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()

            if "trackers" not in existing_tables:
                return BackupResult(
                    success=True,
                    backup_file_path=None,
                    records_backed_up=0,
                    errors=[],
                    message="No trackers table found - backup not needed",
                )

            # Create backup file with timestamp
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            backup_filename = f"tracker_backup_{timestamp}.json"
            backup_file_path = os.path.join(self.backup_directory, backup_filename)

            backup_data = {
                "backup_timestamp": timestamp,
                "backup_version": "1.0",
                "tables": {},
            }
            total_records = 0

            with self.engine.connect() as conn:
                # Backup trackers table
                result = conn.execute(text("SELECT * FROM trackers"))
                trackers = [dict(row._mapping) for row in result]
                backup_data["tables"]["trackers"] = trackers
                total_records += len(trackers)
                self.logger.info(f"Backed up {len(trackers)} tracker records")

                # Backup related tables if they exist
                related_tables = ["items", "logs", "tracker_values"]
                for table_name in related_tables:
                    if table_name in existing_tables:
                        try:
                            result = conn.execute(text(f"SELECT * FROM {table_name}"))
                            records = [dict(row._mapping) for row in result]
                            backup_data["tables"][table_name] = records
                            total_records += len(records)
                            self.logger.info(
                                f"Backed up {len(records)} {table_name} records"
                            )
                        except Exception as e:
                            self.logger.warning(f"Could not backup {table_name}: {e}")

            # Write backup to file
            os.makedirs(self.backup_directory, exist_ok=True)
            with open(backup_file_path, "w") as f:
                json.dump(backup_data, f, indent=2, default=str)

            self.logger.info(
                f"Backup completed: {total_records} total records saved to {backup_file_path}"
            )

            return BackupResult(
                success=True,
                backup_file_path=backup_file_path,
                records_backed_up=total_records,
                errors=[],
                message=f"Successfully backed up {total_records} records to {backup_file_path}",
            )

        except Exception as e:
            error_msg = f"Failed to create backup: {e}"
            self.migration_logger.log_error(e, "tracker data backup")
            return BackupResult(
                success=False,
                backup_file_path=None,
                records_backed_up=0,
                errors=[error_msg],
                message=error_msg,
            )

    def _safe_modify_trackers_table(self, default_user_id: Optional[int]) -> bool:
        """
        Safely modify trackers table to add user_id column with proper constraints.

        This method implements safe schema modification with proper error handling,
        rollback capabilities, and data integrity checks.

        Args:
            default_user_id: ID of default user to assign to existing trackers

        Returns:
            True if successful, False otherwise

        Requirements: 2.3, 3.2
        """
        try:
            with self.engine.connect() as conn:
                # Start a transaction for atomic operations
                trans = conn.begin()

                try:
                    # Check current table structure
                    inspector = inspect(self.engine)
                    columns = inspector.get_columns("trackers")
                    column_names = [col["name"] for col in columns]

                    # Add user_id column if it doesn't exist
                    if "user_id" not in column_names:
                        self.logger.info("Adding user_id column to trackers table...")
                        conn.execute(
                            text("ALTER TABLE trackers ADD COLUMN user_id INTEGER")
                        )
                        self.logger.info("✓ Added user_id column")

                    # Add timestamp columns if they don't exist
                    if "created_at" not in column_names:
                        self.logger.info(
                            "Adding created_at column to trackers table..."
                        )
                        conn.execute(
                            text(
                                "ALTER TABLE trackers ADD COLUMN created_at TIMESTAMP DEFAULT NOW()"
                            )
                        )
                        self.logger.info("✓ Added created_at column")

                    if "updated_at" not in column_names:
                        self.logger.info(
                            "Adding updated_at column to trackers table..."
                        )
                        conn.execute(
                            text(
                                "ALTER TABLE trackers ADD COLUMN updated_at TIMESTAMP DEFAULT NOW()"
                            )
                        )
                        self.logger.info("✓ Added updated_at column")

                    # Set default user_id for existing trackers if provided
                    if default_user_id:
                        self.logger.info(
                            "Setting default user_id for existing trackers..."
                        )
                        result = conn.execute(
                            text(
                                "UPDATE trackers SET user_id = :user_id WHERE user_id IS NULL"
                            ),
                            {"user_id": default_user_id},
                        )
                        updated_count = result.rowcount
                        self.logger.info(
                            f"✓ Set default user_id for {updated_count} existing trackers"
                        )

                    # Commit the transaction
                    trans.commit()
                    self.logger.info(
                        "✓ Trackers table modification committed successfully"
                    )
                    return True

                except Exception as e:
                    # Rollback on any error
                    trans.rollback()
                    self.logger.error(
                        f"Rolling back trackers table modification due to error: {e}"
                    )
                    raise e

        except Exception as e:
            self.migration_logger.log_error(e, "safe trackers table modification")
            return False

    def _atomic_migrate_orphaned_trackers(self, default_user_id: Optional[int]) -> int:
        """
        Atomically migrate existing trackers without user ownership to default user.

        This method ensures atomic operations where all tracker migrations succeed
        or all fail together, preventing partial migration states.

        Args:
            default_user_id: ID of default user to assign orphaned trackers to

        Returns:
            Number of trackers migrated, or -1 if failed

        Requirements: 2.5, 7.1, 7.3
        """
        try:
            if not default_user_id:
                self.logger.warning(
                    "No default user ID provided for orphaned tracker migration"
                )
                return 0

            with self.engine.connect() as conn:
                # Start atomic transaction
                trans = conn.begin()

                try:
                    # Count orphaned trackers first
                    result = conn.execute(
                        text("SELECT COUNT(*) FROM trackers WHERE user_id IS NULL")
                    )
                    orphaned_count = result.scalar()

                    if orphaned_count == 0:
                        trans.commit()
                        self.logger.info("No orphaned trackers found")
                        return 0

                    self.logger.info(
                        f"Found {orphaned_count} orphaned trackers to migrate"
                    )

                    # Verify default user exists before migration
                    result = conn.execute(
                        text("SELECT COUNT(*) FROM users WHERE id = :user_id"),
                        {"user_id": default_user_id},
                    )
                    user_exists = result.scalar() > 0

                    if not user_exists:
                        trans.rollback()
                        self.logger.error(
                            f"Default user {default_user_id} does not exist"
                        )
                        return -1

                    # Atomically migrate all orphaned trackers
                    result = conn.execute(
                        text(
                            "UPDATE trackers SET user_id = :user_id WHERE user_id IS NULL"
                        ),
                        {"user_id": default_user_id},
                    )
                    migrated_count = result.rowcount

                    # Verify migration was successful
                    result = conn.execute(
                        text("SELECT COUNT(*) FROM trackers WHERE user_id IS NULL")
                    )
                    remaining_orphaned = result.scalar()

                    if remaining_orphaned > 0:
                        trans.rollback()
                        self.logger.error(
                            f"Migration incomplete: {remaining_orphaned} trackers still orphaned"
                        )
                        return -1

                    # Commit atomic transaction
                    trans.commit()
                    self.logger.info(
                        f"✓ Atomically migrated {migrated_count} orphaned trackers to default user"
                    )
                    return migrated_count

                except Exception as e:
                    # Rollback on any error to maintain atomicity
                    trans.rollback()
                    self.logger.error(
                        f"Rolling back atomic tracker migration due to error: {e}"
                    )
                    raise e

        except Exception as e:
            self.migration_logger.log_error(e, "atomic orphaned tracker migration")
            return -1

    def _safe_update_constraints_and_indexes(self) -> bool:
        """
        Safely update database constraints and indexes for user ownership.

        This method implements safe constraint and index updates with proper
        error handling and rollback capabilities where possible.

        Returns:
            True if successful, False otherwise

        Requirements: 2.3, 3.2
        """
        try:
            with self.engine.connect() as conn:
                # Start transaction for constraint updates
                trans = conn.begin()

                try:
                    # Drop old unique constraint on tracker name if it exists
                    try:
                        conn.execute(
                            text(
                                "ALTER TABLE trackers DROP CONSTRAINT IF EXISTS trackers_name_key"
                            )
                        )
                        self.logger.info(
                            "✓ Dropped old unique constraint on tracker name"
                        )
                    except Exception as e:
                        self.logger.debug(
                            f"Could not drop old constraint (may not exist): {e}"
                        )

                    # Add foreign key constraint for user_id
                    try:
                        conn.execute(
                            text("""
                            ALTER TABLE trackers 
                            ADD CONSTRAINT fk_tracker_user 
                            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                        """)
                        )
                        self.logger.info("✓ Added foreign key constraint for user_id")
                    except Exception as e:
                        # Check if constraint already exists
                        if (
                            "already exists" in str(e).lower()
                            or "duplicate" in str(e).lower()
                        ):
                            self.logger.info("Foreign key constraint already exists")
                        else:
                            self.logger.warning(
                                f"Could not add foreign key constraint: {e}"
                            )

                    # Add unique constraint for user_id + name combination
                    try:
                        conn.execute(
                            text("""
                            ALTER TABLE trackers 
                            ADD CONSTRAINT unique_user_tracker_name 
                            UNIQUE (user_id, name)
                        """)
                        )
                        self.logger.info("✓ Added unique constraint for user_id + name")
                    except Exception as e:
                        # Check if constraint already exists
                        if (
                            "already exists" in str(e).lower()
                            or "duplicate" in str(e).lower()
                        ):
                            self.logger.info("Unique constraint already exists")
                        else:
                            self.logger.warning(f"Could not add unique constraint: {e}")

                    # Commit constraint changes
                    trans.commit()
                    self.logger.info("✓ Constraint updates committed successfully")

                except Exception as e:
                    # Rollback constraint changes on error
                    trans.rollback()
                    self.logger.error(
                        f"Rolling back constraint updates due to error: {e}"
                    )
                    raise e

                # Add indexes (these don't need transactions)
                try:
                    conn.execute(
                        text(
                            "CREATE INDEX IF NOT EXISTS idx_user_trackers ON trackers(user_id)"
                        )
                    )
                    self.logger.info("✓ Added index for user queries")
                except Exception as e:
                    self.logger.warning(f"Could not add user index: {e}")

                try:
                    conn.execute(
                        text(
                            "CREATE INDEX IF NOT EXISTS idx_tracker_created ON trackers(created_at)"
                        )
                    )
                    self.logger.info("✓ Added index for creation date queries")
                except Exception as e:
                    self.logger.warning(f"Could not add creation date index: {e}")

                # Make user_id column NOT NULL (final step)
                try:
                    with conn.begin() as final_trans:
                        conn.execute(
                            text(
                                "ALTER TABLE trackers ALTER COLUMN user_id SET NOT NULL"
                            )
                        )
                        self.logger.info("✓ Set user_id column to NOT NULL")
                except Exception as e:
                    self.logger.warning(f"Could not set user_id to NOT NULL: {e}")

                return True

        except Exception as e:
            self.migration_logger.log_error(e, "safe constraints and indexes update")
            return False

    def _validate_data_integrity(self) -> bool:
        """
        Validate data integrity after migration to ensure all data is consistent.

        This method performs comprehensive validation to ensure the migration
        was successful and all data relationships are intact.

        Returns:
            True if validation passes, False otherwise

        Requirements: 2.4, 3.5
        """
        try:
            with self.engine.connect() as conn:
                validation_errors = []

                # Check that all trackers have valid user_id references
                result = conn.execute(
                    text("""
                        SELECT COUNT(*) FROM trackers t 
                        LEFT JOIN users u ON t.user_id = u.id 
                        WHERE t.user_id IS NOT NULL AND u.id IS NULL
                    """)
                )
                orphaned_references = result.scalar()
                if orphaned_references > 0:
                    validation_errors.append(
                        f"{orphaned_references} trackers reference non-existent users"
                    )

                # Check that no trackers have NULL user_id
                result = conn.execute(
                    text("SELECT COUNT(*) FROM trackers WHERE user_id IS NULL")
                )
                null_user_ids = result.scalar()
                if null_user_ids > 0:
                    validation_errors.append(
                        f"{null_user_ids} trackers have NULL user_id"
                    )

                # Check that users table exists and has at least one user
                try:
                    result = conn.execute(text("SELECT COUNT(*) FROM users"))
                    user_count = result.scalar()
                    if user_count == 0:
                        validation_errors.append("Users table exists but has no users")
                    else:
                        self.logger.info(f"✓ Found {user_count} users in users table")
                except Exception as e:
                    validation_errors.append(f"Could not query users table: {e}")

                # Check that foreign key constraints are working
                try:
                    # Try to insert a tracker with invalid user_id (should fail)
                    conn.execute(
                        text("""
                            INSERT INTO trackers (name, user_id, created_at, updated_at) 
                            VALUES ('test_invalid_user', 99999, NOW(), NOW())
                        """)
                    )
                    # If we get here, the constraint is not working
                    validation_errors.append(
                        "Foreign key constraint not enforced - invalid user_id accepted"
                    )
                    # Clean up the test record
                    conn.execute(
                        text("DELETE FROM trackers WHERE name = 'test_invalid_user'")
                    )
                except Exception:
                    # This is expected - foreign key constraint is working
                    self.logger.info("✓ Foreign key constraint is properly enforced")

                # Check unique constraint on user_id + name
                try:
                    # Get a valid user_id for testing
                    result = conn.execute(text("SELECT id FROM users LIMIT 1"))
                    user_row = result.fetchone()
                    if user_row:
                        user_id = user_row[0]

                        # Try to insert duplicate tracker name for same user (should fail)
                        conn.execute(
                            text("""
                                INSERT INTO trackers (name, user_id, created_at, updated_at) 
                                VALUES ('test_duplicate', :user_id, NOW(), NOW())
                            """),
                            {"user_id": user_id},
                        )
                        conn.execute(
                            text("""
                                INSERT INTO trackers (name, user_id, created_at, updated_at) 
                                VALUES ('test_duplicate', :user_id, NOW(), NOW())
                            """),
                            {"user_id": user_id},
                        )
                        # If we get here, the unique constraint is not working
                        validation_errors.append(
                            "Unique constraint not enforced - duplicate tracker names accepted"
                        )
                        # Clean up test records
                        conn.execute(
                            text(
                                "DELETE FROM trackers WHERE name = 'test_duplicate' AND user_id = :user_id"
                            ),
                            {"user_id": user_id},
                        )
                except Exception:
                    # This is expected - unique constraint is working
                    self.logger.info(
                        "✓ Unique constraint on user_id + name is properly enforced"
                    )

                if validation_errors:
                    self.logger.error("Data integrity validation failed:")
                    for error in validation_errors:
                        self.logger.error(f"  - {error}")
                    return False
                else:
                    self.logger.info(
                        "✓ Data integrity validation passed - all checks successful"
                    )
                    return True

        except Exception as e:
            self.migration_logger.log_error(e, "data integrity validation")
            return False

    def _is_user_migration_needed(self) -> bool:
        """
        Check if user migration is needed.

        Returns:
            True if users table doesn't exist, False otherwise

        Requirements: 3.1
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()
            return "users" not in existing_tables
        except Exception as e:
            self.logger.error(f"Failed to check if user migration is needed: {e}")
            # Assume migration is needed if we can't determine
            return True

    def _create_users_table(self) -> bool:
        """
        Create the users table using SQLAlchemy metadata.

        Returns:
            True if successful, False otherwise

        Requirements: 3.1
        """
        try:
            # Get the users table from metadata
            users_table = self.metadata.tables.get("users")
            if not users_table:
                self.logger.error("Users table not found in metadata")
                return False

            # Create only the users table
            users_table.create(self.engine, checkfirst=True)

            # Verify table was created
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()
            return "users" in existing_tables

        except Exception as e:
            self.migration_logger.log_error(e, "users table creation")
            return False

    def _create_default_user(self) -> Optional[int]:
        """
        Create a default system user for existing trackers.

        Returns:
            User ID of created default user, or None if failed

        Requirements: 2.4, 3.3, 7.1
        """
        try:
            with self.engine.connect() as conn:
                # Start transaction for atomic user creation
                trans = conn.begin()

                try:
                    # Check if default user already exists
                    result = conn.execute(
                        text("SELECT id FROM users WHERE email = :email"),
                        {"email": "system@trackers.local"},
                    )
                    existing_user = result.fetchone()
                    if existing_user:
                        trans.commit()
                        self.logger.info(
                            f"Default user already exists with ID: {existing_user[0]}"
                        )
                        return existing_user[0]

                    # Create default system user
                    result = conn.execute(
                        text("""
                            INSERT INTO users (google_user_id, email, name, profile_picture_url, created_at, updated_at)
                            VALUES (:google_id, :email, :name, :picture, NOW(), NOW())
                            RETURNING id
                        """),
                        {
                            "google_id": "system-default-user",
                            "email": "system@trackers.local",
                            "name": "System Default User",
                            "picture": None,
                        },
                    )
                    user_row = result.fetchone()

                    if user_row:
                        user_id = user_row[0]
                        trans.commit()
                        self.logger.info(
                            f"✓ Created default system user with ID: {user_id}"
                        )
                        return user_id
                    else:
                        trans.rollback()
                        self.logger.error("Failed to get user ID from insert")
                        return None

                except Exception as e:
                    trans.rollback()
                    self.logger.error(
                        f"Rolling back default user creation due to error: {e}"
                    )
                    raise e

        except Exception as e:
            self.migration_logger.log_error(e, "default user creation")
            return None

    # Legacy methods for backward compatibility
    def _modify_trackers_table(self, default_user_id: Optional[int]) -> bool:
        """
        Legacy method - use _safe_modify_trackers_table instead.

        Maintained for backward compatibility with existing code.
        """
        return self._safe_modify_trackers_table(default_user_id)

    def _migrate_orphaned_trackers(self, default_user_id: Optional[int]) -> int:
        """
        Legacy method - use _atomic_migrate_orphaned_trackers instead.

        Maintained for backward compatibility with existing code.
        """
        return self._atomic_migrate_orphaned_trackers(default_user_id)

    def _update_constraints_and_indexes(self) -> bool:
        """
        Legacy method - use _safe_update_constraints_and_indexes instead.

        Maintained for backward compatibility with existing code.
        """
        return self._safe_update_constraints_and_indexes()

    def get_migration_status(self) -> dict:
        """
        Get current user migration status including backup capabilities.

        Returns:
            dict: Current migration status information with backup details

        Requirements: 3.5
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = inspector.get_table_names()

            status = {
                "users_table_exists": "users" in existing_tables,
                "trackers_table_exists": "trackers" in existing_tables,
                "migration_needed": "users" not in existing_tables,
                "backup_directory": self.backup_directory,
                "backup_directory_writable": os.access(self.backup_directory, os.W_OK)
                if os.path.exists(self.backup_directory)
                else False,
            }

            if "trackers" in existing_tables:
                columns = inspector.get_columns("trackers")
                column_names = [col["name"] for col in columns]
                status.update(
                    {
                        "trackers_has_user_id": "user_id" in column_names,
                        "trackers_has_timestamps": all(
                            col in column_names for col in ["created_at", "updated_at"]
                        ),
                    }
                )

                # Count records that would be backed up
                with self.engine.connect() as conn:
                    result = conn.execute(text("SELECT COUNT(*) FROM trackers"))
                    status["tracker_count"] = result.scalar()

            if "users" in existing_tables:
                with self.engine.connect() as conn:
                    result = conn.execute(text("SELECT COUNT(*) FROM users"))
                    status["user_count"] = result.scalar()

                    if status.get("trackers_has_user_id"):
                        result = conn.execute(
                            text("SELECT COUNT(*) FROM trackers WHERE user_id IS NULL")
                        )
                        status["orphaned_tracker_count"] = result.scalar()

            return status

        except Exception as e:
            self.logger.error(f"Failed to get migration status: {e}")
            return {
                "error": str(e),
                "migration_needed": True,
                "backup_directory": self.backup_directory,
                "backup_directory_writable": False,
            }
