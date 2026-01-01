"""
API Key Migration System for User API Key Management Feature.

This module provides migration functionality to add API key support to the existing
database schema. It handles creating the api_keys table with proper relationships,
constraints, and indexes for secure user API key management.

Requirements: 4.1, 4.2, 4.3, 4.4
"""

import logging
import time
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy import Engine, MetaData, inspect, text

from .migration import MigrationLogger, migration_lock, timeout_handler


@dataclass
class APIKeyMigrationResult:
    """
    Represents the outcome of an API key migration operation.

    Requirements: 4.1, 4.2, 4.3, 4.4
    """

    success: bool
    api_keys_table_created: bool
    foreign_key_created: bool
    indexes_created: List[str]
    constraints_created: List[str]
    errors: List[str]
    duration_seconds: float
    message: str


class APIKeyMigrationEngine:
    """
    Handles migration to add API key support to the database schema.

    This class provides functionality to:
    1. Create the api_keys table with proper structure
    2. Add foreign key relationship to users table
    3. Create necessary indexes for performance
    4. Add constraints for data integrity
    5. Validate the migration was successful

    Requirements: 4.1, 4.2, 4.3, 4.4
    """

    def __init__(
        self,
        engine: Engine,
        metadata: MetaData,
        logger: Optional[logging.Logger] = None,
        timeout_seconds: int = 60,
    ):
        self.engine = engine
        self.metadata = metadata
        self.logger = logger or logging.getLogger(__name__)
        self.timeout_seconds = timeout_seconds
        self.migration_logger = MigrationLogger(self.logger)

    def run_api_key_migration(self) -> APIKeyMigrationResult:
        """
        Run the complete API key migration process.

        This method implements the full migration to add API key support,
        including table creation, relationships, constraints, and validation.

        Returns:
            APIKeyMigrationResult with complete migration details

        Requirements: 4.1, 4.2, 4.3, 4.4
        """
        start_time = time.time()
        result = APIKeyMigrationResult(
            success=False,
            api_keys_table_created=False,
            foreign_key_created=False,
            indexes_created=[],
            constraints_created=[],
            errors=[],
            duration_seconds=0,
            message="",
        )

        try:
            # Implement concurrent migration safety
            with migration_lock():
                # Implement timeout handling
                with timeout_handler(self.timeout_seconds):
                    self.migration_logger.logger.info("=" * 60)
                    self.migration_logger.logger.info("STARTING API KEY MIGRATION")
                    self.migration_logger.logger.info("=" * 60)

                    # Check if migration is needed
                    if not self._is_api_key_migration_needed():
                        result.success = True
                        result.message = "API key migration not needed - api_keys table already exists"
                        self.migration_logger.logger.info(result.message)
                        return result

                    # Step 1: Create api_keys table
                    self.migration_logger.logger.info(
                        "Step 1: Creating api_keys table..."
                    )
                    if self._create_api_keys_table():
                        result.api_keys_table_created = True
                        self.migration_logger.logger.info(
                            "✓ API keys table created successfully"
                        )
                    else:
                        error_msg = "Failed to create api_keys table"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 2: Create foreign key relationship
                    self.migration_logger.logger.info(
                        "Step 2: Creating foreign key relationship..."
                    )
                    if self._create_foreign_key_relationship():
                        result.foreign_key_created = True
                        self.migration_logger.logger.info(
                            "✓ Foreign key relationship created successfully"
                        )
                    else:
                        error_msg = "Failed to create foreign key relationship"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Step 3: Create indexes for performance
                    self.migration_logger.logger.info(
                        "Step 3: Creating performance indexes..."
                    )
                    created_indexes = self._create_performance_indexes()
                    result.indexes_created = created_indexes
                    if created_indexes:
                        self.migration_logger.logger.info(
                            f"✓ Created {len(created_indexes)} indexes: {', '.join(created_indexes)}"
                        )
                    else:
                        self.migration_logger.logger.warning(
                            "⚠ No indexes were created"
                        )

                    # Step 4: Create constraints for data integrity
                    self.migration_logger.logger.info(
                        "Step 4: Creating data integrity constraints..."
                    )
                    created_constraints = self._create_data_constraints()
                    result.constraints_created = created_constraints
                    if created_constraints:
                        self.migration_logger.logger.info(
                            f"✓ Created {len(created_constraints)} constraints: {', '.join(created_constraints)}"
                        )
                    else:
                        self.migration_logger.logger.warning(
                            "⚠ No additional constraints were created"
                        )

                    # Step 5: Validate migration success
                    self.migration_logger.logger.info(
                        "Step 5: Validating migration success..."
                    )
                    if self._validate_api_key_migration():
                        self.migration_logger.logger.info(
                            "✓ API key migration validation passed"
                        )
                    else:
                        error_msg = "API key migration validation failed"
                        result.errors.append(error_msg)
                        self.migration_logger.logger.error(f"✗ {error_msg}")

                    # Determine overall success
                    result.success = len(result.errors) == 0
                    result.duration_seconds = time.time() - start_time

                    if result.success:
                        result.message = f"API key migration completed successfully in {result.duration_seconds:.2f}s"
                        self.migration_logger.logger.info("=" * 60)
                        self.migration_logger.logger.info(
                            "API KEY MIGRATION COMPLETED SUCCESSFULLY"
                        )
                        self.migration_logger.logger.info("=" * 60)
                    else:
                        result.message = f"API key migration completed with {len(result.errors)} errors"
                        self.migration_logger.logger.error("=" * 60)
                        self.migration_logger.logger.error(
                            "API KEY MIGRATION COMPLETED WITH ERRORS"
                        )
                        self.migration_logger.logger.error("=" * 60)
                        for error in result.errors:
                            self.migration_logger.logger.error(f"  - {error}")

                    return result

        except Exception as e:
            # Handle any unexpected errors gracefully
            error_msg = f"API key migration failed with exception: {e}"
            result.errors.append(error_msg)
            result.duration_seconds = time.time() - start_time
            result.message = error_msg
            self.migration_logger.log_error(e, "API key migration")
            return result

    def _is_api_key_migration_needed(self) -> bool:
        """
        Check if API key migration is needed.

        Returns:
            True if api_keys table doesn't exist, False otherwise

        Requirements: 4.1
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())
            return "api_keys" not in existing_tables
        except Exception as e:
            self.logger.error(f"Failed to check if API key migration is needed: {e}")
            # Assume migration is needed if we can't determine
            return True

    def _create_api_keys_table(self) -> bool:
        """
        Create the api_keys table with proper structure.

        Returns:
            True if successful, False otherwise

        Requirements: 4.1, 4.2, 4.3, 4.4
        """
        try:
            with self.engine.connect() as conn:
                # Start a transaction for atomic table creation
                trans = conn.begin()

                try:
                    # Create api_keys table
                    create_table_sql = text("""
                        CREATE TABLE api_keys (
                            id SERIAL PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            name VARCHAR(100) NOT NULL,
                            key_hash VARCHAR(255) NOT NULL UNIQUE,
                            created_at TIMESTAMP DEFAULT NOW() NOT NULL,
                            expires_at TIMESTAMP NULL,
                            last_used_at TIMESTAMP NULL,
                            is_active BOOLEAN DEFAULT TRUE NOT NULL
                        )
                    """)

                    conn.execute(create_table_sql)
                    self.logger.info("✓ Created api_keys table structure")

                    # Commit the transaction
                    trans.commit()
                    self.logger.info("✓ API keys table creation committed successfully")
                    return True

                except Exception as e:
                    # Rollback on any error
                    trans.rollback()
                    self.logger.error(
                        f"Rolling back api_keys table creation due to error: {e}"
                    )
                    raise e

        except Exception as e:
            self.migration_logger.log_error(e, "api_keys table creation")
            return False

    def _create_foreign_key_relationship(self) -> bool:
        """
        Create foreign key relationship between api_keys and users tables.

        Returns:
            True if successful, False otherwise

        Requirements: 4.1
        """
        try:
            with self.engine.connect() as conn:
                # Start a transaction for atomic constraint creation
                trans = conn.begin()

                try:
                    # Add foreign key constraint
                    fk_sql = text("""
                        ALTER TABLE api_keys 
                        ADD CONSTRAINT fk_api_key_user 
                        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                    """)

                    conn.execute(fk_sql)
                    self.logger.info("✓ Added foreign key constraint for user_id")

                    # Commit the transaction
                    trans.commit()
                    self.logger.info(
                        "✓ Foreign key constraint creation committed successfully"
                    )
                    return True

                except Exception as e:
                    # Rollback on any error
                    trans.rollback()
                    # Check if constraint already exists
                    if (
                        "already exists" in str(e).lower()
                        or "duplicate" in str(e).lower()
                    ):
                        self.logger.info("Foreign key constraint already exists")
                        return True
                    else:
                        self.logger.error(
                            f"Rolling back foreign key creation due to error: {e}"
                        )
                        raise e

        except Exception as e:
            self.migration_logger.log_error(e, "foreign key relationship creation")
            return False

    def _create_performance_indexes(self) -> List[str]:
        """
        Create performance indexes for the api_keys table.

        Returns:
            List of successfully created index names

        Requirements: 4.4
        """
        created_indexes = []

        indexes_to_create = [
            (
                "idx_api_keys_user_id",
                "CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)",
            ),
            (
                "idx_api_keys_hash",
                "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)",
            ),
            (
                "idx_api_keys_active",
                "CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)",
            ),
            (
                "idx_api_keys_expires",
                "CREATE INDEX IF NOT EXISTS idx_api_keys_expires ON api_keys(expires_at)",
            ),
        ]

        try:
            with self.engine.connect() as conn:
                for index_name, index_sql in indexes_to_create:
                    try:
                        conn.execute(text(index_sql))
                        created_indexes.append(index_name)
                        self.logger.info(f"✓ Created index: {index_name}")
                    except Exception as e:
                        self.logger.warning(f"Could not create index {index_name}: {e}")

        except Exception as e:
            self.migration_logger.log_error(e, "performance indexes creation")

        return created_indexes

    def _create_data_constraints(self) -> List[str]:
        """
        Create additional data integrity constraints.

        Returns:
            List of successfully created constraint names

        Requirements: 4.2, 4.3
        """
        created_constraints = []

        # Note: Most constraints are already handled by the table definition
        # This method is here for future extensibility

        try:
            with self.engine.connect() as conn:
                # Check if we need to add any additional constraints
                # For now, the table definition handles most constraints
                self.logger.info(
                    "Data integrity constraints handled by table definition"
                )

        except Exception as e:
            self.migration_logger.log_error(e, "data constraints creation")

        return created_constraints

    def _validate_api_key_migration(self) -> bool:
        """
        Validate that the API key migration was successful.

        Returns:
            True if validation passes, False otherwise

        Requirements: 4.1, 4.2, 4.3, 4.4
        """
        try:
            inspector = inspect(self.engine)

            # Check that api_keys table exists
            existing_tables = set(inspector.get_table_names())
            if "api_keys" not in existing_tables:
                self.logger.error("Validation failed: api_keys table does not exist")
                return False

            # Check table structure
            columns = inspector.get_columns("api_keys")
            column_names = [col["name"] for col in columns]

            required_columns = [
                "id",
                "user_id",
                "name",
                "key_hash",
                "created_at",
                "expires_at",
                "last_used_at",
                "is_active",
            ]

            for required_col in required_columns:
                if required_col not in column_names:
                    self.logger.error(
                        f"Validation failed: missing column {required_col}"
                    )
                    return False

            # Check foreign key relationship
            foreign_keys = inspector.get_foreign_keys("api_keys")
            user_fk_exists = False
            for fk in foreign_keys:
                if fk.get("referred_table") == "users" and "user_id" in fk.get(
                    "constrained_columns", []
                ):
                    user_fk_exists = True
                    break

            if not user_fk_exists:
                self.logger.error(
                    "Validation failed: foreign key to users table missing"
                )
                return False

            # Check unique constraint on key_hash
            unique_constraints = inspector.get_unique_constraints("api_keys")
            key_hash_unique = False
            for constraint in unique_constraints:
                if "key_hash" in constraint.get("column_names", []):
                    key_hash_unique = True
                    break

            if not key_hash_unique:
                self.logger.error(
                    "Validation failed: unique constraint on key_hash missing"
                )
                return False

            self.logger.info("✓ API key migration validation passed")
            return True

        except Exception as e:
            self.migration_logger.log_error(e, "API key migration validation")
            return False


def create_api_keys_table(engine: Engine) -> bool:
    """
    Standalone function to create API keys table.

    This function provides a simple interface for creating the API keys table
    without the full migration engine, useful for testing and manual operations.

    Args:
        engine: SQLAlchemy engine instance

    Returns:
        True if successful, False otherwise

    Requirements: 4.1, 4.2, 4.3, 4.4
    """
    try:
        # Create a minimal metadata object for the migration
        metadata = MetaData()

        # Create migration engine
        migration_engine = APIKeyMigrationEngine(engine, metadata)

        # Run the migration
        result = migration_engine.run_api_key_migration()

        return result.success

    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to create API keys table: {e}")
        return False
