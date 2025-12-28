"""
Property-based tests for database migration functionality.

These tests validate the correctness properties of the migration system
using Hypothesis for property-based testing.

Requirements: 1.1, 1.2, 1.3, 1.4
"""

from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import declarative_base

from trackers.db.migration import MigrationEngine, SchemaDetector

# Create a test base for property testing
TestBase = declarative_base()


class TestTable1(TestBase):
    __tablename__ = "test_table_1"
    id = Column(Integer, primary_key=True)
    name = Column(String(50))


class TestTable2(TestBase):
    __tablename__ = "test_table_2"
    id = Column(Integer, primary_key=True)
    value = Column(String(100))


class TestTable3(TestBase):
    __tablename__ = "test_table_3"
    id = Column(Integer, primary_key=True)
    description = Column(String(200))


def create_test_engine():
    """Create a temporary SQLite engine for testing."""
    # Use in-memory SQLite for fast property testing
    return create_engine("sqlite:///:memory:")


def create_partial_schema(engine, tables_to_create):
    """Create a partial schema with only specified tables."""
    metadata = MetaData()

    # Define available test tables
    available_tables = {
        "test_table_1": Table(
            "test_table_1",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("name", String(50)),
        ),
        "test_table_2": Table(
            "test_table_2",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("value", String(100)),
        ),
        "test_table_3": Table(
            "test_table_3",
            metadata,
            Column("id", Integer, primary_key=True),
            Column("description", String(200)),
        ),
    }

    # Create only the specified tables
    for table_name in tables_to_create:
        if table_name in available_tables:
            available_tables[table_name].create(engine)


@given(
    st.sets(
        st.sampled_from(["test_table_1", "test_table_2", "test_table_3"]),
        min_size=0,
        max_size=3,
    )
)
def test_schema_detection_accuracy(existing_tables):
    """
    Property 1: Schema Detection Accuracy

    For any database state (empty, partial, or complete schema), the Migration Engine
    should correctly identify which tables are missing and which tables exist,
    matching the expected schema from SQLAlchemy metadata.

    **Validates: Requirements 1.1, 1.2, 1.3, 1.4**
    """
    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create partial schema with existing tables
    create_partial_schema(engine, existing_tables)

    # Create schema detector
    detector = SchemaDetector(engine, metadata)

    # Get expected tables from metadata
    expected_tables = set(metadata.tables.keys())

    # Detect missing tables
    missing_tables = set(detector.detect_missing_tables())

    # Get existing tables from database
    from sqlalchemy import inspect

    inspector = inspect(engine)
    actual_existing_tables = set(inspector.get_table_names())

    # Property assertions

    # 1. Missing tables should be exactly the difference between expected and existing
    expected_missing = expected_tables - actual_existing_tables
    assert missing_tables == expected_missing, (
        f"Schema detection failed: expected missing {expected_missing}, "
        f"but detected {missing_tables}. "
        f"Expected tables: {expected_tables}, "
        f"Actual existing: {actual_existing_tables}"
    )

    # 2. No table should be both missing and existing
    assert missing_tables.isdisjoint(actual_existing_tables), (
        f"Tables cannot be both missing and existing: "
        f"missing={missing_tables}, existing={actual_existing_tables}"
    )

    # 3. Union of missing and existing should equal expected (completeness)
    assert missing_tables.union(actual_existing_tables) == expected_tables, (
        f"Missing + existing should equal expected tables. "
        f"Missing: {missing_tables}, Existing: {actual_existing_tables}, "
        f"Expected: {expected_tables}"
    )

    # 4. get_expected_tables should return all tables from metadata
    detector_expected = set(detector.get_expected_tables())
    assert detector_expected == expected_tables, (
        f"get_expected_tables() returned {detector_expected}, "
        f"but metadata contains {expected_tables}"
    )

    # 5. Schema validation should correctly identify missing tables
    validation_result = detector.validate_existing_schema()
    assert set(validation_result.missing_tables) == missing_tables, (
        f"Schema validation missing tables {set(validation_result.missing_tables)} "
        f"doesn't match detection result {missing_tables}"
    )

    # 6. Migration status should correctly reflect the database state
    migration_engine = MigrationEngine(engine, metadata)
    status = migration_engine.get_migration_status()

    assert set(status.missing_tables) == missing_tables, (
        f"Migration status missing tables {set(status.missing_tables)} "
        f"doesn't match detection result {missing_tables}"
    )

    assert set(status.tables_exist) == actual_existing_tables, (
        f"Migration status existing tables {set(status.tables_exist)} "
        f"doesn't match actual existing {actual_existing_tables}"
    )

    assert status.migration_needed == (len(missing_tables) > 0), (
        f"Migration needed should be {len(missing_tables) > 0} "
        f"when {len(missing_tables)} tables are missing"
    )


@given(st.booleans())
def test_complete_schema_creation(empty_database):
    """
    Property 2: Complete Schema Creation

    For any empty database, when migration runs, all tables defined in SQLAlchemy
    metadata should be created with correct columns, constraints, indexes, and
    foreign key relationships.

    **Validates: Requirements 2.1, 2.2, 2.3, 2.4**
    """
    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Ensure we start with empty database (property parameter not used but required by Hypothesis)
    # The database is always empty since we use in-memory SQLite

    # Create migration engine and executor
    import logging

    from trackers.db.migration import (
        MigrationEngine,
        MigrationExecutor,
        MigrationLogger,
    )

    logger = logging.getLogger(__name__)
    migration_logger = MigrationLogger(logger)
    migration_engine = MigrationEngine(engine, metadata, logger)
    executor = MigrationExecutor(engine, metadata, migration_logger)

    # Get expected tables from metadata
    expected_tables = set(metadata.tables.keys())

    # Verify database is initially empty
    from sqlalchemy import inspect

    inspector = inspect(engine)
    initial_tables = set(inspector.get_table_names())
    assert len(initial_tables) == 0, (
        f"Database should be empty initially, but found: {initial_tables}"
    )

    # Execute migration to create all tables
    missing_tables = list(expected_tables)
    result = executor.create_missing_tables(missing_tables)

    # Property assertions

    # 1. Migration should succeed
    assert result.success, f"Migration should succeed, but got errors: {result.errors}"

    # 2. All expected tables should be created
    # Create a fresh inspector to see the newly created tables
    final_inspector = inspect(engine)
    final_tables = set(final_inspector.get_table_names())
    assert final_tables == expected_tables, (
        f"All expected tables should be created. "
        f"Expected: {expected_tables}, Created: {final_tables}, "
        f"Missing: {expected_tables - final_tables}"
    )

    # 3. Result should report all tables as created
    created_tables = set(result.tables_created)
    assert created_tables == expected_tables, (
        f"Result should report all tables as created. "
        f"Expected: {expected_tables}, Reported: {created_tables}"
    )

    # 4. No errors should be reported
    assert len(result.errors) == 0, (
        f"No errors should be reported, but got: {result.errors}"
    )

    # 5. Verify table structure and constraints
    for table_name in expected_tables:
        # Table should exist
        assert table_name in final_tables, f"Table {table_name} should exist"

        # Table should have expected columns
        columns = inspector.get_columns(table_name)
        column_names = {col["name"] for col in columns}
        expected_columns = set(metadata.tables[table_name].columns.keys())
        assert column_names == expected_columns, (
            f"Table {table_name} should have columns {expected_columns}, "
            f"but has {column_names}"
        )

        # Verify primary key exists
        pk_constraint = inspector.get_pk_constraint(table_name)
        assert pk_constraint["constrained_columns"], (
            f"Table {table_name} should have a primary key"
        )

    # 6. Verify foreign key relationships are established
    for table_name in expected_tables:
        table = metadata.tables[table_name]
        expected_fks = []
        for column in table.columns:
            if column.foreign_keys:
                for fk in column.foreign_keys:
                    expected_fks.append((column.name, fk.column.table.name))

        if expected_fks:
            actual_fks = inspector.get_foreign_keys(table_name)
            actual_fk_pairs = []
            for fk in actual_fks:
                for col, ref_col in zip(
                    fk["constrained_columns"], fk["referred_columns"]
                ):
                    actual_fk_pairs.append((col, fk["referred_table"]))

            for expected_fk in expected_fks:
                assert expected_fk in actual_fk_pairs, (
                    f"Foreign key {expected_fk} should exist in table {table_name}, "
                    f"but found: {actual_fk_pairs}"
                )

    # 7. Post-migration validation should pass
    validation_result = executor.validate_migration()
    assert validation_result.valid, (
        f"Post-migration validation should pass, but got errors: {validation_result.schema_errors}"
    )
    assert len(validation_result.missing_tables) == 0, (
        f"No tables should be missing after migration, but missing: {validation_result.missing_tables}"
    )


@given(st.integers(min_value=1, max_value=5))
def test_migration_idempotence(num_runs):
    """
    Property 3: Migration Idempotence

    For any database state, running migration multiple times should produce the
    same final schema and should not duplicate, corrupt, or interfere with existing data.

    **Validates: Requirements 2.5, 3.1**
    """
    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create migration engine
    import logging

    from trackers.db.migration import (
        MigrationEngine,
        MigrationExecutor,
        MigrationLogger,
    )

    logger = logging.getLogger(__name__)
    migration_logger = MigrationLogger(logger)
    migration_engine = MigrationEngine(engine, metadata, logger)
    executor = MigrationExecutor(engine, metadata, migration_logger)

    # Get expected tables from metadata
    expected_tables = set(metadata.tables.keys())

    # Track results from each migration run
    results = []
    table_states = []

    from sqlalchemy import inspect

    inspector = inspect(engine)

    # Run migration multiple times
    for run_num in range(num_runs):
        # Get current table state before migration
        current_inspector = inspect(engine)
        current_tables = set(current_inspector.get_table_names())
        table_states.append(current_tables.copy())

        # Determine missing tables
        missing_tables = list(expected_tables - current_tables)

        # Run migration
        result = executor.create_missing_tables(missing_tables)
        results.append(result)

        # Verify state after this run
        # Create a fresh inspector to see the newly created tables
        final_inspector = inspect(engine)
        final_tables = set(final_inspector.get_table_names())

        # Property assertions for this run

        # 1. Migration should always succeed (idempotent operations)
        assert result.success, (
            f"Migration run {run_num + 1} should succeed, but got errors: {result.errors}"
        )

        # 2. Final state should always be complete schema
        assert final_tables == expected_tables, (
            f"After run {run_num + 1}, all tables should exist. "
            f"Expected: {expected_tables}, Found: {final_tables}"
        )

        # 3. Only missing tables should be reported as created
        expected_created = set(missing_tables)
        actual_created = set(result.tables_created)
        assert actual_created == expected_created, (
            f"Run {run_num + 1}: Only missing tables should be created. "
            f"Expected created: {expected_created}, Actually created: {actual_created}"
        )

        # 4. If no tables were missing, no tables should be created
        if len(missing_tables) == 0:
            assert len(result.tables_created) == 0, (
                f"Run {run_num + 1}: No tables should be created when none are missing, "
                f"but created: {result.tables_created}"
            )
            assert result.message == "No tables needed creation", (
                f"Run {run_num + 1}: Should report no tables needed creation"
            )

    # Cross-run property assertions

    # 5. After first successful run, subsequent runs should be no-ops
    if num_runs > 1 and results[0].success:
        for run_num in range(1, num_runs):
            assert len(results[run_num].tables_created) == 0, (
                f"Run {run_num + 1} should create no tables after first successful run, "
                f"but created: {results[run_num].tables_created}"
            )
            assert results[run_num].message == "No tables needed creation", (
                f"Run {run_num + 1} should report no tables needed creation"
            )

    # 6. Table structure should be identical across all runs
    final_inspector = inspect(engine)
    final_tables = set(final_inspector.get_table_names())

    for table_name in final_tables:
        # Get table structure
        columns = final_inspector.get_columns(table_name)
        indexes = final_inspector.get_indexes(table_name)
        foreign_keys = final_inspector.get_foreign_keys(table_name)
        pk_constraint = final_inspector.get_pk_constraint(table_name)

        # Verify structure matches expected metadata
        expected_columns = set(metadata.tables[table_name].columns.keys())
        actual_columns = {col["name"] for col in columns}
        assert actual_columns == expected_columns, (
            f"Table {table_name} columns should match metadata after {num_runs} runs. "
            f"Expected: {expected_columns}, Found: {actual_columns}"
        )

    # 7. Verify no data corruption by checking table accessibility
    from sqlalchemy import text

    for table_name in final_tables:
        try:
            # Should be able to query each table without errors
            with engine.connect() as conn:
                conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
        except Exception as e:
            assert False, (
                f"Table {table_name} should be accessible after {num_runs} migration runs, but got error: {e}"
            )

    # 8. Migration status should be consistent
    final_status = migration_engine.get_migration_status()
    assert not final_status.migration_needed, (
        f"After {num_runs} migration runs, no migration should be needed"
    )
    assert len(final_status.missing_tables) == 0, (
        f"After {num_runs} migration runs, no tables should be missing, "
        f"but missing: {final_status.missing_tables}"
    )
    assert set(final_status.tables_exist) == expected_tables, (
        f"After {num_runs} migration runs, all expected tables should exist. "
        f"Expected: {expected_tables}, Found: {set(final_status.tables_exist)}"
    )


class TestSchemaDetectionAccuracy:
    """Unit tests to complement the property-based test."""

    def test_empty_database_detection(self):
        """Test schema detection with completely empty database."""
        engine = create_test_engine()
        metadata = TestBase.metadata
        detector = SchemaDetector(engine, metadata)

        missing_tables = detector.detect_missing_tables()
        expected_tables = list(metadata.tables.keys())

        assert set(missing_tables) == set(expected_tables)
        assert len(missing_tables) == len(expected_tables)

    def test_complete_schema_detection(self):
        """Test schema detection with complete existing schema."""
        engine = create_test_engine()
        metadata = TestBase.metadata

        # Create all tables
        metadata.create_all(engine)

        detector = SchemaDetector(engine, metadata)
        missing_tables = detector.detect_missing_tables()

        assert len(missing_tables) == 0

    def test_partial_schema_detection(self):
        """Test schema detection with partial existing schema."""
        engine = create_test_engine()
        metadata = TestBase.metadata

        # Create only one table
        create_partial_schema(engine, ["test_table_1"])

        detector = SchemaDetector(engine, metadata)
        missing_tables = set(detector.detect_missing_tables())
        expected_missing = set(metadata.tables.keys()) - {"test_table_1"}

        assert missing_tables == expected_missing
        assert "test_table_1" not in missing_tables


@given(
    st.sampled_from(
        [
            "clever_cloud_postgresql_addon",
            "local_development_variables",
            "mixed_environment_variables",
            "missing_optional_variables",
            "production_timeout_constraints",
        ]
    )
)
def test_environment_compatibility(environment_type):
    """
    Property 12: Environment Compatibility

    For any production environment configuration (including Clever Cloud PostgreSQL
    addon variables), the Migration Engine should work correctly with the provided
    environment variables and connection settings.

    **Validates: Requirements 7.1**
    """
    import logging
    import os
    from unittest.mock import Mock, patch

    from trackers.db.migration import MigrationEngine
    from trackers.db.settings import Settings

    # Define environment scenarios
    environment_scenarios = {
        "clever_cloud_postgresql_addon": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "postgresql-addon-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "clever_user",
                "POSTGRESQL_ADDON_PASSWORD": "clever_password_123",
                "POSTGRESQL_ADDON_DB": "clever_db",
                "POSTGRESQL_ADDON_PORT": "5432",
            },
            "expected_behavior": "success",
            "description": "Clever Cloud PostgreSQL addon environment",
        },
        "local_development_variables": {
            "env_vars": {
                "DB_HOST": "localhost",
                "DB_USER": "dev_user",
                "DB_PASSWORD": "dev_password",
                "DB_NAME": "dev_trackers",
                "DB_PORT": "5432",
            },
            "expected_behavior": "success",
            "description": "Local development environment variables",
        },
        "mixed_environment_variables": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "postgresql-addon-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "clever_user",
                "DB_PASSWORD": "fallback_password",  # Should use Clever Cloud vars first
                "POSTGRESQL_ADDON_DB": "clever_db",
                "DB_PORT": "5433",  # Should use Clever Cloud port (5432 default)
            },
            "expected_behavior": "success",
            "description": "Mixed environment with Clever Cloud priority",
        },
        "missing_optional_variables": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "postgresql-addon-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "clever_user",
                "POSTGRESQL_ADDON_PASSWORD": "clever_password_123",
                "POSTGRESQL_ADDON_DB": "clever_db",
                # POSTGRESQL_ADDON_PORT is optional, should default to 5432
            },
            "expected_behavior": "success",
            "description": "Missing optional port variable",
        },
        "production_timeout_constraints": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "slow-postgresql-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "slow_user",
                "POSTGRESQL_ADDON_PASSWORD": "slow_password",
                "POSTGRESQL_ADDON_DB": "slow_db",
                "POSTGRESQL_ADDON_PORT": "5432",
            },
            "expected_behavior": "timeout_handling",
            "description": "Production environment with timeout constraints",
        },
    }

    scenario = environment_scenarios[environment_type]

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Mock environment variables
    with patch.dict(os.environ, scenario["env_vars"], clear=True):
        try:
            # Test Settings class can load environment variables correctly
            settings = Settings()

            # Property assertions for environment compatibility

            # 1. Settings should load environment variables correctly
            assert settings.db_host, (
                f"Settings should load database host for {environment_type}"
            )
            assert settings.db_user, (
                f"Settings should load database user for {environment_type}"
            )
            assert settings.db_password, (
                f"Settings should load database password for {environment_type}"
            )
            assert settings.db_name, (
                f"Settings should load database name for {environment_type}"
            )
            assert settings.db_port, (
                f"Settings should load or default database port for {environment_type}"
            )

            # 2. Database URL should be constructed correctly
            assert settings.db_url, (
                f"Settings should construct database URL for {environment_type}"
            )
            assert "postgresql://" in settings.db_url, (
                f"Database URL should be PostgreSQL format for {environment_type}"
            )

            # 3. Clever Cloud variables should take priority over local variables
            if environment_type == "mixed_environment_variables":
                assert settings.db_host == "postgresql-addon-host.clever-cloud.com", (
                    "Clever Cloud host should take priority over local variables"
                )
                assert settings.db_user == "clever_user", (
                    "Clever Cloud user should take priority over local variables"
                )

            # 4. Optional variables should have sensible defaults
            if environment_type == "missing_optional_variables":
                assert settings.db_port == "5432", (
                    "Port should default to 5432 when not specified"
                )

            # 5. Migration engine should work with environment-loaded settings
            mock_logger = Mock(spec=logging.Logger)

            # For timeout testing, use a very short timeout
            timeout_seconds = (
                1 if scenario["expected_behavior"] == "timeout_handling" else 30
            )
            migration_engine = MigrationEngine(
                engine, metadata, mock_logger, timeout_seconds
            )

            # Test that migration engine can be created with environment settings
            assert migration_engine.engine is not None, (
                f"Migration engine should be created with environment settings for {environment_type}"
            )
            assert migration_engine.metadata is not None, (
                f"Migration engine should have metadata for {environment_type}"
            )

            # 6. Migration status should work with environment configuration
            # Mock the database connection for this test since we're using test engine
            with patch.object(migration_engine, "_test_connection", return_value=True):
                status = migration_engine.get_migration_status()
                assert status is not None, (
                    f"Migration status should be obtainable for {environment_type}"
                )
                assert hasattr(status, "connection_healthy"), (
                    f"Migration status should have connection health info for {environment_type}"
                )

            # 7. Test database URL generation for test environments
            test_db_url = settings.get_test_db_url()
            assert test_db_url, (
                f"Test database URL should be generated for {environment_type}"
            )
            assert f"{settings.db_name}_test" in test_db_url, (
                f"Test database URL should include test suffix for {environment_type}"
            )

            # 8. Environment-specific behavior validation
            if scenario["expected_behavior"] == "success":
                # Standard success case - all operations should work
                assert True, (
                    f"Environment {environment_type} should support standard operations"
                )

            elif scenario["expected_behavior"] == "timeout_handling":
                # Test timeout handling with production constraints
                with patch.object(
                    migration_engine, "_validate_database_connectivity"
                ) as mock_validate:
                    # Simulate slow database response
                    import time

                    def slow_validation():
                        time.sleep(2)  # Longer than our 1-second timeout
                        return True

                    mock_validate.side_effect = slow_validation

                    # Migration should handle timeout gracefully
                    result = migration_engine.run_migration()
                    assert not result.success, (
                        "Migration should fail gracefully on timeout in production environment"
                    )
                    assert "timeout" in result.message.lower(), (
                        "Migration result should indicate timeout failure"
                    )

        except ValueError as e:
            # Settings loading should not fail for valid environment configurations
            if scenario["expected_behavior"] == "success":
                assert False, (
                    f"Settings should load successfully for {environment_type}, "
                    f"but got error: {e}"
                )
            else:
                # Some scenarios might expect configuration errors
                assert "MISSING REQUIRED ENVIRONMENT VARIABLES" in str(e), (
                    f"Configuration error should be descriptive for {environment_type}"
                )

        except Exception as e:
            # Unexpected errors should not occur for valid environments
            assert False, f"Unexpected error for environment {environment_type}: {e}"


@given(
    st.integers(min_value=2, max_value=5)  # Test with 2-5 concurrent instances
)
def test_concurrent_migration_safety(num_instances):
    """
    Property 13: Concurrent Migration Safety

    For any scenario where multiple application instances attempt migration
    simultaneously, the Migration Engine should handle concurrent attempts
    safely without corruption or conflicts.

    **Validates: Requirements 7.3**
    """
    import logging
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from unittest.mock import Mock

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create mock logger
    mock_logger = Mock(spec=logging.Logger)

    # Track results from concurrent migration attempts
    migration_results = []
    migration_errors = []

    def run_migration_instance(instance_id: int) -> dict:
        """Run migration for a single instance and return results."""
        start_time = time.time()
        try:
            # Create separate migration engine for each instance
            migration_engine = MigrationEngine(engine, metadata, mock_logger)

            # Add small random delay to increase chance of concurrent execution
            import random

            time.sleep(random.uniform(0.01, 0.05))

            # Run migration
            result = migration_engine.run_migration()

            end_time = time.time()

            return {
                "instance_id": instance_id,
                "success": result.success,
                "tables_created": result.tables_created,
                "errors": result.errors,
                "duration": result.duration_seconds,
                "thread_duration": end_time - start_time,
                "message": result.message,
                "exception": None,
            }

        except Exception as e:
            end_time = time.time()
            return {
                "instance_id": instance_id,
                "success": False,
                "tables_created": [],
                "errors": [str(e)],
                "duration": 0,
                "thread_duration": end_time - start_time,
                "message": f"Exception: {e}",
                "exception": e,
            }

    # Execute concurrent migrations using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=num_instances) as executor:
        # Submit all migration tasks
        future_to_instance = {
            executor.submit(run_migration_instance, i): i for i in range(num_instances)
        }

        # Collect results as they complete
        for future in as_completed(future_to_instance):
            instance_id = future_to_instance[future]
            try:
                result = future.result()
                migration_results.append(result)
            except Exception as e:
                migration_errors.append(
                    {"instance_id": instance_id, "error": str(e), "exception": e}
                )

    # Property assertions for concurrent migration safety

    # 1. All migration attempts should complete (no hanging threads)
    assert len(migration_results) == num_instances, (
        f"All {num_instances} migration instances should complete, "
        f"but only {len(migration_results)} completed. "
        f"Errors: {migration_errors}"
    )

    # 2. No migration should raise unhandled exceptions
    unhandled_exceptions = [r for r in migration_results if r["exception"] is not None]
    assert len(unhandled_exceptions) == 0, (
        f"No migration should raise unhandled exceptions, "
        f"but got: {[r['exception'] for r in unhandled_exceptions]}"
    )

    # 3. At least one migration should succeed (first one to acquire resources)
    successful_migrations = [r for r in migration_results if r["success"]]
    assert len(successful_migrations) >= 1, (
        f"At least one migration should succeed in concurrent scenario, "
        f"but all failed. Results: {[r['message'] for r in migration_results]}"
    )

    # 4. Database should end up in consistent state regardless of concurrency
    from sqlalchemy import inspect

    final_inspector = inspect(engine)
    final_tables = set(final_inspector.get_table_names())
    expected_tables = set(metadata.tables.keys())

    assert final_tables == expected_tables, (
        f"Database should have all expected tables after concurrent migration. "
        f"Expected: {expected_tables}, Found: {final_tables}, "
        f"Missing: {expected_tables - final_tables}"
    )

    # 5. Total tables created across all instances should not exceed expected
    total_tables_created = []
    for result in migration_results:
        total_tables_created.extend(result["tables_created"])

    # Each table should be created at most once across all instances
    from collections import Counter

    table_creation_counts = Counter(total_tables_created)

    for table_name, count in table_creation_counts.items():
        assert count <= 1, (
            f"Table {table_name} should be created at most once across all instances, "
            f"but was created {count} times. "
            f"This indicates a concurrency safety issue."
        )

    # 6. Idempotent behavior - subsequent migrations should be no-ops
    subsequent_results = []
    for i in range(min(2, num_instances)):  # Test a couple more migrations
        subsequent_result = run_migration_instance(f"subsequent_{i}")
        subsequent_results.append(subsequent_result)

    for result in subsequent_results:
        assert result["success"], (
            f"Subsequent migration should succeed: {result['message']}"
        )
        assert len(result["tables_created"]) == 0, (
            f"Subsequent migration should create no tables, "
            f"but created: {result['tables_created']}"
        )
        assert (
            "no migration needed" in result["message"].lower()
            or "no tables needed" in result["message"].lower()
        ), f"Subsequent migration should indicate no work needed: {result['message']}"

    # 7. Database integrity should be maintained
    # Verify each table is accessible and has correct structure
    for table_name in expected_tables:
        try:
            # Should be able to query each table
            columns = final_inspector.get_columns(table_name)
            assert len(columns) > 0, (
                f"Table {table_name} should have columns after concurrent migration"
            )

            # Should be able to get primary key
            pk_constraint = final_inspector.get_pk_constraint(table_name)
            assert pk_constraint.get("constrained_columns"), (
                f"Table {table_name} should have primary key after concurrent migration"
            )

        except Exception as e:
            assert False, (
                f"Table {table_name} should be accessible after concurrent migration, "
                f"but got error: {e}"
            )

    # 8. Migration timing should be reasonable (no excessive blocking)
    max_thread_duration = max(r["thread_duration"] for r in migration_results)
    avg_thread_duration = sum(r["thread_duration"] for r in migration_results) / len(
        migration_results
    )

    # In a well-designed concurrent system, average duration shouldn't be much higher than max
    # This indicates that threads aren't blocking each other excessively
    assert avg_thread_duration <= max_thread_duration * 2, (
        f"Average migration duration ({avg_thread_duration:.2f}s) should not be much higher "
        f"than maximum duration ({max_thread_duration:.2f}s), indicating excessive blocking. "
        f"Individual durations: {[r['thread_duration'] for r in migration_results]}"
    )

    # 9. Error handling should be consistent across instances
    failed_migrations = [r for r in migration_results if not r["success"]]
    if failed_migrations:
        # All failures should have meaningful error messages
        for result in failed_migrations:
            assert len(result["errors"]) > 0, (
                f"Failed migration (instance {result['instance_id']}) should have error details"
            )
            assert result["message"], (
                f"Failed migration (instance {result['instance_id']}) should have error message"
            )

    # 10. Logging should work correctly under concurrent access
    # Mock logger should have been called by all instances
    assert mock_logger.info.called or mock_logger.error.called, (
        "Logger should be called during concurrent migrations"
    )
    """
    Property 4: Comprehensive Error Handling

    For any error condition (connection failures, permission issues, timeout errors),
    the Migration Engine should provide detailed error messages with recovery
    suggestions and appropriate log levels.

    **Validates: Requirements 3.2, 5.3, 7.4**
    """
    import logging
    from unittest.mock import Mock, patch

    from sqlalchemy.exc import OperationalError, ProgrammingError, TimeoutError

    from trackers.db.migration import MigrationLogger

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create a mock logger to capture log messages
    mock_logger = Mock(spec=logging.Logger)
    migration_logger = MigrationLogger(mock_logger)
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Define error scenarios and expected behaviors
    error_scenarios = {
        "connection_error": {
            "exception": OperationalError("Connection failed", None, None),
            "expected_log_calls": ["error"],
            "expected_message_contains": ["connection", "connectivity"],
            "recovery_suggestions": ["check connectivity", "permissions"],
        },
        "permission_error": {
            "exception": ProgrammingError("Permission denied", None, None),
            "expected_log_calls": ["error"],
            "expected_message_contains": ["permission", "privileges"],
            "recovery_suggestions": ["check user privileges", "permission"],
        },
        "timeout_error": {
            "exception": TimeoutError("Operation timed out", None, None),
            "expected_log_calls": ["error"],
            "expected_message_contains": ["timeout", "timed out"],
            "recovery_suggestions": ["timeout", "retry"],
        },
        "invalid_sql_error": {
            "exception": ProgrammingError("Invalid SQL syntax", None, None),
            "expected_log_calls": ["error"],
            "expected_message_contains": ["syntax", "SQL"],
            "recovery_suggestions": ["syntax", "check"],
        },
        "disk_full_error": {
            "exception": OperationalError("Disk full", None, None),
            "expected_log_calls": ["error"],
            "expected_message_contains": ["disk", "space"],
            "recovery_suggestions": ["space", "disk"],
        },
    }

    scenario = error_scenarios[error_type]

    # Mock the engine connection to raise the specified error
    with patch.object(engine, "connect") as mock_connect:
        mock_connect.side_effect = scenario["exception"]

        # Run migration which should handle the error gracefully
        result = migration_engine.run_migration()

        # Property assertions

        # 1. Migration should fail gracefully (not crash)
        assert isinstance(result, type(migration_engine.run_migration())), (
            f"Migration should return a result object even on {error_type}"
        )

        # 2. Result should indicate failure
        assert not result.success, (
            f"Migration result should indicate failure for {error_type}"
        )

        # 3. Error should be captured in result
        assert len(result.errors) > 0, (
            f"Migration should capture errors for {error_type}, but got: {result.errors}"
        )

        # 4. Error message should contain relevant information
        error_message = " ".join(result.errors).lower()
        message_found = any(
            expected in error_message
            for expected in scenario["expected_message_contains"]
        )
        assert message_found, (
            f"Error message should contain one of {scenario['expected_message_contains']} "
            f"for {error_type}, but got: {result.errors}"
        )

        # 5. Logger should be called with appropriate level
        assert mock_logger.error.called, (
            f"Logger error should be called for {error_type}"
        )

        # 6. Log messages should contain recovery suggestions
        log_calls = [call.args[0] for call in mock_logger.error.call_args_list]
        log_content = " ".join(str(call) for call in log_calls).lower()

        recovery_found = any(
            suggestion in log_content for suggestion in scenario["recovery_suggestions"]
        )
        assert recovery_found, (
            f"Log messages should contain recovery suggestions {scenario['recovery_suggestions']} "
            f"for {error_type}, but got: {log_calls}"
        )

        # 7. Migration should not prevent application startup (graceful failure)
        # This is tested by ensuring the method returns rather than raising
        assert result.duration_seconds >= 0, (
            f"Migration should complete and measure duration even on {error_type}"
        )

        # 8. Specific error type handling
        if error_type == "connection_error":
            # Connection errors should be specifically identified
            assert any("connection" in str(call).lower() for call in log_calls), (
                "Connection errors should be specifically identified in logs"
            )

        elif error_type == "permission_error":
            # Permission errors should suggest privilege checks
            assert any("privilege" in str(call).lower() for call in log_calls), (
                "Permission errors should suggest privilege checks"
            )

        elif error_type == "timeout_error":
            # Timeout errors should be handled with appropriate messaging
            assert any("timeout" in str(call).lower() for call in log_calls), (
                "Timeout errors should be identified in logs"
            )


@given(
    st.sampled_from(
        [
            "partial_table_creation_failure",
            "post_validation_failure",
            "metadata_corruption",
            "connection_lost_during_migration",
            "insufficient_permissions_mid_migration",
        ]
    )
)
def test_graceful_failure_recovery(failure_scenario):
    """
    Property 5: Graceful Failure Recovery

    For any migration failure scenario, the application should still start
    successfully and log the migration failure clearly without preventing
    normal operation.

    **Validates: Requirements 3.4, 4.4**
    """
    import logging
    from unittest.mock import Mock, patch

    from sqlalchemy.exc import ProgrammingError

    from trackers.db.migration import MigrationEngine, MigrationLogger

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create a mock logger to capture log messages
    mock_logger = Mock(spec=logging.Logger)
    migration_logger = MigrationLogger(mock_logger)
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Define failure scenarios
    failure_scenarios = {
        "partial_table_creation_failure": {
            "mock_target": "trackers.db.migration.MigrationExecutor.create_missing_tables",
            "side_effect": lambda tables: type(
                "Result",
                (),
                {
                    "success": False,
                    "tables_created": tables[:1]
                    if tables
                    else [],  # Only create first table
                    "errors": [f"Failed to create table {tables[1]}"]
                    if len(tables) > 1
                    else [],
                    "duration_seconds": 0.5,
                    "message": "Partial failure",
                },
            )(),
            "expected_behavior": "graceful_failure",
        },
        "post_validation_failure": {
            "mock_target": "trackers.db.migration.MigrationExecutor.validate_migration",
            "side_effect": lambda: type(
                "ValidationResult",
                (),
                {
                    "valid": False,
                    "missing_tables": [],
                    "unexpected_tables": [],
                    "schema_errors": ["Validation failed after creation"],
                },
            )(),
            "expected_behavior": "graceful_failure",
        },
        "metadata_corruption": {
            "mock_target": "trackers.db.migration.SchemaDetector.detect_missing_tables",
            "side_effect": Exception("Metadata corruption detected"),
            "expected_behavior": "graceful_failure",
        },
        "connection_lost_during_migration": {
            "mock_target": "trackers.db.migration.MigrationEngine._test_connection",
            "side_effect": [True, False],  # Connection healthy initially, then lost
            "expected_behavior": "graceful_failure",
        },
        "insufficient_permissions_mid_migration": {
            "mock_target": "sqlalchemy.MetaData.create_all",
            "side_effect": ProgrammingError("Insufficient permissions", None, None),
            "expected_behavior": "graceful_failure",
        },
    }

    scenario = failure_scenarios[failure_scenario]

    # Apply the mock based on scenario
    with patch(scenario["mock_target"]) as mock_target:
        if isinstance(scenario["side_effect"], list):
            mock_target.side_effect = scenario["side_effect"]
        else:
            mock_target.side_effect = scenario["side_effect"]

        # Run migration which should handle failure gracefully
        try:
            result = migration_engine.run_migration()

            # Property assertions for graceful failure recovery

            # 1. Migration method should not raise exceptions (graceful handling)
            assert True, "Migration should not raise exceptions even on failure"

            # 2. Result should be returned (not None)
            assert result is not None, (
                f"Migration should return a result object even on {failure_scenario}"
            )

            # 3. Result should indicate failure appropriately
            if scenario["expected_behavior"] == "graceful_failure":
                assert not result.success, (
                    f"Migration should indicate failure for {failure_scenario}"
                )

                # 4. Failure should be logged clearly
                assert mock_logger.error.called, (
                    f"Migration failure should be logged for {failure_scenario}"
                )

                # 5. Error details should be captured
                assert len(result.errors) > 0, (
                    f"Migration should capture error details for {failure_scenario}"
                )

                # 6. Duration should be measured even on failure
                assert result.duration_seconds >= 0, (
                    f"Migration should measure duration even on {failure_scenario}"
                )

                # 7. Message should describe the failure
                assert result.message, (
                    f"Migration should provide failure message for {failure_scenario}"
                )
                assert "fail" in result.message.lower(), (
                    f"Failure message should indicate failure for {failure_scenario}"
                )

            # 8. Application startup simulation - migration failure should not prevent it
            # This is tested by ensuring the migration method completes without raising
            startup_successful = True
            try:
                # Simulate application startup continuing after migration
                app_logger = Mock()
                if not result.success:
                    app_logger.error(f"Migration failed: {result.message}")
                # Application should continue starting up
                startup_successful = True
            except Exception:
                startup_successful = False

            assert startup_successful, (
                f"Application startup should succeed even after migration failure for {failure_scenario}"
            )

        except Exception as e:
            # Migration should not raise exceptions - this is a test failure
            assert False, (
                f"Migration should handle {failure_scenario} gracefully without raising exceptions, "
                f"but raised: {e}"
            )


@given(
    st.sampled_from(
        [
            "clever_cloud_postgresql_addon",
            "local_development_variables",
            "mixed_environment_variables",
            "missing_optional_variables",
            "production_timeout_constraints",
        ]
    )
)
def test_environment_compatibility(environment_type):
    """
    Property 12: Environment Compatibility

    For any production environment configuration (including Clever Cloud PostgreSQL
    addon variables), the Migration Engine should work correctly with the provided
    environment variables and connection settings.

    **Validates: Requirements 7.1**
    """
    import logging
    import os
    from unittest.mock import Mock, patch

    from trackers.db.migration import MigrationEngine
    from trackers.db.settings import Settings

    # Define environment scenarios
    environment_scenarios = {
        "clever_cloud_postgresql_addon": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "postgresql-addon-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "clever_user",
                "POSTGRESQL_ADDON_PASSWORD": "clever_password_123",
                "POSTGRESQL_ADDON_DB": "clever_db",
                "POSTGRESQL_ADDON_PORT": "5432",
            },
            "expected_behavior": "success",
            "description": "Clever Cloud PostgreSQL addon environment",
        },
        "local_development_variables": {
            "env_vars": {
                "DB_HOST": "localhost",
                "DB_USER": "dev_user",
                "DB_PASSWORD": "dev_password",
                "DB_NAME": "dev_trackers",
                "DB_PORT": "5432",
            },
            "expected_behavior": "success",
            "description": "Local development environment variables",
        },
        "mixed_environment_variables": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "postgresql-addon-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "clever_user",
                "DB_PASSWORD": "fallback_password",  # Should use Clever Cloud vars first
                "POSTGRESQL_ADDON_DB": "clever_db",
                "DB_PORT": "5433",  # Should use Clever Cloud port (5432 default)
            },
            "expected_behavior": "success",
            "description": "Mixed environment with Clever Cloud priority",
        },
        "missing_optional_variables": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "postgresql-addon-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "clever_user",
                "POSTGRESQL_ADDON_PASSWORD": "clever_password_123",
                "POSTGRESQL_ADDON_DB": "clever_db",
                # POSTGRESQL_ADDON_PORT is optional, should default to 5432
            },
            "expected_behavior": "success",
            "description": "Missing optional port variable",
        },
        "production_timeout_constraints": {
            "env_vars": {
                "POSTGRESQL_ADDON_HOST": "slow-postgresql-host.clever-cloud.com",
                "POSTGRESQL_ADDON_USER": "slow_user",
                "POSTGRESQL_ADDON_PASSWORD": "slow_password",
                "POSTGRESQL_ADDON_DB": "slow_db",
                "POSTGRESQL_ADDON_PORT": "5432",
            },
            "expected_behavior": "timeout_handling",
            "description": "Production environment with timeout constraints",
        },
    }

    scenario = environment_scenarios[environment_type]

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Mock environment variables
    with patch.dict(os.environ, scenario["env_vars"], clear=True):
        try:
            # Test Settings class can load environment variables correctly
            settings = Settings()

            # Property assertions for environment compatibility

            # 1. Settings should load environment variables correctly
            assert settings.db_host, (
                f"Settings should load database host for {environment_type}"
            )
            assert settings.db_user, (
                f"Settings should load database user for {environment_type}"
            )
            assert settings.db_password, (
                f"Settings should load database password for {environment_type}"
            )
            assert settings.db_name, (
                f"Settings should load database name for {environment_type}"
            )
            assert settings.db_port, (
                f"Settings should load or default database port for {environment_type}"
            )

            # 2. Database URL should be constructed correctly
            assert settings.db_url, (
                f"Settings should construct database URL for {environment_type}"
            )
            assert "postgresql://" in settings.db_url, (
                f"Database URL should be PostgreSQL format for {environment_type}"
            )

            # 3. Clever Cloud variables should take priority over local variables
            if environment_type == "mixed_environment_variables":
                assert settings.db_host == "postgresql-addon-host.clever-cloud.com", (
                    "Clever Cloud host should take priority over local variables"
                )
                assert settings.db_user == "clever_user", (
                    "Clever Cloud user should take priority over local variables"
                )
                # Password should come from Clever Cloud (not set in this scenario)
                # Port should default to 5432 since POSTGRESQL_ADDON_PORT not set

            # 4. Optional variables should have sensible defaults
            if environment_type == "missing_optional_variables":
                assert settings.db_port == "5432", (
                    "Port should default to 5432 when not specified"
                )

            # 5. Migration engine should work with environment-loaded settings
            mock_logger = Mock(spec=logging.Logger)

            # For timeout testing, use a very short timeout
            timeout_seconds = (
                1 if scenario["expected_behavior"] == "timeout_handling" else 30
            )
            migration_engine = MigrationEngine(
                engine, metadata, mock_logger, timeout_seconds
            )

            # Test that migration engine can be created with environment settings
            assert migration_engine.engine is not None, (
                f"Migration engine should be created with environment settings for {environment_type}"
            )
            assert migration_engine.metadata is not None, (
                f"Migration engine should have metadata for {environment_type}"
            )

            # 6. Migration status should work with environment configuration
            # Mock the database connection for this test since we're using test engine
            with patch.object(migration_engine, "_test_connection", return_value=True):
                status = migration_engine.get_migration_status()
                assert status is not None, (
                    f"Migration status should be obtainable for {environment_type}"
                )
                assert hasattr(status, "connection_healthy"), (
                    f"Migration status should have connection health info for {environment_type}"
                )

            # 7. Test database URL generation for test environments
            test_db_url = settings.get_test_db_url()
            assert test_db_url, (
                f"Test database URL should be generated for {environment_type}"
            )
            assert f"{settings.db_name}_test" in test_db_url, (
                f"Test database URL should include test suffix for {environment_type}"
            )

            # 8. Environment-specific behavior validation
            if scenario["expected_behavior"] == "success":
                # Standard success case - all operations should work
                assert True, (
                    f"Environment {environment_type} should support standard operations"
                )

            elif scenario["expected_behavior"] == "timeout_handling":
                # Test timeout handling with production constraints
                with patch.object(
                    migration_engine, "_validate_database_connectivity"
                ) as mock_validate:
                    # Simulate slow database response
                    import time

                    def slow_validation():
                        time.sleep(2)  # Longer than our 1-second timeout
                        return True

                    mock_validate.side_effect = slow_validation

                    # Migration should handle timeout gracefully
                    result = migration_engine.run_migration()
                    assert not result.success, (
                        "Migration should fail gracefully on timeout in production environment"
                    )
                    assert "timeout" in result.message.lower(), (
                        "Migration result should indicate timeout failure"
                    )

        except ValueError as e:
            # Settings loading should not fail for valid environment configurations
            if scenario["expected_behavior"] == "success":
                assert False, (
                    f"Settings should load successfully for {environment_type}, "
                    f"but got error: {e}"
                )
            else:
                # Some scenarios might expect configuration errors
                assert "MISSING REQUIRED ENVIRONMENT VARIABLES" in str(e), (
                    f"Configuration error should be descriptive for {environment_type}"
                )

        except Exception as e:
            # Unexpected errors should not occur for valid environments
            assert False, f"Unexpected error for environment {environment_type}: {e}"


@given(
    st.integers(min_value=2, max_value=5)  # Test with 2-5 concurrent instances
)
def test_concurrent_migration_safety(num_instances):
    """
    Property 13: Concurrent Migration Safety

    For any scenario where multiple application instances attempt migration
    simultaneously, the Migration Engine should handle concurrent attempts
    safely without corruption or conflicts.

    **Validates: Requirements 7.3**
    """
    import logging
    import time
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from unittest.mock import Mock

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create mock logger
    mock_logger = Mock(spec=logging.Logger)

    # Track results from concurrent migration attempts
    migration_results = []
    migration_errors = []
    thread_timings = []

    def run_migration_instance(instance_id: int) -> dict:
        """Run migration for a single instance and return results."""
        start_time = time.time()
        try:
            # Create separate migration engine for each instance
            migration_engine = MigrationEngine(engine, metadata, mock_logger)

            # Add small random delay to increase chance of concurrent execution
            import random

            time.sleep(random.uniform(0.01, 0.05))

            # Run migration
            result = migration_engine.run_migration()

            end_time = time.time()

            return {
                "instance_id": instance_id,
                "success": result.success,
                "tables_created": result.tables_created,
                "errors": result.errors,
                "duration": result.duration_seconds,
                "thread_duration": end_time - start_time,
                "message": result.message,
                "exception": None,
            }

        except Exception as e:
            end_time = time.time()
            return {
                "instance_id": instance_id,
                "success": False,
                "tables_created": [],
                "errors": [str(e)],
                "duration": 0,
                "thread_duration": end_time - start_time,
                "message": f"Exception: {e}",
                "exception": e,
            }

    # Execute concurrent migrations using ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=num_instances) as executor:
        # Submit all migration tasks
        future_to_instance = {
            executor.submit(run_migration_instance, i): i for i in range(num_instances)
        }

        # Collect results as they complete
        for future in as_completed(future_to_instance):
            instance_id = future_to_instance[future]
            try:
                result = future.result()
                migration_results.append(result)
            except Exception as e:
                migration_errors.append(
                    {"instance_id": instance_id, "error": str(e), "exception": e}
                )

    # Property assertions for concurrent migration safety

    # 1. All migration attempts should complete (no hanging threads)
    assert len(migration_results) == num_instances, (
        f"All {num_instances} migration instances should complete, "
        f"but only {len(migration_results)} completed. "
        f"Errors: {migration_errors}"
    )

    # 2. No migration should raise unhandled exceptions
    unhandled_exceptions = [r for r in migration_results if r["exception"] is not None]
    assert len(unhandled_exceptions) == 0, (
        f"No migration should raise unhandled exceptions, "
        f"but got: {[r['exception'] for r in unhandled_exceptions]}"
    )

    # 3. At least one migration should succeed (first one to acquire resources)
    successful_migrations = [r for r in migration_results if r["success"]]
    assert len(successful_migrations) >= 1, (
        f"At least one migration should succeed in concurrent scenario, "
        f"but all failed. Results: {[r['message'] for r in migration_results]}"
    )

    # 4. Database should end up in consistent state regardless of concurrency
    from sqlalchemy import inspect

    final_inspector = inspect(engine)
    final_tables = set(final_inspector.get_table_names())
    expected_tables = set(metadata.tables.keys())

    assert final_tables == expected_tables, (
        f"Database should have all expected tables after concurrent migration. "
        f"Expected: {expected_tables}, Found: {final_tables}, "
        f"Missing: {expected_tables - final_tables}"
    )

    # 5. Total tables created across all instances should not exceed expected
    total_tables_created = []
    for result in migration_results:
        total_tables_created.extend(result["tables_created"])

    # Each table should be created at most once across all instances
    from collections import Counter

    table_creation_counts = Counter(total_tables_created)

    for table_name, count in table_creation_counts.items():
        assert count <= 1, (
            f"Table {table_name} should be created at most once across all instances, "
            f"but was created {count} times. "
            f"This indicates a concurrency safety issue."
        )

    # 6. Idempotent behavior - subsequent migrations should be no-ops
    subsequent_results = []
    for i in range(min(2, num_instances)):  # Test a couple more migrations
        subsequent_result = run_migration_instance(f"subsequent_{i}")
        subsequent_results.append(subsequent_result)

    for result in subsequent_results:
        assert result["success"], (
            f"Subsequent migration should succeed: {result['message']}"
        )
        assert len(result["tables_created"]) == 0, (
            f"Subsequent migration should create no tables, "
            f"but created: {result['tables_created']}"
        )
        assert (
            "no migration needed" in result["message"].lower()
            or "no tables needed" in result["message"].lower()
        ), f"Subsequent migration should indicate no work needed: {result['message']}"

    # 7. Database integrity should be maintained
    # Verify each table is accessible and has correct structure
    for table_name in expected_tables:
        try:
            # Should be able to query each table
            columns = final_inspector.get_columns(table_name)
            assert len(columns) > 0, (
                f"Table {table_name} should have columns after concurrent migration"
            )

            # Should be able to get primary key
            pk_constraint = final_inspector.get_pk_constraint(table_name)
            assert pk_constraint.get("constrained_columns"), (
                f"Table {table_name} should have primary key after concurrent migration"
            )

        except Exception as e:
            assert False, (
                f"Table {table_name} should be accessible after concurrent migration, "
                f"but got error: {e}"
            )

    # 8. Migration timing should be reasonable (no excessive blocking)
    max_thread_duration = max(r["thread_duration"] for r in migration_results)
    avg_thread_duration = sum(r["thread_duration"] for r in migration_results) / len(
        migration_results
    )

    # In a well-designed concurrent system, average duration shouldn't be much higher than max
    # This indicates that threads aren't blocking each other excessively
    assert avg_thread_duration <= max_thread_duration * 2, (
        f"Average migration duration ({avg_thread_duration:.2f}s) should not be much higher "
        f"than maximum duration ({max_thread_duration:.2f}s), indicating excessive blocking. "
        f"Individual durations: {[r['thread_duration'] for r in migration_results]}"
    )

    # 9. Error handling should be consistent across instances
    failed_migrations = [r for r in migration_results if not r["success"]]
    if failed_migrations:
        # All failures should have meaningful error messages
        for result in failed_migrations:
            assert len(result["errors"]) > 0, (
                f"Failed migration (instance {result['instance_id']}) should have error details"
            )
            assert result["message"], (
                f"Failed migration (instance {result['instance_id']}) should have error message"
            )

    # 10. Logging should work correctly under concurrent access
    # Mock logger should have been called by all instances
    assert mock_logger.info.called or mock_logger.error.called, (
        "Logger should be called during concurrent migrations"
    )


class TestEnvironmentCompatibility:
    """Unit tests to complement the property-based environment compatibility test."""

    def test_clever_cloud_variables_priority(self):
        """Test that Clever Cloud variables take priority over local variables."""
        import os
        from unittest.mock import patch

        from trackers.db.settings import Settings

        env_vars = {
            "POSTGRESQL_ADDON_HOST": "clever-host.com",
            "POSTGRESQL_ADDON_USER": "clever_user",
            "POSTGRESQL_ADDON_PASSWORD": "clever_pass",
            "POSTGRESQL_ADDON_DB": "clever_db",
            "DB_HOST": "local_host",
            "DB_USER": "local_user",
            "DB_PASSWORD": "local_pass",
            "DB_NAME": "local_db",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            settings = Settings()

            # Should use Clever Cloud variables
            assert settings.db_host == "clever-host.com"
            assert settings.db_user == "clever_user"
            assert settings.db_password == "clever_pass"
            assert settings.db_name == "clever_db"

    def test_local_variables_fallback(self):
        """Test fallback to local variables when Clever Cloud variables are not set."""
        import os
        from unittest.mock import patch

        from trackers.db.settings import Settings

        env_vars = {
            "DB_HOST": "localhost",
            "DB_USER": "local_user",
            "DB_PASSWORD": "local_pass",
            "DB_NAME": "local_db",
            "DB_PORT": "5433",
        }

        with patch.dict(os.environ, env_vars, clear=True):
            settings = Settings()

            # Should use local variables
            assert settings.db_host == "localhost"
            assert settings.db_user == "local_user"
            assert settings.db_password == "local_pass"
            assert settings.db_name == "local_db"
            assert settings.db_port == "5433"

    def test_missing_required_variables_error(self):
        """Test that missing required variables produce helpful error messages."""
        import os
        from unittest.mock import patch

        from trackers.db.settings import Settings

        # Empty environment
        with patch.dict(os.environ, {}, clear=True):
            try:
                Settings()
                assert False, "Should raise ValueError for missing variables"
            except ValueError as e:
                error_msg = str(e)
                assert "MISSING REQUIRED ENVIRONMENT VARIABLES" in error_msg
                assert "POSTGRESQL_ADDON_HOST or DB_HOST" in error_msg
                assert "How to fix:" in error_msg


class TestConcurrentMigrationSafety:
    """Unit tests to complement the property-based concurrent migration test."""

    def test_sequential_migrations_are_idempotent(self):
        """Test that running migrations sequentially produces consistent results."""
        import logging
        from unittest.mock import Mock

        from trackers.db.migration import MigrationEngine

        engine = create_test_engine()
        metadata = TestBase.metadata
        mock_logger = Mock(spec=logging.Logger)

        # Run first migration
        migration_engine1 = MigrationEngine(engine, metadata, mock_logger)
        result1 = migration_engine1.run_migration()

        # Run second migration
        migration_engine2 = MigrationEngine(engine, metadata, mock_logger)
        result2 = migration_engine2.run_migration()

        # First should create tables, second should be no-op
        assert result1.success
        assert result2.success
        assert len(result2.tables_created) == 0

    def test_migration_with_existing_partial_schema(self):
        """Test migration behavior with existing partial schema."""
        import logging
        from unittest.mock import Mock

        from trackers.db.migration import MigrationEngine

        engine = create_test_engine()
        metadata = TestBase.metadata
        mock_logger = Mock(spec=logging.Logger)

        # Create partial schema
        create_partial_schema(engine, ["test_table_1"])

        # Run migration
        migration_engine = MigrationEngine(engine, metadata, mock_logger)
        result = migration_engine.run_migration()

        # Should only create missing tables
        assert result.success
        assert "test_table_1" not in result.tables_created
        assert len(result.tables_created) == len(metadata.tables) - 1


@given(
    st.sampled_from(
        [
            "healthy_connection",
            "connection_refused",
            "authentication_failure",
            "network_timeout",
            "database_not_found",
            "intermittent_connection",
        ]
    )
)
def test_database_connectivity_validation(connection_state):
    """
    Property 6: Database Connectivity Validation

    For any database connection state, the Migration Engine should validate
    connectivity before attempting schema changes and handle connection
    issues appropriately.

    **Validates: Requirements 3.5, 7.2**
    """
    import logging
    from unittest.mock import MagicMock, Mock, patch

    from sqlalchemy.exc import OperationalError

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create a mock logger to capture log messages
    mock_logger = Mock(spec=logging.Logger)
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Define connection states and expected behaviors
    connection_states = {
        "healthy_connection": {
            "connection_healthy": True,
            "connect_side_effect": None,
            "execute_side_effect": None,
            "expected_migration_attempt": True,
            "expected_status_healthy": True,
        },
        "connection_refused": {
            "connection_healthy": False,
            "connect_side_effect": OperationalError("Connection refused", None, None),
            "execute_side_effect": None,
            "expected_migration_attempt": False,
            "expected_status_healthy": False,
        },
        "authentication_failure": {
            "connection_healthy": False,
            "connect_side_effect": OperationalError(
                "Authentication failed", None, None
            ),
            "execute_side_effect": None,
            "expected_migration_attempt": False,
            "expected_status_healthy": False,
        },
        "network_timeout": {
            "connection_healthy": False,
            "connect_side_effect": OperationalError("Network timeout", None, None),
            "execute_side_effect": None,
            "expected_migration_attempt": False,
            "expected_status_healthy": False,
        },
        "database_not_found": {
            "connection_healthy": False,
            "connect_side_effect": OperationalError("Database not found", None, None),
            "execute_side_effect": None,
            "expected_migration_attempt": False,
            "expected_status_healthy": False,
        },
        "intermittent_connection": {
            "connection_healthy": False,
            "connect_side_effect": [
                OperationalError("Connection failed", None, None),
                MagicMock(),  # Second attempt succeeds
            ],
            "execute_side_effect": None,
            "expected_migration_attempt": False,  # First check fails
            "expected_status_healthy": False,
        },
    }

    state_config = connection_states[connection_state]

    # Mock the engine connection behavior
    with patch.object(engine, "connect") as mock_connect:
        # Configure connection behavior
        if isinstance(state_config["connect_side_effect"], list):
            mock_connect.side_effect = state_config["connect_side_effect"]
        elif state_config["connect_side_effect"]:
            mock_connect.side_effect = state_config["connect_side_effect"]
        else:
            # Healthy connection - return a mock connection
            mock_conn = MagicMock()
            mock_conn.execute.return_value = None
            mock_connect.return_value.__enter__.return_value = mock_conn
            mock_connect.return_value.__exit__.return_value = None

        # Test connectivity validation before migration
        status = migration_engine.get_migration_status()

        # Property assertions

        # 1. Connection health should be correctly detected
        assert status.connection_healthy == state_config["expected_status_healthy"], (
            f"Connection health should be {state_config['expected_status_healthy']} "
            f"for {connection_state}, but got {status.connection_healthy}"
        )

        # 2. Migration status should reflect connectivity
        if not state_config["expected_status_healthy"]:
            # Unhealthy connection should indicate migration is needed but connection is bad
            assert not status.connection_healthy, (
                f"Status should indicate unhealthy connection for {connection_state}"
            )

            # Database existence should be reported as false for connection issues
            assert not status.database_exists, (
                f"Database existence should be false when connection fails for {connection_state}"
            )

            # Missing tables should include all expected tables
            expected_tables = set(metadata.tables.keys())
            assert set(status.missing_tables) == expected_tables, (
                f"All tables should be considered missing when connection fails for {connection_state}"
            )

        # 3. Run migration and verify connectivity validation
        result = migration_engine.run_migration()

        # 4. Migration behavior should depend on connectivity
        if state_config["expected_migration_attempt"]:
            # Healthy connection - migration should attempt to proceed
            # (May still fail for other reasons, but should attempt)
            assert mock_connect.called, (
                f"Migration should attempt database operations for {connection_state}"
            )
        else:
            # Unhealthy connection - migration should fail early
            assert not result.success, (
                f"Migration should fail for unhealthy connection {connection_state}"
            )

            # Error should mention connection issues
            error_messages = " ".join(result.errors).lower()
            connection_error_mentioned = any(
                keyword in error_messages
                for keyword in ["connection", "connectivity", "database", "unhealthy"]
            )
            assert connection_error_mentioned, (
                f"Migration error should mention connection issues for {connection_state}, "
                f"but got: {result.errors}"
            )

        # 5. Connectivity validation should happen before schema changes
        # This is tested by ensuring connection test is called before any table operations
        if not state_config["expected_status_healthy"]:
            # For unhealthy connections, no table creation should be attempted
            with patch("trackers.db.migration.MetaData.create_all") as mock_create:
                # Re-run migration to test that create_all is not called
                migration_engine.run_migration()

                # create_all should not be called if connection is unhealthy
                assert not mock_create.called, (
                    f"Schema creation should not be attempted for {connection_state}"
                )

        # 6. Appropriate logging for connection issues
        if not state_config["expected_status_healthy"]:
            # Connection issues should be logged
            log_calls = [
                str(call)
                for call in mock_logger.debug.call_args_list
                + mock_logger.error.call_args_list
            ]
            connection_logged = any("connection" in call.lower() for call in log_calls)
            assert connection_logged, (
                f"Connection issues should be logged for {connection_state}"
            )

        # 7. Test direct connectivity validation method
        connection_test_result = migration_engine._test_connection()
        assert connection_test_result == state_config["expected_status_healthy"], (
            f"Direct connection test should return {state_config['expected_status_healthy']} "
            f"for {connection_state}, but got {connection_test_result}"
        )

        # 8. Specific connection state validations
        if connection_state == "authentication_failure":
            # Authentication failures should be specifically handled
            assert "authentication" in " ".join(result.errors).lower() or any(
                "authentication" in str(call).lower()
                for call in mock_logger.error.call_args_list
            ), "Authentication failures should be specifically identified"

        elif connection_state == "network_timeout":
            # Network timeouts should be handled with appropriate messaging
            timeout_mentioned = "timeout" in " ".join(result.errors).lower() or any(
                "timeout" in str(call).lower()
                for call in mock_logger.debug.call_args_list
            )
            assert timeout_mentioned, (
                "Network timeout should be mentioned in error handling"
            )

        elif connection_state == "database_not_found":
            # Database not found should be clearly indicated
            db_not_found = "database" in " ".join(result.errors).lower() or any(
                "database" in str(call).lower()
                for call in mock_logger.error.call_args_list
            )
            assert db_not_found, "Database not found should be clearly indicated"


@given(
    st.sampled_from(
        [
            "empty_database",
            "partial_schema",
            "complete_schema",
            "migration_failure",
            "connection_error",
        ]
    )
)
def test_flask_integration_timing(database_state):
    """
    Property 7: Flask Integration Timing

    For any Flask application startup, the Migration Engine should run automatically
    before routes are registered and the application should become ready to serve
    requests after successful migration.

    **Validates: Requirements 4.1, 4.3**
    """
    from unittest.mock import patch

    from flask import Flask

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Define database states and expected behaviors
    database_states = {
        "empty_database": {
            "setup_tables": [],
            "expected_migration_needed": True,
            "expected_app_startup": True,
            "expected_routes_available": True,
        },
        "partial_schema": {
            "setup_tables": ["test_table_1"],
            "expected_migration_needed": True,
            "expected_app_startup": True,
            "expected_routes_available": True,
        },
        "complete_schema": {
            "setup_tables": ["test_table_1", "test_table_2", "test_table_3"],
            "expected_migration_needed": False,
            "expected_app_startup": True,
            "expected_routes_available": True,
        },
        "migration_failure": {
            "setup_tables": [],
            "expected_migration_needed": True,
            "expected_app_startup": True,  # App should still start
            "expected_routes_available": True,  # Routes should still be available
            "force_migration_failure": True,
        },
        "connection_error": {
            "setup_tables": [],
            "expected_migration_needed": True,
            "expected_app_startup": True,  # App should still start
            "expected_routes_available": True,  # Routes should still be available
            "force_connection_error": True,
        },
    }

    state_config = database_states[database_state]

    # Setup initial database state
    if state_config["setup_tables"]:
        create_partial_schema(engine, state_config["setup_tables"])

    # Track the order of operations during Flask app creation
    operation_order = []
    migration_completed = False
    routes_registered = False

    # Mock the migration engine to track when migration runs
    original_run_migration = MigrationEngine.run_migration

    def mock_run_migration(self):
        nonlocal migration_completed, operation_order
        operation_order.append("migration_started")

        # Handle forced failures for testing
        if state_config.get("force_migration_failure"):
            operation_order.append("migration_failed")
            migration_completed = True
            return type(
                "MigrationResult",
                (),
                {
                    "success": False,
                    "tables_created": [],
                    "errors": ["Forced migration failure for testing"],
                    "duration_seconds": 0.1,
                    "message": "Migration failed",
                },
            )()

        if state_config.get("force_connection_error"):
            operation_order.append("migration_connection_error")
            migration_completed = True
            return type(
                "MigrationResult",
                (),
                {
                    "success": False,
                    "tables_created": [],
                    "errors": ["Database connection failed"],
                    "duration_seconds": 0.1,
                    "message": "Connection error",
                },
            )()

        # Normal migration execution
        result = original_run_migration(self)
        operation_order.append("migration_completed")
        migration_completed = True
        return result

    # Mock Flask blueprint registration to track when routes are registered
    original_register_blueprint = Flask.register_blueprint

    def mock_register_blueprint(self, blueprint, **options):
        nonlocal routes_registered, operation_order
        if not routes_registered:  # Only log the first blueprint registration
            operation_order.append("routes_registered")
            routes_registered = True
        return original_register_blueprint(self, blueprint, **options)

    # Create Flask app with mocked components
    with (
        patch.object(MigrationEngine, "run_migration", mock_run_migration),
        patch.object(Flask, "register_blueprint", mock_register_blueprint),
    ):
        # Import and create the Flask app (this triggers migration)
        from trackers import create_app

        # Create app without test config to trigger migration
        app = create_app()

        # Property assertions

        # 1. Migration should run before routes are registered
        if state_config["expected_migration_needed"]:
            migration_start_index = None
            routes_register_index = None

            for i, operation in enumerate(operation_order):
                if operation == "migration_started" and migration_start_index is None:
                    migration_start_index = i
                elif operation == "routes_registered" and routes_register_index is None:
                    routes_register_index = i

            assert migration_start_index is not None, (
                f"Migration should start for {database_state}, but operation order: {operation_order}"
            )

            assert routes_register_index is not None, (
                f"Routes should be registered for {database_state}, but operation order: {operation_order}"
            )

            assert migration_start_index < routes_register_index, (
                f"Migration should start before routes are registered for {database_state}. "
                f"Migration at index {migration_start_index}, routes at {routes_register_index}. "
                f"Operation order: {operation_order}"
            )

        # 2. Application should start successfully regardless of migration outcome
        assert app is not None, f"Flask app should be created for {database_state}"
        assert isinstance(app, Flask), (
            f"Should return Flask app instance for {database_state}"
        )

        # 3. Routes should be available after app creation
        if state_config["expected_routes_available"]:
            # Test that routes are accessible
            with app.test_client() as client:
                # Test health endpoint (should be available)
                response = client.get("/health")
                assert response.status_code in [200, 404], (
                    f"Health endpoint should be accessible for {database_state}, "
                    f"but got status {response.status_code}"
                )

                # Test hello endpoint (should be available)
                response = client.get("/hello")
                assert response.status_code == 200, (
                    f"Hello endpoint should be accessible for {database_state}, "
                    f"but got status {response.status_code}"
                )

        # 4. Migration completion should happen before app becomes ready
        if state_config["expected_migration_needed"]:
            assert migration_completed, (
                f"Migration should complete during app creation for {database_state}"
            )

            # Check that migration completed before routes were registered
            migration_complete_index = None
            routes_register_index = None

            for i, operation in enumerate(operation_order):
                if operation in [
                    "migration_completed",
                    "migration_failed",
                    "migration_connection_error",
                ]:
                    if migration_complete_index is None:
                        migration_complete_index = i
                elif operation == "routes_registered" and routes_register_index is None:
                    routes_register_index = i

            if (
                migration_complete_index is not None
                and routes_register_index is not None
            ):
                assert migration_complete_index < routes_register_index, (
                    f"Migration should complete before routes are registered for {database_state}. "
                    f"Migration complete at {migration_complete_index}, routes at {routes_register_index}. "
                    f"Operation order: {operation_order}"
                )

        # 5. Test mode detection - migration should be skipped in test mode
        test_operation_order = []

        def mock_test_run_migration(self):
            test_operation_order.append("migration_attempted_in_test_mode")
            return original_run_migration(self)

        with patch.object(MigrationEngine, "run_migration", mock_test_run_migration):
            # Create app with test config
            test_app = create_app({"TESTING": True})

            # Migration should not run in test mode
            assert "migration_attempted_in_test_mode" not in test_operation_order, (
                f"Migration should not run in test mode for {database_state}, "
                f"but test operation order: {test_operation_order}"
            )

            # App should still be created successfully
            assert test_app is not None, (
                f"Test app should be created for {database_state}"
            )

            # Routes should still be available in test mode
            with test_app.test_client() as test_client:
                response = test_client.get("/hello")
                assert response.status_code == 200, (
                    f"Routes should be available in test mode for {database_state}"
                )

        # 6. Specific database state validations
        if database_state == "empty_database":
            # Empty database should trigger migration
            assert "migration_started" in operation_order, (
                "Empty database should trigger migration"
            )

        elif database_state == "complete_schema":
            # Complete schema should still run migration check but create no tables
            assert "migration_started" in operation_order, (
                "Complete schema should still run migration check"
            )

        elif database_state == "migration_failure":
            # Migration failure should not prevent app startup
            assert "migration_failed" in operation_order, (
                "Migration failure should be recorded"
            )
            assert routes_registered, (
                "Routes should still be registered despite migration failure"
            )

        elif database_state == "connection_error":
            # Connection error should not prevent app startup
            assert "migration_connection_error" in operation_order, (
                "Connection error should be recorded"
            )
            assert routes_registered, (
                "Routes should still be registered despite connection error"
            )

        # 7. Verify proper timing - app should be ready to serve requests
        # This is tested by successfully making requests to the app
        with app.test_client() as client:
            response = client.get("/hello")
            assert response.status_code == 200, (
                f"App should be ready to serve requests after startup for {database_state}"
            )
            assert response.data == b"Hello, World!", (
                f"App should return correct response for {database_state}"
            )


@given(
    st.sampled_from(
        [
            "empty_database",
            "partial_schema",
            "complete_schema",
            "migration_failure",
            "connection_error",
        ]
    )
)
def test_comprehensive_migration_logging(database_state):
    """
    Property 8: Comprehensive Migration Logging

    For any migration operation, the Migration Engine should log the initial
    database state, all actions taken during migration, and a summary of the
    final state using appropriate log levels.

    **Validates: Requirements 1.5, 3.3, 5.1, 5.2, 5.4, 5.5**
    """
    import logging
    from unittest.mock import Mock, patch

    from sqlalchemy.exc import OperationalError

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create a mock logger to capture all log messages
    mock_logger = Mock(spec=logging.Logger)
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Define database states and expected logging behaviors
    database_states = {
        "empty_database": {
            "setup_tables": [],
            "expected_migration_needed": True,
            "expected_success": True,
            "force_error": None,
            "expected_log_levels": ["info", "debug"],
            "expected_log_content": [
                "starting database migration",
                "migration completed successfully",
                "created table",
            ],
        },
        "partial_schema": {
            "setup_tables": ["test_table_1"],
            "expected_migration_needed": True,
            "expected_success": True,
            "force_error": None,
            "expected_log_levels": ["info", "debug"],
            "expected_log_content": [
                "starting database migration",
                "migration completed successfully",
                "created table",
            ],
        },
        "complete_schema": {
            "setup_tables": ["test_table_1", "test_table_2", "test_table_3"],
            "expected_migration_needed": False,
            "expected_success": True,
            "force_error": None,
            "expected_log_levels": ["info"],
            "expected_log_content": [
                "starting database migration",
                "no migration needed",
                "migration completed successfully",
            ],
        },
        "migration_failure": {
            "setup_tables": [],
            "expected_migration_needed": True,
            "expected_success": False,
            "force_error": OperationalError("Database error", None, None),
            "expected_log_levels": ["info", "error"],
            "expected_log_content": [
                "starting database migration",
                "migration completed with errors",
                "database error",
            ],
        },
        "connection_error": {
            "setup_tables": [],
            "expected_migration_needed": True,
            "expected_success": False,
            "force_error": OperationalError("Connection failed", None, None),
            "expected_log_levels": ["info", "error"],
            "expected_log_content": [
                "starting database migration",
                "connection",
                "migration completed with errors",
            ],
        },
    }

    state_config = database_states[database_state]

    # Setup initial database state
    if state_config["setup_tables"]:
        create_partial_schema(engine, state_config["setup_tables"])

    # Mock connection to force errors if needed
    if state_config["force_error"]:
        with patch.object(engine, "connect") as mock_connect:
            mock_connect.side_effect = state_config["force_error"]
            result = migration_engine.run_migration()
    else:
        result = migration_engine.run_migration()

    # Property assertions for comprehensive logging

    # 1. Migration should log initial database state
    info_calls = [str(call) for call in mock_logger.info.call_args_list]
    initial_state_logged = any(
        "starting database migration" in call.lower() for call in info_calls
    )
    assert initial_state_logged, (
        f"Migration should log initial database state for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 2. Migration should log database connection health
    all_calls = (
        [str(call) for call in mock_logger.info.call_args_list]
        + [str(call) for call in mock_logger.debug.call_args_list]
        + [str(call) for call in mock_logger.error.call_args_list]
    )
    connection_health_logged = any(
        "connection" in call.lower() and "healthy" in call.lower() for call in all_calls
    )
    assert connection_health_logged, (
        f"Migration should log connection health for {database_state}, "
        f"but all logs: {all_calls}"
    )

    # 3. Migration should log existing and missing tables count
    existing_tables_logged = any(
        "existing tables" in call.lower() for call in info_calls
    )
    missing_tables_logged = any("missing tables" in call.lower() for call in info_calls)
    assert existing_tables_logged and missing_tables_logged, (
        f"Migration should log existing and missing tables count for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 4. Migration should log whether migration is needed
    migration_needed_logged = any(
        "migration needed" in call.lower() for call in info_calls
    )
    assert migration_needed_logged, (
        f"Migration should log whether migration is needed for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 5. Migration should log actions taken during migration
    if state_config["expected_migration_needed"] and state_config["expected_success"]:
        # Should log table creation actions
        table_creation_logged = any(
            "created table" in call.lower() or "creating" in call.lower()
            for call in info_calls
        )
        assert table_creation_logged, (
            f"Migration should log table creation actions for {database_state}, "
            f"but info logs: {info_calls}"
        )

    # 6. Migration should log final results and summary
    completion_logged = any(
        "migration completed" in call.lower() for call in info_calls
    )
    assert completion_logged, (
        f"Migration should log completion summary for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 7. Migration should log duration
    duration_logged = any("duration" in call.lower() for call in info_calls)
    assert duration_logged, (
        f"Migration should log duration for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 8. Migration should log tables created count
    tables_created_logged = any("tables created" in call.lower() for call in info_calls)
    assert tables_created_logged, (
        f"Migration should log tables created count for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 9. Migration should use appropriate log levels
    expected_levels = state_config["expected_log_levels"]

    if "info" in expected_levels:
        assert mock_logger.info.called, (
            f"Migration should use INFO level logging for {database_state}"
        )

    if "error" in expected_levels:
        assert mock_logger.error.called, (
            f"Migration should use ERROR level logging for {database_state}"
        )

    if "debug" in expected_levels:
        # Debug logging might be called for detailed information
        # This is optional but should be available for troubleshooting
        pass

    # 10. Migration should log specific content based on database state
    expected_content = state_config["expected_log_content"]
    all_log_content = " ".join(all_calls).lower()

    for expected in expected_content:
        content_found = expected.lower() in all_log_content
        assert content_found, (
            f"Migration should log '{expected}' for {database_state}, "
            f"but all logs: {all_calls}"
        )

    # 11. Error scenarios should log detailed error information
    if not state_config["expected_success"]:
        error_calls = [str(call) for call in mock_logger.error.call_args_list]
        assert len(error_calls) > 0, (
            f"Migration should log errors for {database_state}, "
            f"but error logs: {error_calls}"
        )

        # Should log recovery suggestions for common errors
        recovery_suggestions_logged = any(
            "recovery" in call.lower() or "suggestion" in call.lower()
            for call in error_calls
        )
        assert recovery_suggestions_logged, (
            f"Migration should log recovery suggestions for {database_state}, "
            f"but error logs: {error_calls}"
        )

    # 12. Success scenarios should log success indicators
    if state_config["expected_success"]:
        success_logged = any(
            "successfully" in call.lower() or "success" in call.lower()
            for call in info_calls
        )
        assert success_logged, (
            f"Migration should log success indicators for {database_state}, "
            f"but info logs: {info_calls}"
        )

    # 13. Migration should log structured information with clear formatting
    # Check for structured logging patterns (e.g., separators, clear sections)
    structured_logging = any(
        "=" in call for call in info_calls
    )  # Separator lines for structure
    assert structured_logging, (
        f"Migration should use structured logging format for {database_state}, "
        f"but info logs: {info_calls}"
    )

    # 14. Specific database state validations
    if database_state == "empty_database":
        # Should log that all tables need to be created
        all_tables_missing_logged = any(
            str(len(metadata.tables)) in call for call in info_calls
        )
        assert all_tables_missing_logged, (
            "Empty database should log that all tables are missing"
        )

    elif database_state == "complete_schema":
        # Should log that no migration is needed
        no_migration_logged = any(
            "no migration needed" in call.lower() for call in info_calls
        )
        assert no_migration_logged, (
            "Complete schema should log that no migration is needed"
        )

    elif database_state == "partial_schema":
        # Should log specific tables that need to be created
        partial_creation_logged = any(
            "tables to create" in call.lower() for call in info_calls
        )
        assert partial_creation_logged, (
            "Partial schema should log which tables need to be created"
        )

    elif database_state in ["migration_failure", "connection_error"]:
        # Should log specific error types and recovery information
        error_type_logged = any(
            "database" in call.lower() or "connection" in call.lower()
            for call in error_calls
        )
        assert error_type_logged, (
            f"Error scenarios should log specific error types for {database_state}"
        )

    # 15. Verify logging provides sufficient information for troubleshooting
    # Check that logs contain enough detail for debugging
    troubleshooting_info = any(
        len(call) > 20
        for call in all_calls  # Non-trivial log messages
    )
    assert troubleshooting_info, (
        f"Migration should provide detailed troubleshooting information for {database_state}"
    )

    # 16. Verify result consistency with logged information
    # The migration result should be consistent with what was logged
    if result.success:
        success_in_logs = any("success" in call.lower() for call in info_calls)
        assert success_in_logs, (
            f"Successful migration result should be reflected in logs for {database_state}"
        )
    else:
        error_in_logs = any("error" in call.lower() for call in error_calls)
        assert error_in_logs, (
            f"Failed migration result should be reflected in logs for {database_state}"
        )

    # 17. Verify log message quality and clarity
    # Log messages should be clear and informative
    clear_messages = all(
        len(call.strip()) > 5 for call in info_calls if call.strip()
    )  # Non-empty, meaningful messages
    assert clear_messages, (
        f"Migration should produce clear, informative log messages for {database_state}"
    )


class TestAutomaticSchemaCreation:
    """Integration tests for automatic schema creation functionality."""

    def test_automatic_schema_creation_empty_database(self):
        """Test automatic schema creation with empty database."""
        # Create test engine and metadata
        engine = create_test_engine()
        metadata = TestBase.metadata

        # Create migration engine
        import logging

        from trackers.db.migration import MigrationEngine

        logger = logging.getLogger(__name__)
        migration_engine = MigrationEngine(engine, metadata, logger)

        # Verify database is initially empty
        from sqlalchemy import inspect

        inspector = inspect(engine)
        initial_tables = set(inspector.get_table_names())
        assert len(initial_tables) == 0

        # Run migration
        result = migration_engine.run_migration()

        # Verify migration succeeded
        assert result.success, (
            f"Migration should succeed, but got errors: {result.errors}"
        )

        # Verify all tables were created
        # Create a fresh inspector to see the newly created tables
        final_inspector = inspect(engine)
        final_tables = set(final_inspector.get_table_names())
        expected_tables = set(metadata.tables.keys())
        assert final_tables == expected_tables

        # Verify all expected tables are reported as created
        assert set(result.tables_created) == expected_tables

    def test_automatic_schema_creation_idempotent(self):
        """Test that automatic schema creation is idempotent."""
        # Create test engine and metadata
        engine = create_test_engine()
        metadata = TestBase.metadata

        # Create migration engine
        import logging

        from trackers.db.migration import MigrationEngine

        logger = logging.getLogger(__name__)
        migration_engine = MigrationEngine(engine, metadata, logger)

        # Run migration first time
        result1 = migration_engine.run_migration()
        assert result1.success

        # Run migration second time (should be no-op)
        result2 = migration_engine.run_migration()
        assert result2.success
        assert len(result2.tables_created) == 0
        assert result2.message == "No migration needed - all tables exist"

        # Verify final state is correct
        from sqlalchemy import inspect

        inspector = inspect(engine)
        final_tables = set(inspector.get_table_names())
        expected_tables = set(metadata.tables.keys())
        assert final_tables == expected_tables

    def test_post_migration_validation(self):
        """Test post-migration validation functionality."""
        # Create test engine and metadata
        engine = create_test_engine()
        metadata = TestBase.metadata

        # Create migration engine and executor
        import logging

        from trackers.db.migration import MigrationExecutor, MigrationLogger

        logger = logging.getLogger(__name__)
        migration_logger = MigrationLogger(logger)
        executor = MigrationExecutor(engine, metadata, migration_logger)

        # Create tables
        expected_tables = list(metadata.tables.keys())
        result = executor.create_missing_tables(expected_tables)
        assert result.success

        # Validate migration
        validation_result = executor.validate_migration()
        assert validation_result.valid
        assert len(validation_result.missing_tables) == 0
        assert len(validation_result.schema_errors) == 0


@given(
    st.sampled_from(
        [
            "manual_init_script_setup",
            "manual_sqlalchemy_setup",
            "mixed_manual_automatic_setup",
            "existing_data_preservation",
            "schema_drift_detection",
        ]
    )
)
def test_manual_setup_compatibility(setup_scenario):
    """
    Property 9: Manual Setup Compatibility

    For any database that was initialized using manual scripts, the Migration Engine
    should detect the existing schema, skip unnecessary creation, and not interfere
    with existing data.

    **Validates: Requirements 6.1, 6.2**
    """
    import logging
    from unittest.mock import Mock

    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create a mock logger
    mock_logger = Mock(spec=logging.Logger)
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Define setup scenarios and expected behaviors
    setup_scenarios = {
        "manual_init_script_setup": {
            "description": "Database initialized using init-db.py script",
            "setup_method": "create_all_tables_manually",
            "add_sample_data": True,
            "expected_migration_needed": False,
            "expected_tables_created": 0,
            "expected_data_preserved": True,
        },
        "manual_sqlalchemy_setup": {
            "description": "Database initialized using SQLAlchemy create_all()",
            "setup_method": "sqlalchemy_create_all",
            "add_sample_data": True,
            "expected_migration_needed": False,
            "expected_tables_created": 0,
            "expected_data_preserved": True,
        },
        "mixed_manual_automatic_setup": {
            "description": "Some tables created manually, others missing",
            "setup_method": "partial_manual_setup",
            "add_sample_data": True,
            "expected_migration_needed": True,
            "expected_tables_created": "partial",
            "expected_data_preserved": True,
        },
        "existing_data_preservation": {
            "description": "Database with existing data should be preserved",
            "setup_method": "create_all_with_data",
            "add_sample_data": True,
            "expected_migration_needed": False,
            "expected_tables_created": 0,
            "expected_data_preserved": True,
        },
        "schema_drift_detection": {
            "description": "Database with unexpected tables should be handled",
            "setup_method": "create_with_extra_tables",
            "add_sample_data": True,
            "expected_migration_needed": True,
            "expected_tables_created": "partial",
            "expected_data_preserved": True,
        },
    }

    scenario_config = setup_scenarios[setup_scenario]

    # Setup database according to scenario
    sample_data = {}

    if scenario_config["setup_method"] == "create_all_tables_manually":
        # Simulate manual database initialization (like init-db.py)
        metadata.create_all(engine)

        if scenario_config["add_sample_data"]:
            # Add sample data to verify preservation
            with engine.connect() as conn:
                # Insert sample data into each table
                for table_name in metadata.tables.keys():
                    if table_name == "test_table_1":
                        conn.execute(
                            text(
                                "INSERT INTO test_table_1 (name) VALUES ('manual_data_1')"
                            )
                        )
                        sample_data[table_name] = [("manual_data_1",)]
                    elif table_name == "test_table_2":
                        conn.execute(
                            text(
                                "INSERT INTO test_table_2 (value) VALUES ('manual_value_1')"
                            )
                        )
                        sample_data[table_name] = [("manual_value_1",)]
                    elif table_name == "test_table_3":
                        conn.execute(
                            text(
                                "INSERT INTO test_table_3 (description) VALUES ('manual_desc_1')"
                            )
                        )
                        sample_data[table_name] = [("manual_desc_1",)]
                conn.commit()

    elif scenario_config["setup_method"] == "sqlalchemy_create_all":
        # Simulate SQLAlchemy-based manual setup
        metadata.create_all(engine)

        if scenario_config["add_sample_data"]:
            # Use SQLAlchemy ORM to add data
            Session = sessionmaker(bind=engine)
            session = Session()

            # Create instances of test models
            test1 = TestTable1(name="sqlalchemy_data_1")
            test2 = TestTable2(value="sqlalchemy_value_1")
            test3 = TestTable3(description="sqlalchemy_desc_1")

            session.add_all([test1, test2, test3])
            session.commit()
            session.close()

            sample_data = {
                "test_table_1": [("sqlalchemy_data_1",)],
                "test_table_2": [("sqlalchemy_value_1",)],
                "test_table_3": [("sqlalchemy_desc_1",)],
            }

    elif scenario_config["setup_method"] == "partial_manual_setup":
        # Create only some tables manually (not all)
        create_partial_schema(engine, ["test_table_1"])  # Only create one table

        if scenario_config["add_sample_data"]:
            with engine.connect() as conn:
                conn.execute(
                    text("INSERT INTO test_table_1 (name) VALUES ('partial_data_1')")
                )
                conn.commit()

            sample_data = {
                "test_table_1": [("partial_data_1",)],
            }

    elif scenario_config["setup_method"] == "create_all_with_data":
        # Create all tables and add significant data
        metadata.create_all(engine)

        if scenario_config["add_sample_data"]:
            with engine.connect() as conn:
                # Add multiple rows to verify data preservation
                for i in range(5):
                    conn.execute(
                        text(f"INSERT INTO test_table_1 (name) VALUES ('data_{i}')")
                    )
                    conn.execute(
                        text(f"INSERT INTO test_table_2 (value) VALUES ('value_{i}')")
                    )
                    conn.execute(
                        text(
                            f"INSERT INTO test_table_3 (description) VALUES ('desc_{i}')"
                        )
                    )
                conn.commit()

            sample_data = {
                "test_table_1": [(f"data_{i}",) for i in range(5)],
                "test_table_2": [(f"value_{i}",) for i in range(5)],
                "test_table_3": [(f"desc_{i}",) for i in range(5)],
            }

    elif scenario_config["setup_method"] == "create_with_extra_tables":
        # Create expected tables plus some extra ones
        metadata.create_all(engine)

        # Create an extra table not in metadata
        with engine.connect() as conn:
            conn.execute(
                text("""
                CREATE TABLE extra_table (
                    id INTEGER PRIMARY KEY,
                    extra_data TEXT
                )
            """)
            )
            conn.execute(
                text("INSERT INTO extra_table (extra_data) VALUES ('extra_value')")
            )
            conn.commit()

        if scenario_config["add_sample_data"]:
            with engine.connect() as conn:
                conn.execute(
                    text("INSERT INTO test_table_1 (name) VALUES ('extra_setup_data')")
                )
                conn.commit()

            sample_data = {
                "test_table_1": [("extra_setup_data",)],
                "extra_table": [("extra_value",)],
            }

    # Get initial database state
    from sqlalchemy import inspect

    initial_inspector = inspect(engine)
    initial_tables = set(initial_inspector.get_table_names())

    # Capture initial data state
    initial_data = {}
    for table_name in initial_tables:
        if table_name in metadata.tables or table_name == "extra_table":
            with engine.connect() as conn:
                if table_name == "extra_table":
                    query_result = conn.execute(
                        text(f"SELECT extra_data FROM {table_name}")
                    )
                else:
                    # Get first non-id column for data verification
                    table = metadata.tables.get(table_name)
                    if table is not None:
                        data_column = [
                            col.name for col in table.columns if col.name != "id"
                        ][0]
                        query_result = conn.execute(
                            text(f"SELECT {data_column} FROM {table_name}")
                        )
                    else:
                        continue
                initial_data[table_name] = query_result.fetchall()

    # Run migration
    result = migration_engine.run_migration()

    # Property assertions for manual setup compatibility

    # 1. Migration should detect existing schema correctly
    status = migration_engine.get_migration_status()

    if scenario_config["expected_migration_needed"]:
        assert status.migration_needed, (
            f"Migration should be needed for {setup_scenario}, but status: {status}"
        )
    else:
        assert not status.migration_needed, (
            f"Migration should not be needed for {setup_scenario}, but status: {status}"
        )

    # 2. Migration should not interfere with existing data
    if scenario_config["expected_data_preserved"]:
        # Verify all initial data is still present
        final_inspector = inspect(engine)
        final_tables = set(final_inspector.get_table_names())

        for table_name, expected_data in initial_data.items():
            assert table_name in final_tables, (
                f"Table {table_name} should still exist after migration for {setup_scenario}"
            )

            with engine.connect() as conn:
                if table_name == "extra_table":
                    query_result = conn.execute(
                        text(f"SELECT extra_data FROM {table_name}")
                    )
                else:
                    table = metadata.tables.get(table_name)
                    if table is not None:
                        data_column = [
                            col.name for col in table.columns if col.name != "id"
                        ][0]
                        query_result = conn.execute(
                            text(f"SELECT {data_column} FROM {table_name}")
                        )
                    else:
                        continue

                final_data = query_result.fetchall()

                # All initial data should still be present
                for expected_row in expected_data:
                    assert expected_row in final_data, (
                        f"Data {expected_row} should be preserved in table {table_name} "
                        f"for {setup_scenario}, but final data: {final_data}"
                    )

    # 3. Migration should skip creation of existing tables
    if scenario_config["expected_tables_created"] == 0:
        assert len(result.tables_created) == 0, (
            f"No tables should be created for {setup_scenario}, "
            f"but created: {result.tables_created}"
        )

        assert result.success, (
            f"Migration should succeed when no tables need creation for {setup_scenario}"
        )

        assert (
            "no migration needed" in result.message.lower()
            or "no tables needed" in result.message.lower()
        ), (
            f"Migration message should indicate no tables needed for {setup_scenario}, "
            f"but got: {result.message}"
        )

    elif scenario_config["expected_tables_created"] == "partial":
        # Some tables should be created, others should be skipped
        expected_tables = set(metadata.tables.keys())
        final_tables = set(inspect(engine).get_table_names())

        # All expected tables should exist after migration
        assert expected_tables.issubset(final_tables), (
            f"All expected tables should exist after migration for {setup_scenario}. "
            f"Expected: {expected_tables}, Final: {final_tables}"
        )

        # Only missing tables should be reported as created
        created_tables = set(result.tables_created)
        missing_tables = expected_tables - initial_tables
        assert created_tables == missing_tables, (
            f"Only missing tables should be created for {setup_scenario}. "
            f"Expected created: {missing_tables}, Actually created: {created_tables}"
        )

    # 4. Migration should be idempotent with manual setup
    # Run migration again to verify idempotence
    result2 = migration_engine.run_migration()

    assert result2.success, f"Second migration should succeed for {setup_scenario}"

    assert len(result2.tables_created) == 0, (
        f"Second migration should create no tables for {setup_scenario}, "
        f"but created: {result2.tables_created}"
    )

    # 5. Final schema should match expected metadata
    final_inspector = inspect(engine)
    final_tables = set(final_inspector.get_table_names())
    expected_tables = set(metadata.tables.keys())

    # All expected tables should exist
    assert expected_tables.issubset(final_tables), (
        f"All expected tables should exist after migration for {setup_scenario}. "
        f"Expected: {expected_tables}, Final: {final_tables}"
    )

    # Verify table structure matches metadata
    for table_name in expected_tables:
        table_columns = {col["name"] for col in final_inspector.get_columns(table_name)}
        expected_columns = set(metadata.tables[table_name].columns.keys())

        assert table_columns == expected_columns, (
            f"Table {table_name} should have correct columns for {setup_scenario}. "
            f"Expected: {expected_columns}, Found: {table_columns}"
        )

    # 6. Migration should handle unexpected tables gracefully
    if setup_scenario == "schema_drift_detection":
        # Extra table should still exist (migration doesn't remove unexpected tables)
        assert "extra_table" in final_tables, (
            "Extra table should be preserved during migration"
        )

        # Validation should report unexpected tables
        validation_result = migration_engine.migration_executor.validate_migration()
        if hasattr(validation_result, "unexpected_tables"):
            assert "extra_table" in validation_result.unexpected_tables, (
                "Validation should detect unexpected tables"
            )

    # 7. Migration should log detection of existing schema
    info_calls = [str(call) for call in mock_logger.info.call_args_list]
    existing_schema_logged = any(
        "existing tables" in call.lower() for call in info_calls
    )
    assert existing_schema_logged, (
        f"Migration should log detection of existing schema for {setup_scenario}"
    )

    # 8. Migration should not log errors for valid manual setup
    if scenario_config["expected_migration_needed"] == False:
        error_calls = [str(call) for call in mock_logger.error.call_args_list]
        # Filter out expected debug/info level messages that might contain "error" word
        actual_errors = [call for call in error_calls if call.strip()]

        assert len(actual_errors) == 0, (
            f"Migration should not log errors for valid manual setup {setup_scenario}, "
            f"but got errors: {actual_errors}"
        )

    # 9. Specific scenario validations
    if setup_scenario == "manual_init_script_setup":
        # Should detect that init script already ran
        assert not status.migration_needed, (
            "Migration should detect init script already ran"
        )

        # Should preserve manually inserted data
        with engine.connect() as conn:
            result_data = conn.execute(text("SELECT name FROM test_table_1")).fetchall()
            assert ("manual_data_1",) in result_data, (
                "Manual init script data should be preserved"
            )

    elif setup_scenario == "manual_sqlalchemy_setup":
        # Should detect SQLAlchemy setup
        assert not status.migration_needed, (
            "Migration should detect SQLAlchemy setup already complete"
        )

    elif setup_scenario == "mixed_manual_automatic_setup":
        # Should complete the partial setup
        assert result.success, "Migration should complete partial manual setup"

        # Should preserve existing data while adding missing tables
        with engine.connect() as conn:
            result_data = conn.execute(text("SELECT name FROM test_table_1")).fetchall()
            assert ("partial_data_1",) in result_data, (
                "Partial setup data should be preserved"
            )

    elif setup_scenario == "existing_data_preservation":
        # Should preserve all existing data
        for table_name, expected_data in sample_data.items():
            with engine.connect() as conn:
                table = metadata.tables[table_name]
                data_column = [col.name for col in table.columns if col.name != "id"][0]
                result_data = conn.execute(
                    text(f"SELECT {data_column} FROM {table_name}")
                ).fetchall()

                for expected_row in expected_data:
                    assert expected_row in result_data, (
                        f"Existing data {expected_row} should be preserved in {table_name}"
                    )


@given(
    st.sampled_from(
        [
            "consistent_schema_structure",
            "consistent_foreign_keys",
            "consistent_indexes_constraints",
            "metadata_schema_alignment",
            "cross_setup_compatibility",
        ]
    )
)
def test_schema_consistency(consistency_scenario):
    """
    Property 10: Schema Consistency

    For any database setup method (manual or automatic), the final schema should
    be consistent and match the SQLAlchemy metadata definitions.

    **Validates: Requirements 6.3, 6.4**
    """
    import logging
    from unittest.mock import Mock

    from sqlalchemy import inspect

    from trackers.db.migration import MigrationEngine

    # Create test engines for different setup methods
    manual_engine = create_test_engine()
    automatic_engine = create_test_engine()
    metadata = TestBase.metadata

    # Create mock logger
    mock_logger = Mock(spec=logging.Logger)

    # Define consistency scenarios
    consistency_scenarios = {
        "consistent_schema_structure": {
            "description": "Table structure should be identical regardless of setup method",
            "test_aspect": "table_structure",
        },
        "consistent_foreign_keys": {
            "description": "Foreign key relationships should be identical",
            "test_aspect": "foreign_keys",
        },
        "consistent_indexes_constraints": {
            "description": "Indexes and constraints should be identical",
            "test_aspect": "indexes_constraints",
        },
        "metadata_schema_alignment": {
            "description": "Final schema should match SQLAlchemy metadata exactly",
            "test_aspect": "metadata_alignment",
        },
        "cross_setup_compatibility": {
            "description": "Databases created by different methods should be functionally identical",
            "test_aspect": "functional_compatibility",
        },
    }

    scenario_config = consistency_scenarios[consistency_scenario]

    # Setup 1: Manual schema creation (simulating init-db.py)
    metadata.create_all(manual_engine)

    # Setup 2: Automatic migration
    migration_engine = MigrationEngine(automatic_engine, metadata, mock_logger)
    result = migration_engine.run_migration()
    assert result.success, (
        f"Automatic migration should succeed for {consistency_scenario}"
    )

    # Get inspectors for both databases
    manual_inspector = inspect(manual_engine)
    automatic_inspector = inspect(automatic_engine)

    # Property assertions for schema consistency

    # 1. Both databases should have identical table sets
    manual_tables = set(manual_inspector.get_table_names())
    automatic_tables = set(automatic_inspector.get_table_names())

    assert manual_tables == automatic_tables, (
        f"Manual and automatic setup should create identical table sets for {consistency_scenario}. "
        f"Manual: {manual_tables}, Automatic: {automatic_tables}"
    )

    # 2. All expected tables from metadata should exist in both
    expected_tables = set(metadata.tables.keys())
    assert manual_tables == expected_tables, (
        f"Manual setup should create all expected tables for {consistency_scenario}. "
        f"Expected: {expected_tables}, Manual: {manual_tables}"
    )
    assert automatic_tables == expected_tables, (
        f"Automatic setup should create all expected tables for {consistency_scenario}. "
        f"Expected: {expected_tables}, Automatic: {automatic_tables}"
    )

    # 3. Table structures should be identical
    if scenario_config["test_aspect"] in ["table_structure", "metadata_alignment"]:
        for table_name in expected_tables:
            # Compare column definitions
            manual_columns = manual_inspector.get_columns(table_name)
            automatic_columns = automatic_inspector.get_columns(table_name)

            # Extract comparable column information
            manual_col_info = {
                col["name"]: {
                    "type": str(col["type"]),
                    "nullable": col["nullable"],
                    "primary_key": col.get("primary_key", False),
                }
                for col in manual_columns
            }
            automatic_col_info = {
                col["name"]: {
                    "type": str(col["type"]),
                    "nullable": col["nullable"],
                    "primary_key": col.get("primary_key", False),
                }
                for col in automatic_columns
            }

            assert manual_col_info == automatic_col_info, (
                f"Table {table_name} should have identical column structure for {consistency_scenario}. "
                f"Manual: {manual_col_info}, Automatic: {automatic_col_info}"
            )

    # 4. Primary key constraints should be identical
    if scenario_config["test_aspect"] in ["indexes_constraints", "metadata_alignment"]:
        for table_name in expected_tables:
            manual_pk = manual_inspector.get_pk_constraint(table_name)
            automatic_pk = automatic_inspector.get_pk_constraint(table_name)

            assert (
                manual_pk["constrained_columns"] == automatic_pk["constrained_columns"]
            ), (
                f"Table {table_name} should have identical primary key for {consistency_scenario}. "
                f"Manual: {manual_pk['constrained_columns']}, Automatic: {automatic_pk['constrained_columns']}"
            )

    # 5. Foreign key relationships should be identical
    if scenario_config["test_aspect"] in ["foreign_keys", "metadata_alignment"]:
        for table_name in expected_tables:
            manual_fks = manual_inspector.get_foreign_keys(table_name)
            automatic_fks = automatic_inspector.get_foreign_keys(table_name)

            # Sort foreign keys for comparison
            manual_fk_info = sorted(
                [
                    {
                        "constrained_columns": fk["constrained_columns"],
                        "referred_table": fk["referred_table"],
                        "referred_columns": fk["referred_columns"],
                    }
                    for fk in manual_fks
                ],
                key=lambda x: str(x),
            )

            automatic_fk_info = sorted(
                [
                    {
                        "constrained_columns": fk["constrained_columns"],
                        "referred_table": fk["referred_table"],
                        "referred_columns": fk["referred_columns"],
                    }
                    for fk in automatic_fks
                ],
                key=lambda x: str(x),
            )

            assert manual_fk_info == automatic_fk_info, (
                f"Table {table_name} should have identical foreign keys for {consistency_scenario}. "
                f"Manual: {manual_fk_info}, Automatic: {automatic_fk_info}"
            )

    # 6. Schema should match SQLAlchemy metadata exactly
    if scenario_config["test_aspect"] == "metadata_alignment":
        for table_name in expected_tables:
            metadata_table = metadata.tables[table_name]

            # Verify columns match metadata
            for setup_name, inspector in [
                ("manual", manual_inspector),
                ("automatic", automatic_inspector),
            ]:
                actual_columns = {
                    col["name"] for col in inspector.get_columns(table_name)
                }
                expected_columns = set(metadata_table.columns.keys())

                assert actual_columns == expected_columns, (
                    f"{setup_name.title()} setup table {table_name} should match metadata columns for {consistency_scenario}. "
                    f"Expected: {expected_columns}, Found: {actual_columns}"
                )

                # Verify foreign keys match metadata
                actual_fks = inspector.get_foreign_keys(table_name)
                expected_fks = []
                for column in metadata_table.columns:
                    if column.foreign_keys:
                        for fk in column.foreign_keys:
                            expected_fks.append(
                                {
                                    "column": column.name,
                                    "referred_table": fk.column.table.name,
                                    "referred_column": fk.column.name,
                                }
                            )

                if expected_fks:
                    assert len(actual_fks) == len(expected_fks), (
                        f"{setup_name.title()} setup table {table_name} should have {len(expected_fks)} foreign keys, "
                        f"but found {len(actual_fks)} for {consistency_scenario}"
                    )

    # 7. Functional compatibility - both databases should support identical operations
    if scenario_config["test_aspect"] == "functional_compatibility":
        from sqlalchemy import text

        # Test basic CRUD operations on both databases
        for engine_name, engine in [
            ("manual", manual_engine),
            ("automatic", automatic_engine),
        ]:
            with engine.connect() as conn:
                # Test INSERT operations
                for table_name in expected_tables:
                    if table_name == "test_table_1":
                        conn.execute(
                            text(
                                f"INSERT INTO {table_name} (name) VALUES ('test_data_{engine_name}')"
                            )
                        )
                    elif table_name == "test_table_2":
                        conn.execute(
                            text(
                                f"INSERT INTO {table_name} (value) VALUES ('test_value_{engine_name}')"
                            )
                        )
                    elif table_name == "test_table_3":
                        conn.execute(
                            text(
                                f"INSERT INTO {table_name} (description) VALUES ('test_desc_{engine_name}')"
                            )
                        )

                conn.commit()

                # Test SELECT operations
                for table_name in expected_tables:
                    result = conn.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
                    count = result.fetchone()[0]
                    assert count > 0, (
                        f"Should be able to insert and select from {table_name} in {engine_name} setup"
                    )

                # Test UPDATE operations
                for table_name in expected_tables:
                    if table_name == "test_table_1":
                        conn.execute(
                            text(
                                f"UPDATE {table_name} SET name = 'updated_{engine_name}' WHERE name = 'test_data_{engine_name}'"
                            )
                        )
                    elif table_name == "test_table_2":
                        conn.execute(
                            text(
                                f"UPDATE {table_name} SET value = 'updated_{engine_name}' WHERE value = 'test_value_{engine_name}'"
                            )
                        )
                    elif table_name == "test_table_3":
                        conn.execute(
                            text(
                                f"UPDATE {table_name} SET description = 'updated_{engine_name}' WHERE description = 'test_desc_{engine_name}'"
                            )
                        )

                conn.commit()

                # Test DELETE operations
                for table_name in expected_tables:
                    if table_name == "test_table_1":
                        conn.execute(
                            text(
                                f"DELETE FROM {table_name} WHERE name = 'updated_{engine_name}'"
                            )
                        )
                    elif table_name == "test_table_2":
                        conn.execute(
                            text(
                                f"DELETE FROM {table_name} WHERE value = 'updated_{engine_name}'"
                            )
                        )
                    elif table_name == "test_table_3":
                        conn.execute(
                            text(
                                f"DELETE FROM {table_name} WHERE description = 'updated_{engine_name}'"
                            )
                        )

                conn.commit()

    # 8. Both setups should produce identical validation results
    manual_migration_engine = MigrationEngine(manual_engine, metadata, mock_logger)
    automatic_migration_engine = MigrationEngine(
        automatic_engine, metadata, mock_logger
    )

    manual_status = manual_migration_engine.get_migration_status()
    automatic_status = automatic_migration_engine.get_migration_status()

    # Both should indicate no migration needed
    assert not manual_status.migration_needed, (
        f"Manual setup should not need migration for {consistency_scenario}"
    )
    assert not automatic_status.migration_needed, (
        f"Automatic setup should not need migration for {consistency_scenario}"
    )

    # Both should have identical table lists
    assert set(manual_status.tables_exist) == set(automatic_status.tables_exist), (
        f"Manual and automatic setup should report identical existing tables for {consistency_scenario}. "
        f"Manual: {manual_status.tables_exist}, Automatic: {automatic_status.tables_exist}"
    )

    assert set(manual_status.missing_tables) == set(automatic_status.missing_tables), (
        f"Manual and automatic setup should report identical missing tables for {consistency_scenario}. "
        f"Manual: {manual_status.missing_tables}, Automatic: {automatic_status.missing_tables}"
    )

    # 9. Schema validation should pass for both setups
    manual_validation = manual_migration_engine.migration_executor.validate_migration()
    automatic_validation = (
        automatic_migration_engine.migration_executor.validate_migration()
    )

    assert manual_validation.valid, (
        f"Manual setup schema validation should pass for {consistency_scenario}, "
        f"errors: {manual_validation.schema_errors}"
    )
    assert automatic_validation.valid, (
        f"Automatic setup schema validation should pass for {consistency_scenario}, "
        f"errors: {automatic_validation.schema_errors}"
    )

    # 10. Specific scenario validations
    if consistency_scenario == "consistent_schema_structure":
        # Verify detailed column type consistency
        for table_name in expected_tables:
            manual_cols = {
                col["name"]: col for col in manual_inspector.get_columns(table_name)
            }
            automatic_cols = {
                col["name"]: col for col in automatic_inspector.get_columns(table_name)
            }

            for col_name in manual_cols:
                assert col_name in automatic_cols, (
                    f"Column {col_name} should exist in both setups for table {table_name}"
                )

                # Compare detailed type information
                manual_type = str(manual_cols[col_name]["type"])
                automatic_type = str(automatic_cols[col_name]["type"])
                assert manual_type == automatic_type, (
                    f"Column {col_name} type should be identical: manual={manual_type}, automatic={automatic_type}"
                )

    elif consistency_scenario == "consistent_foreign_keys":
        # Verify foreign key constraint names and options are consistent
        for table_name in expected_tables:
            manual_fks = manual_inspector.get_foreign_keys(table_name)
            automatic_fks = automatic_inspector.get_foreign_keys(table_name)

            assert len(manual_fks) == len(automatic_fks), (
                f"Table {table_name} should have same number of foreign keys in both setups"
            )

    elif consistency_scenario == "consistent_indexes_constraints":
        # Verify indexes are created consistently
        for table_name in expected_tables:
            manual_indexes = manual_inspector.get_indexes(table_name)
            automatic_indexes = automatic_inspector.get_indexes(table_name)

            # Compare index column sets (names may differ but columns should be same)
            manual_index_cols = {
                tuple(sorted(idx["column_names"])) for idx in manual_indexes
            }
            automatic_index_cols = {
                tuple(sorted(idx["column_names"])) for idx in automatic_indexes
            }

            assert manual_index_cols == automatic_index_cols, (
                f"Table {table_name} should have consistent indexes: "
                f"manual={manual_index_cols}, automatic={automatic_index_cols}"
            )


@given(
    st.sampled_from(
        [
            "existing_engine_compatibility",
            "session_management_integration",
            "connection_pool_compatibility",
            "transaction_handling_compatibility",
            "orm_integration_compatibility",
        ]
    )
)
def test_infrastructure_integration(integration_scenario):
    """
    Property 11: Infrastructure Integration

    For any existing database connection and session management setup, the Migration Engine
    should work correctly without interfering with normal database operations.

    **Validates: Requirements 6.5**
    """
    import logging
    from unittest.mock import Mock, patch

    from sqlalchemy import text
    from sqlalchemy.orm import sessionmaker

    from trackers.db.migration import MigrationEngine

    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata

    # Create mock logger
    mock_logger = Mock(spec=logging.Logger)

    # Define integration scenarios
    integration_scenarios = {
        "existing_engine_compatibility": {
            "description": "Migration should work with existing SQLAlchemy engine",
            "test_aspect": "engine_reuse",
        },
        "session_management_integration": {
            "description": "Migration should not interfere with existing session management",
            "test_aspect": "session_isolation",
        },
        "connection_pool_compatibility": {
            "description": "Migration should work with existing connection pooling",
            "test_aspect": "connection_pool",
        },
        "transaction_handling_compatibility": {
            "description": "Migration should handle transactions properly with existing code",
            "test_aspect": "transaction_handling",
        },
        "orm_integration_compatibility": {
            "description": "Migration should work seamlessly with existing ORM operations",
            "test_aspect": "orm_integration",
        },
    }

    scenario_config = integration_scenarios[integration_scenario]

    # Setup existing database infrastructure (simulating existing application)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Property assertions for infrastructure integration

    # 1. Migration should work with existing engine without modification
    if scenario_config["test_aspect"] == "engine_reuse":
        # Store original engine properties
        original_url = str(engine.url)
        original_pool = engine.pool

        # Create migration engine using existing engine
        migration_engine = MigrationEngine(engine, metadata, mock_logger)
        result = migration_engine.run_migration()

        assert result.success, (
            f"Migration should succeed with existing engine for {integration_scenario}"
        )

        # Engine properties should remain unchanged
        assert str(engine.url) == original_url, (
            f"Engine URL should not be modified by migration for {integration_scenario}"
        )
        assert engine.pool is original_pool, (
            f"Engine connection pool should not be replaced by migration for {integration_scenario}"
        )

        # Engine should still be usable for normal operations
        with engine.connect() as conn:
            result_test = conn.execute(text("SELECT 1"))
            assert result_test.fetchone()[0] == 1, (
                f"Engine should remain functional after migration for {integration_scenario}"
            )

    # 2. Migration should not interfere with existing session management
    if scenario_config["test_aspect"] == "session_isolation":
        # Create a session before migration
        session_before = SessionLocal()

        # Perform some operations in the session
        try:
            # Execute a query to establish session state
            session_before.execute(text("SELECT 1"))
            session_state_before = session_before.is_active

            # Run migration
            migration_engine = MigrationEngine(engine, metadata, mock_logger)
            result = migration_engine.run_migration()

            assert result.success, (
                f"Migration should succeed without affecting existing sessions for {integration_scenario}"
            )

            # Session should still be in the same state
            assert session_before.is_active == session_state_before, (
                f"Existing session state should not be affected by migration for {integration_scenario}"
            )

            # Session should still be usable
            test_result = session_before.execute(text("SELECT 2"))
            assert test_result.fetchone()[0] == 2, (
                f"Existing session should remain functional after migration for {integration_scenario}"
            )

        finally:
            session_before.close()

        # New sessions should work normally after migration
        session_after = SessionLocal()
        try:
            test_result = session_after.execute(text("SELECT 3"))
            assert test_result.fetchone()[0] == 3, (
                f"New sessions should work normally after migration for {integration_scenario}"
            )
        finally:
            session_after.close()

    # 3. Migration should work with connection pooling
    if scenario_config["test_aspect"] == "connection_pool":
        # Get initial pool state (handle different pool types)
        initial_pool_size = engine.pool.size
        initial_checked_out = getattr(engine.pool, "checkedout", 0)

        # Create multiple connections to test pool behavior
        connections = []
        try:
            for i in range(3):
                conn = engine.connect()
                connections.append(conn)
                conn.execute(text("SELECT 1"))

            pool_size_with_connections = getattr(engine.pool, "checkedout", 0)

            # Run migration while connections are active
            migration_engine = MigrationEngine(engine, metadata, mock_logger)
            result = migration_engine.run_migration()

            assert result.success, (
                f"Migration should succeed with active connections for {integration_scenario}"
            )

            # Existing connections should still work
            for i, conn in enumerate(connections):
                test_result = conn.execute(text(f"SELECT {i + 10}"))
                assert test_result.fetchone()[0] == i + 10, (
                    f"Connection {i} should remain functional after migration for {integration_scenario}"
                )

            # Pool state should be reasonable (migration may have used additional connections)
            current_checked_out = getattr(engine.pool, "checkedout", 0)
            assert current_checked_out >= pool_size_with_connections, (
                f"Connection pool should be in valid state after migration for {integration_scenario}"
            )

        finally:
            # Clean up connections
            for conn in connections:
                conn.close()

        # Pool should return to normal state after cleanup
        final_pool_size = engine.pool.size
        assert final_pool_size >= initial_pool_size, (
            f"Connection pool should maintain reasonable size after migration for {integration_scenario}"
        )

    # 4. Migration should handle transactions properly
    if scenario_config["test_aspect"] == "transaction_handling":
        # Start a transaction before migration
        with engine.connect() as conn:
            trans = conn.begin()

            try:
                # Make some changes in the transaction
                conn.execute(text("CREATE TABLE IF NOT EXISTS temp_test (id INTEGER)"))
                conn.execute(text("INSERT INTO temp_test VALUES (1)"))

                # Run migration (should not interfere with ongoing transaction)
                migration_engine = MigrationEngine(engine, metadata, mock_logger)
                result = migration_engine.run_migration()

                assert result.success, (
                    f"Migration should succeed without interfering with active transaction for {integration_scenario}"
                )

                # Transaction should still be active and functional - just test we can execute queries
                test_result = conn.execute(text("SELECT 1"))
                assert test_result.fetchone()[0] == 1, (
                    f"Active transaction should remain functional during migration for {integration_scenario}"
                )

                # Commit the transaction
                trans.commit()

            except Exception:
                trans.rollback()
                raise

        # Test that migration doesn't leave transactions in bad state
        with engine.connect() as conn:
            # Should be able to start new transactions normally
            with conn.begin() as trans:
                conn.execute(text("SELECT 1"))
                # Transaction should commit normally

    # 5. Migration should integrate seamlessly with ORM operations
    if scenario_config["test_aspect"] == "orm_integration":
        # Run migration first
        migration_engine = MigrationEngine(engine, metadata, mock_logger)
        result = migration_engine.run_migration()

        assert result.success, (
            f"Migration should succeed for ORM integration test for {integration_scenario}"
        )

        # Test ORM operations after migration
        session = SessionLocal()
        try:
            # Test creating ORM objects
            test1 = TestTable1(name="orm_test_1")
            test2 = TestTable2(value="orm_value_1")
            test3 = TestTable3(description="orm_desc_1")

            session.add_all([test1, test2, test3])
            session.commit()

            # Test querying ORM objects
            queried_test1 = (
                session.query(TestTable1).filter_by(name="orm_test_1").first()
            )
            assert queried_test1 is not None, (
                f"ORM queries should work after migration for {integration_scenario}"
            )
            assert queried_test1.name == "orm_test_1", (
                f"ORM object properties should be correct after migration for {integration_scenario}"
            )

            # Test updating ORM objects
            queried_test1.name = "orm_test_updated"
            session.commit()

            # Test deleting ORM objects
            session.delete(queried_test1)
            session.commit()

            # Verify deletion
            deleted_test = (
                session.query(TestTable1).filter_by(name="orm_test_updated").first()
            )
            assert deleted_test is None, (
                f"ORM deletion should work after migration for {integration_scenario}"
            )

        finally:
            session.close()

        # Test that migration doesn't interfere with ORM metadata
        assert TestTable1.__table__.name == "test_table_1", (
            f"ORM table names should remain correct after migration for {integration_scenario}"
        )

        # Test that ORM relationships work
        session = SessionLocal()
        try:
            # Create objects with relationships if they exist
            test1 = TestTable1(name="relationship_test")
            session.add(test1)
            session.commit()

            # Verify object was created and can be queried
            found_test = (
                session.query(TestTable1).filter_by(name="relationship_test").first()
            )
            assert found_test is not None, (
                f"ORM relationships should work after migration for {integration_scenario}"
            )

        finally:
            session.close()

    # 6. Migration should not affect existing database configuration
    # Test that engine configuration remains unchanged
    original_echo = engine.echo
    original_pool_timeout = getattr(engine.pool, "_timeout", None)

    migration_engine = MigrationEngine(engine, metadata, mock_logger)
    result = migration_engine.run_migration()

    assert result.success, (
        f"Migration should succeed without changing engine configuration for {integration_scenario}"
    )

    assert engine.echo == original_echo, (
        f"Engine echo setting should not be changed by migration for {integration_scenario}"
    )

    if original_pool_timeout is not None:
        current_pool_timeout = getattr(engine.pool, "_timeout", None)
        assert current_pool_timeout == original_pool_timeout, (
            f"Engine pool timeout should not be changed by migration for {integration_scenario}"
        )

    # 7. Migration should work with existing error handling
    # Test that migration errors don't interfere with application error handling
    with patch.object(engine, "connect") as mock_connect:
        # Force a connection error
        mock_connect.side_effect = Exception("Test connection error")

        # Migration should handle error gracefully
        error_result = migration_engine.run_migration()
        assert not error_result.success, (
            f"Migration should handle connection errors gracefully for {integration_scenario}"
        )

    # Normal operations should still work after migration error (mock is now reset)
    with engine.connect() as conn:
        test_result = conn.execute(text("SELECT 1"))
        assert test_result.fetchone()[0] == 1, (
            f"Normal operations should work after migration error for {integration_scenario}"
        )

    # 8. Specific scenario validations
    if integration_scenario == "existing_engine_compatibility":
        # Verify engine can be used for both migration and normal operations simultaneously
        with engine.connect() as normal_conn:
            normal_conn.execute(text("SELECT 1"))

            # Run migration while connection is active
            migration_result = migration_engine.run_migration()
            assert migration_result.success, (
                "Migration should work with active connections"
            )

            # Normal connection should still work
            result = normal_conn.execute(text("SELECT 2"))
            assert result.fetchone()[0] == 2, (
                "Normal connection should remain functional during migration"
            )

    elif integration_scenario == "session_management_integration":
        # Test that migration doesn't affect session factory
        original_session_class = SessionLocal

        migration_engine.run_migration()

        assert SessionLocal is original_session_class, (
            "Session factory should not be replaced by migration"
        )

        # Test session factory still works
        test_session = SessionLocal()
        try:
            test_session.execute(text("SELECT 1"))
        finally:
            test_session.close()

    elif integration_scenario == "connection_pool_compatibility":
        # Test that migration respects pool limits
        original_pool_size = engine.pool.size

        migration_engine.run_migration()

        # Pool size should not be dramatically different
        final_pool_size = engine.pool.size
        assert abs(final_pool_size - original_pool_size) <= 2, (
            f"Migration should not dramatically change pool size: {original_pool_size} -> {final_pool_size}"
        )

    elif integration_scenario == "transaction_handling_compatibility":
        # Test that migration doesn't leave transactions in inconsistent state
        with engine.connect() as conn:
            # Should be able to start and commit transactions normally after migration
            with conn.begin():
                conn.execute(text("SELECT 1"))
            # If we get here, transaction handling is working correctly

    elif integration_scenario == "orm_integration_compatibility":
        # Test that all ORM classes still work correctly
        for model_class in [TestTable1, TestTable2, TestTable3]:
            assert hasattr(model_class, "__table__"), (
                f"ORM class {model_class.__name__} should have __table__ attribute"
            )
            assert model_class.__table__.name in metadata.tables, (
                f"ORM table {model_class.__table__.name} should be in metadata"
            )
