"""
Basic tests for migration functionality to verify production enhancements don't break core features.
"""

import logging
from unittest.mock import Mock

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import declarative_base

from trackers.db.migration import MigrationEngine

# Create a test base for testing
TestBase = declarative_base()


class TestTable1(TestBase):
    __tablename__ = "test_table_1"
    id = Column(Integer, primary_key=True)
    name = Column(String(50))


def create_test_engine():
    """Create a temporary SQLite engine for testing."""
    return create_engine("sqlite:///:memory:")


def test_basic_migration_functionality():
    """Test that basic migration functionality still works with production enhancements."""
    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata
    mock_logger = Mock(spec=logging.Logger)

    # Create migration engine
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Run migration
    result = migration_engine.run_migration()

    # Verify migration succeeded
    assert result.success, f"Migration should succeed, but got errors: {result.errors}"
    assert len(result.tables_created) > 0, "Migration should create tables"
    assert "test_table_1" in result.tables_created, "Should create test_table_1"

    # Verify table was actually created
    from sqlalchemy import inspect

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    assert "test_table_1" in tables, "Table should exist in database"


def test_migration_idempotence():
    """Test that running migration multiple times is safe."""
    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata
    mock_logger = Mock(spec=logging.Logger)

    # Create migration engine
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Run first migration
    result1 = migration_engine.run_migration()
    assert result1.success, "First migration should succeed"

    # Run second migration
    result2 = migration_engine.run_migration()
    assert result2.success, "Second migration should succeed"
    assert len(result2.tables_created) == 0, "Second migration should create no tables"
    assert (
        "no migration needed" in result2.message.lower()
        or "no tables needed" in result2.message.lower()
    )


def test_migration_status():
    """Test that migration status works correctly."""
    # Create test engine and metadata
    engine = create_test_engine()
    metadata = TestBase.metadata
    mock_logger = Mock(spec=logging.Logger)

    # Create migration engine
    migration_engine = MigrationEngine(engine, metadata, mock_logger)

    # Get initial status
    status = migration_engine.get_migration_status()
    assert status.migration_needed, "Migration should be needed initially"
    assert len(status.missing_tables) > 0, "Should have missing tables"

    # Run migration
    result = migration_engine.run_migration()
    assert result.success, "Migration should succeed"

    # Get status after migration
    status_after = migration_engine.get_migration_status()
    assert not status_after.migration_needed, (
        "Migration should not be needed after completion"
    )
    assert len(status_after.missing_tables) == 0, "Should have no missing tables"
