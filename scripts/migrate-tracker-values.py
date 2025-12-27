#!/usr/bin/env python3
"""
Database migration script to add tracker_values table.

This script adds the tracker_values table to an existing trackers database.
It includes proper foreign key constraints, unique constraints, and indexes.

Usage:
    python scripts/migrate-tracker-values.py [--rollback]

Options:
    --rollback      Remove the tracker_values table and related constraints
    --help          Show this help message

Environment Variables Required:
    DB_HOST         PostgreSQL server host
    DB_USER         Database username
    DB_PASSWORD     Password for the database user
    DB_NAME         Database name
"""

import argparse
import logging
import os
import sys
from pathlib import Path

# Add the project root to Python path so we can import trackers module
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Load environment variables from .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    # dotenv is optional, continue without it
    pass

from sqlalchemy import create_engine, text

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def load_environment():
    """Load and validate required environment variables."""
    required_vars = ["DB_HOST", "DB_USER", "DB_PASSWORD", "DB_NAME"]
    missing_vars = []

    env_vars = {}
    for var in required_vars:
        value = os.getenv(var)
        if not value:
            missing_vars.append(var)
        env_vars[var] = value

    if missing_vars:
        logger.error(
            "Missing required environment variables: %s", ", ".join(missing_vars)
        )
        logger.error("Please set these variables or create a .env file")
        sys.exit(1)

    return env_vars


def get_database_connection(env_vars):
    """Create database connection."""
    db_url = f"postgresql://{env_vars['DB_USER']}:{env_vars['DB_PASSWORD']}@{env_vars['DB_HOST']}/{env_vars['DB_NAME']}"

    try:
        engine = create_engine(db_url)
        return engine
    except Exception as e:
        logger.error("Failed to connect to database: %s", e)
        logger.error("Database URL pattern: postgresql://user:password@host/database")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  1. Verify all environment variables are set correctly")
        logger.error("  2. Check database connection string format")
        logger.error("  3. Ensure PostgreSQL is running and accessible")
        logger.error("  4. Verify the database exists")
        sys.exit(1)


def apply_migration(engine):
    """Apply the tracker_values table migration."""
    logger.info("Applying tracker_values table migration...")

    try:
        with engine.connect() as conn:
            # Check if table already exists
            result = conn.execute(
                text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'tracker_values'
                )
            """)
            )

            if result.fetchone()[0]:
                logger.info("tracker_values table already exists, skipping migration")
                return

            # Create the tracker_values table
            conn.execute(
                text("""
                CREATE TABLE tracker_values (
                    id SERIAL PRIMARY KEY,
                    tracker_id INTEGER NOT NULL REFERENCES trackers(id) ON DELETE CASCADE,
                    date DATE NOT NULL,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
                    CONSTRAINT unique_tracker_date UNIQUE(tracker_id, date)
                )
            """)
            )

            # Create index for efficient queries
            conn.execute(
                text("""
                CREATE INDEX idx_tracker_date ON tracker_values(tracker_id, date)
            """)
            )

            conn.commit()
            logger.info("✓ tracker_values table created successfully")
            logger.info("✓ Unique constraint on (tracker_id, date) added")
            logger.info("✓ Index on (tracker_id, date) created")

    except Exception as e:
        logger.error("Failed to apply migration: %s", e)
        sys.exit(1)


def rollback_migration(engine):
    """Rollback the tracker_values table migration."""
    logger.info("Rolling back tracker_values table migration...")

    try:
        with engine.connect() as conn:
            # Check if table exists
            result = conn.execute(
                text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'tracker_values'
                )
            """)
            )

            if not result.fetchone()[0]:
                logger.info("tracker_values table does not exist, nothing to rollback")
                return

            # Drop the table (this will also drop the index and constraints)
            conn.execute(text("DROP TABLE tracker_values CASCADE"))

            conn.commit()
            logger.info("✓ tracker_values table dropped successfully")

    except Exception as e:
        logger.error("Failed to rollback migration: %s", e)
        sys.exit(1)


def verify_migration(engine):
    """Verify the migration was applied correctly."""
    logger.info("Verifying migration...")

    try:
        with engine.connect() as conn:
            # Check table exists
            result = conn.execute(
                text("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'public' 
                    AND table_name = 'tracker_values'
                )
            """)
            )

            if not result.fetchone()[0]:
                logger.error(
                    "Migration verification failed: tracker_values table not found"
                )
                sys.exit(1)

            # Check columns
            result = conn.execute(
                text("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public' 
                AND table_name = 'tracker_values'
                ORDER BY ordinal_position
            """)
            )

            columns = result.fetchall()
            expected_columns = [
                ("id", "integer", "NO"),
                ("tracker_id", "integer", "NO"),
                ("date", "date", "NO"),
                ("value", "text", "NO"),
                ("created_at", "timestamp with time zone", "NO"),
                ("updated_at", "timestamp with time zone", "NO"),
            ]

            for expected in expected_columns:
                if expected not in columns:
                    logger.error(f"Missing expected column: {expected}")
                    sys.exit(1)

            # Check constraints
            result = conn.execute(
                text("""
                SELECT constraint_name, constraint_type
                FROM information_schema.table_constraints
                WHERE table_schema = 'public' 
                AND table_name = 'tracker_values'
            """)
            )

            constraints = {row[0]: row[1] for row in result.fetchall()}

            if "unique_tracker_date" not in constraints:
                logger.error("Missing unique constraint: unique_tracker_date")
                sys.exit(1)

            # Check indexes
            result = conn.execute(
                text("""
                SELECT indexname
                FROM pg_indexes
                WHERE tablename = 'tracker_values'
                AND schemaname = 'public'
            """)
            )

            indexes = [row[0] for row in result.fetchall()]

            if "idx_tracker_date" not in indexes:
                logger.error("Missing index: idx_tracker_date")
                sys.exit(1)

            logger.info("✓ Migration verification successful")
            logger.info(f"✓ Found {len(columns)} columns")
            logger.info(f"✓ Found {len(constraints)} constraints")
            logger.info(f"✓ Found {len(indexes)} indexes")

    except Exception as e:
        logger.error("Migration verification failed: %s", e)
        sys.exit(1)


def main():
    """Main migration function."""
    parser = argparse.ArgumentParser(
        description="Migrate tracker_values table",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Remove the tracker_values table and related constraints",
    )

    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("TRACKER VALUES TABLE MIGRATION")
    logger.info("=" * 60)

    # Load environment variables
    env_vars = load_environment()

    logger.info("Configuration:")
    logger.info("  Host: %s", env_vars["DB_HOST"])
    logger.info("  Database: %s", env_vars["DB_NAME"])
    logger.info("  User: %s", env_vars["DB_USER"])
    logger.info("  Operation: %s", "rollback" if args.rollback else "apply")
    logger.info("")

    # Get database connection
    engine = get_database_connection(env_vars)

    # Apply or rollback migration
    if args.rollback:
        rollback_migration(engine)
    else:
        apply_migration(engine)
        verify_migration(engine)

    logger.info("=" * 60)
    logger.info("MIGRATION COMPLETE")
    logger.info("=" * 60)
    logger.info("")

    if not args.rollback:
        logger.info("Next steps:")
        logger.info("1. Update your application to use the new TrackerValueModel")
        logger.info("2. Run tests to verify the migration: pytest")
        logger.info("3. Start using the tracker values API endpoints")
    else:
        logger.info("Rollback complete. The tracker_values table has been removed.")


if __name__ == "__main__":
    main()
