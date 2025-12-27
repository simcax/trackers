#!/usr/bin/env python3
"""
Database initialization script for the trackers application.

This script:
1. Creates a new database user with appropriate privileges
2. Creates the main database
3. Applies all schema definitions from SQLAlchemy models
4. Optionally creates sample data

Usage:
    python scripts/init-db.py [--sample-data] [--force]

Options:
    --sample-data    Create sample tracker data after initialization
    --force         Drop existing database and user if they exist
    --help          Show this help message

Environment Variables Required:
    DB_HOST         PostgreSQL server host
    DB_USER         Database username to create
    DB_PASSWORD     Password for the database user
    DB_NAME         Database name to create
    POSTGRES_USER   PostgreSQL superuser (default: postgres)
    POSTGRES_PASSWORD PostgreSQL superuser password (default: postgres)
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to Python path so we can import trackers module
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
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

    # Optional superuser credentials (defaults to postgres/postgres)
    env_vars["POSTGRES_USER"] = os.getenv("POSTGRES_USER", "postgres")
    env_vars["POSTGRES_PASSWORD"] = os.getenv("POSTGRES_PASSWORD", "postgres")

    return env_vars


def connect_as_superuser(env_vars):
    """Connect to PostgreSQL as superuser."""
    try:
        conn = psycopg2.connect(
            host=env_vars["DB_HOST"],
            user=env_vars["POSTGRES_USER"],
            password=env_vars["POSTGRES_PASSWORD"],
            database="postgres",
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        return conn
    except psycopg2.OperationalError as e:
        logger.error("Failed to connect as superuser: %s", e)
        logger.error("Connection details:")
        logger.error("  Host: %s", env_vars["DB_HOST"])
        logger.error("  User: %s", env_vars["POSTGRES_USER"])
        logger.error("  Database: postgres")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  1. Verify PostgreSQL is running")
        logger.error("  2. Check superuser credentials")
        logger.error("  3. Ensure host is accessible")
        sys.exit(1)


def create_user(conn, env_vars, force=False):
    """Create database user with appropriate privileges."""
    cursor = conn.cursor()

    try:
        if force:
            logger.info("Dropping existing user if exists: %s", env_vars["DB_USER"])
            cursor.execute(f"DROP USER IF EXISTS {env_vars['DB_USER']}")

        logger.info("Creating database user: %s", env_vars["DB_USER"])
        cursor.execute(f"""
            CREATE USER {env_vars["DB_USER"]} 
            WITH ENCRYPTED PASSWORD '{env_vars["DB_PASSWORD"]}'
            CREATEDB
        """)
        logger.info("✓ User created successfully")

    except psycopg2.errors.DuplicateObject:
        if not force:
            logger.info(
                "User %s already exists, skipping creation", env_vars["DB_USER"]
            )
        else:
            logger.error("Failed to create user even with --force flag")
            sys.exit(1)
    except Exception as e:
        logger.error("Failed to create user: %s", e)
        sys.exit(1)
    finally:
        cursor.close()


def create_database(conn, env_vars, force=False):
    """Create the main database."""
    cursor = conn.cursor()

    try:
        if force:
            logger.info("Dropping existing database if exists: %s", env_vars["DB_NAME"])
            # Terminate active connections to the database
            cursor.execute(f"""
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = '{env_vars["DB_NAME"]}' AND pid <> pg_backend_pid()
            """)
            cursor.execute(f"DROP DATABASE IF EXISTS {env_vars['DB_NAME']}")

        logger.info("Creating database: %s", env_vars["DB_NAME"])
        cursor.execute(
            f"CREATE DATABASE {env_vars['DB_NAME']} OWNER {env_vars['DB_USER']}"
        )
        logger.info("✓ Database created successfully")

    except psycopg2.errors.DuplicateDatabase:
        if not force:
            logger.info(
                "Database %s already exists, skipping creation", env_vars["DB_NAME"]
            )
        else:
            logger.error("Failed to create database even with --force flag")
            sys.exit(1)
    except Exception as e:
        logger.error("Failed to create database: %s", e)
        sys.exit(1)
    finally:
        cursor.close()


def apply_schema(env_vars):
    """Apply SQLAlchemy schema to the database."""
    logger.info("Applying database schema...")

    # Construct database URL
    db_url = f"postgresql://{env_vars['DB_USER']}:{env_vars['DB_PASSWORD']}@{env_vars['DB_HOST']}/{env_vars['DB_NAME']}"

    try:
        # Import models to register them with Base
        try:
            from trackers.db.database import Base
            from trackers.models.tracker_model import ItemModel, LogModel, TrackerModel
        except ImportError as e:
            logger.error("Failed to import trackers module: %s", e)
            logger.error(
                "Make sure you're running this script from the project root directory"
            )
            logger.error("Current working directory: %s", os.getcwd())
            logger.error("Python path: %s", sys.path)
            sys.exit(1)

        # Create engine and apply schema
        engine = create_engine(db_url)
        Base.metadata.create_all(engine)

        # Log created tables
        tables = list(Base.metadata.tables.keys())
        logger.info("✓ Schema applied successfully")
        logger.info("Created tables: %s", ", ".join(tables))

        return engine

    except Exception as e:
        logger.error("Failed to apply schema: %s", e)
        sys.exit(1)


def create_sample_data(engine):
    """Create sample tracker data."""
    logger.info("Creating sample data...")

    try:
        from sqlalchemy.orm import sessionmaker

        from trackers.models.tracker_model import ItemModel, LogModel, TrackerModel

        Session = sessionmaker(bind=engine)
        session = Session()

        # Create sample trackers
        trackers = [
            TrackerModel(
                name="Fitness Goals",
                description="Track daily exercise and health metrics",
            ),
            TrackerModel(
                name="Reading List", description="Books to read and reading progress"
            ),
            TrackerModel(
                name="Project Tasks", description="Development tasks and milestones"
            ),
        ]

        for tracker in trackers:
            session.add(tracker)

        session.commit()

        # Create sample items
        items = [
            ItemModel(name="Morning Run", tracker_id=1, date=datetime.now()),
            ItemModel(
                name="The Pragmatic Programmer", tracker_id=2, date=datetime.now()
            ),
            ItemModel(name="Database Setup", tracker_id=3, date=datetime.now()),
        ]

        for item in items:
            session.add(item)

        session.commit()

        # Create sample logs
        logs = [
            LogModel(message="Started fitness tracking", tracker_id=1),
            LogModel(message="Added first book to reading list", tracker_id=2),
            LogModel(message="Project initialization complete", tracker_id=3),
        ]

        for log in logs:
            session.add(log)

        session.commit()
        session.close()

        logger.info("✓ Sample data created successfully")
        logger.info(
            "Created %d trackers, %d items, %d logs",
            len(trackers),
            len(items),
            len(logs),
        )

    except Exception as e:
        logger.error("Failed to create sample data: %s", e)
        sys.exit(1)


def verify_setup(env_vars):
    """Verify the database setup is working correctly."""
    logger.info("Verifying database setup...")

    db_url = f"postgresql://{env_vars['DB_USER']}:{env_vars['DB_PASSWORD']}@{env_vars['DB_HOST']}/{env_vars['DB_NAME']}"

    try:
        engine = create_engine(db_url)

        with engine.connect() as conn:
            # Test basic connectivity
            result = conn.execute(text("SELECT version()"))
            version = result.fetchone()[0]
            logger.info("✓ Database connection successful")
            logger.info("PostgreSQL version: %s", version.split(",")[0])

            # Test table existence
            result = conn.execute(
                text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public'
                ORDER BY table_name
            """)
            )
            tables = [row[0] for row in result.fetchall()]
            logger.info("✓ Tables verified: %s", ", ".join(tables))

            # Test basic operations
            result = conn.execute(text("SELECT COUNT(*) FROM trackers"))
            tracker_count = result.fetchone()[0]
            logger.info(
                "✓ Database operations working (found %d trackers)", tracker_count
            )

        logger.info("✓ Database setup verification complete")

    except Exception as e:
        logger.error("Database verification failed: %s", e)
        sys.exit(1)


def main():
    """Main initialization function."""
    parser = argparse.ArgumentParser(
        description="Initialize the trackers database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--sample-data",
        action="store_true",
        help="Create sample tracker data after initialization",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Drop existing database and user if they exist",
    )

    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("TRACKERS DATABASE INITIALIZATION")
    logger.info("=" * 60)

    # Load environment variables
    env_vars = load_environment()

    logger.info("Configuration:")
    logger.info("  Host: %s", env_vars["DB_HOST"])
    logger.info("  Database: %s", env_vars["DB_NAME"])
    logger.info("  User: %s", env_vars["DB_USER"])
    logger.info("  Force mode: %s", args.force)
    logger.info("  Sample data: %s", args.sample_data)
    logger.info("")

    # Connect as superuser
    conn = connect_as_superuser(env_vars)

    try:
        # Create user and database
        create_user(conn, env_vars, args.force)
        create_database(conn, env_vars, args.force)

    finally:
        conn.close()

    # Apply schema
    engine = apply_schema(env_vars)

    # Create sample data if requested
    if args.sample_data:
        create_sample_data(engine)

    # Verify setup
    verify_setup(env_vars)

    logger.info("=" * 60)
    logger.info("DATABASE INITIALIZATION COMPLETE")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Next steps:")
    logger.info("1. Update your .env file with the database credentials")
    logger.info("2. Run tests: pytest")
    logger.info("3. Start the application: python main.py")
    logger.info("")
    logger.info("Database connection string:")
    logger.info(
        "postgresql://%s:***@%s/%s",
        env_vars["DB_USER"],
        env_vars["DB_HOST"],
        env_vars["DB_NAME"],
    )


if __name__ == "__main__":
    main()
