import logging
import os
from unittest.mock import patch

import pytest
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError, ProgrammingError

# Configure logging for database operations
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables before importing settings
load_dotenv()

# Now import settings after environment variables are loaded
from trackers.db.settings import settings

# Test database naming follows {DB_NAME}_test pattern
DB_NAME = f"{settings.db_name}_test"
settings.db_url = settings.get_test_db_url(DB_NAME)

# Reinitialize the database engine with the test database URL
# This MUST happen before importing the app
from trackers.db.database import reinit_engine

reinit_engine()

# NOW import the app after database is configured for testing
from trackers import create_app


@pytest.fixture
def app():
    # Disable all authentication for tests by default
    with patch.dict(
        os.environ,
        {
            "API_KEYS": "",  # Disable API key auth
            "GOOGLE_CLIENT_ID": "",  # Disable Google OAuth
            "GOOGLE_CLIENT_SECRET": "",  # Disable Google OAuth
            "GOOGLE_REDIRECT_URI": "",  # Disable Google OAuth
            "EMAIL_PASSWORD_AUTH_ENABLED": "false",  # Disable email/password auth
            "TESTING": "true",  # Enable testing mode
        },
        clear=False,
    ):
        app = create_app(
            {
                "TESTING": True,
            }
        )

        yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


@pytest.fixture(scope="session", autouse=True)
def fake_db():
    """
    Session-scoped fixture that creates and initializes the test database.
    Automatically runs once per test session.

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 6.1, 6.3
    """
    logger.info("=" * 60)
    logger.info("Starting test database setup")
    logger.info("=" * 60)

    # Connect to PostgreSQL server (not a specific database)
    # Requirement 6.1: Display specific error and connection details
    logger.info(f"Connecting to PostgreSQL server at {settings.db_host}")
    logger.info(f"Using database user: {settings.db_user}")

    try:
        engine = create_engine(
            f"postgresql://{settings.db_user}:{settings.db_password}@{settings.db_host}/postgres",
            isolation_level="AUTOCOMMIT",
        )
    except Exception as e:
        # Requirement 6.1, 6.4: Connection error with helpful messages
        logger.error("=" * 60)
        logger.error("FAILED TO CREATE DATABASE ENGINE")
        logger.error("=" * 60)
        logger.error(f"Error: {e}")
        logger.error("Connection details:")
        logger.error(f"  Host: {settings.db_host}")
        logger.error(f"  User: {settings.db_user}")
        logger.error("  Database: postgres")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  1. Check if PostgreSQL is running:")
        logger.error("     - Linux: sudo systemctl status postgresql")
        logger.error("     - macOS: brew services list")
        logger.error("     - Docker: docker ps | grep postgres")
        logger.error("  2. Verify connection settings in .env file")
        logger.error("  3. Check if PostgreSQL is listening on the correct host/port")
        logger.error("  4. Verify database user credentials are correct")
        logger.error("=" * 60)
        raise

    try:
        with engine.connect() as conn:
            # Drop existing test database if it exists (Requirement 2.1)
            logger.info(f"Attempting to drop existing test database: {DB_NAME}")
            try:
                conn.execute(text(f"DROP DATABASE IF EXISTS {DB_NAME}"))
                logger.info(f"Successfully dropped existing database: {DB_NAME}")
            except ProgrammingError as e:
                logger.warning(
                    f"Could not drop database (probably does not exist): {e}"
                )
            except OperationalError as e:
                # Requirement 2.5, 6.4: Clear error message for active connections
                logger.error("=" * 60)
                logger.error("CANNOT DROP TEST DATABASE - ACTIVE CONNECTIONS")
                logger.error("=" * 60)
                logger.error(f"Database: {DB_NAME}")
                logger.error(f"Error: {e}")
                logger.error("")
                logger.error("Common fixes:")
                logger.error(
                    "  1. Close any open psql prompts connected to this database"
                )
                logger.error(
                    "  2. Close any database GUI tools (pgAdmin, DBeaver, etc.)"
                )
                logger.error("  3. Stop any running application instances")
                logger.error("  4. Terminate connections manually:")
                logger.error(f'     psql -U {settings.db_user} -d postgres -c "')
                logger.error("       SELECT pg_terminate_backend(pid)")
                logger.error("       FROM pg_stat_activity")
                logger.error(f"       WHERE datname = '{DB_NAME}';\"")
                logger.error("=" * 60)
                raise

            # Create new test database (Requirement 2.2)
            logger.info(f"Creating new test database: {DB_NAME}")
            try:
                conn.execute(text(f"CREATE DATABASE {DB_NAME}"))
                logger.info(f"Successfully created test database: {DB_NAME}")
            except ProgrammingError as e:
                # Requirement 6.1, 6.4: Permission error with privilege suggestions
                if "permission denied" in str(e).lower():
                    logger.error("=" * 60)
                    logger.error("PERMISSION DENIED - CANNOT CREATE DATABASE")
                    logger.error("=" * 60)
                    logger.error(f"User: {settings.db_user}")
                    logger.error(f"Error: {e}")
                    logger.error("")
                    logger.error("Required privileges:")
                    logger.error("  The database user needs CREATEDB privilege")
                    logger.error("")
                    logger.error("To grant privileges, run as PostgreSQL superuser:")
                    logger.error(
                        f'  psql -U postgres -c "ALTER USER {settings.db_user} CREATEDB;"'
                    )
                    logger.error("")
                    logger.error("Or create the database manually:")
                    logger.error(f'  psql -U postgres -c "CREATE DATABASE {DB_NAME};"')
                    logger.error(
                        f'  psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE {DB_NAME} TO {settings.db_user};"'
                    )
                    logger.error("=" * 60)
                    raise
                else:
                    logger.error(f"Failed to create test database: {e}")
                    raise
            except Exception as e:
                logger.error(f"Failed to create test database: {e}")
                raise

            # Create user if needed and grant privileges
            try:
                conn.execute(
                    text(
                        f"CREATE USER {settings.db_user} WITH ENCRYPTED PASSWORD '{settings.db_password}'"
                    )
                )
                logger.info(f"Created database user: {settings.db_user}")
            except ProgrammingError:
                logger.info(f"User {settings.db_user} already exists")

            try:
                conn.execute(
                    text(
                        f"GRANT ALL PRIVILEGES ON DATABASE {DB_NAME} TO {settings.db_user}"
                    )
                )
                logger.info(f"Granted privileges on {DB_NAME} to {settings.db_user}")
            except ProgrammingError as e:
                # Requirement 6.1, 6.4: Permission error with privilege suggestions
                if "permission denied" in str(e).lower():
                    logger.error("=" * 60)
                    logger.error("PERMISSION DENIED - CANNOT GRANT PRIVILEGES")
                    logger.error("=" * 60)
                    logger.error(f"User: {settings.db_user}")
                    logger.error(f"Database: {DB_NAME}")
                    logger.error(f"Error: {e}")
                    logger.error("")
                    logger.error(
                        "This usually means you're not connected as a superuser."
                    )
                    logger.error("To grant privileges, run as PostgreSQL superuser:")
                    logger.error(
                        f'  psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE {DB_NAME} TO {settings.db_user};"'
                    )
                    logger.error("=" * 60)
                    raise
                else:
                    logger.warning(f"Could not grant privileges: {e}")
            except Exception as e:
                logger.warning(f"Could not grant privileges: {e}")

    except OperationalError as e:
        # Requirement 6.1, 6.4: Connection error with helpful messages
        logger.error("=" * 60)
        logger.error("DATABASE CONNECTION FAILED")
        logger.error("=" * 60)
        logger.error(f"Error: {e}")
        logger.error("Connection details:")
        logger.error(f"  Host: {settings.db_host}")
        logger.error(f"  User: {settings.db_user}")
        logger.error("  Database: postgres")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  1. Check if PostgreSQL is running:")
        logger.error("     - Linux: sudo systemctl status postgresql")
        logger.error("     - macOS: brew services list")
        logger.error("     - Docker: docker ps | grep postgres")
        logger.error(
            "  2. Verify the host is correct (localhost, 127.0.0.1, or container name)"
        )
        logger.error("  3. Check if PostgreSQL is listening on port 5432")
        logger.error("  4. Verify firewall settings allow connections")
        logger.error("  5. Check pg_hba.conf for authentication settings")
        logger.error("=" * 60)
        raise

    # Import models before schema creation (Requirement 2.3)
    logger.info("Importing ORM models")
    from trackers.db.database import Base, SessionLocal

    # Apply schema to test database (Requirement 2.3)
    logger.info(f"Applying schema to test database: {DB_NAME}")
    try:
        test_engine = create_engine(settings.db_url)
        Base.metadata.create_all(test_engine)
        logger.info("Schema creation complete")
    except OperationalError as e:
        # Requirement 6.1, 6.4: Connection error with helpful messages
        logger.error("=" * 60)
        logger.error("FAILED TO APPLY SCHEMA TO TEST DATABASE")
        logger.error("=" * 60)
        logger.error(f"Database: {DB_NAME}")
        logger.error(f"Error: {e}")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  1. Verify the test database was created successfully")
        logger.error("  2. Check if the database user has sufficient privileges")
        logger.error(
            f'  3. Grant privileges: psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE {DB_NAME} TO {settings.db_user};"'
        )
        logger.error("=" * 60)
        raise
    except Exception as e:
        logger.error(f"Failed to apply schema: {e}")
        raise

    # Log all created tables
    logger.info(f"Created tables: {', '.join(Base.metadata.tables.keys())}")

    db = SessionLocal()
    logger.info("=" * 60)
    logger.info(f"Test database {DB_NAME} is ready!")
    logger.info("=" * 60)

    try:
        yield db
    finally:
        db.close()
        # Requirement 6.2: Database state preserved for inspection
        logger.info(
            "Test session complete - database remains available for inspection (Requirement 2.4, 6.2)"
        )


@pytest.fixture(scope="function")
def db_session():
    """
    Function-scoped fixture that provides a fresh database session for each test.
    Automatically rolls back transactions and closes the session after each test.

    Requirements: 3.1, 3.2, 3.3, 3.4
    """
    from trackers.db.database import SessionLocal

    # Create a new session for this test (Requirement 3.1)
    session = SessionLocal()

    try:
        # Yield the session to the test function
        yield session
    finally:
        # Rollback any uncommitted transactions (Requirement 3.2, 3.4)
        session.rollback()
        # Close the session to prevent connection leaks (Requirement 3.3)
        session.close()
