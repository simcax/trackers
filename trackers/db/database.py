import logging
import os
import time
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from .settings import settings

logger = logging.getLogger(__name__)


def _create_engine():
    """
    Create engine using current settings.db_url value.

    Requirements: 6.1, 6.4 - Connection error handling with helpful messages
    """
    try:
        # Determine SSL mode
        if settings.ssl_mode == "auto":
            # Auto-detect based on environment
            is_production = any(
                [
                    settings.db_url.startswith("postgresql://")
                    and "clever-cloud" in settings.db_url,
                    "POSTGRESQL_ADDON_HOST" in os.environ,
                    os.environ.get("ENVIRONMENT") == "production",
                ]
            )
            ssl_mode = "require" if is_production else "prefer"
        else:
            # Use explicitly configured SSL mode
            ssl_mode = settings.ssl_mode

        # Determine if we're in production for other settings
        is_production = any(
            [
                settings.db_url.startswith("postgresql://")
                and "clever-cloud" in settings.db_url,
                "POSTGRESQL_ADDON_HOST" in os.environ,
                os.environ.get("ENVIRONMENT") == "production",
                ssl_mode
                == "require",  # If SSL is required, assume production-like environment
            ]
        )

        # Configure connection timeout based on SSL mode
        if ssl_mode in ["require", "verify-ca", "verify-full"]:
            connect_timeout = 15  # Longer timeout for SSL handshake
        else:
            connect_timeout = 10  # Standard timeout for local development

        # Configure engine with environment-appropriate settings
        engine_kwargs = {
            # Connection pool settings
            "pool_size": 3 if is_production else 5,  # Smaller pool for Clever Cloud
            "max_overflow": 5 if is_production else 10,
            "pool_timeout": 20,
            "pool_recycle": 1800
            if is_production
            else 3600,  # Shorter recycle for production
            "pool_pre_ping": True,  # Validate connections before use
            # SSL and connection settings
            "connect_args": {
                "sslmode": ssl_mode,
                "connect_timeout": connect_timeout,
                "application_name": "trackers-app",
            },
        }

        # Add production-specific connection settings
        if is_production:
            engine_kwargs["connect_args"].update(
                {
                    "keepalives_idle": 600,  # Keep connection alive (10 minutes)
                    "keepalives_interval": 30,  # Check every 30 seconds
                    "keepalives_count": 3,  # 3 failed checks before considering connection dead
                    "tcp_user_timeout": 30000,  # 30 second TCP timeout (milliseconds)
                }
            )

        return create_engine(settings.db_url, **engine_kwargs)
    except Exception as e:
        logger.error("=" * 60)
        logger.error("FAILED TO CREATE DATABASE ENGINE")
        logger.error("=" * 60)
        logger.error(f"Error: {e}")
        logger.error("Database URL pattern: postgresql://user:password@host/database")
        logger.error("")
        logger.error("Common fixes:")
        logger.error("  1. Verify all environment variables are set correctly")
        logger.error("  2. Check database connection string format")
        logger.error("  3. Ensure PostgreSQL is running and accessible")
        logger.error("=" * 60)
        raise


engine = _create_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """
    Dependency injection for database sessions.
    Creates a new session, yields it, and ensures cleanup.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_session():
    """
    Context manager for database sessions with improved error handling and retry logic.
    Creates a new session, yields it, and ensures cleanup.

    Usage:
        with get_db_session() as db:
            # Use db session here
            pass
    """
    max_retries = 3
    retry_delay = 0.5  # Start with 500ms delay

    for attempt in range(max_retries):
        db = SessionLocal()
        try:
            yield db
            db.commit()
            return  # Success, exit retry loop
        except Exception as e:
            db.rollback()

            # Check for connection-related errors that might benefit from retry
            error_str = str(e).lower()
            is_connection_error = any(
                phrase in error_str
                for phrase in [
                    "ssl syscall error",
                    "eof detected",
                    "connection reset",
                    "connection closed",
                    "server closed the connection",
                    "connection timed out",
                    "connection refused",
                ]
            )

            if is_connection_error and attempt < max_retries - 1:
                logger.warning(
                    f"Database connection error on attempt {attempt + 1}: {e}"
                )
                logger.info(f"Retrying in {retry_delay} seconds...")
                db.close()  # Close the failed connection
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
            else:
                # Log connection errors for debugging
                if is_connection_error:
                    logger.error(
                        f"Database connection failed after {max_retries} attempts: {e}"
                    )
                    logger.info(
                        "This may indicate persistent SSL or network connectivity issues"
                    )
                raise
        finally:
            db.close()


def reinit_engine():
    """
    Reinitialize the database engine and session factory.
    Used for testing to recreate engine after test database URL is set.
    """
    global engine, SessionLocal
    engine = _create_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
