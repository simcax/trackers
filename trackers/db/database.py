import logging
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
        return create_engine(settings.db_url)
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
    Context manager for database sessions.
    Creates a new session, yields it, and ensures cleanup.

    Usage:
        with get_db_session() as db:
            # Use db session here
            pass
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
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
