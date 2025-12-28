"""
Migration utility functions for manual migration triggering and status reporting.

This module provides utility functions for manual migration operations,
status reporting, and migration management outside of automatic startup.

Requirements: All requirements (supporting functionality)
"""

import logging
from typing import Any, Dict, Optional

from sqlalchemy import Engine, MetaData

from trackers.db.migration import MigrationEngine, MigrationResult
from trackers.db.migration_config import MigrationConfig, migration_config


def _safe_get_engine_url(engine: Engine) -> str:
    """
    Safely get engine URL with password masked.

    Handles both real SQLAlchemy engines and mock objects for testing.
    """
    try:
        url_str = str(engine.url)
        if hasattr(engine.url, "password") and engine.url.password:
            return url_str.replace(str(engine.url.password), "***")
        return url_str
    except (AttributeError, TypeError):
        # Handle mock objects or other edge cases
        return "mock://engine/url"


def trigger_manual_migration(
    engine: Engine,
    metadata: MetaData,
    config: Optional[MigrationConfig] = None,
    logger: Optional[logging.Logger] = None,
) -> MigrationResult:
    """
    Manually trigger database migration.

    This utility function allows manual triggering of database migration
    outside of the automatic startup process. Useful for maintenance,
    debugging, or custom deployment scenarios.

    Args:
        engine: SQLAlchemy engine instance
        metadata: SQLAlchemy metadata instance
        config: Optional migration configuration (uses default if None)
        logger: Optional logger instance (creates default if None)

    Returns:
        MigrationResult with migration outcome

    Requirements: All requirements (supporting functionality)
    """
    if config is None:
        config = migration_config

    if logger is None:
        logger = logging.getLogger(__name__)

    # Validate configuration
    config.validate()

    # Create migration engine with configuration
    migration_engine = MigrationEngine(
        engine=engine,
        metadata=metadata,
        logger=logger,
        timeout_seconds=config.timeout_seconds,
    )

    # Run migration if enabled
    if not config.enabled:
        logger.info("Migration is disabled by configuration")
        return MigrationResult(
            success=True,
            tables_created=[],
            errors=[],
            duration_seconds=0.0,
            message="Migration disabled by configuration",
        )

    logger.info("Starting manual migration...")
    result = migration_engine.run_migration()

    if result.success:
        logger.info(
            f"Manual migration completed successfully in {result.duration_seconds:.2f}s"
        )
    else:
        logger.error(f"Manual migration failed: {result.message}")

    return result


def get_migration_status_report(
    engine: Engine, metadata: MetaData, logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Get comprehensive migration status report.

    This utility function provides detailed information about the current
    migration status, database state, and configuration for monitoring
    and debugging purposes.

    Args:
        engine: SQLAlchemy engine instance
        metadata: SQLAlchemy metadata instance
        logger: Optional logger instance (creates default if None)

    Returns:
        Dictionary with comprehensive migration status information

    Requirements: All requirements (supporting functionality)
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        # Create migration engine for status checking
        migration_engine = MigrationEngine(engine, metadata, logger)

        # Get current migration status
        status = migration_engine.get_migration_status()

        # Get configuration information
        config = migration_config

        # Build comprehensive report
        report = {
            "migration_status": {
                "database_exists": status.database_exists,
                "connection_healthy": status.connection_healthy,
                "migration_needed": status.migration_needed,
                "existing_tables": status.tables_exist,
                "missing_tables": status.missing_tables,
                "total_expected_tables": len(metadata.tables.keys()),
                "total_existing_tables": len(status.tables_exist),
            },
            "configuration": {
                "enabled": config.enabled,
                "timeout_seconds": config.timeout_seconds,
                "lock_timeout_seconds": config.lock_timeout_seconds,
                "enable_logging": config.enable_logging,
                "log_level": config.log_level,
                "skip_validation": config.skip_validation,
                "concurrent_safety": config.concurrent_safety,
            },
            "database_info": {
                "engine_url": _safe_get_engine_url(engine),
                "expected_tables": list(metadata.tables.keys()),
            },
        }

        # Add health assessment
        if status.connection_healthy and not status.migration_needed:
            report["health"] = "healthy"
            report["health_message"] = "Database is healthy and up to date"
        elif status.connection_healthy and status.migration_needed:
            report["health"] = "needs_migration"
            report["health_message"] = (
                f"Database is accessible but needs {len(status.missing_tables)} tables created"
            )
        else:
            report["health"] = "unhealthy"
            report["health_message"] = "Database connection is not healthy"

        return report

    except Exception as e:
        logger.error(f"Failed to generate migration status report: {e}")
        return {
            "error": str(e),
            "health": "error",
            "health_message": f"Failed to assess migration status: {e}",
        }


def validate_migration_environment() -> Dict[str, Any]:
    """
    Validate migration environment and configuration.

    This utility function checks that the migration environment is properly
    configured and ready for migration operations. Useful for deployment
    validation and troubleshooting.

    Returns:
        Dictionary with validation results and recommendations

    Requirements: All requirements (supporting functionality)
    """
    validation_results = {
        "valid": True,
        "warnings": [],
        "errors": [],
        "recommendations": [],
    }

    try:
        # Validate configuration
        config = migration_config

        try:
            config.validate()
            validation_results["configuration"] = "valid"
        except ValueError as e:
            validation_results["valid"] = False
            validation_results["errors"].append(f"Configuration validation failed: {e}")

        # Check environment variables
        import os

        # Check database environment variables
        db_vars = [
            ("POSTGRESQL_ADDON_HOST", "DB_HOST"),
            ("POSTGRESQL_ADDON_USER", "DB_USER"),
            ("POSTGRESQL_ADDON_PASSWORD", "DB_PASSWORD"),
            ("POSTGRESQL_ADDON_DB", "DB_NAME"),
        ]

        missing_db_vars = []
        for clever_var, local_var in db_vars:
            if not os.getenv(clever_var) and not os.getenv(local_var):
                missing_db_vars.append(f"{clever_var} or {local_var}")

        if missing_db_vars:
            validation_results["valid"] = False
            validation_results["errors"].append(
                f"Missing database environment variables: {', '.join(missing_db_vars)}"
            )

        # Check migration-specific environment variables
        migration_vars = {
            "MIGRATION_ENABLED": config.enabled,
            "MIGRATION_TIMEOUT": config.timeout_seconds,
            "MIGRATION_LOCK_TIMEOUT": config.lock_timeout_seconds,
            "MIGRATION_LOGGING": config.enable_logging,
            "MIGRATION_LOG_LEVEL": config.log_level,
            "MIGRATION_SKIP_VALIDATION": config.skip_validation,
            "MIGRATION_CONCURRENT_SAFETY": config.concurrent_safety,
        }

        validation_results["migration_config"] = migration_vars

        # Add recommendations
        if not config.enabled:
            validation_results["warnings"].append(
                "Migration is disabled - enable with MIGRATION_ENABLED=true"
            )

        if config.timeout_seconds < 30:
            validation_results["warnings"].append(
                "Migration timeout is less than 30 seconds - consider increasing for production"
            )

        if config.skip_validation:
            validation_results["warnings"].append(
                "Post-migration validation is disabled - consider enabling for safety"
            )

        if not config.concurrent_safety:
            validation_results["warnings"].append(
                "Concurrent migration safety is disabled - enable for production deployments"
            )

        # Add general recommendations
        validation_results["recommendations"].extend(
            [
                "Ensure database user has CREATE TABLE privileges",
                "Test migration in staging environment before production",
                "Monitor migration logs during deployment",
                "Consider setting MIGRATION_TIMEOUT higher for large schemas",
            ]
        )

    except Exception as e:
        validation_results["valid"] = False
        validation_results["errors"].append(f"Environment validation failed: {e}")

    return validation_results


def format_migration_report(report: Dict[str, Any]) -> str:
    """
    Format migration status report for human-readable output.

    Args:
        report: Migration status report from get_migration_status_report()

    Returns:
        Formatted string representation of the report

    Requirements: All requirements (supporting functionality)
    """
    if "error" in report:
        return (
            f"Migration Status Report - ERROR\n{'=' * 40}\nError: {report['error']}\n"
        )

    lines = []
    lines.append("Migration Status Report")
    lines.append("=" * 40)

    # Health status
    health = report.get("health", "unknown")
    health_msg = report.get("health_message", "No health information available")
    lines.append(f"Health: {health.upper()}")
    lines.append(f"Message: {health_msg}")
    lines.append("")

    # Migration status
    if "migration_status" in report:
        status = report["migration_status"]
        lines.append("Database Status:")
        lines.append(
            f"  Connection Healthy: {status.get('connection_healthy', 'unknown')}"
        )
        lines.append(f"  Migration Needed: {status.get('migration_needed', 'unknown')}")
        lines.append(f"  Existing Tables: {status.get('total_existing_tables', 0)}")
        lines.append(f"  Expected Tables: {status.get('total_expected_tables', 0)}")

        if status.get("missing_tables"):
            lines.append(f"  Missing Tables: {', '.join(status['missing_tables'])}")
        lines.append("")

    # Configuration
    if "configuration" in report:
        config = report["configuration"]
        lines.append("Migration Configuration:")
        lines.append(f"  Enabled: {config.get('enabled', 'unknown')}")
        lines.append(f"  Timeout: {config.get('timeout_seconds', 'unknown')}s")
        lines.append(
            f"  Lock Timeout: {config.get('lock_timeout_seconds', 'unknown')}s"
        )
        lines.append(f"  Logging: {config.get('enable_logging', 'unknown')}")
        lines.append(f"  Log Level: {config.get('log_level', 'unknown')}")
        lines.append(
            f"  Concurrent Safety: {config.get('concurrent_safety', 'unknown')}"
        )
        lines.append("")

    # Database info
    if "database_info" in report:
        db_info = report["database_info"]
        lines.append("Database Information:")
        lines.append(f"  Engine URL: {db_info.get('engine_url', 'unknown')}")
        if db_info.get("expected_tables"):
            lines.append(f"  Expected Tables: {', '.join(db_info['expected_tables'])}")
        lines.append("")

    lines.append("=" * 40)

    return "\n".join(lines)
