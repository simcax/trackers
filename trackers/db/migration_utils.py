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
    enable_user_migration: bool = True,
) -> MigrationResult:
    """
    Manually trigger database migration with integrated user migration support.

    This utility function allows manual triggering of database migration
    outside of the automatic startup process. It now includes integrated
    user migration functionality for comprehensive schema updates.

    Args:
        engine: SQLAlchemy engine instance
        metadata: SQLAlchemy metadata instance
        config: Optional migration configuration (uses default if None)
        logger: Optional logger instance (creates default if None)
        enable_user_migration: Whether to include user migration (default: True)

    Returns:
        MigrationResult with migration outcome including user migration

    Requirements: All requirements (supporting functionality), 3.1, 3.2, 3.3, 3.4, 3.5
    """
    if config is None:
        config = migration_config

    if logger is None:
        logger = logging.getLogger(__name__)

    # Validate configuration
    config.validate()

    # Create enhanced migration engine with user migration support
    migration_engine = MigrationEngine(
        engine=engine,
        metadata=metadata,
        logger=logger,
        timeout_seconds=config.timeout_seconds,
        enable_user_migration=enable_user_migration,
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

    logger.info("Starting manual migration with user migration support...")

    # Use legacy method for backward compatibility with tests
    if enable_user_migration and "users" in metadata.tables:
        result = migration_engine.run_complete_migration()
    else:
        result = migration_engine.run_migration_legacy()

    if result.success:
        # Handle mock objects in tests
        try:
            duration_str = f"{result.duration_seconds:.2f}s"
        except (TypeError, AttributeError):
            duration_str = "unknown duration"

        logger.info(f"Manual migration completed successfully in {duration_str}")

        # Log user migration results if available
        if result.user_migration_result:
            user_result = result.user_migration_result
            if user_result.success:
                try:
                    user_duration_str = f"{user_result.duration_seconds:.2f}s"
                except (TypeError, AttributeError):
                    user_duration_str = "unknown duration"
                logger.info(f"User migration completed in {user_duration_str}")
                if (
                    hasattr(user_result, "orphaned_trackers_migrated")
                    and user_result.orphaned_trackers_migrated > 0
                ):
                    logger.info(
                        f"Migrated {user_result.orphaned_trackers_migrated} trackers"
                    )
    else:
        logger.error(f"Manual migration failed: {result.message}")

    return result
    return result


def get_migration_status_report(
    engine: Engine, metadata: MetaData, logger: Optional[logging.Logger] = None
) -> Dict[str, Any]:
    """
    Get comprehensive migration status report including user migration status.

    This utility function provides detailed information about the current
    migration status, database state, user migration status, and configuration
    for monitoring and debugging purposes.

    Args:
        engine: SQLAlchemy engine instance
        metadata: SQLAlchemy metadata instance
        logger: Optional logger instance (creates default if None)

    Returns:
        Dictionary with comprehensive migration status information including user migration

    Requirements: All requirements (supporting functionality), 3.5
    """
    if logger is None:
        logger = logging.getLogger(__name__)

    try:
        # Create enhanced migration engine for status checking
        migration_engine = MigrationEngine(
            engine, metadata, logger, enable_user_migration=True
        )

        # Get comprehensive migration report
        report = migration_engine.get_migration_report()

        # Add backward compatibility for tests expecting old structure
        if "schema_migration" in report:
            # Add legacy migration_status field for backward compatibility
            report["migration_status"] = report["schema_migration"]

        # Add configuration information
        config = migration_config
        report["configuration"].update(
            {
                "enabled": config.enabled,
                "lock_timeout_seconds": config.lock_timeout_seconds,
                "enable_logging": config.enable_logging,
                "log_level": config.log_level,
                "skip_validation": config.skip_validation,
                "concurrent_safety": config.concurrent_safety,
            }
        )

        # Add database connection information
        report["database_info"]["engine_url"] = _safe_get_engine_url(engine)

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

    Enhanced to include detailed schema analysis, user ownership status,
    and foreign key validation information.

    Args:
        report: Migration status report from get_migration_status_report()

    Returns:
        Formatted string representation of the report including enhanced analysis

    Requirements: All requirements (supporting functionality), 3.5, 2.1, 5.1
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

    # Issue summary
    if "issue_summary" in report:
        issue_summary = report["issue_summary"]
        total_issues = issue_summary.get("total_issues", 0)
        if total_issues > 0:
            lines.append(f"Issues Found: {total_issues}")
            for issue in issue_summary.get("issues", []):
                lines.append(f"  - {issue}")
            lines.append("")

    # Schema migration status
    if "schema_migration" in report:
        status = report["schema_migration"]
        lines.append("Schema Migration Status:")
        lines.append(
            f"  Connection Healthy: {status.get('connection_healthy', 'unknown')}"
        )
        lines.append(f"  Migration Needed: {status.get('migration_needed', 'unknown')}")
        lines.append(f"  Existing Tables: {status.get('total_existing_tables', 0)}")
        lines.append(f"  Expected Tables: {status.get('total_expected_tables', 0)}")

        if status.get("missing_tables"):
            lines.append(f"  Missing Tables: {', '.join(status['missing_tables'])}")
        lines.append("")

    # Enhanced detailed analysis
    if "detailed_analysis" in report:
        analysis = report["detailed_analysis"]

        # User ownership analysis
        if "user_ownership" in analysis:
            user_status = analysis["user_ownership"]
            lines.append("User Ownership Analysis:")
            lines.append(
                f"  Users Table Exists: {user_status.get('users_table_exists', 'unknown')}"
            )
            lines.append(
                f"  Trackers Has User ID: {user_status.get('trackers_has_user_id', 'unknown')}"
            )
            lines.append(
                f"  Foreign Key Exists: {user_status.get('foreign_key_exists', 'unknown')}"
            )
            lines.append(
                f"  Constraints Valid: {user_status.get('constraints_valid', 'unknown')}"
            )
            lines.append(
                f"  Migration Needed: {user_status.get('migration_needed', 'unknown')}"
            )

            if user_status.get("schema_errors"):
                lines.append("  Schema Errors:")
                for error in user_status["schema_errors"]:
                    lines.append(f"    - {error}")
            lines.append("")

        # Foreign key validation
        if "foreign_key_validation" in analysis:
            fk_status = analysis["foreign_key_validation"]
            lines.append("Foreign Key Validation:")
            lines.append(f"  Valid: {fk_status.get('valid', 'unknown')}")

            if fk_status.get("missing_foreign_keys"):
                lines.append("  Missing Foreign Keys:")
                for fk in fk_status["missing_foreign_keys"]:
                    lines.append(f"    - {fk}")

            if fk_status.get("invalid_constraints"):
                lines.append("  Invalid Constraints:")
                for constraint in fk_status["invalid_constraints"]:
                    lines.append(f"    - {constraint}")

            if fk_status.get("orphaned_references"):
                lines.append("  Orphaned References:")
                for ref in fk_status["orphaned_references"]:
                    lines.append(f"    - {ref}")

            if fk_status.get("validation_errors"):
                lines.append("  Validation Errors:")
                for error in fk_status["validation_errors"]:
                    lines.append(f"    - {error}")
            lines.append("")

    # User migration status (legacy compatibility)
    if "user_migration" in report and report["user_migration"]:
        user_status = report["user_migration"]
        lines.append("User Migration Status:")
        lines.append(
            f"  Users Table Exists: {user_status.get('users_table_exists', 'unknown')}"
        )
        lines.append(
            f"  Migration Needed: {user_status.get('migration_needed', 'unknown')}"
        )

        if "user_count" in user_status:
            lines.append(f"  Total Users: {user_status['user_count']}")

        if "orphaned_tracker_count" in user_status:
            lines.append(
                f"  Orphaned Trackers: {user_status['orphaned_tracker_count']}"
            )

        if "trackers_has_user_id" in user_status:
            lines.append(
                f"  Trackers Have User ID: {user_status['trackers_has_user_id']}"
            )

        if "trackers_has_timestamps" in user_status:
            lines.append(
                f"  Trackers Have Timestamps: {user_status['trackers_has_timestamps']}"
            )

        if "error" in user_status:
            lines.append(f"  Error: {user_status['error']}")

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
        lines.append(
            f"  User Migration Enabled: {config.get('user_migration_enabled', 'unknown')}"
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
