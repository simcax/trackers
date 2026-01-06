"""
Job Migration for automated job scheduling system.

This module provides migration functionality for creating job-related database tables
and ensuring proper foreign key relationships with users and trackers.

Requirements: 9.1, 9.2, 9.3
"""

import logging
import time
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy import Engine, MetaData, inspect
from sqlalchemy.exc import OperationalError, ProgrammingError

logger = logging.getLogger(__name__)


@dataclass
class JobMigrationResult:
    """
    Represents the outcome of a job migration operation.

    Requirements: 9.1, 9.2, 9.3
    """

    success: bool
    jobs_table_created: bool
    job_execution_logs_table_created: bool
    foreign_keys_created: bool
    indexes_created: bool
    errors: List[str]
    duration_seconds: float
    message: str


class JobMigration:
    """
    Handles migration of job-related database schema.

    This class creates the jobs and job_execution_logs tables with proper
    foreign key relationships to users and trackers tables.

    Requirements: 9.1, 9.2, 9.3
    """

    def __init__(
        self,
        engine: Engine,
        metadata: MetaData,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize job migration.

        Args:
            engine: SQLAlchemy database engine
            metadata: SQLAlchemy metadata containing job models
            logger: Optional logger instance

        Requirements: 9.1
        """
        self.engine = engine
        self.metadata = metadata
        self.logger = logger or logging.getLogger(__name__)

    def is_migration_needed(self) -> bool:
        """
        Check if job migration is needed.

        Returns:
            True if job tables need to be created or updated

        Requirements: 9.1, 9.2
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())

            # Check if job tables exist
            jobs_table_exists = "jobs" in existing_tables
            job_logs_table_exists = "job_execution_logs" in existing_tables

            if not jobs_table_exists or not job_logs_table_exists:
                return True

            # Check if foreign key relationships exist
            if jobs_table_exists:
                foreign_keys = inspector.get_foreign_keys("jobs")
                has_user_fk = any(
                    fk.get("referred_table") == "users"
                    and "user_id" in fk.get("constrained_columns", [])
                    for fk in foreign_keys
                )
                has_tracker_fk = any(
                    fk.get("referred_table") == "trackers"
                    and "tracker_id" in fk.get("constrained_columns", [])
                    for fk in foreign_keys
                )

                if not has_user_fk or not has_tracker_fk:
                    return True

            return False

        except Exception as e:
            self.logger.error(f"Failed to check if job migration is needed: {e}")
            # Assume migration is needed if we can't determine
            return True

    def get_migration_status(self) -> dict:
        """
        Get detailed status of job migration requirements.

        Returns:
            Dictionary with migration status details

        Requirements: 9.1, 9.2, 9.3
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())

            status = {
                "migration_needed": False,
                "jobs_table_exists": "jobs" in existing_tables,
                "job_execution_logs_table_exists": "job_execution_logs"
                in existing_tables,
                "foreign_keys_valid": True,
                "indexes_exist": True,
                "issues": [],
            }

            # Check jobs table
            if not status["jobs_table_exists"]:
                status["migration_needed"] = True
                status["issues"].append("Jobs table is missing")
            else:
                # Check foreign keys for jobs table
                foreign_keys = inspector.get_foreign_keys("jobs")
                has_user_fk = any(
                    fk.get("referred_table") == "users"
                    and "user_id" in fk.get("constrained_columns", [])
                    for fk in foreign_keys
                )
                has_tracker_fk = any(
                    fk.get("referred_table") == "trackers"
                    and "tracker_id" in fk.get("constrained_columns", [])
                    for fk in foreign_keys
                )

                if not has_user_fk:
                    status["foreign_keys_valid"] = False
                    status["migration_needed"] = True
                    status["issues"].append("Jobs table missing foreign key to users")

                if not has_tracker_fk:
                    status["foreign_keys_valid"] = False
                    status["migration_needed"] = True
                    status["issues"].append(
                        "Jobs table missing foreign key to trackers"
                    )

            # Check job execution logs table
            if not status["job_execution_logs_table_exists"]:
                status["migration_needed"] = True
                status["issues"].append("Job execution logs table is missing")
            else:
                # Check foreign key for job execution logs table
                foreign_keys = inspector.get_foreign_keys("job_execution_logs")
                has_job_fk = any(
                    fk.get("referred_table") == "jobs"
                    and "job_id" in fk.get("constrained_columns", [])
                    for fk in foreign_keys
                )

                if not has_job_fk:
                    status["foreign_keys_valid"] = False
                    status["migration_needed"] = True
                    status["issues"].append(
                        "Job execution logs table missing foreign key to jobs"
                    )

            return status

        except Exception as e:
            self.logger.error(f"Failed to get job migration status: {e}")
            return {
                "migration_needed": True,
                "jobs_table_exists": False,
                "job_execution_logs_table_exists": False,
                "foreign_keys_valid": False,
                "indexes_exist": False,
                "issues": [f"Failed to check migration status: {e}"],
            }

    def apply_migration(self) -> JobMigrationResult:
        """
        Apply job migration to create tables and relationships.

        Returns:
            JobMigrationResult with migration details

        Requirements: 9.1, 9.2, 9.3
        """
        start_time = time.time()
        errors = []
        jobs_table_created = False
        job_execution_logs_table_created = False
        foreign_keys_created = False
        indexes_created = False

        try:
            self.logger.info("Starting job migration...")

            # Check if migration is needed
            migration_needed = self.is_migration_needed()
            if not migration_needed:
                self.logger.info("Job migration not needed - tables already exist")
                # Even if tables exist, ensure permissions are granted
                job_tables = ["jobs", "job_execution_logs"]
                existing_job_tables = [
                    self.metadata.tables[name]
                    for name in job_tables
                    if name in self.metadata.tables
                ]
                if existing_job_tables:
                    self.logger.info(
                        "Ensuring permissions are granted on existing job tables..."
                    )
                    self._grant_table_permissions(existing_job_tables)

                return JobMigrationResult(
                    success=True,
                    jobs_table_created=False,
                    job_execution_logs_table_created=False,
                    foreign_keys_created=False,
                    indexes_created=False,
                    errors=[],
                    duration_seconds=time.time() - start_time,
                    message="No migration needed - job tables already exist, permissions verified",
                )

            # Verify prerequisite tables exist
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())

            if "users" not in existing_tables:
                error_msg = "Cannot create job tables - users table does not exist"
                errors.append(error_msg)
                self.logger.error(error_msg)
                return JobMigrationResult(
                    success=False,
                    jobs_table_created=False,
                    job_execution_logs_table_created=False,
                    foreign_keys_created=False,
                    indexes_created=False,
                    errors=errors,
                    duration_seconds=time.time() - start_time,
                    message=error_msg,
                )

            if "trackers" not in existing_tables:
                error_msg = "Cannot create job tables - trackers table does not exist"
                errors.append(error_msg)
                self.logger.error(error_msg)
                return JobMigrationResult(
                    success=False,
                    jobs_table_created=False,
                    job_execution_logs_table_created=False,
                    foreign_keys_created=False,
                    indexes_created=False,
                    errors=errors,
                    duration_seconds=time.time() - start_time,
                    message=error_msg,
                )

            # Create job tables using metadata
            try:
                # Only create job-related tables
                job_tables = ["jobs", "job_execution_logs"]
                tables_to_create = []

                for table_name in job_tables:
                    if (
                        table_name in self.metadata.tables
                        and table_name not in existing_tables
                    ):
                        tables_to_create.append(self.metadata.tables[table_name])

                if tables_to_create:
                    self.logger.info(f"Creating {len(tables_to_create)} job tables...")

                    # Create tables
                    for table in tables_to_create:
                        table.create(self.engine)
                        self.logger.info(f"Created table: {table.name}")

                        if table.name == "jobs":
                            jobs_table_created = True
                        elif table.name == "job_execution_logs":
                            job_execution_logs_table_created = True

                    foreign_keys_created = True  # Foreign keys are created with tables
                    indexes_created = True  # Indexes are created with tables

                    # Grant permissions on newly created job tables
                    self._grant_table_permissions(tables_to_create)

                else:
                    self.logger.info("All job tables already exist")
                    # Even if tables exist, ensure permissions are granted
                    existing_job_tables = [
                        self.metadata.tables[name]
                        for name in job_tables
                        if name in self.metadata.tables and name in existing_tables
                    ]
                    if existing_job_tables:
                        self._grant_table_permissions(existing_job_tables)

            except (OperationalError, ProgrammingError) as e:
                error_msg = f"Failed to create job tables: {e}"
                errors.append(error_msg)
                self.logger.error(error_msg)

            # Verify tables were created successfully
            try:
                inspector = inspect(self.engine)
                updated_tables = set(inspector.get_table_names())

                if "jobs" not in updated_tables:
                    errors.append("Jobs table was not created successfully")
                if "job_execution_logs" not in updated_tables:
                    errors.append(
                        "Job execution logs table was not created successfully"
                    )

            except Exception as e:
                error_msg = f"Failed to verify table creation: {e}"
                errors.append(error_msg)
                self.logger.error(error_msg)

            success = len(errors) == 0
            message = (
                "Job migration completed successfully"
                if success
                else f"Job migration completed with {len(errors)} errors"
            )

            if success:
                self.logger.info("✓ Job migration completed successfully")
            else:
                self.logger.error(
                    f"✗ Job migration completed with errors: {'; '.join(errors)}"
                )

            return JobMigrationResult(
                success=success,
                jobs_table_created=jobs_table_created,
                job_execution_logs_table_created=job_execution_logs_table_created,
                foreign_keys_created=foreign_keys_created,
                indexes_created=indexes_created,
                errors=errors,
                duration_seconds=time.time() - start_time,
                message=message,
            )

        except Exception as e:
            error_msg = f"Job migration failed with exception: {e}"
            errors.append(error_msg)
            self.logger.error(error_msg)

            return JobMigrationResult(
                success=False,
                jobs_table_created=jobs_table_created,
                job_execution_logs_table_created=job_execution_logs_table_created,
                foreign_keys_created=foreign_keys_created,
                indexes_created=indexes_created,
                errors=errors,
                duration_seconds=time.time() - start_time,
                message=error_msg,
            )

    def validate_job_schema(self) -> bool:
        """
        Validate that job schema is properly configured.

        Returns:
            True if job schema is valid

        Requirements: 9.2, 9.3
        """
        try:
            inspector = inspect(self.engine)
            existing_tables = set(inspector.get_table_names())

            # Check that all required tables exist
            required_tables = ["jobs", "job_execution_logs", "users", "trackers"]
            for table in required_tables:
                if table not in existing_tables:
                    self.logger.error(f"Required table {table} is missing")
                    return False

            # Validate jobs table structure
            jobs_columns = {col["name"]: col for col in inspector.get_columns("jobs")}
            required_jobs_columns = [
                "id",
                "name",
                "job_type",
                "user_id",
                "tracker_id",
                "config",
                "cron_schedule",
                "is_active",
                "created_at",
                "updated_at",
            ]

            for col in required_jobs_columns:
                if col not in jobs_columns:
                    self.logger.error(f"Jobs table missing required column: {col}")
                    return False

            # Validate foreign key relationships
            jobs_fks = inspector.get_foreign_keys("jobs")
            has_user_fk = any(
                fk.get("referred_table") == "users"
                and "user_id" in fk.get("constrained_columns", [])
                for fk in jobs_fks
            )
            has_tracker_fk = any(
                fk.get("referred_table") == "trackers"
                and "tracker_id" in fk.get("constrained_columns", [])
                for fk in jobs_fks
            )

            if not has_user_fk:
                self.logger.error("Jobs table missing foreign key to users")
                return False
            if not has_tracker_fk:
                self.logger.error("Jobs table missing foreign key to trackers")
                return False

            # Validate job execution logs table
            logs_fks = inspector.get_foreign_keys("job_execution_logs")
            has_job_fk = any(
                fk.get("referred_table") == "jobs"
                and "job_id" in fk.get("constrained_columns", [])
                for fk in logs_fks
            )

            if not has_job_fk:
                self.logger.error(
                    "Job execution logs table missing foreign key to jobs"
                )
                return False

            self.logger.info("Job schema validation passed")
            return True

        except Exception as e:
            self.logger.error(f"Job schema validation failed: {e}")
            return False

    def _grant_table_permissions(self, tables: List) -> None:
        """
        Grant necessary permissions on job tables to the database user.

        This method attempts to grant permissions but handles failures gracefully
        since permission granting may require superuser privileges.

        Args:
            tables: List of SQLAlchemy Table objects to grant permissions on

        Requirements: 9.1, 9.2, 9.3
        """
        try:
            # Get database user from connection URL
            db_user = self._get_database_user()
            if not db_user:
                self.logger.warning(
                    "Could not determine database user for permission grants"
                )
                return

            with self.engine.connect() as conn:
                for table in tables:
                    table_name = table.name
                    try:
                        # Grant table permissions
                        grant_sql = text(
                            f"GRANT ALL PRIVILEGES ON TABLE {table_name} TO {db_user}"
                        )
                        conn.execute(grant_sql)
                        self.logger.info(
                            f"✓ Granted table permissions on {table_name} to {db_user}"
                        )

                        # Grant sequence permissions for auto-increment columns
                        # Check if table has sequences (auto-increment columns)
                        for column in table.columns:
                            if column.autoincrement:
                                sequence_name = f"{table_name}_{column.name}_seq"
                                try:
                                    sequence_sql = text(
                                        f"GRANT USAGE, SELECT ON SEQUENCE {sequence_name} TO {db_user}"
                                    )
                                    conn.execute(sequence_sql)
                                    self.logger.info(
                                        f"✓ Granted sequence permissions on {sequence_name} to {db_user}"
                                    )
                                except Exception as seq_e:
                                    # Sequence might not exist or have different name, this is not critical
                                    self.logger.debug(
                                        f"Could not grant sequence permissions on {sequence_name}: {seq_e}"
                                    )

                    except Exception as table_e:
                        # Permission errors are common in production environments
                        # where the application user doesn't have GRANT privileges
                        if "permission denied" in str(table_e).lower():
                            self.logger.warning(
                                f"Could not grant permissions on {table_name}: insufficient privileges. "
                                f"Database administrator may need to run: GRANT ALL PRIVILEGES ON TABLE {table_name} TO {db_user};"
                            )
                        else:
                            self.logger.warning(
                                f"Could not grant permissions on {table_name}: {table_e}"
                            )

                # Commit the permission changes
                conn.commit()

        except Exception as e:
            self.logger.warning(f"Permission grant operation failed: {e}")
            self.logger.info(
                "Job tables created successfully, but permissions may need manual configuration"
            )

    def _get_database_user(self) -> Optional[str]:
        """
        Extract database user from the engine connection URL.

        Returns:
            Database username or None if not found
        """
        try:
            url = self.engine.url
            return url.username
        except Exception as e:
            self.logger.debug(f"Could not extract database user: {e}")
            return None
