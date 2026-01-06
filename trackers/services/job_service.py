"""
Job Service for automated job scheduling system.

This module provides the JobService class for managing scheduled jobs with
comprehensive security controls, user authorization, and audit logging.

Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from trackers.models.job_model import JobExecutionLogModel, JobModel
from trackers.models.tracker_model import TrackerModel
from trackers.security.job_config_encryption import JobConfigEncryption
from trackers.services.job_providers.job_config_validator import JobConfigValidator
from trackers.services.job_scheduler import JobExecutionResult, JobScheduler

logger = logging.getLogger(__name__)


class JobSecurityLogger:
    """
    Security-focused logging for job operations.

    This class provides comprehensive audit logging for all job-related
    security events including creation, access, and unauthorized attempts.

    Requirements: 8.2, 8.3
    """

    def __init__(self):
        """Initialize security logger."""
        self.security_logger = logging.getLogger("job_security")

    def log_job_creation(self, user_id: int, job_id: int, job_type: str) -> None:
        """
        Log job creation with user context.

        Args:
            user_id: User who created the job
            job_id: ID of the created job
            job_type: Type of job created

        Requirements: 8.2, 8.3
        """
        self.security_logger.info(
            f"Job created - User: {user_id}, Job: {job_id}, Type: {job_type}",
            extra={
                "event": "job_created",
                "user_id": user_id,
                "job_id": job_id,
                "job_type": job_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def log_job_update(
        self, user_id: int, job_id: int, fields_updated: List[str]
    ) -> None:
        """
        Log job configuration updates.

        Args:
            user_id: User who updated the job
            job_id: ID of the updated job
            fields_updated: List of fields that were updated

        Requirements: 8.2, 8.3
        """
        self.security_logger.info(
            f"Job updated - User: {user_id}, Job: {job_id}, Fields: {', '.join(fields_updated)}",
            extra={
                "event": "job_updated",
                "user_id": user_id,
                "job_id": job_id,
                "fields_updated": fields_updated,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def log_job_deletion(self, user_id: int, job_id: int, job_name: str) -> None:
        """
        Log job deletion.

        Args:
            user_id: User who deleted the job
            job_id: ID of the deleted job
            job_name: Name of the deleted job

        Requirements: 8.2, 8.3
        """
        self.security_logger.info(
            f"Job deleted - User: {user_id}, Job: {job_id}, Name: {job_name}",
            extra={
                "event": "job_deleted",
                "user_id": user_id,
                "job_id": job_id,
                "job_name": job_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def log_credential_access(self, user_id: int, job_id: int, field_name: str) -> None:
        """
        Log when encrypted credentials are accessed.

        Args:
            user_id: User accessing the credentials
            job_id: Job containing the credentials
            field_name: Name of the credential field accessed

        Requirements: 8.2, 8.3
        """
        self.security_logger.info(
            f"Credential accessed - User: {user_id}, Job: {job_id}, Field: {field_name}",
            extra={
                "event": "credential_accessed",
                "user_id": user_id,
                "job_id": job_id,
                "field_name": field_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def log_unauthorized_access(
        self, user_id: int, attempted_job_id: int, action: str
    ) -> None:
        """
        Log unauthorized job access attempts.

        Args:
            user_id: User who attempted unauthorized access
            attempted_job_id: Job ID they tried to access
            action: Action they attempted (view, update, delete, etc.)

        Requirements: 8.2, 8.3
        """
        self.security_logger.warning(
            f"Unauthorized access attempt - User: {user_id}, Job: {attempted_job_id}, Action: {action}",
            extra={
                "event": "unauthorized_access",
                "user_id": user_id,
                "attempted_job_id": attempted_job_id,
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "warning",
            },
        )

    def log_job_test_execution(self, user_id: int, job_id: int, success: bool) -> None:
        """
        Log job test execution attempts.

        Args:
            user_id: User who executed the test
            job_id: Job that was tested
            success: Whether the test was successful

        Requirements: 8.2, 8.3
        """
        self.security_logger.info(
            f"Job test executed - User: {user_id}, Job: {job_id}, Success: {success}",
            extra={
                "event": "job_test_executed",
                "user_id": user_id,
                "job_id": job_id,
                "success": success,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    def log_validation_failure(
        self, user_id: int, job_type: str, errors: List[str]
    ) -> None:
        """
        Log job configuration validation failures.

        Args:
            user_id: User who submitted invalid configuration
            job_type: Type of job that failed validation
            errors: List of validation errors

        Requirements: 8.2, 8.3
        """
        self.security_logger.warning(
            f"Job validation failed - User: {user_id}, Type: {job_type}, Errors: {len(errors)}",
            extra={
                "event": "validation_failed",
                "user_id": user_id,
                "job_type": job_type,
                "error_count": len(errors),
                "errors": errors,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


class AuthorizationError(Exception):
    """Exception raised when user is not authorized to perform an action."""

    pass


class ValidationError(Exception):
    """Exception raised when job configuration validation fails."""

    def __init__(self, message: str, errors: List[str]):
        super().__init__(message)
        self.errors = errors


class JobService:
    """
    Service class for job management with comprehensive security controls.

    This class provides CRUD operations for scheduled jobs with user authorization
    checks, configuration validation, encryption, and comprehensive audit logging.

    Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
    """

    def __init__(self, db_session: Session, scheduler: Optional[JobScheduler] = None):
        """
        Initialize Job Service with database session and optional scheduler.

        Args:
            db_session: SQLAlchemy database session
            scheduler: JobScheduler instance for managing scheduled jobs

        Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
        """
        self.db = db_session
        self.scheduler = scheduler
        self.validator = JobConfigValidator()
        self.encryptor = JobConfigEncryption()
        self.security_logger = JobSecurityLogger()

    def create_job(self, user_id: int, job_data: Dict) -> JobModel:
        """
        Create and schedule a new job with comprehensive security validation.

        Args:
            user_id: ID of the user creating the job
            job_data: Dictionary containing job configuration

        Returns:
            JobModel: Created job model

        Raises:
            AuthorizationError: If user doesn't own the target tracker
            ValidationError: If job configuration is invalid
            IntegrityError: If database constraint violation occurs

        Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
        """
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user ID")

        # Validate required fields
        required_fields = ["name", "job_type", "tracker_id", "config", "cron_schedule"]
        for field in required_fields:
            if field not in job_data:
                raise ValueError(f"Missing required field: {field}")

        try:
            # Verify user owns the target tracker
            tracker = self._verify_tracker_ownership(user_id, job_data["tracker_id"])

            # Resolve environment variables in configuration
            resolved_config = self.validator.resolve_environment_variables(
                job_data["config"]
            )

            # Validate and sanitize configuration
            sanitized_config = self.validator.sanitize_config(resolved_config)
            validation_errors = self.validator.validate_job_config(
                job_data["job_type"], sanitized_config
            )

            if validation_errors:
                self.security_logger.log_validation_failure(
                    user_id, job_data["job_type"], validation_errors
                )
                raise ValidationError("Invalid job configuration", validation_errors)

            # Validate cron schedule
            cron_errors = self.validator.validate_cron_schedule(
                job_data["cron_schedule"]
            )
            if cron_errors:
                self.security_logger.log_validation_failure(
                    user_id, job_data["job_type"], cron_errors
                )
                raise ValidationError("Invalid cron schedule", cron_errors)

            # Encrypt sensitive configuration data
            encrypted_config = self.encryptor.encrypt_config(sanitized_config)

            # Create job record
            job = JobModel(
                user_id=user_id,
                tracker_id=job_data["tracker_id"],
                name=job_data["name"].strip(),
                job_type=job_data["job_type"],
                config=json.dumps(encrypted_config),
                cron_schedule=job_data["cron_schedule"].strip(),
                is_active=job_data.get("is_active", True),
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )

            self.db.add(job)
            self.db.flush()  # Get the ID without committing
            self.db.refresh(job)

            # Add to scheduler if active and scheduler is available
            if job.is_active and self.scheduler:
                scheduler_success = self.scheduler.add_job(job)
                if not scheduler_success:
                    logger.warning(f"Failed to add job {job.id} to scheduler")

            # Security logging
            self.security_logger.log_job_creation(user_id, job.id, job.job_type)

            logger.info(f"Created job {job.id} ({job.name}) for user {user_id}")
            return job

        except (AuthorizationError, ValidationError):
            # Re-raise these specific exceptions
            raise
        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"Database integrity error creating job: {str(e)}")
            raise IntegrityError(
                f"Failed to create job due to database constraint: {str(e)}",
                params=None,
                orig=e.orig,
            )
        except Exception as e:
            self.db.rollback()
            logger.error(f"Unexpected error creating job: {str(e)}")
            raise

    def update_job(self, job_id: int, user_id: int, job_data: Dict) -> JobModel:
        """
        Update existing job configuration with security checks.

        Args:
            job_id: ID of the job to update
            user_id: ID of the user updating the job
            job_data: Dictionary containing updated job configuration

        Returns:
            JobModel: Updated job model

        Raises:
            AuthorizationError: If user doesn't own the job
            ValidationError: If job configuration is invalid

        Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            raise ValueError("Invalid job ID")
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user ID")

        try:
            # Verify ownership
            job = self._get_user_job(job_id, user_id)
            fields_updated = []

            # Update configuration with same security measures as create
            if "config" in job_data:
                # Resolve environment variables
                resolved_config = self.validator.resolve_environment_variables(
                    job_data["config"]
                )

                # Validate and sanitize
                sanitized_config = self.validator.sanitize_config(resolved_config)
                validation_errors = self.validator.validate_job_config(
                    job.job_type, sanitized_config
                )

                if validation_errors:
                    self.security_logger.log_validation_failure(
                        user_id, job.job_type, validation_errors
                    )
                    raise ValidationError(
                        "Invalid job configuration", validation_errors
                    )

                # Encrypt and update
                encrypted_config = self.encryptor.encrypt_config(sanitized_config)
                job.config = json.dumps(encrypted_config)
                fields_updated.append("config")

            # Update cron schedule with validation
            if "cron_schedule" in job_data:
                cron_errors = self.validator.validate_cron_schedule(
                    job_data["cron_schedule"]
                )
                if cron_errors:
                    self.security_logger.log_validation_failure(
                        user_id, job.job_type, cron_errors
                    )
                    raise ValidationError("Invalid cron schedule", cron_errors)

                job.cron_schedule = job_data["cron_schedule"].strip()
                fields_updated.append("cron_schedule")

            # Update other fields
            for field in ["name", "is_active"]:
                if field in job_data:
                    if field == "name":
                        setattr(job, field, job_data[field].strip())
                    else:
                        setattr(job, field, job_data[field])
                    fields_updated.append(field)

            # Update tracker_id with ownership verification
            if "tracker_id" in job_data:
                self._verify_tracker_ownership(user_id, job_data["tracker_id"])
                job.tracker_id = job_data["tracker_id"]
                fields_updated.append("tracker_id")

            job.updated_at = datetime.now(timezone.utc)
            self.db.flush()

            # Update scheduler if available
            if self.scheduler:
                if job.is_active:
                    scheduler_success = self.scheduler.add_job(
                        job
                    )  # This updates existing job
                    if not scheduler_success:
                        logger.warning(f"Failed to update job {job.id} in scheduler")
                else:
                    self.scheduler.remove_job(job.id)

            # Security logging
            self.security_logger.log_job_update(user_id, job.id, fields_updated)

            logger.info(f"Updated job {job.id} for user {user_id}")
            return job

        except (AuthorizationError, ValidationError):
            # Re-raise these specific exceptions
            raise
        except Exception as e:
            self.db.rollback()
            logger.error(f"Unexpected error updating job {job_id}: {str(e)}")
            raise

    def delete_job(self, job_id: int, user_id: int) -> bool:
        """
        Delete job and remove from scheduler with security checks.

        Args:
            job_id: ID of the job to delete
            user_id: ID of the user deleting the job

        Returns:
            bool: True if job was deleted successfully

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            raise ValueError("Invalid job ID")
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user ID")

        try:
            job = self._get_user_job(job_id, user_id)
            job_name = job.name

            # Remove from scheduler first
            if self.scheduler:
                self.scheduler.remove_job(job.id)

            # Delete from database (cascade will handle execution logs)
            self.db.delete(job)
            self.db.flush()

            # Security logging
            self.security_logger.log_job_deletion(user_id, job_id, job_name)

            logger.info(f"Deleted job {job_id} ({job_name}) for user {user_id}")
            return True

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            self.db.rollback()
            logger.error(f"Unexpected error deleting job {job_id}: {str(e)}")
            raise

    def get_user_jobs(self, user_id: int) -> List[JobModel]:
        """
        Get all jobs for a user (security: only user's own jobs).

        Args:
            user_id: ID of the user

        Returns:
            List[JobModel]: List of user's jobs

        Requirements: 1.4, 1.5, 8.2, 8.3
        """
        if not user_id or user_id <= 0:
            return []

        try:
            jobs = (
                self.db.query(JobModel)
                .filter(JobModel.user_id == user_id)
                .order_by(JobModel.created_at.desc())
                .all()
            )

            return jobs

        except Exception as e:
            logger.error(f"Error getting jobs for user {user_id}: {str(e)}")
            return []

    def get_job(self, job_id: int, user_id: int) -> Optional[JobModel]:
        """
        Get specific job for a user with ownership verification.

        Args:
            job_id: ID of the job
            user_id: ID of the user

        Returns:
            Optional[JobModel]: Job model if found and owned by user

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            return None
        if not user_id or user_id <= 0:
            return None

        try:
            return self._get_user_job(job_id, user_id)
        except AuthorizationError:
            raise
        except Exception as e:
            logger.error(f"Error getting job {job_id} for user {user_id}: {str(e)}")
            return None

    def test_job(self, job_id: int, user_id: int) -> JobExecutionResult:
        """
        Execute job immediately for testing with security validation.

        Args:
            job_id: ID of the job to test
            user_id: ID of the user testing the job

        Returns:
            JobExecutionResult: Result of the job execution

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 5.3, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            raise ValueError("Invalid job ID")
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user ID")

        try:
            # Verify ownership
            job = self._get_user_job(job_id, user_id)

            if not self.scheduler:
                return JobExecutionResult(
                    success=False,
                    error_message="Job scheduler not available",
                    execution_time=0.0,
                )

            # Execute the job
            result = self.scheduler.execute_job_now(job_id)

            # Security logging
            self.security_logger.log_job_test_execution(user_id, job_id, result.success)

            logger.info(
                f"Test executed for job {job_id} by user {user_id}: {result.success}"
            )
            return result

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(f"Error testing job {job_id} for user {user_id}: {str(e)}")
            return JobExecutionResult(
                success=False,
                error_message=f"Test execution failed: {str(e)}",
                execution_time=0.0,
            )

    def get_job_execution_history(
        self, job_id: int, user_id: int, limit: int = 50
    ) -> List[JobExecutionLogModel]:
        """
        Get execution history for a job with ownership verification.

        Args:
            job_id: ID of the job
            user_id: ID of the user
            limit: Maximum number of execution logs to return

        Returns:
            List[JobExecutionLogModel]: List of execution logs

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 7.3, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            return []
        if not user_id or user_id <= 0:
            return []

        try:
            # Verify ownership
            self._get_user_job(job_id, user_id)

            # Get execution history for last 30 days (Requirements: 7.3)
            from datetime import timedelta

            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

            execution_logs = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.job_id == job_id)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .order_by(JobExecutionLogModel.executed_at.desc())
                .limit(limit)
                .all()
            )

            return execution_logs

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(f"Error getting execution history for job {job_id}: {str(e)}")
            return []

    def get_job_execution_statistics(self, job_id: int, user_id: int) -> Dict:
        """
        Get detailed execution statistics for a specific job.

        Args:
            job_id: ID of the job
            user_id: ID of the user

        Returns:
            Dict: Detailed execution statistics

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 7.1, 7.4
        """
        if not job_id or job_id <= 0:
            return {}
        if not user_id or user_id <= 0:
            return {}

        try:
            # Verify ownership
            job = self._get_user_job(job_id, user_id)

            from datetime import timedelta

            from sqlalchemy import func

            # Get 30-day execution statistics (Requirements: 7.3, 7.4)
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

            # Total executions in last 30 days
            total_executions = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.job_id == job_id)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .count()
            )

            # Successful executions in last 30 days
            successful_executions = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.job_id == job_id)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .filter(JobExecutionLogModel.success == True)
                .count()
            )

            # Calculate success rate
            success_rate = (
                (successful_executions / total_executions * 100)
                if total_executions > 0
                else 0
            )

            # Average execution time for successful runs
            avg_execution_time = (
                self.db.query(func.avg(JobExecutionLogModel.duration_seconds))
                .filter(JobExecutionLogModel.job_id == job_id)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .filter(JobExecutionLogModel.success == True)
                .scalar()
            ) or 0

            # Get most recent execution
            latest_execution = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.job_id == job_id)
                .order_by(JobExecutionLogModel.executed_at.desc())
                .first()
            )

            # Get most recent successful execution
            latest_success = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.job_id == job_id)
                .filter(JobExecutionLogModel.success == True)
                .order_by(JobExecutionLogModel.executed_at.desc())
                .first()
            )

            return {
                "job_id": job_id,
                "job_name": job.name,
                "is_active": job.is_active,
                "is_problematic": job.is_problematic(),  # Requirements: 7.2
                "current_failure_count": job.failure_count,
                "last_execution": {
                    "executed_at": latest_execution.executed_at.isoformat()
                    if latest_execution
                    else None,
                    "success": latest_execution.success if latest_execution else None,
                    "duration_seconds": latest_execution.duration_seconds
                    if latest_execution
                    else None,
                    "error_message": latest_execution.error_message
                    if latest_execution
                    else None,
                }
                if latest_execution
                else None,
                "last_successful_execution": {
                    "executed_at": latest_success.executed_at.isoformat()
                    if latest_success
                    else None,
                    "duration_seconds": latest_success.duration_seconds
                    if latest_success
                    else None,
                    "value_extracted": latest_success.value_extracted
                    if latest_success
                    else None,
                }
                if latest_success
                else None,
                "thirty_day_statistics": {
                    "total_executions": total_executions,
                    "successful_executions": successful_executions,
                    "failed_executions": total_executions - successful_executions,
                    "success_rate_percent": round(success_rate, 2),
                    "average_execution_time_seconds": round(
                        float(avg_execution_time), 2
                    ),
                },
                "cron_schedule": job.cron_schedule,
                "next_run_description": job.get_next_run_description(),
            }

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(
                f"Error getting execution statistics for job {job_id}: {str(e)}"
            )
            return {}

    def get_problematic_jobs(
        self, user_id: int, failure_threshold: int = 5
    ) -> List[JobModel]:
        """
        Get jobs that are marked as problematic due to repeated failures.

        Args:
            user_id: ID of the user
            failure_threshold: Number of consecutive failures to consider problematic

        Returns:
            List[JobModel]: List of problematic jobs

        Requirements: 1.4, 1.5, 7.2
        """
        if not user_id or user_id <= 0:
            return []

        try:
            problematic_jobs = (
                self.db.query(JobModel)
                .filter(JobModel.user_id == user_id)
                .filter(JobModel.failure_count >= failure_threshold)
                .order_by(JobModel.failure_count.desc(), JobModel.last_run_at.desc())
                .all()
            )

            return problematic_jobs

        except Exception as e:
            logger.error(f"Error getting problematic jobs for user {user_id}: {str(e)}")
            return []

    def reset_job_failure_count(self, job_id: int, user_id: int) -> bool:
        """
        Reset the failure count for a job (useful after fixing issues).

        Args:
            job_id: ID of the job
            user_id: ID of the user

        Returns:
            bool: True if reset was successful

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 7.2
        """
        if not job_id or job_id <= 0:
            return False
        if not user_id or user_id <= 0:
            return False

        try:
            # Verify ownership
            job = self._get_user_job(job_id, user_id)

            # Reset failure count and clear last error
            job.failure_count = 0
            job.last_error = None
            job.updated_at = datetime.now(timezone.utc)

            self.db.flush()

            logger.info(f"Reset failure count for job {job_id} by user {user_id}")
            return True

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(f"Error resetting failure count for job {job_id}: {str(e)}")
            return False

    def cleanup_old_execution_logs(self, days_to_keep: int = 30) -> int:
        """
        Clean up execution logs older than specified days.

        Args:
            days_to_keep: Number of days of execution logs to keep

        Returns:
            int: Number of logs deleted

        Requirements: 7.3
        """
        try:
            from datetime import timedelta

            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)

            # Delete old execution logs
            deleted_count = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at < cutoff_date)
                .delete()
            )

            self.db.flush()

            if deleted_count > 0:
                logger.info(
                    f"Cleaned up {deleted_count} old execution logs (older than {days_to_keep} days)"
                )

            return deleted_count

        except Exception as e:
            logger.error(f"Error cleaning up old execution logs: {str(e)}")
            return 0

    def get_decrypted_job_config(self, job_id: int, user_id: int) -> Optional[Dict]:
        """
        Get decrypted job configuration with security logging.

        Args:
            job_id: ID of the job
            user_id: ID of the user

        Returns:
            Optional[Dict]: Decrypted job configuration

        Raises:
            AuthorizationError: If user doesn't own the job

        Requirements: 1.4, 1.5, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            return None
        if not user_id or user_id <= 0:
            return None

        try:
            # Verify ownership
            job = self._get_user_job(job_id, user_id)

            # Parse and decrypt configuration
            encrypted_config = json.loads(job.config)
            decrypted_config = self.encryptor.decrypt_config(encrypted_config)

            # Log credential access for sensitive fields
            for field_name in decrypted_config.keys():
                if self.encryptor._is_sensitive_field(
                    field_name, decrypted_config[field_name]
                ):
                    self.security_logger.log_credential_access(
                        user_id, job_id, field_name
                    )

            return decrypted_config

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(f"Error decrypting config for job {job_id}: {str(e)}")
            return None

    def _verify_tracker_ownership(self, user_id: int, tracker_id: int) -> TrackerModel:
        """
        Verify user owns the specified tracker.

        Args:
            user_id: ID of the user
            tracker_id: ID of the tracker

        Returns:
            TrackerModel: The tracker model if owned by user

        Raises:
            AuthorizationError: If tracker not found or not owned by user

        Requirements: 1.4, 1.5, 8.2, 8.3
        """
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user ID")
        if not tracker_id or tracker_id <= 0:
            raise ValueError("Invalid tracker ID")

        try:
            tracker = (
                self.db.query(TrackerModel)
                .filter(TrackerModel.id == tracker_id, TrackerModel.user_id == user_id)
                .first()
            )

            if not tracker:
                self.security_logger.log_unauthorized_access(
                    user_id, tracker_id, "access_tracker"
                )
                raise AuthorizationError("Tracker not found or not owned by user")

            return tracker

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(f"Error verifying tracker ownership: {str(e)}")
            raise AuthorizationError("Failed to verify tracker ownership")

    def _get_user_job(self, job_id: int, user_id: int) -> JobModel:
        """
        Get job ensuring user ownership.

        Args:
            job_id: ID of the job
            user_id: ID of the user

        Returns:
            JobModel: The job model if owned by user

        Raises:
            AuthorizationError: If job not found or not owned by user

        Requirements: 1.4, 1.5, 8.2, 8.3
        """
        if not job_id or job_id <= 0:
            raise ValueError("Invalid job ID")
        if not user_id or user_id <= 0:
            raise ValueError("Invalid user ID")

        try:
            job = (
                self.db.query(JobModel)
                .filter(JobModel.id == job_id, JobModel.user_id == user_id)
                .first()
            )

            if not job:
                self.security_logger.log_unauthorized_access(
                    user_id, job_id, "access_job"
                )
                raise AuthorizationError("Job not found or not owned by user")

            return job

        except AuthorizationError:
            # Re-raise authorization errors
            raise
        except Exception as e:
            logger.error(f"Error getting user job: {str(e)}")
            raise AuthorizationError("Failed to verify job ownership")

    def get_job_statistics(self, user_id: int) -> Dict:
        """
        Get job statistics for a user.

        Args:
            user_id: ID of the user

        Returns:
            Dict: Job statistics including counts and success rates

        Requirements: 1.4, 1.5, 7.4
        """
        if not user_id or user_id <= 0:
            return {}

        try:
            from datetime import timedelta

            from sqlalchemy import func

            # Get basic job counts
            total_jobs = (
                self.db.query(JobModel).filter(JobModel.user_id == user_id).count()
            )

            active_jobs = (
                self.db.query(JobModel)
                .filter(JobModel.user_id == user_id, JobModel.is_active == True)
                .count()
            )

            # Get jobs by type
            job_types = (
                self.db.query(JobModel.job_type, func.count(JobModel.id))
                .filter(JobModel.user_id == user_id)
                .group_by(JobModel.job_type)
                .all()
            )

            # Get problematic jobs (Requirements: 7.2)
            problematic_jobs = (
                self.db.query(JobModel)
                .filter(JobModel.user_id == user_id, JobModel.failure_count >= 5)
                .count()
            )

            # Get recent execution statistics (today)
            today_start = datetime.now(timezone.utc).replace(
                hour=0, minute=0, second=0, microsecond=0
            )

            recent_executions = (
                self.db.query(JobExecutionLogModel)
                .join(JobModel)
                .filter(JobModel.user_id == user_id)
                .filter(JobExecutionLogModel.executed_at >= today_start)
                .count()
            )

            successful_executions = (
                self.db.query(JobExecutionLogModel)
                .join(JobModel)
                .filter(JobModel.user_id == user_id)
                .filter(JobExecutionLogModel.success == True)
                .filter(JobExecutionLogModel.executed_at >= today_start)
                .count()
            )

            # Get 30-day execution statistics (Requirements: 7.3, 7.4)
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

            monthly_executions = (
                self.db.query(JobExecutionLogModel)
                .join(JobModel)
                .filter(JobModel.user_id == user_id)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .count()
            )

            monthly_successful = (
                self.db.query(JobExecutionLogModel)
                .join(JobModel)
                .filter(JobModel.user_id == user_id)
                .filter(JobExecutionLogModel.success == True)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .count()
            )

            # Calculate average execution time (Requirements: 7.4)
            avg_execution_time = (
                self.db.query(func.avg(JobExecutionLogModel.duration_seconds))
                .join(JobModel)
                .filter(JobModel.user_id == user_id)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .filter(JobExecutionLogModel.success == True)
                .scalar()
            ) or 0

            return {
                "total_jobs": total_jobs,
                "active_jobs": active_jobs,
                "inactive_jobs": total_jobs - active_jobs,
                "job_types": dict(job_types),
                "problematic_jobs": problematic_jobs,
                "today_executions": recent_executions,
                "today_successful": successful_executions,
                "today_success_rate": (
                    (successful_executions / recent_executions * 100)
                    if recent_executions > 0
                    else 0
                ),
                "monthly_executions": monthly_executions,
                "monthly_successful": monthly_successful,
                "monthly_success_rate": (
                    (monthly_successful / monthly_executions * 100)
                    if monthly_executions > 0
                    else 0
                ),
                "average_execution_time_seconds": round(float(avg_execution_time), 2),
            }

        except Exception as e:
            logger.error(f"Error getting job statistics for user {user_id}: {str(e)}")
            return {}
