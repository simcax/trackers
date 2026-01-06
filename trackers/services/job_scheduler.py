"""
Job Scheduler Service for automated job scheduling system.

This module provides the JobScheduler class that integrates with APScheduler
to manage and execute scheduled jobs that fetch data from external APIs.
Includes comprehensive error handling, failure isolation, and resilience features.

Requirements: 2.1, 2.2, 2.4, 6.2, 6.5
"""

import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from flask import Flask

from trackers.db.database import get_db_session
from trackers.models.job_model import JobExecutionLogModel, JobModel
from trackers.services.job_providers import (
    BaseJobProvider,
    GenericJobProvider,
    StockJobProvider,
)
from trackers.services.job_providers.base_job_provider import JobExecutionResult
from trackers.services.job_providers.error_handling import (
    ErrorCategory,
    ErrorSeverity,
    JobFailureIsolation,
    StructuredErrorLogger,
)

logger = logging.getLogger(__name__)


class JobScheduler:
    """
    APScheduler-based job scheduler for automated data fetching.

    This class manages the lifecycle of scheduled jobs, integrating with
    APScheduler to execute jobs at specified intervals. Jobs are loaded
    from the database and executed in separate threads to avoid blocking
    the main Flask application. Includes failure isolation to prevent
    problematic jobs from crashing the scheduler.

    Requirements: 2.1, 2.2, 2.4, 6.5
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize JobScheduler with optional Flask app context.

        Args:
            app: Flask application instance (optional)

        Requirements: 2.1, 6.5
        """
        self.app = app
        self.scheduler: Optional[BackgroundScheduler] = None
        self.is_running = False
        self._lock = threading.Lock()
        self._scheduled_jobs: Dict[int, str] = {}  # job_id -> scheduler_job_id mapping

        # Initialize failure isolation and error handling
        self.failure_isolation = JobFailureIsolation(max_consecutive_failures=5)
        self.error_logger = StructuredErrorLogger("job_scheduler")

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize scheduler with Flask application.

        Args:
            app: Flask application instance

        Requirements: 2.1
        """
        self.app = app

        # Configure APScheduler
        app.config.setdefault("SCHEDULER_TIMEZONE", "UTC")
        app.config.setdefault("SCHEDULER_API_ENABLED", False)

        # Initialize scheduler
        self.scheduler = BackgroundScheduler(
            timezone=app.config["SCHEDULER_TIMEZONE"],
            daemon=True,  # Dies when main thread dies
        )

        # Register shutdown handler
        app.teardown_appcontext(self._cleanup_context)

        logger.info("JobScheduler initialized with Flask app")

    def start(self) -> None:
        """
        Start the background scheduler and load active jobs.

        This method starts the APScheduler background scheduler and loads
        all active jobs from the database. Jobs are scheduled according
        to their cron expressions.

        Requirements: 2.1, 2.2
        """
        if not self.scheduler:
            raise RuntimeError("JobScheduler not initialized with Flask app")

        with self._lock:
            if self.is_running:
                logger.warning("JobScheduler is already running")
                return

            try:
                # Start the scheduler
                self.scheduler.start()
                self.is_running = True
                logger.info("APScheduler started successfully")

                # Load and schedule active jobs from database
                self._load_jobs_from_database()

                logger.info(
                    f"JobScheduler started with {len(self._scheduled_jobs)} active jobs"
                )

            except Exception as e:
                logger.error(f"Failed to start JobScheduler: {str(e)}")
                self.is_running = False
                raise

    def stop(self) -> None:
        """
        Stop the scheduler gracefully and clean up resources.

        This method stops the APScheduler and cleans up all scheduled jobs.
        It waits for currently executing jobs to complete before shutting down.

        Requirements: 2.4
        """
        with self._lock:
            if not self.is_running:
                logger.info("JobScheduler is not running")
                return

            try:
                if self.scheduler:
                    # Shutdown scheduler, waiting for jobs to complete
                    self.scheduler.shutdown(wait=True)
                    logger.info("APScheduler stopped gracefully")

                self.is_running = False
                self._scheduled_jobs.clear()
                logger.info("JobScheduler stopped successfully")

            except Exception as e:
                logger.error(f"Error stopping JobScheduler: {str(e)}")
                self.is_running = False
                raise

    def add_job(self, job_config: JobModel) -> bool:
        """
        Add or update a scheduled job in the scheduler.

        Args:
            job_config: JobModel instance with job configuration

        Returns:
            bool: True if job was added/updated successfully, False otherwise

        Requirements: 2.2, 6.5, 7.5
        """
        if not self.is_running:
            logger.warning(f"Cannot add job {job_config.id}: scheduler not running")
            return False

        # Requirements: 7.5 - Remove disabled jobs from scheduler but preserve configuration
        if not job_config.is_active:
            logger.info(
                f"Job {job_config.id} is disabled, removing from scheduler but preserving configuration"
            )
            return self.remove_job(job_config.id)

        # Check if job is isolated due to failures
        if self.failure_isolation.is_job_isolated(job_config.id):
            isolation_status = self.failure_isolation.get_isolation_status(
                job_config.id
            )
            logger.warning(
                f"Job {job_config.id} is isolated due to failures. "
                f"Time remaining: {isolation_status.get('time_remaining', 0):.1f}s"
            )
            return False

        try:
            # Remove existing job if it exists
            self.remove_job(job_config.id)

            # Create cron trigger
            trigger = CronTrigger.from_crontab(job_config.cron_schedule)

            # Add job to scheduler with failure isolation wrapper
            scheduler_job = self.scheduler.add_job(
                func=self._execute_job_with_isolation,
                trigger=trigger,
                args=[job_config.id],
                id=f"job_{job_config.id}",
                name=f"{job_config.name} (ID: {job_config.id})",
                replace_existing=True,
                max_instances=1,  # Prevent overlapping executions
                coalesce=True,  # Combine missed executions
                misfire_grace_time=300,  # 5 minutes grace time for missed executions
            )

            # Track the scheduled job
            self._scheduled_jobs[job_config.id] = scheduler_job.id

            logger.info(
                f"Added job {job_config.id} ({job_config.name}) with schedule '{job_config.cron_schedule}'"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to add job {job_config.id}: {str(e)}")

            # Log structured error
            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.SYSTEM,
                severity=ErrorSeverity.HIGH,
                job_id=job_config.id,
                context={
                    "operation": "add_job",
                    "cron_schedule": job_config.cron_schedule,
                },
            )
            self.error_logger.log_error(error_details)

            return False

    def remove_job(self, job_id: int) -> bool:
        """
        Remove a job from the scheduler.

        Args:
            job_id: Database ID of the job to remove

        Returns:
            bool: True if job was removed successfully, False otherwise

        Requirements: 2.2
        """
        if not self.is_running:
            logger.warning(f"Cannot remove job {job_id}: scheduler not running")
            return False

        try:
            scheduler_job_id = f"job_{job_id}"

            # Remove from APScheduler
            if self.scheduler.get_job(scheduler_job_id):
                self.scheduler.remove_job(scheduler_job_id)
                logger.info(f"Removed job {job_id} from scheduler")

            # Remove from tracking
            self._scheduled_jobs.pop(job_id, None)

            return True

        except Exception as e:
            logger.error(f"Failed to remove job {job_id}: {str(e)}")
            return False

    def execute_job_now(self, job_id: int) -> JobExecutionResult:
        """
        Execute a job immediately for manual testing/monitoring purposes.

        This method executes a job immediately and saves the execution log
        to provide visibility into job performance and results.

        Args:
            job_id: Database ID of the job to execute

        Returns:
            JobExecutionResult: Result of the job execution

        Requirements: 2.2
        """
        logger.info(f"Executing job {job_id} immediately (manual execution)")

        try:
            # Execute the job directly (not through scheduler)
            import asyncio

            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            # Execute with is_test=False so logs are saved, but mark as manual execution
            return loop.run_until_complete(
                self._execute_job_async(job_id, is_test=False, is_manual=True)
            )

        except Exception as e:
            logger.error(f"Failed to execute job {job_id} immediately: {str(e)}")
            return JobExecutionResult(
                success=False,
                error_message=f"Failed to execute job: {str(e)}",
                execution_time=0.0,
            )

    def get_scheduled_jobs(self) -> List[dict]:
        """
        Get information about currently scheduled jobs.

        Returns:
            List[dict]: List of scheduled job information

        Requirements: 2.2
        """
        if not self.is_running or not self.scheduler:
            return []

        scheduled_jobs = []
        for job in self.scheduler.get_jobs():
            job_info = {
                "scheduler_job_id": job.id,
                "name": job.name,
                "next_run_time": job.next_run_time.isoformat()
                if job.next_run_time
                else None,
                "trigger": str(job.trigger),
            }
            scheduled_jobs.append(job_info)

        return scheduled_jobs

    def get_scheduler_status(self) -> dict:
        """
        Get current scheduler status and statistics.

        Returns:
            dict: Scheduler status information

        Requirements: 2.2, 6.5
        """
        return {
            "is_running": self.is_running,
            "scheduled_jobs_count": len(self._scheduled_jobs),
            "scheduler_state": self.scheduler.state if self.scheduler else None,
            "scheduler_running": self.scheduler.running if self.scheduler else False,
            "failure_isolation": {
                "isolated_jobs_count": len(self.failure_isolation.isolated_jobs),
                "jobs_with_failures": len(self.failure_isolation.failure_counts),
                "max_consecutive_failures": self.failure_isolation.max_consecutive_failures,
                "isolation_duration": self.failure_isolation.isolation_duration,
            },
        }

    def _load_jobs_from_database(self) -> None:
        """
        Load all active jobs from database and schedule them.

        Requirements: 2.1
        """
        try:
            with get_db_session() as db:
                active_jobs = (
                    db.query(JobModel).filter(JobModel.is_active == True).all()
                )

                loaded_count = 0
                for job in active_jobs:
                    if self.add_job(job):
                        loaded_count += 1

                logger.info(f"Loaded {loaded_count} active jobs from database")

        except Exception as e:
            logger.error(f"Failed to load jobs from database: {str(e)}")

    def _execute_job_with_isolation(
        self, job_id: int, is_test: bool = False
    ) -> JobExecutionResult:
        """
        Execute a job with failure isolation to prevent scheduler crashes.

        This wrapper method ensures that job failures don't crash the scheduler
        and implements failure isolation for problematic jobs.

        Args:
            job_id: Database ID of the job to execute
            is_test: Whether this is a test execution

        Returns:
            JobExecutionResult: Result of the job execution

        Requirements: 6.5
        """
        try:
            # Check if job is isolated
            if not is_test and self.failure_isolation.is_job_isolated(job_id):
                isolation_status = self.failure_isolation.get_isolation_status(job_id)
                error_msg = (
                    f"Job {job_id} is isolated due to {isolation_status['failure_count']} "
                    f"consecutive failures. Time remaining: {isolation_status.get('time_remaining', 0):.1f}s"
                )
                logger.warning(error_msg)

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    execution_time=0.0,
                )

            # Execute the job
            result = self._execute_job(job_id, is_test)

            # Record success or failure for isolation tracking
            if not is_test:
                if result.success:
                    self.failure_isolation.record_success(job_id)
                else:
                    should_isolate = self.failure_isolation.record_failure(job_id)
                    if should_isolate:
                        logger.error(
                            f"Job {job_id} has been isolated due to consecutive failures. "
                            f"It will be re-enabled after {self.failure_isolation.isolation_duration}s"
                        )

                        # Log isolation event
                        error_details = self.error_logger.create_error_details(
                            exception=Exception(
                                f"Job isolated due to {self.failure_isolation.max_consecutive_failures} consecutive failures"
                            ),
                            category=ErrorCategory.SYSTEM,
                            severity=ErrorSeverity.HIGH,
                            job_id=job_id,
                            context={
                                "isolation_duration": self.failure_isolation.isolation_duration,
                                "failure_count": self.failure_isolation.failure_counts.get(
                                    job_id, 0
                                ),
                            },
                        )
                        self.error_logger.log_error(error_details)

            return result

        except Exception as e:
            # This is the ultimate safety net - even if job execution completely fails,
            # we don't want to crash the scheduler
            error_msg = f"Critical error in job execution wrapper: {str(e)}"
            logger.critical(error_msg, exc_info=True)

            # Log critical error
            error_details = self.error_logger.create_error_details(
                exception=e,
                category=ErrorCategory.SYSTEM,
                severity=ErrorSeverity.CRITICAL,
                job_id=job_id,
                context={"wrapper_failure": True, "is_test": is_test},
            )
            self.error_logger.log_error(error_details)

            # Record failure for isolation (if not test)
            if not is_test:
                self.failure_isolation.record_failure(job_id)

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                execution_time=0.0,
            )

    def _execute_job(self, job_id: int, is_test: bool = False) -> JobExecutionResult:
        """
        Execute a single job and handle all aspects of execution.

        This method runs in a separate thread and handles job execution,
        error handling, logging, and database updates. It wraps the async
        execution to work with APScheduler.

        Args:
            job_id: Database ID of the job to execute
            is_test: Whether this is a test execution

        Returns:
            JobExecutionResult: Result of the job execution

        Requirements: 2.2, 2.4, 6.2
        """
        import asyncio

        # Run the async job execution in the current thread
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        return loop.run_until_complete(
            self._execute_job_async(job_id, is_test, is_manual=False)
        )

    async def _execute_job_async(
        self, job_id: int, is_test: bool = False, is_manual: bool = False
    ) -> JobExecutionResult:
        """
        Execute a single job and handle all aspects of execution.

        This method runs in a separate thread and handles job execution,
        error handling, logging, and database updates.

        Args:
            job_id: Database ID of the job to execute
            is_test: Whether this is a test execution

        Returns:
            JobExecutionResult: Result of the job execution

        Requirements: 2.2, 2.4
        """
        start_time = datetime.now(timezone.utc)
        execution_result = None

        try:
            # Create new database session for this job execution
            with get_db_session() as db:
                # Get job configuration
                job = db.query(JobModel).filter(JobModel.id == job_id).first()
                if not job:
                    error_msg = f"Job {job_id} not found in database"
                    logger.error(error_msg)
                    return JobExecutionResult(
                        success=False,
                        error_message=error_msg,
                        execution_time=0.0,
                    )

                if not job.is_active and not is_test:
                    error_msg = f"Job {job_id} is not active"
                    logger.warning(error_msg)
                    return JobExecutionResult(
                        success=False,
                        error_message=error_msg,
                        execution_time=0.0,
                    )

                logger.info(
                    f"Executing job {job_id} ({job.name}) - Type: {job.job_type}"
                )

                # Create appropriate job provider based on job type
                job_provider = self._create_job_provider(job)
                if not job_provider:
                    error_msg = f"Unsupported job type: {job.job_type}"
                    logger.error(error_msg)
                    return JobExecutionResult(
                        success=False,
                        error_message=error_msg,
                        execution_time=(
                            datetime.now(timezone.utc) - start_time
                        ).total_seconds(),
                    )

                # Execute the job
                execution_result = await job_provider.execute()

                # Update job execution tracking (only for non-test executions)
                if not is_test:
                    job.update_last_run(
                        success=execution_result.success,
                        error_message=execution_result.error_message,
                    )

                    # Create execution log with enhanced error information
                    # Create enhanced error message with detailed information
                    error_message = execution_result.error_message
                    if (
                        execution_result.error_details
                        or execution_result.error_category
                    ):
                        # Create a detailed error message that includes structured information
                        detailed_parts = [error_message] if error_message else []

                        if execution_result.error_category:
                            detailed_parts.append(
                                f"Category: {execution_result.error_category}"
                            )

                        if execution_result.error_details:
                            # Add key error details in a readable format
                            details = execution_result.error_details
                            if isinstance(details, dict):
                                for key, value in details.items():
                                    if key in [
                                        "provider",
                                        "symbol",
                                        "api_error",
                                        "exception_type",
                                        "missing_credential",
                                    ]:
                                        detailed_parts.append(
                                            f"{key.replace('_', ' ').title()}: {value}"
                                        )

                                # Add specific troubleshooting info
                                if "possible_causes" in details and isinstance(
                                    details["possible_causes"], list
                                ):
                                    detailed_parts.append(
                                        f"Possible causes: {', '.join(details['possible_causes'][:3])}"
                                    )

                                if "solution" in details:
                                    detailed_parts.append(
                                        f"Solution: {details['solution']}"
                                    )

                        error_message = " | ".join(detailed_parts)

                    # Add manual execution prefix
                    if is_manual and error_message:
                        error_message = f"[Manual] {error_message}"
                    elif is_manual and not error_message:
                        # For successful manual executions, we can add a note in a different way
                        pass  # Keep error_message as None for successful executions

                    execution_log = JobExecutionLogModel(
                        job_id=job_id,
                        success=execution_result.success,
                        duration_seconds=int(execution_result.execution_time),
                        value_extracted=str(execution_result.value)
                        if execution_result.value
                        else None,
                        error_message=error_message,
                        http_status_code=execution_result.http_status,
                        response_size=execution_result.response_size,
                    )

                    db.add(execution_log)
                    db.commit()

                if execution_result.success:
                    execution_type = "manually" if is_manual else "automatically"
                    logger.info(
                        f"Job {job_id} executed {execution_type} and succeeded in {execution_result.execution_time:.2f}s"
                    )
                else:
                    execution_type = "manual" if is_manual else "scheduled"
                    logger.warning(
                        f"Job {job_id} ({execution_type} execution) failed: {execution_result.error_message}"
                    )

                    # Log structured error for job failure
                    error_details = self.error_logger.create_error_details(
                        exception=Exception(
                            execution_result.error_message or "Job execution failed"
                        ),
                        category=ErrorCategory.SYSTEM,
                        severity=ErrorSeverity.MEDIUM,
                        job_id=job_id,
                        context={
                            "execution_time": execution_result.execution_time,
                            "job_type": job.job_type,
                            "is_test": is_test,
                        },
                    )
                    self.error_logger.log_error(error_details)

        except Exception as e:
            execution_time = (datetime.now(timezone.utc) - start_time).total_seconds()
            error_message = f"Job execution failed: {str(e)}"
            logger.error(f"Job {job_id} execution failed: {str(e)}", exc_info=True)

            execution_result = JobExecutionResult(
                success=False,
                error_message=error_message,
                execution_time=execution_time,
            )

            # Update job failure tracking (only for non-test executions)
            if not is_test:
                try:
                    with get_db_session() as db:
                        job = db.query(JobModel).filter(JobModel.id == job_id).first()
                        if job:
                            job.update_last_run(
                                success=False, error_message=error_message
                            )

                            # Create failure log with enhanced error information
                            # Add note for manual executions
                            log_error_message = error_message
                            if is_manual:
                                log_error_message = f"[Manual] {error_message}"

                            execution_log = JobExecutionLogModel(
                                job_id=job_id,
                                success=False,
                                duration_seconds=int(execution_time),
                                error_message=log_error_message,
                            )

                            db.add(execution_log)
                            db.commit()

                except Exception as log_error:
                    logger.error(
                        f"Failed to log job {job_id} failure: {str(log_error)}"
                    )

                    # Log the logging error itself
                    error_details = self.error_logger.create_error_details(
                        exception=log_error,
                        category=ErrorCategory.SYSTEM,
                        severity=ErrorSeverity.HIGH,
                        job_id=job_id,
                        context={
                            "operation": "log_failure",
                            "original_error": error_message,
                        },
                    )
                    self.error_logger.log_error(error_details)

        return execution_result

    def _create_job_provider(self, job_config: JobModel) -> Optional[BaseJobProvider]:
        """
        Create appropriate job provider based on job type.

        Args:
            job_config: JobModel instance containing job configuration

        Returns:
            Job provider instance or None if job type is unsupported

        Requirements: 2.2
        """
        try:
            if job_config.job_type == "stock":
                return StockJobProvider(job_config)
            elif job_config.job_type == "generic":
                return GenericJobProvider(job_config)
            else:
                logger.error(f"Unsupported job type: {job_config.job_type}")
                return None

        except Exception as e:
            logger.error(f"Failed to create job provider for job {job_config.id}: {e}")
            return None

    def _cleanup_context(self, exception=None) -> None:
        """
        Clean up resources when Flask application context is torn down.

        Args:
            exception: Exception that caused the teardown (if any)

        Requirements: 2.4
        """
        # This is called when Flask app context is torn down
        # We don't stop the scheduler here as it should continue running
        # across requests. The scheduler is stopped when the app shuts down.
        pass

    def get_job_isolation_status(self, job_id: int) -> Dict[str, Any]:
        """
        Get isolation status for a specific job.

        Args:
            job_id: ID of the job to check

        Returns:
            Dictionary with isolation status information

        Requirements: 6.5
        """
        return self.failure_isolation.get_isolation_status(job_id)

    def get_all_isolation_statuses(self) -> List[Dict[str, Any]]:
        """
        Get isolation status for all jobs with failures or isolation.

        Returns:
            List of isolation status dictionaries

        Requirements: 6.5
        """
        statuses = []

        # Get status for all jobs with failures
        for job_id in self.failure_isolation.failure_counts.keys():
            statuses.append(self.failure_isolation.get_isolation_status(job_id))

        # Get status for all isolated jobs (in case some don't have failure counts)
        for job_id in self.failure_isolation.isolated_jobs.keys():
            if job_id not in self.failure_isolation.failure_counts:
                statuses.append(self.failure_isolation.get_isolation_status(job_id))

        return statuses

    def reset_job_isolation(self, job_id: int) -> bool:
        """
        Reset isolation status for a job (admin function).

        Args:
            job_id: ID of the job to reset

        Returns:
            True if reset was successful

        Requirements: 6.5
        """
        try:
            self.failure_isolation.record_success(job_id)
            logger.info(f"Reset isolation status for job {job_id}")

            # Log reset event
            error_details = self.error_logger.create_error_details(
                exception=Exception("Job isolation manually reset"),
                category=ErrorCategory.SYSTEM,
                severity=ErrorSeverity.LOW,
                job_id=job_id,
                context={"operation": "reset_isolation", "admin_action": True},
            )
            self.error_logger.log_error(error_details)

            return True
        except Exception as e:
            logger.error(f"Failed to reset isolation for job {job_id}: {e}")
            return False

    def __del__(self):
        """
        Destructor to ensure scheduler is stopped when object is destroyed.

        Requirements: 2.4
        """
        try:
            if self.is_running:
                self.stop()
        except Exception as e:
            logger.error(f"Error in JobScheduler destructor: {str(e)}")
