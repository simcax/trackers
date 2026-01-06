"""
Base Job Provider for Automated Job Scheduling.

This module provides the abstract base class for all job providers and
the JobExecutionResult data class for tracking execution results.

Requirements: 5.1, 5.2, 5.4, 8.4, 8.5
"""

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from trackers.models.job_model import JobModel
from trackers.security.job_config_encryption import JobConfigEncryption

logger = logging.getLogger(__name__)


@dataclass
class JobExecutionResult:
    """
    Result of a job execution containing success status and metadata.

    This class encapsulates all information about a job execution,
    including success status, extracted value, error details, and
    performance metrics.

    Requirements: 5.1, 5.2
    """

    success: bool
    value: Optional[float] = None
    error_message: Optional[str] = None
    execution_time: float = 0.0
    timestamp: datetime = None
    http_status: Optional[int] = None
    response_size: Optional[int] = None
    # Enhanced error details
    error_category: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    api_response: Optional[str] = None  # Truncated API response for debugging

    def __post_init__(self):
        """Set timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "success": self.success,
            "value": self.value,
            "error_message": self.error_message,
            "execution_time": self.execution_time,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "http_status": self.http_status,
            "response_size": self.response_size,
            "error_category": self.error_category,
            "error_details": self.error_details,
            "api_response": self.api_response,
        }


class BaseJobProvider(ABC):
    """
    Abstract base class for all job providers.

    This class defines the common interface and functionality that all
    job providers must implement. It handles configuration decryption,
    common validation, and provides the framework for job execution.

    Requirements: 5.1, 5.2, 5.4, 8.4, 8.5
    """

    def __init__(self, job_config: JobModel):
        """
        Initialize job provider with configuration.

        Args:
            job_config: JobModel instance containing job configuration

        Requirements: 5.1, 8.4
        """
        self.job_config = job_config
        self.logger = logging.getLogger(f"{self.__class__.__name__}")

        # Initialize encryption system
        self.encryptor = JobConfigEncryption()

        # Decrypt and parse configuration
        try:
            encrypted_config = json.loads(job_config.config)
            self.config = self.encryptor.decrypt_config(encrypted_config)
            self.logger.debug(f"Configuration decrypted for job {job_config.id}")
        except Exception as e:
            self.logger.error(f"Failed to decrypt job configuration: {e}")
            self.config = {}

    @abstractmethod
    async def fetch_data(self) -> Optional[float]:
        """
        Fetch numeric data from external source.

        This method must be implemented by concrete job providers to
        fetch data from their specific external sources.

        Returns:
            Numeric value fetched from external source, or None if failed.
            Can also return a JobExecutionResult for enhanced error reporting.

        Requirements: 5.1, 5.2
        """
        pass

    @abstractmethod
    def validate_config(self) -> List[str]:
        """
        Validate job configuration and return list of errors.

        This method must be implemented by concrete job providers to
        validate their specific configuration requirements.

        Returns:
            List of validation error messages (empty if valid)

        Requirements: 5.1, 5.4
        """
        pass

    async def execute(self) -> JobExecutionResult:
        """
        Execute the job and return execution result.

        This method orchestrates the complete job execution process:
        1. Validates configuration
        2. Fetches data from external source
        3. Stores result in tracker (if successful)
        4. Returns execution result with metadata

        Returns:
            JobExecutionResult with execution details

        Requirements: 5.1, 5.2, 5.4
        """
        start_time = datetime.now(timezone.utc)

        try:
            # Validate configuration before execution
            validation_errors = self.validate_config()
            if validation_errors:
                error_msg = (
                    f"Configuration validation failed: {'; '.join(validation_errors)}"
                )
                self.logger.error(error_msg)
                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    execution_time=self._calculate_execution_time(start_time),
                    timestamp=start_time,
                    error_category="configuration",
                    error_details={
                        "validation_errors": validation_errors,
                        "job_type": self.job_config.job_type,
                        "job_id": self.job_config.id,
                    },
                )

            # Fetch data from external source
            self.logger.info(
                f"Executing job {self.job_config.id} ({self.job_config.name})"
            )

            # Store the result from fetch_data which may include detailed error info
            fetch_result = await self.fetch_data()
            execution_time = self._calculate_execution_time(start_time)

            # Check if fetch_data returned a JobExecutionResult (enhanced error handling)
            if isinstance(fetch_result, JobExecutionResult):
                # fetch_data returned detailed error information
                fetch_result.execution_time = execution_time
                fetch_result.timestamp = start_time

                if fetch_result.success and fetch_result.value is not None:
                    # Store value in tracker
                    await self._store_tracker_value(fetch_result.value)
                    self.logger.info(
                        f"Job {self.job_config.id} completed successfully: value={fetch_result.value}, "
                        f"time={execution_time:.2f}s"
                    )
                else:
                    self.logger.warning(
                        f"Job {self.job_config.id} failed: {fetch_result.error_message}"
                    )

                return fetch_result

            # Legacy behavior: fetch_data returned Optional[float]
            elif fetch_result is not None:
                # Store value in tracker
                await self._store_tracker_value(fetch_result)

                self.logger.info(
                    f"Job {self.job_config.id} completed successfully: value={fetch_result}, "
                    f"time={execution_time:.2f}s"
                )

                return JobExecutionResult(
                    success=True,
                    value=fetch_result,
                    execution_time=execution_time,
                    timestamp=start_time,
                )
            else:
                # Generic failure - this should be rare with enhanced error handling
                error_msg = "Failed to fetch data from external source"
                self.logger.warning(f"Job {self.job_config.id} failed: {error_msg}")

                return JobExecutionResult(
                    success=False,
                    error_message=error_msg,
                    execution_time=execution_time,
                    timestamp=start_time,
                    error_category="data_fetch",
                    error_details={
                        "job_type": self.job_config.job_type,
                        "job_id": self.job_config.id,
                        "reason": "fetch_data returned None without detailed error info",
                    },
                )

        except Exception as e:
            execution_time = self._calculate_execution_time(start_time)
            error_msg = f"Job execution failed: {str(e)}"

            self.logger.error(
                f"Job {self.job_config.id} failed with exception: {e}", exc_info=True
            )

            return JobExecutionResult(
                success=False,
                error_message=error_msg,
                execution_time=execution_time,
                timestamp=start_time,
                error_category="system",
                error_details={
                    "exception_type": type(e).__name__,
                    "job_type": self.job_config.job_type,
                    "job_id": self.job_config.id,
                    "traceback": str(e),
                },
            )

    async def _store_tracker_value(self, value: float) -> None:
        """
        Store the fetched value in the associated tracker.

        Args:
            value: Numeric value to store

        Requirements: 5.2
        """
        try:
            from trackers.db.database import SessionLocal
            from trackers.models.tracker_value_model import TrackerValueModel

            # Create database session
            db_session = SessionLocal()

            try:
                # Create new tracker value
                tracker_value = TrackerValueModel(
                    tracker_id=self.job_config.tracker_id,
                    value=value,
                    date=datetime.now(timezone.utc).date(),
                )

                db_session.add(tracker_value)
                db_session.commit()

                self.logger.debug(
                    f"Stored value {value} for tracker {self.job_config.tracker_id}"
                )

            finally:
                db_session.close()

        except Exception as e:
            self.logger.error(f"Failed to store tracker value: {e}")
            raise

    def _calculate_execution_time(self, start_time: datetime) -> float:
        """
        Calculate execution time in seconds.

        Args:
            start_time: Job execution start time

        Returns:
            Execution time in seconds
        """
        return (datetime.now(timezone.utc) - start_time).total_seconds()

    def _get_secure_credential(self, field_name: str) -> Optional[str]:
        """
        Safely retrieve and decrypt credential from configuration.

        Args:
            field_name: Name of the credential field

        Returns:
            Decrypted credential value or None if not found

        Requirements: 8.4, 8.5
        """
        return self.encryptor.get_secure_credential(self.config, field_name)

    def get_job_info(self) -> Dict[str, Any]:
        """
        Get information about this job provider.

        Returns:
            Dictionary with job provider information

        Requirements: 5.1
        """
        return {
            "job_id": self.job_config.id,
            "job_name": self.job_config.name,
            "job_type": self.job_config.job_type,
            "provider_class": self.__class__.__name__,
            "tracker_id": self.job_config.tracker_id,
            "user_id": self.job_config.user_id,
            "is_active": self.job_config.is_active,
            "cron_schedule": self.job_config.cron_schedule,
        }
