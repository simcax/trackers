"""
Job Model for automated job scheduling system.

This module provides the JobModel class for storing scheduled job configurations
that automatically fetch data from external APIs and populate tracker values.

Requirements: 9.1, 9.2, 9.3, 8.1
"""

from datetime import datetime, timezone


def _utc_now():
    """Helper function to get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class JobModel(Base):
    """
    Database model for storing scheduled job configurations.

    This model stores job information for automated data fetching from external APIs.
    Jobs are tied to users and can only access user-owned trackers. Configuration
    data is encrypted before storage for security.

    Requirements: 9.1, 9.2, 9.3, 8.1
    """

    __tablename__ = "jobs"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Job identification and metadata
    name = Column(String(100), nullable=False)
    job_type = Column(String(50), nullable=False)  # 'stock', 'generic'

    # User ownership - Requirements: 9.2
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Tracker relationship - Requirements: 9.2
    tracker_id = Column(
        Integer,
        ForeignKey("trackers.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Job configuration and scheduling - Requirements: 9.1, 8.1
    config = Column(Text, nullable=False)  # Encrypted JSON configuration
    cron_schedule = Column(String(50), nullable=False)  # Cron expression
    is_active = Column(Boolean, default=True, nullable=False)

    # Timestamp fields
    created_at = Column(DateTime, default=_utc_now, nullable=False)
    updated_at = Column(
        DateTime,
        default=_utc_now,
        onupdate=_utc_now,
        nullable=False,
    )

    # Execution tracking
    last_run_at = Column(DateTime, nullable=True)
    last_success_at = Column(DateTime, nullable=True)
    failure_count = Column(Integer, default=0, nullable=False)
    last_error = Column(Text, nullable=True)

    # Relationships - Requirements: 9.2
    user = relationship("UserModel", back_populates="jobs")
    tracker = relationship("TrackerModel", back_populates="jobs")
    execution_logs = relationship(
        "JobExecutionLogModel",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="JobExecutionLogModel.executed_at.desc()",
    )

    # Indexes for performance - Requirements: 9.3
    __table_args__ = (
        Index("idx_jobs_user_id", "user_id"),
        Index("idx_jobs_tracker_id", "tracker_id"),
        Index("idx_jobs_type", "job_type"),
        Index("idx_jobs_active", "is_active"),
        Index("idx_jobs_last_run", "last_run_at"),
        Index("idx_jobs_created", "created_at"),
        Index("idx_jobs_user_tracker", "user_id", "tracker_id"),
    )

    def __repr__(self) -> str:
        """String representation of the job model."""
        return f"<JobModel(id={self.id}, name='{self.name}', type='{self.job_type}', user_id={self.user_id})>"

    def update_last_run(self, success: bool = True, error_message: str = None) -> None:
        """
        Update job execution tracking information.

        Args:
            success: Whether the job execution was successful
            error_message: Error message if execution failed

        Requirements: 9.3
        """
        self.last_run_at = datetime.now(timezone.utc)

        if success:
            self.last_success_at = datetime.now(timezone.utc)
            self.failure_count = 0
            self.last_error = None
        else:
            self.failure_count += 1
            self.last_error = error_message

    def is_problematic(self, failure_threshold: int = 5) -> bool:
        """
        Check if job has too many consecutive failures.

        Args:
            failure_threshold: Number of failures to consider problematic

        Returns:
            True if job has exceeded failure threshold

        Requirements: 9.3
        """
        return self.failure_count >= failure_threshold

    def get_next_run_description(self) -> str:
        """
        Get human-readable description of when job will run next.

        Returns:
            String description of cron schedule

        Requirements: 9.1
        """
        # Basic cron description - could be enhanced with croniter library
        if self.cron_schedule == "0 9 * * *":
            return "Daily at 9:00 AM"
        elif self.cron_schedule == "0 */6 * * *":
            return "Every 6 hours"
        elif self.cron_schedule == "*/15 * * * *":
            return "Every 15 minutes"
        else:
            return f"Cron: {self.cron_schedule}"

    def to_dict(self) -> dict:
        """
        Convert job model to dictionary representation.

        Returns:
            dict: Job data as dictionary (config is not included for security)

        Requirements: 9.1, 8.1, 7.1
        """
        return {
            "id": self.id,
            "name": self.name,
            "job_type": self.job_type,
            "user_id": self.user_id,
            "tracker_id": self.tracker_id,
            "cron_schedule": self.cron_schedule,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_success_at": self.last_success_at.isoformat()
            if self.last_success_at
            else None,
            "failure_count": self.failure_count,
            "last_error": self.last_error,
            "next_run_description": self.get_next_run_description(),
            "is_problematic": self.is_problematic(),
            "status_summary": self.get_status_summary(),  # Requirements: 7.1, 7.2
        }

    def get_status_summary(self) -> dict:
        """
        Get a summary of the job's current status for monitoring.

        Returns:
            dict: Status summary including health indicators

        Requirements: 7.1, 7.2
        """
        status = "healthy"
        message = "Job is running normally"

        if not self.is_active:
            status = "disabled"
            message = "Job is disabled"
        elif self.is_problematic():
            status = "problematic"
            message = f"Job has failed {self.failure_count} consecutive times"
        elif self.failure_count > 0:
            status = "warning"
            message = f"Job has {self.failure_count} recent failures"
        elif self.last_run_at is None:
            status = "pending"
            message = "Job has not run yet"

        return {
            "status": status,
            "message": message,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "last_success_at": self.last_success_at.isoformat()
            if self.last_success_at
            else None,
            "failure_count": self.failure_count,
            "is_problematic": self.is_problematic(),
        }


class JobExecutionLogModel(Base):
    """
    Database model for storing job execution history.

    This model tracks individual job executions for monitoring and debugging.
    It provides detailed execution history and statistics.

    Requirements: 9.3
    """

    __tablename__ = "job_execution_logs"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Job relationship
    job_id = Column(
        Integer, ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Execution details
    executed_at = Column(DateTime, default=_utc_now, nullable=False)
    success = Column(Boolean, nullable=False)
    duration_seconds = Column(Integer, nullable=True)  # Execution duration in seconds
    value_extracted = Column(String(50), nullable=True)  # The value that was extracted
    error_message = Column(Text, nullable=True)
    http_status_code = Column(Integer, nullable=True)  # HTTP response status
    response_size = Column(Integer, nullable=True)  # Response size in bytes

    # Relationships
    job = relationship("JobModel", back_populates="execution_logs")

    # Indexes for performance
    __table_args__ = (
        Index("idx_job_logs_job_id", "job_id"),
        Index("idx_job_logs_executed", "executed_at"),
        Index("idx_job_logs_success", "success"),
        Index("idx_job_logs_job_executed", "job_id", "executed_at"),
    )

    def __repr__(self) -> str:
        """String representation of the job execution log model."""
        status = "SUCCESS" if self.success else "FAILED"
        return f"<JobExecutionLogModel(id={self.id}, job_id={self.job_id}, status={status})>"

    def to_dict(self) -> dict:
        """
        Convert job execution log to dictionary representation.

        Returns:
            dict: Execution log data as dictionary

        Requirements: 9.3
        """
        return {
            "id": self.id,
            "job_id": self.job_id,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "success": self.success,
            "duration_seconds": self.duration_seconds,
            "value_extracted": self.value_extracted,
            "error_message": self.error_message,
            "http_status_code": self.http_status_code,
            "response_size": self.response_size,
        }
