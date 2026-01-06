"""
Job Monitoring Service for automated job scheduling system.

This module provides monitoring utilities for job execution history,
statistics calculation, and maintenance tasks like cleanup of old logs.

Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from trackers.models.job_model import JobExecutionLogModel, JobModel

logger = logging.getLogger(__name__)


class JobMonitoringService:
    """
    Service for monitoring job execution and maintaining execution history.

    This service provides utilities for monitoring job health, calculating
    statistics, and performing maintenance tasks like cleanup of old logs.

    Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
    """

    def __init__(self, db_session: Session):
        """
        Initialize Job Monitoring Service with database session.

        Args:
            db_session: SQLAlchemy database session

        Requirements: 7.1, 7.2, 7.3, 7.4, 7.5
        """
        self.db = db_session

    def get_system_job_statistics(self) -> Dict:
        """
        Get system-wide job statistics across all users.

        Returns:
            Dict: System-wide job statistics

        Requirements: 7.4
        """
        try:
            # Get basic job counts
            total_jobs = self.db.query(JobModel).count()
            active_jobs = (
                self.db.query(JobModel).filter(JobModel.is_active == True).count()
            )
            problematic_jobs = (
                self.db.query(JobModel).filter(JobModel.failure_count >= 5).count()
            )

            # Get jobs by type
            job_types = (
                self.db.query(JobModel.job_type, func.count(JobModel.id))
                .group_by(JobModel.job_type)
                .all()
            )

            # Get execution statistics for last 24 hours
            yesterday = datetime.now(timezone.utc) - timedelta(days=1)

            daily_executions = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at >= yesterday)
                .count()
            )

            daily_successful = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at >= yesterday)
                .filter(JobExecutionLogModel.success == True)
                .count()
            )

            # Get execution statistics for last 30 days
            thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)

            monthly_executions = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .count()
            )

            monthly_successful = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .filter(JobExecutionLogModel.success == True)
                .count()
            )

            # Calculate average execution time
            avg_execution_time = (
                self.db.query(func.avg(JobExecutionLogModel.duration_seconds))
                .filter(JobExecutionLogModel.executed_at >= thirty_days_ago)
                .filter(JobExecutionLogModel.success == True)
                .scalar()
            ) or 0

            return {
                "total_jobs": total_jobs,
                "active_jobs": active_jobs,
                "inactive_jobs": total_jobs - active_jobs,
                "problematic_jobs": problematic_jobs,
                "job_types": dict(job_types),
                "daily_statistics": {
                    "executions": daily_executions,
                    "successful": daily_successful,
                    "failed": daily_executions - daily_successful,
                    "success_rate_percent": (
                        (daily_successful / daily_executions * 100)
                        if daily_executions > 0
                        else 0
                    ),
                },
                "monthly_statistics": {
                    "executions": monthly_executions,
                    "successful": monthly_successful,
                    "failed": monthly_executions - monthly_successful,
                    "success_rate_percent": (
                        (monthly_successful / monthly_executions * 100)
                        if monthly_executions > 0
                        else 0
                    ),
                    "average_execution_time_seconds": round(
                        float(avg_execution_time), 2
                    ),
                },
            }

        except Exception as e:
            logger.error(f"Error getting system job statistics: {str(e)}")
            return {}

    def get_job_health_report(self, user_id: Optional[int] = None) -> Dict:
        """
        Get a comprehensive health report for jobs.

        Args:
            user_id: Optional user ID to filter jobs (None for system-wide)

        Returns:
            Dict: Job health report

        Requirements: 7.1, 7.2
        """
        try:
            # Build base query
            query = self.db.query(JobModel)
            if user_id:
                query = query.filter(JobModel.user_id == user_id)

            jobs = query.all()

            # Categorize jobs by health status
            healthy_jobs = []
            warning_jobs = []
            problematic_jobs = []
            disabled_jobs = []

            for job in jobs:
                status_summary = job.get_status_summary()
                job_data = {
                    "id": job.id,
                    "name": job.name,
                    "job_type": job.job_type,
                    "user_id": job.user_id,
                    "status": status_summary["status"],
                    "message": status_summary["message"],
                    "failure_count": job.failure_count,
                    "last_run_at": job.last_run_at.isoformat()
                    if job.last_run_at
                    else None,
                    "last_success_at": job.last_success_at.isoformat()
                    if job.last_success_at
                    else None,
                }

                if status_summary["status"] == "healthy":
                    healthy_jobs.append(job_data)
                elif status_summary["status"] == "warning":
                    warning_jobs.append(job_data)
                elif status_summary["status"] == "problematic":
                    problematic_jobs.append(job_data)
                elif status_summary["status"] == "disabled":
                    disabled_jobs.append(job_data)

            return {
                "total_jobs": len(jobs),
                "healthy_jobs": {
                    "count": len(healthy_jobs),
                    "jobs": healthy_jobs,
                },
                "warning_jobs": {
                    "count": len(warning_jobs),
                    "jobs": warning_jobs,
                },
                "problematic_jobs": {
                    "count": len(problematic_jobs),
                    "jobs": problematic_jobs,
                },
                "disabled_jobs": {
                    "count": len(disabled_jobs),
                    "jobs": disabled_jobs,
                },
                "health_summary": {
                    "healthy_percentage": (len(healthy_jobs) / len(jobs) * 100)
                    if jobs
                    else 0,
                    "needs_attention": len(warning_jobs) + len(problematic_jobs),
                },
            }

        except Exception as e:
            logger.error(f"Error getting job health report: {str(e)}")
            return {}

    def cleanup_old_execution_logs(self, days_to_keep: int = 30) -> Dict:
        """
        Clean up execution logs older than specified days.

        Args:
            days_to_keep: Number of days of execution logs to keep

        Returns:
            Dict: Cleanup results

        Requirements: 7.3
        """
        try:
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=days_to_keep)

            # Count logs to be deleted
            logs_to_delete = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at < cutoff_date)
                .count()
            )

            if logs_to_delete == 0:
                return {
                    "deleted_count": 0,
                    "cutoff_date": cutoff_date.isoformat(),
                    "message": "No old execution logs found to delete",
                }

            # Delete old execution logs
            deleted_count = (
                self.db.query(JobExecutionLogModel)
                .filter(JobExecutionLogModel.executed_at < cutoff_date)
                .delete()
            )

            self.db.flush()

            logger.info(
                f"Cleaned up {deleted_count} old execution logs (older than {days_to_keep} days)"
            )

            return {
                "deleted_count": deleted_count,
                "cutoff_date": cutoff_date.isoformat(),
                "days_kept": days_to_keep,
                "message": f"Successfully deleted {deleted_count} execution logs older than {days_to_keep} days",
            }

        except Exception as e:
            logger.error(f"Error cleaning up old execution logs: {str(e)}")
            return {
                "deleted_count": 0,
                "error": str(e),
                "message": "Failed to clean up old execution logs",
            }

    def get_execution_trends(
        self, days: int = 7, user_id: Optional[int] = None
    ) -> Dict:
        """
        Get execution trends over the specified number of days.

        Args:
            days: Number of days to analyze
            user_id: Optional user ID to filter jobs (None for system-wide)

        Returns:
            Dict: Execution trends data

        Requirements: 7.4
        """
        try:
            start_date = datetime.now(timezone.utc) - timedelta(days=days)

            # Build base query
            query = self.db.query(JobExecutionLogModel)
            if user_id:
                query = query.join(JobModel).filter(JobModel.user_id == user_id)

            # Get daily execution counts
            daily_stats = []
            for i in range(days):
                day_start = start_date + timedelta(days=i)
                day_end = day_start + timedelta(days=1)

                day_query = query.filter(
                    JobExecutionLogModel.executed_at >= day_start,
                    JobExecutionLogModel.executed_at < day_end,
                )

                total_executions = day_query.count()
                successful_executions = day_query.filter(
                    JobExecutionLogModel.success == True
                ).count()

                daily_stats.append(
                    {
                        "date": day_start.date().isoformat(),
                        "total_executions": total_executions,
                        "successful_executions": successful_executions,
                        "failed_executions": total_executions - successful_executions,
                        "success_rate_percent": (
                            (successful_executions / total_executions * 100)
                            if total_executions > 0
                            else 0
                        ),
                    }
                )

            # Calculate overall trends
            total_executions = sum(day["total_executions"] for day in daily_stats)
            total_successful = sum(day["successful_executions"] for day in daily_stats)

            return {
                "period_days": days,
                "start_date": start_date.date().isoformat(),
                "end_date": datetime.now(timezone.utc).date().isoformat(),
                "daily_statistics": daily_stats,
                "period_summary": {
                    "total_executions": total_executions,
                    "successful_executions": total_successful,
                    "failed_executions": total_executions - total_successful,
                    "overall_success_rate_percent": (
                        (total_successful / total_executions * 100)
                        if total_executions > 0
                        else 0
                    ),
                    "average_daily_executions": total_executions / days
                    if days > 0
                    else 0,
                },
            }

        except Exception as e:
            logger.error(f"Error getting execution trends: {str(e)}")
            return {}

    def identify_jobs_needing_attention(
        self, user_id: Optional[int] = None
    ) -> List[Dict]:
        """
        Identify jobs that need attention based on various criteria.

        Args:
            user_id: Optional user ID to filter jobs (None for system-wide)

        Returns:
            List[Dict]: Jobs that need attention with reasons

        Requirements: 7.2
        """
        try:
            # Build base query
            query = self.db.query(JobModel)
            if user_id:
                query = query.filter(JobModel.user_id == user_id)

            jobs = query.all()
            jobs_needing_attention = []

            for job in jobs:
                reasons = []

                # Check for problematic jobs (5+ consecutive failures)
                if job.is_problematic():
                    reasons.append(f"Has {job.failure_count} consecutive failures")

                # Check for jobs that haven't run recently (if active)
                if job.is_active and job.last_run_at:
                    days_since_last_run = (
                        datetime.now(timezone.utc) - job.last_run_at
                    ).days
                    if days_since_last_run > 7:
                        reasons.append(f"Has not run for {days_since_last_run} days")

                # Check for jobs that have never run (if active and created more than 1 day ago)
                if job.is_active and not job.last_run_at:
                    days_since_created = (
                        datetime.now(timezone.utc) - job.created_at
                    ).days
                    if days_since_created > 1:
                        reasons.append(
                            f"Has never run (created {days_since_created} days ago)"
                        )

                # Check for jobs with recent failures but not yet problematic
                if job.failure_count > 0 and job.failure_count < 5:
                    reasons.append(f"Has {job.failure_count} recent failures")

                if reasons:
                    jobs_needing_attention.append(
                        {
                            "id": job.id,
                            "name": job.name,
                            "job_type": job.job_type,
                            "user_id": job.user_id,
                            "is_active": job.is_active,
                            "failure_count": job.failure_count,
                            "last_run_at": job.last_run_at.isoformat()
                            if job.last_run_at
                            else None,
                            "last_success_at": job.last_success_at.isoformat()
                            if job.last_success_at
                            else None,
                            "last_error": job.last_error,
                            "reasons": reasons,
                            "priority": "high" if job.is_problematic() else "medium",
                        }
                    )

            # Sort by priority (high first) and then by failure count
            jobs_needing_attention.sort(
                key=lambda x: (x["priority"] == "medium", x["failure_count"])
            )

            return jobs_needing_attention

        except Exception as e:
            logger.error(f"Error identifying jobs needing attention: {str(e)}")
            return []
