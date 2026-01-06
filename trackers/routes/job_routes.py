"""
Job Management API Routes

This module provides RESTful API endpoints for managing scheduled jobs
with comprehensive security controls, user authorization, and audit logging.

Requirements: 1.1, 1.2, 1.3, 1.4, 5.3, 7.1
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy.exc import IntegrityError

from trackers.auth.decorators import require_auth
from trackers.db import database as db_module
from trackers.services.job_service import (
    AuthorizationError,
    JobService,
    ValidationError,
)

logger = logging.getLogger(__name__)

# Create blueprint for job management routes
job_bp = Blueprint("jobs", __name__, url_prefix="/api/jobs")


def _get_job_service() -> JobService:
    """
    Get JobService instance with database session and scheduler.

    Returns:
        JobService: Configured job service instance
    """
    db = db_module.SessionLocal()
    scheduler = getattr(current_app, "job_scheduler", None)
    return JobService(db, scheduler)


def _get_current_user_id() -> Optional[int]:
    """
    Get current user ID from authentication context.

    Returns:
        Optional[int]: User ID if authenticated, None otherwise
    """
    from trackers.auth.decorators import get_auth_context
    from trackers.services.user_service import UserService

    auth_context = get_auth_context()

    # Handle public access (testing mode)
    if auth_context.public_access:
        # For public access during testing, create or use a default test user
        db = db_module.SessionLocal()
        try:
            user_service = UserService(db)
            default_user = user_service.get_or_create_default_system_user()
            return default_user.id if default_user else None
        finally:
            db.close()

    if not auth_context.is_authenticated:
        return None

    # Handle different authentication methods
    if auth_context.user_info:
        db = db_module.SessionLocal()
        try:
            user_service = UserService(db)

            if auth_context.user_info.google_id:
                # Google OAuth authentication
                current_user = user_service.get_user_by_google_id(
                    auth_context.user_info.google_id
                )
            else:
                # Email/password authentication (google_id is None)
                current_user = user_service.get_user_by_email(
                    auth_context.user_info.email
                )

            return current_user.id if current_user else None
        finally:
            db.close()
    elif auth_context.api_key_valid:
        # Environment API key - use default system user
        db = db_module.SessionLocal()
        try:
            user_service = UserService(db)
            default_user = user_service.get_or_create_default_system_user()
            return default_user.id if default_user else None
        finally:
            db.close()

    return None


def _handle_job_service_error(e: Exception, operation: str) -> tuple:
    """
    Handle JobService exceptions and return appropriate HTTP responses.

    Args:
        e: Exception that occurred
        operation: Operation being performed (for logging)

    Returns:
        tuple: JSON response and HTTP status code
    """
    if isinstance(e, AuthorizationError):
        logger.warning(f"Authorization error during {operation}: {str(e)}")
        return jsonify({"error": "Forbidden", "message": str(e)}), 403
    elif isinstance(e, ValidationError):
        logger.warning(f"Validation error during {operation}: {str(e)}")
        return jsonify(
            {"error": "Bad Request", "message": str(e), "validation_errors": e.errors}
        ), 400
    elif isinstance(e, IntegrityError):
        logger.error(f"Database integrity error during {operation}: {str(e)}")
        return jsonify(
            {"error": "Conflict", "message": "Database constraint violation"}
        ), 409
    elif isinstance(e, ValueError):
        logger.warning(f"Value error during {operation}: {str(e)}")
        return jsonify({"error": "Bad Request", "message": str(e)}), 400
    else:
        logger.error(f"Unexpected error during {operation}: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "An unexpected error occurred",
            }
        ), 500


def _serialize_job(job) -> Dict:
    """
    Serialize job model to dictionary for JSON response.

    Args:
        job: JobModel instance

    Returns:
        Dict: Serialized job data
    """
    return {
        "id": job.id,
        "name": job.name,
        "job_type": job.job_type,
        "tracker_id": job.tracker_id,
        "cron_schedule": job.cron_schedule,
        "is_active": job.is_active,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "updated_at": job.updated_at.isoformat() if job.updated_at else None,
        "last_run_at": job.last_run_at.isoformat() if job.last_run_at else None,
        "last_success_at": job.last_success_at.isoformat()
        if job.last_success_at
        else None,
        "failure_count": job.failure_count,
        "last_error": job.last_error,
    }


def _serialize_execution_log(log) -> Dict:
    """
    Serialize job execution log to dictionary for JSON response.

    Args:
        log: JobExecutionLogModel instance

    Returns:
        Dict: Serialized execution log data
    """
    return {
        "id": log.id,
        "job_id": log.job_id,
        "executed_at": log.executed_at.isoformat() if log.executed_at else None,
        "success": log.success,
        "error_message": log.error_message,
        "execution_time": log.execution_time,
        "value_stored": log.value_stored,
    }


@job_bp.route("", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def list_jobs():
    """
    List all jobs for the authenticated user.

    Returns:
        200 OK: List of user's jobs
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 1.1, 1.4, 7.1
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            jobs = job_service.get_user_jobs(user_id)

            # Serialize jobs for response
            jobs_data = [_serialize_job(job) for job in jobs]

            return jsonify({"jobs": jobs_data, "total": len(jobs_data)}), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "list jobs")


@job_bp.route("", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def create_job():
    """
    Create a new scheduled job.

    Request Body:
        {
            "name": "string (required)",
            "job_type": "string (required, 'stock' or 'generic')",
            "tracker_id": "integer (required)",
            "config": "object (required)",
            "cron_schedule": "string (required)",
            "is_active": "boolean (optional, default: true)"
        }

    Returns:
        201 Created: Job created successfully
        400 Bad Request: Invalid request data
        401 Unauthorized: User not authenticated
        403 Forbidden: User doesn't own target tracker
        409 Conflict: Database constraint violation
        500 Internal Server Error: Server error

    Requirements: 1.1, 1.4, 5.3
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify(
                {"error": "Bad Request", "message": "Request body is required"}
            ), 400

        # Check required fields
        required_fields = ["name", "job_type", "tracker_id", "config", "cron_schedule"]
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": f"Missing required fields: {', '.join(missing_fields)}",
                }
            ), 400

        job_service = _get_job_service()
        try:
            # Create job
            job = job_service.create_job(user_id, data)
            job_service.db.commit()

            logger.info(f"Created job {job.id} ({job.name}) for user {user_id}")

            return jsonify(
                {"message": "Job created successfully", "job": _serialize_job(job)}
            ), 201

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "create job")


@job_bp.route("/<int:job_id>", methods=["GET"])
@require_auth(
    allow_api_key=True,
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=False,
)
def get_job(job_id: int):
    """
    Get a specific job by ID.

    Args:
        job_id: ID of the job to retrieve

    Returns:
        200 OK: Job found and owned by user
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 1.1, 1.4, 7.1
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            job = job_service.get_job(job_id, user_id)

            if not job:
                return jsonify({"error": "Not Found", "message": "Job not found"}), 404

            return jsonify({"job": _serialize_job(job)}), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job")


@job_bp.route("/<int:job_id>", methods=["PUT"])
@require_auth(
    allow_api_key=True,
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=False,
)
def update_job(job_id: int):
    """
    Update a specific job.

    Args:
        job_id: ID of the job to update

    Request Body:
        {
            "name": "string (optional)",
            "config": "object (optional)",
            "cron_schedule": "string (optional)",
            "is_active": "boolean (optional)",
            "tracker_id": "integer (optional)"
        }

    Returns:
        200 OK: Job updated successfully
        400 Bad Request: Invalid request data
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        409 Conflict: Database constraint violation
        500 Internal Server Error: Server error

    Requirements: 1.2, 1.4, 5.3
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        # Validate request data
        data = request.get_json()
        if not data:
            return jsonify(
                {"error": "Bad Request", "message": "Request body is required"}
            ), 400

        # Check that at least one field is provided
        updatable_fields = [
            "name",
            "config",
            "cron_schedule",
            "is_active",
            "tracker_id",
        ]
        if not any(field in data for field in updatable_fields):
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": f"At least one field must be provided: {', '.join(updatable_fields)}",
                }
            ), 400

        job_service = _get_job_service()
        try:
            # Update job
            job = job_service.update_job(job_id, user_id, data)
            job_service.db.commit()

            logger.info(f"Updated job {job.id} for user {user_id}")

            return jsonify(
                {"message": "Job updated successfully", "job": _serialize_job(job)}
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "update job")


@job_bp.route("/<int:job_id>", methods=["DELETE"])
@require_auth(
    allow_api_key=True,
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=False,
)
def delete_job(job_id: int):
    """
    Delete a specific job.

    Args:
        job_id: ID of the job to delete

    Returns:
        204 No Content: Job deleted successfully
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 1.3, 1.4
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            # Delete job
            success = job_service.delete_job(job_id, user_id)
            job_service.db.commit()

            if success:
                logger.info(f"Deleted job {job_id} for user {user_id}")
                return "", 204
            else:
                return jsonify({"error": "Not Found", "message": "Job not found"}), 404

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "delete job")


@job_bp.route("/<int:job_id>/test", methods=["POST"])
@require_auth(
    allow_api_key=True,
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=False,
)
def test_job(job_id: int):
    """
    Execute a job immediately for testing purposes.

    Args:
        job_id: ID of the job to test

    Returns:
        200 OK: Job test executed (check success field for result)
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 5.3, 7.1
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            # Test job execution
            result = job_service.test_job(job_id, user_id)

            logger.info(
                f"Test executed for job {job_id} by user {user_id}: {result.success}"
            )

            return jsonify(
                {
                    "success": result.success,
                    "message": "Job test completed",
                    "result": {
                        "success": result.success,
                        "value": result.value,
                        "error_message": result.error_message,
                        "execution_time": result.execution_time,
                        "timestamp": result.timestamp.isoformat()
                        if result.timestamp
                        else None,
                        "http_status": result.http_status,
                        "response_size": result.response_size,
                    },
                }
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "test job")


@job_bp.route("/<int:job_id>/status", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_job_status(job_id: int):
    """
    Get job status and basic execution information.

    Args:
        job_id: ID of the job

    Returns:
        200 OK: Job status information
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 7.1, 7.2
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            job = job_service.get_job(job_id, user_id)

            if not job:
                return jsonify({"error": "Not Found", "message": "Job not found"}), 404

            # Get status summary using the new method
            status_summary = job.get_status_summary()

            # Get recent execution statistics
            recent_executions = job_service.get_job_execution_history(
                job_id, user_id, limit=10
            )
            recent_success_count = sum(1 for log in recent_executions if log.success)

            return jsonify(
                {
                    "job_id": job.id,
                    "name": job.name,
                    "status": status_summary["status"],
                    "status_message": status_summary["message"],
                    "is_active": job.is_active,
                    "is_problematic": job.is_problematic(),
                    "last_run_at": job.last_run_at.isoformat()
                    if job.last_run_at
                    else None,
                    "last_success_at": job.last_success_at.isoformat()
                    if job.last_success_at
                    else None,
                    "failure_count": job.failure_count,
                    "last_error": job.last_error,
                    "recent_executions": len(recent_executions),
                    "recent_success_rate": (
                        recent_success_count / len(recent_executions) * 100
                    )
                    if recent_executions
                    else 0,
                    "cron_schedule": job.cron_schedule,
                    "next_run_description": job.get_next_run_description(),
                }
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job status")


@job_bp.route("/<int:job_id>/history", methods=["GET"])
@require_auth(
    allow_api_key=True,
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=False,
)
def get_job_history(job_id: int):
    """
    Get job execution history.

    Args:
        job_id: ID of the job

    Query Parameters:
        limit: Maximum number of execution logs to return (default: 50, max: 100)

    Returns:
        200 OK: Job execution history
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 7.1, 7.3
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        # Parse query parameters
        limit = request.args.get("limit", 50, type=int)
        limit = min(max(1, limit), 100)  # Clamp between 1 and 100

        job_service = _get_job_service()
        try:
            # Get execution history (last 30 days)
            execution_logs = job_service.get_job_execution_history(
                job_id, user_id, limit
            )

            # Serialize execution logs
            logs_data = []
            for log in execution_logs:
                logs_data.append(
                    {
                        "id": log.id,
                        "executed_at": log.executed_at.isoformat()
                        if log.executed_at
                        else None,
                        "success": log.success,
                        "duration_seconds": log.duration_seconds,
                        "value_extracted": log.value_extracted,
                        "error_message": log.error_message,
                        "http_status_code": log.http_status_code,
                        "response_size": log.response_size,
                    }
                )

            return jsonify(
                {
                    "job_id": job_id,
                    "execution_history": logs_data,
                    "total_returned": len(logs_data),
                    "limit": limit,
                    "note": "History limited to last 30 days",
                }
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job history")


@job_bp.route("/<int:job_id>/statistics", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_job_statistics(job_id: int):
    """
    Get detailed execution statistics for a specific job.

    Args:
        job_id: ID of the job

    Returns:
        200 OK: Job execution statistics
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 7.1, 7.4
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            # Get detailed statistics
            statistics = job_service.get_job_execution_statistics(job_id, user_id)

            if not statistics:
                return jsonify({"error": "Not Found", "message": "Job not found"}), 404

            return jsonify({"statistics": statistics}), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job statistics")


@job_bp.route("/statistics", methods=["GET"])
@require_auth(
    allow_api_key=True,
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=False,
)
def get_user_job_statistics():
    """
    Get overall job statistics for the authenticated user.

    Returns:
        200 OK: User's job statistics
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 7.4
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            # Get user statistics
            statistics = job_service.get_job_statistics(user_id)

            return jsonify({"statistics": statistics}), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get user job statistics")


@job_bp.route("/problematic", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_problematic_jobs():
    """
    Get jobs that are marked as problematic due to repeated failures.

    Query Parameters:
        threshold: Number of consecutive failures to consider problematic (default: 5)

    Returns:
        200 OK: List of problematic jobs
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 7.2
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        # Parse query parameters
        threshold = request.args.get("threshold", 5, type=int)
        threshold = max(1, threshold)  # Minimum threshold of 1

        job_service = _get_job_service()
        try:
            # Get problematic jobs
            problematic_jobs = job_service.get_problematic_jobs(user_id, threshold)

            # Serialize jobs for response
            jobs_data = []
            for job in problematic_jobs:
                job_data = _serialize_job(job)
                job_data["status_summary"] = job.get_status_summary()
                jobs_data.append(job_data)

            return jsonify(
                {
                    "problematic_jobs": jobs_data,
                    "total": len(jobs_data),
                    "failure_threshold": threshold,
                    "message": f"Jobs with {threshold} or more consecutive failures",
                }
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get problematic jobs")


@job_bp.route("/<int:job_id>/reset-failures", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def reset_job_failures(job_id: int):
    """
    Reset the failure count for a job (useful after fixing issues).

    Args:
        job_id: ID of the job

    Returns:
        200 OK: Failure count reset successfully
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 7.2
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            # Reset failure count
            success = job_service.reset_job_failure_count(job_id, user_id)
            job_service.db.commit()

            if success:
                logger.info(f"Reset failure count for job {job_id} by user {user_id}")
                return jsonify({"message": "Job failure count reset successfully"}), 200
            else:
                return jsonify({"error": "Not Found", "message": "Job not found"}), 404

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "reset job failures")


@job_bp.route("/monitoring/health", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_job_health_report():
    """
    Get a comprehensive health report for user's jobs.

    Returns:
        200 OK: Job health report
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 7.1, 7.2
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        from trackers.services.job_monitoring import JobMonitoringService

        db = db_module.SessionLocal()
        try:
            monitoring_service = JobMonitoringService(db)
            health_report = monitoring_service.get_job_health_report(user_id)

            return jsonify({"health_report": health_report}), 200

        finally:
            db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job health report")


@job_bp.route("/monitoring/trends", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_execution_trends():
    """
    Get execution trends over the specified number of days.

    Query Parameters:
        days: Number of days to analyze (default: 7, max: 30)

    Returns:
        200 OK: Execution trends data
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 7.4
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        # Parse query parameters
        days = request.args.get("days", 7, type=int)
        days = min(max(1, days), 30)  # Clamp between 1 and 30

        from trackers.services.job_monitoring import JobMonitoringService

        db = db_module.SessionLocal()
        try:
            monitoring_service = JobMonitoringService(db)
            trends = monitoring_service.get_execution_trends(days, user_id)

            return jsonify({"trends": trends}), 200

        finally:
            db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get execution trends")


@job_bp.route("/monitoring/attention", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_jobs_needing_attention():
    """
    Get jobs that need attention based on various criteria.

    Returns:
        200 OK: Jobs needing attention
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 7.2
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        from trackers.services.job_monitoring import JobMonitoringService

        db = db_module.SessionLocal()
        try:
            monitoring_service = JobMonitoringService(db)
            jobs_needing_attention = monitoring_service.identify_jobs_needing_attention(
                user_id
            )

            return jsonify(
                {
                    "jobs_needing_attention": jobs_needing_attention,
                    "total": len(jobs_needing_attention),
                    "high_priority": len(
                        [j for j in jobs_needing_attention if j["priority"] == "high"]
                    ),
                    "medium_priority": len(
                        [j for j in jobs_needing_attention if j["priority"] == "medium"]
                    ),
                }
            ), 200

        finally:
            db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get jobs needing attention")

        job_service = _get_job_service()
        try:
            # Get execution history
            execution_logs = job_service.get_job_execution_history(
                job_id, user_id, limit
            )

            # Serialize execution logs
            logs_data = [_serialize_execution_log(log) for log in execution_logs]

            # Calculate summary statistics
            total_executions = len(logs_data)
            successful_executions = sum(1 for log in logs_data if log["success"])
            success_rate = (
                (successful_executions / total_executions * 100)
                if total_executions > 0
                else 0
            )

            return jsonify(
                {
                    "job_id": job_id,
                    "execution_history": logs_data,
                    "summary": {
                        "total_executions": total_executions,
                        "successful_executions": successful_executions,
                        "failed_executions": total_executions - successful_executions,
                        "success_rate": round(success_rate, 2),
                    },
                    "limit": limit,
                }
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job history")


@job_bp.route("/statistics", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_user_statistics():
    """
    Get job statistics for the authenticated user.

    Returns:
        200 OK: Job statistics
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Requirements: 7.1
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            statistics = job_service.get_job_statistics(user_id)

            return jsonify(
                {
                    "user_id": user_id,
                    "statistics": statistics,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job statistics")


@job_bp.route("/<int:job_id>/config", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_job_config(job_id: int):
    """
    Get decrypted job configuration (sensitive data masked).

    Args:
        job_id: ID of the job

    Returns:
        200 OK: Job configuration (with sensitive fields masked)
        401 Unauthorized: User not authenticated
        403 Forbidden: Job exists but not owned by user
        404 Not Found: Job doesn't exist
        500 Internal Server Error: Server error

    Requirements: 1.4, 5.3
    """
    try:
        user_id = _get_current_user_id()
        if not user_id:
            return jsonify(
                {"error": "Unauthorized", "message": "User authentication required"}
            ), 401

        job_service = _get_job_service()
        try:
            # Get job to verify ownership
            job = job_service.get_job(job_id, user_id)
            if not job:
                return jsonify({"error": "Not Found", "message": "Job not found"}), 404

            # Get decrypted configuration
            config = job_service.get_decrypted_job_config(job_id, user_id)

            if config is None:
                return jsonify(
                    {
                        "error": "Internal Server Error",
                        "message": "Failed to decrypt job configuration",
                    }
                ), 500

            # Mask sensitive fields for security
            masked_config = _mask_sensitive_fields(config)

            return jsonify(
                {"job_id": job_id, "job_type": job.job_type, "config": masked_config}
            ), 200

        finally:
            job_service.db.close()

    except Exception as e:
        return _handle_job_service_error(e, "get job config")


def _mask_sensitive_fields(config: Dict) -> Dict:
    """
    Mask sensitive fields in job configuration for API responses.

    Args:
        config: Job configuration dictionary

    Returns:
        Dict: Configuration with sensitive fields masked
    """
    masked_config = config.copy()

    # List of sensitive field patterns
    sensitive_patterns = [
        "api_key",
        "token",
        "password",
        "secret",
        "authorization",
        "bearer_token",
        "client_secret",
    ]

    for key, value in config.items():
        # Check if field name indicates sensitive data
        if any(pattern in key.lower() for pattern in sensitive_patterns):
            if isinstance(value, str) and len(value) > 4:
                # Show first 4 characters and mask the rest
                masked_config[key] = value[:4] + "*" * (len(value) - 4)
            else:
                masked_config[key] = "***"

        # Handle nested dictionaries (like headers)
        elif isinstance(value, dict):
            masked_config[key] = _mask_sensitive_fields(value)

    return masked_config


# Error handler for blueprint-specific errors
@job_bp.errorhandler(404)
def handle_not_found(error):
    """Handle 404 errors for job routes."""
    return jsonify(
        {"error": "Not Found", "message": "The requested job resource was not found"}
    ), 404


@job_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle 500 errors for job routes."""
    logger.error(f"Internal server error in job routes: {str(error)}")
    return jsonify(
        {"error": "Internal Server Error", "message": "An unexpected error occurred"}
    ), 500


# Job Configuration Testing and Validation Endpoints
# Requirements: 5.1, 5.4, 10.1, 10.2


@job_bp.route("/validate/cron", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def validate_cron_expression():
    """
    Validate cron expression with detailed feedback.

    Expected JSON payload:
    {
        "cron_expression": "0 9 * * *"
    }

    Requirements: 5.1, 5.4
    """
    try:
        data = request.get_json()
        if not data or "cron_expression" not in data:
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": "Missing 'cron_expression' in request body",
                }
            ), 400

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        validation_result = testing_service.validate_cron_expression(
            data["cron_expression"]
        )

        return jsonify(validation_result), 200

    except Exception as e:
        logger.error(f"Error validating cron expression: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "Failed to validate cron expression",
            }
        ), 500


@job_bp.route("/validate/config", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def validate_job_config():
    """
    Validate job configuration without creating the job.

    Expected JSON payload:
    {
        "job_type": "stock",
        "config": {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_key"
        }
    }

    Requirements: 5.1, 5.4
    """
    try:
        data = request.get_json()
        if not data or "job_type" not in data or "config" not in data:
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": "Missing 'job_type' or 'config' in request body",
                }
            ), 400

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        validation_result = testing_service.validate_job_config_only(
            data["job_type"], data["config"]
        )

        return jsonify(validation_result), 200

    except Exception as e:
        logger.error(f"Error validating job config: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "Failed to validate job configuration",
            }
        ), 500


@job_bp.route("/test/config", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def test_job_configuration():
    """
    Test complete job configuration without scheduling.

    Expected JSON payload:
    {
        "job_type": "stock",
        "config": {
            "symbol": "AAPL",
            "provider": "alpha_vantage",
            "api_key": "test_key"
        },
        "cron_schedule": "0 9 * * *",
        "use_mocks": true
    }

    Requirements: 5.1, 5.4, 10.1, 10.2
    """
    try:
        data = request.get_json()
        required_fields = ["job_type", "config", "cron_schedule"]

        if not data or not all(field in data for field in required_fields):
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": f"Missing required fields: {required_fields}",
                }
            ), 400

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        use_mocks = data.get("use_mocks", True)

        test_result = testing_service.test_job_configuration(
            data["job_type"], data["config"], data["cron_schedule"], use_mocks
        )

        return jsonify(test_result), 200

    except Exception as e:
        logger.error(f"Error testing job configuration: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "Failed to test job configuration",
            }
        ), 500


@job_bp.route("/examples", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_job_examples():
    """
    Get job configuration examples and templates.

    Query parameters:
    - job_type: Optional filter for job type ("stock" or "generic")

    Requirements: 10.1, 10.2
    """
    try:
        job_type = request.args.get("job_type")

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        examples = testing_service.get_job_examples(job_type)

        return jsonify(examples), 200

    except Exception as e:
        logger.error(f"Error getting job examples: {str(e)}")
        return jsonify(
            {"error": "Internal Server Error", "message": "Failed to get job examples"}
        ), 500


@job_bp.route("/templates/<job_type>", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_configuration_template(job_type: str):
    """
    Get configuration template for specific job type.

    Path parameters:
    - job_type: Type of job ("stock" or "generic")

    Requirements: 10.1, 10.2
    """
    try:
        if job_type not in ["stock", "generic"]:
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": "job_type must be 'stock' or 'generic'",
                }
            ), 400

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        template = testing_service.get_configuration_template(job_type)

        return jsonify(template), 200

    except Exception as e:
        logger.error(f"Error getting configuration template: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "Failed to get configuration template",
            }
        ), 500


@job_bp.route("/help/validation", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_validation_help():
    """
    Get validation help and guidance.

    Query parameters:
    - job_type: Optional job type for specific help ("stock" or "generic")

    Requirements: 5.1, 5.4, 10.1, 10.2
    """
    try:
        job_type = request.args.get("job_type", "generic")

        if job_type not in ["stock", "generic"]:
            job_type = "generic"

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        help_info = testing_service.get_validation_help(job_type)

        return jsonify(help_info), 200

    except Exception as e:
        logger.error(f"Error getting validation help: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "Failed to get validation help",
            }
        ), 500


@job_bp.route("/test/scenarios", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def test_api_scenarios():
    """
    Test job configuration with different API scenarios.

    Expected JSON payload:
    {
        "job_type": "stock",
        "config": {
            "symbol": "AAPL",
            "provider": "alpha_vantage"
        },
        "scenarios": ["success", "rate_limit", "timeout", "connection_error"]
    }

    Requirements: 10.1, 10.2
    """
    try:
        data = request.get_json()
        required_fields = ["job_type", "config", "scenarios"]

        if not data or not all(field in data for field in required_fields):
            return jsonify(
                {
                    "error": "Bad Request",
                    "message": f"Missing required fields: {required_fields}",
                }
            ), 400

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        scenario_results = testing_service.simulate_api_scenarios(
            data["job_type"], data["config"], data["scenarios"]
        )

        return jsonify(
            {
                "job_type": data["job_type"],
                "scenarios_tested": data["scenarios"],
                "results": scenario_results,
            }
        ), 200

    except Exception as e:
        logger.error(f"Error testing API scenarios: {str(e)}")
        return jsonify(
            {
                "error": "Internal Server Error",
                "message": "Failed to test API scenarios",
            }
        ), 500
