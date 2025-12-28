"""
Health check routes for monitoring application status.

Provides endpoints for checking application health, database connectivity,
and overall system status for monitoring and deployment purposes.
"""

import logging
from datetime import datetime, timezone

from flask import Blueprint, jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from trackers.db.database import SessionLocal

# Configure logger
logger = logging.getLogger(__name__)

# Create blueprint for health check routes
health_bp = Blueprint("health", __name__)


@health_bp.route("/health", methods=["GET"])
def health_check():
    """
    Basic health check endpoint.

    Returns a simple status indicating the application is running.
    This is a lightweight check suitable for load balancers and basic monitoring.

    Returns:
        JSON response with status and timestamp
    """
    return jsonify(
        {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "trackers-api",
        }
    ), 200


@health_bp.route("/health/detailed", methods=["GET"])
def detailed_health_check():
    """
    Detailed health check endpoint.

    Performs comprehensive health checks including:
    - Application status
    - Database connectivity
    - Database query execution

    Returns detailed status information for each component.

    Returns:
        JSON response with detailed health information
    """
    health_status = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "trackers-api",
        "checks": {
            "application": {"status": "healthy"},
            "database": {"status": "unknown"},
        },
    }

    overall_healthy = True

    # Check database connectivity
    try:
        db_session = SessionLocal()

        # Test basic database connection
        try:
            # Execute a simple query to verify database is responsive
            result = db_session.execute(text("SELECT 1 as health_check"))
            row = result.fetchone()

            if row and row[0] == 1:
                health_status["checks"]["database"] = {
                    "status": "healthy",
                    "message": "Database connection successful",
                }
            else:
                health_status["checks"]["database"] = {
                    "status": "unhealthy",
                    "message": "Database query returned unexpected result",
                }
                overall_healthy = False

        except SQLAlchemyError as e:
            logger.error(f"Database health check failed: {e}")
            health_status["checks"]["database"] = {
                "status": "unhealthy",
                "message": f"Database query failed: {str(e)}",
            }
            overall_healthy = False

        finally:
            db_session.close()

    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        health_status["checks"]["database"] = {
            "status": "unhealthy",
            "message": f"Database connection failed: {str(e)}",
        }
        overall_healthy = False

    # Set overall status
    health_status["status"] = "healthy" if overall_healthy else "unhealthy"

    # Return appropriate HTTP status code
    status_code = 200 if overall_healthy else 503

    return jsonify(health_status), status_code


@health_bp.route("/health/ready", methods=["GET"])
def readiness_check():
    """
    Readiness check endpoint for Kubernetes/container orchestration.

    Indicates whether the application is ready to serve traffic.
    This includes checking that all critical dependencies are available.

    Returns:
        JSON response indicating readiness status
    """
    ready = True
    checks = {}

    # Check database readiness
    try:
        db_session = SessionLocal()

        try:
            # Verify we can connect and execute queries
            db_session.execute(text("SELECT 1"))
            checks["database"] = {"ready": True, "message": "Database ready"}
        except Exception as e:
            logger.error(f"Database readiness check failed: {e}")
            checks["database"] = {
                "ready": False,
                "message": f"Database not ready: {str(e)}",
            }
            ready = False
        finally:
            db_session.close()

    except Exception as e:
        logger.error(f"Database connection failed during readiness check: {e}")
        checks["database"] = {
            "ready": False,
            "message": f"Database connection failed: {str(e)}",
        }
        ready = False

    response = {
        "ready": ready,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "trackers-api",
        "checks": checks,
    }

    status_code = 200 if ready else 503
    return jsonify(response), status_code


@health_bp.route("/health/live", methods=["GET"])
def liveness_check():
    """
    Liveness check endpoint for Kubernetes/container orchestration.

    Indicates whether the application is alive and should not be restarted.
    This is a minimal check that only verifies the application process is running.

    Returns:
        JSON response indicating liveness status
    """
    return jsonify(
        {
            "alive": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": "trackers-api",
        }
    ), 200
