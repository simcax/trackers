"""
Comprehensive error handling for the tracker values system.

This module provides centralized error handling, consistent error response formats,
logging capabilities, and proper HTTP status codes for all API endpoints.

Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
"""

import logging
import traceback
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple, Union

from flask import Flask, request
from sqlalchemy.exc import IntegrityError, OperationalError
from werkzeug.exceptions import BadRequest, NotFound

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("tracker_errors.log")],
)

logger = logging.getLogger(__name__)


class TrackerError(Exception):
    """Base exception class for tracker-related errors."""

    def __init__(
        self, message: str, status_code: int = 500, details: Optional[Dict] = None
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class ValidationError(TrackerError):
    """Exception for validation failures."""

    def __init__(self, message: str, details: Optional[Dict] = None):
        super().__init__(message, 400, details)


class ResourceNotFoundError(TrackerError):
    """Exception for resource not found errors."""

    def __init__(
        self,
        resource_type: str,
        resource_id: Union[str, int],
        details: Optional[Dict] = None,
    ):
        message = f"{resource_type} with ID {resource_id} not found"
        super().__init__(message, 404, details)
        self.resource_type = resource_type
        self.resource_id = resource_id


class DatabaseError(TrackerError):
    """Exception for database-related errors."""

    def __init__(self, message: str, original_error: Optional[Exception] = None):
        super().__init__(message, 500)
        self.original_error = original_error


def create_error_response(
    error_type: str,
    message: str,
    status_code: int,
    details: Optional[Dict] = None,
    request_id: Optional[str] = None,
) -> Tuple[Dict, int]:
    """
    Create a consistent error response format.

    Args:
        error_type: Type of error (validation, not_found, server_error, etc.)
        message: Human-readable error message
        status_code: HTTP status code
        details: Additional error details
        request_id: Unique request identifier for tracking

    Returns:
        Tuple of (response_dict, status_code)

    Validates: Requirements 7.1, 7.4, 7.5
    """
    response = {
        "error": {
            "type": error_type,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "status_code": status_code,
        }
    }

    if details:
        response["error"]["details"] = details

    if request_id:
        response["error"]["request_id"] = request_id

    # Add helpful suggestions based on error type
    if error_type == "validation_error":
        response["error"]["help"] = (
            "Check the request format and ensure all required fields are provided with valid values."
        )
    elif error_type == "not_found":
        response["error"]["help"] = (
            "Verify the resource ID and ensure the resource exists."
        )
    elif error_type == "server_error":
        response["error"]["help"] = (
            "This is an internal server error. Please try again later or contact support."
        )
    else:
        response["error"]["help"] = "Please check your request and try again."

    return response, status_code


def log_error(
    error: Exception, request_info: Optional[Dict] = None, user_id: Optional[str] = None
) -> str:
    """
    Log error with context information for debugging and monitoring.

    Args:
        error: The exception that occurred
        request_info: Information about the request (method, path, data)
        user_id: User identifier if available

    Returns:
        Unique error ID for tracking

    Validates: Requirements 7.2
    """
    error_id = f"ERR_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{id(error)}"

    log_data = {
        "error_id": error_id,
        "error_type": type(error).__name__,
        "error_message": str(error),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if request_info:
        log_data["request"] = request_info

    if user_id:
        log_data["user_id"] = user_id

    # Log stack trace for debugging
    if hasattr(error, "__traceback__"):
        log_data["traceback"] = traceback.format_exception(
            type(error), error, error.__traceback__
        )

    logger.error(f"Error occurred: {log_data}")

    return error_id


def get_request_info() -> Dict:
    """
    Extract relevant request information for logging.

    Returns:
        Dictionary with request details
    """
    return {
        "method": request.method,
        "path": request.path,
        "remote_addr": request.remote_addr,
        "user_agent": request.headers.get("User-Agent", "Unknown"),
        "content_type": request.headers.get("Content-Type", "Unknown"),
    }


def register_error_handlers(app: Flask) -> None:
    """
    Register centralized error handlers with the Flask application.

    Args:
        app: Flask application instance

    Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5
    """

    @app.errorhandler(ValidationError)
    def handle_validation_error(error: ValidationError):
        """Handle validation errors with detailed feedback."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        return create_error_response(
            error_type="validation_error",
            message=error.message,
            status_code=error.status_code,
            details=error.details,
            request_id=error_id,
        )

    @app.errorhandler(ResourceNotFoundError)
    def handle_not_found_error(error: ResourceNotFoundError):
        """Handle resource not found errors with specific resource identification."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        details = {
            "resource_type": error.resource_type,
            "resource_id": error.resource_id,
        }

        return create_error_response(
            error_type="not_found",
            message=error.message,
            status_code=error.status_code,
            details=details,
            request_id=error_id,
        )

    @app.errorhandler(DatabaseError)
    def handle_database_error(error: DatabaseError):
        """Handle database errors with safe error information."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        # Don't expose internal database details to users
        safe_message = "A database error occurred. Please try again later."

        return create_error_response(
            error_type="server_error",
            message=safe_message,
            status_code=error.status_code,
            request_id=error_id,
        )

    @app.errorhandler(IntegrityError)
    def handle_integrity_error(error: IntegrityError):
        """Handle database integrity constraint violations."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        # Provide helpful message based on constraint type
        message = "Data integrity constraint violation"
        details = {}

        error_str = str(error.orig).lower()
        if "unique" in error_str:
            message = "A record with this combination already exists"
            details["constraint_type"] = "unique_violation"
        elif "foreign key" in error_str:
            message = "Referenced resource does not exist"
            details["constraint_type"] = "foreign_key_violation"
        elif "not null" in error_str:
            message = "Required field cannot be empty"
            details["constraint_type"] = "not_null_violation"

        return create_error_response(
            error_type="validation_error",
            message=message,
            status_code=409,
            details=details,
            request_id=error_id,
        )

    @app.errorhandler(OperationalError)
    def handle_operational_error(error: OperationalError):
        """Handle database operational errors."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        # Don't expose database connection details
        safe_message = (
            "Database service temporarily unavailable. Please try again later."
        )

        return create_error_response(
            error_type="server_error",
            message=safe_message,
            status_code=503,
            request_id=error_id,
        )

    @app.errorhandler(BadRequest)
    def handle_bad_request(error: BadRequest):
        """Handle malformed requests."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        message = "Invalid request format"
        details = {}

        if "JSON" in str(error):
            message = "Invalid JSON format in request body"
            details["expected_format"] = "Valid JSON object"

        return create_error_response(
            error_type="validation_error",
            message=message,
            status_code=400,
            details=details,
            request_id=error_id,
        )

    @app.errorhandler(NotFound)
    def handle_not_found(error: NotFound):
        """Handle 404 errors for unknown endpoints."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        return create_error_response(
            error_type="not_found",
            message=f"Endpoint {request.path} not found",
            status_code=404,
            details={
                "available_endpoints": "Check API documentation for valid endpoints"
            },
            request_id=error_id,
        )

    @app.errorhandler(Exception)
    def handle_generic_error(error: Exception):
        """Handle all other unexpected errors."""
        request_info = get_request_info()
        error_id = log_error(error, request_info)

        # Log full details but return safe message to user
        logger.critical(f"Unhandled exception: {error}", exc_info=True)

        return create_error_response(
            error_type="server_error",
            message="An unexpected error occurred. Please try again later.",
            status_code=500,
            request_id=error_id,
        )


def validate_and_raise(
    condition: bool, message: str, details: Optional[Dict] = None
) -> None:
    """
    Utility function to validate conditions and raise ValidationError if failed.

    Args:
        condition: Condition to check (should be True for valid)
        message: Error message if condition fails
        details: Additional error details

    Raises:
        ValidationError: If condition is False
    """
    if not condition:
        raise ValidationError(message, details)


def not_found_if_none(
    resource: Optional[object], resource_type: str, resource_id: Union[str, int]
) -> object:
    """
    Utility function to raise ResourceNotFoundError if resource is None.

    Args:
        resource: Resource object or None
        resource_type: Type of resource (e.g., "Tracker", "TrackerValue")
        resource_id: ID of the resource

    Returns:
        The resource object if not None

    Raises:
        ResourceNotFoundError: If resource is None
    """
    if resource is None:
        raise ResourceNotFoundError(resource_type, resource_id)
    return resource
