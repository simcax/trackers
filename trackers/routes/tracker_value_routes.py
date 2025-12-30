"""
API routes for tracker value operations.

This module provides RESTful endpoints for managing daily tracker values,
including create, read, update, and delete operations with comprehensive error handling
and user ownership access control.

Validates: Requirements 2.1, 2.2, 2.5, 3.1, 3.2, 3.4, 4.1, 4.2, 5.1, 5.2, 5.3, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
"""

from flask import Blueprint, jsonify, request
from sqlalchemy.exc import IntegrityError

from trackers.auth.context import get_current_user
from trackers.auth.decorators import require_auth
from trackers.db import database as db_module
from trackers.db.tracker_values_db import (
    create_or_update_value,
    delete_all_tracker_values,
    delete_value,
    get_tracker_values,
    get_value,
    update_value,
)
from trackers.db.trackerdb import get_user_tracker
from trackers.error_handling import (
    DatabaseError,
    ResourceNotFoundError,
    ValidationError,
    get_request_info,
    log_error,
    not_found_if_none,
)
from trackers.services.user_service import UserService
from trackers.validation.tracker_value_validation import (
    sanitize_value_input,
    validate_update_data,
    validate_value_data,
)

tracker_value_bp = Blueprint("tracker_value", __name__)


def _verify_tracker_ownership(db, tracker_id, user_id):
    """
    Verify that a tracker belongs to the specified user.

    Args:
        db: Database session
        tracker_id: ID of the tracker to verify
        user_id: ID of the user who should own the tracker

    Returns:
        tuple: (tracker_exists, user_owns_tracker, tracker_object)

    Validates: Requirements 6.1, 6.3, 6.4
    """
    # Check if tracker exists and is owned by user
    user_tracker = get_user_tracker(db, tracker_id, user_id)
    if user_tracker:
        return True, True, user_tracker

    # Check if tracker exists at all (for 403 vs 404 distinction)
    from trackers.db.trackerdb import get_tracker as get_any_tracker

    any_tracker = get_any_tracker(db, tracker_id)
    if any_tracker:
        return True, False, None  # Tracker exists but not owned by user
    else:
        return False, False, None  # Tracker doesn't exist


def _get_current_database_user(db):
    """
    Get the current authenticated user's database record.

    Args:
        db: Database session

    Returns:
        tuple: (user_model, error_response)

    Validates: Requirements 6.1
    """
    # Get current user from authentication context
    current_user_info = get_current_user()
    if not current_user_info:
        return None, (jsonify({"error": "User authentication required"}), 401)

    # Get user's database record
    user_service = UserService(db)
    current_user = user_service.get_user_by_google_id(current_user_info.google_id)
    if not current_user:
        return None, (jsonify({"error": "User not found in database"}), 401)

    return current_user, None


@tracker_value_bp.route("/api/trackers/<int:tracker_id>/values", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def create_tracker_value(tracker_id):
    """
    Create or update a tracker value for a specific date with user ownership verification.

    Implements upsert logic - if a value already exists for the given
    tracker and date, it updates the existing record. Otherwise, creates new.

    Args:
        tracker_id: ID of the tracker

    Request Body:
        {
            "date": "YYYY-MM-DD",
            "value": "string"
        }

    Returns:
        201 Created: New value created
        200 OK: Existing value updated
        400 Bad Request: Validation errors
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Tracker doesn't exist
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Validates: Requirements 2.1, 2.2, 2.5, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
    """
    try:
        data = request.get_json()

        # Validate request data
        validation_errors = validate_value_data(data)
        if validation_errors:
            raise ValidationError(
                "Validation failed", details={"validation_errors": validation_errors}
            )

        # Get SessionLocal from the module
        db = db_module.SessionLocal()
        try:
            # Get current user and verify authentication
            current_user, error_response = _get_current_database_user(db)
            if error_response:
                return error_response

            # Verify tracker ownership
            tracker_exists, user_owns_tracker, tracker = _verify_tracker_ownership(
                db, tracker_id, current_user.id
            )

            if not tracker_exists:
                raise ResourceNotFoundError("Tracker", tracker_id)
            elif not user_owns_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403

            # Sanitize input
            sanitized_value = sanitize_value_input(data["value"])

            # Check if value already exists to determine response code
            existing_value = get_value(db, tracker_id, data["date"])
            is_update = existing_value is not None

            # Create or update value
            tracker_value = create_or_update_value(
                db, tracker_id, data["date"], sanitized_value
            )
            db.commit()

            # Return created/updated value data
            response_data = {
                "message": "Value updated successfully"
                if is_update
                else "Value created successfully",
                "value": {
                    "id": tracker_value.id,
                    "tracker_id": tracker_value.tracker_id,
                    "date": tracker_value.date.isoformat(),
                    "value": tracker_value.value,
                    "created_at": tracker_value.created_at.isoformat(),
                    "updated_at": tracker_value.updated_at.isoformat(),
                },
            }

            status_code = 200 if is_update else 201
            return jsonify(response_data), status_code

        except (ValidationError, ResourceNotFoundError):
            db.rollback()
            raise
        except IntegrityError:
            db.rollback()
            # Let the centralized error handler deal with this
            raise
        except Exception as e:
            db.rollback()
            # Log the error and raise a DatabaseError
            error_id = log_error(e, get_request_info())
            raise DatabaseError("Failed to create/update value", e)
        finally:
            db.close()

    except (ValidationError, ResourceNotFoundError, DatabaseError):
        # These will be handled by centralized error handlers
        raise
    except Exception as e:
        # Log unexpected errors
        error_id = log_error(e, get_request_info())
        raise


@tracker_value_bp.route("/api/trackers/<int:tracker_id>/values/<date>", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_tracker_value(tracker_id, date):
    """
    Get a specific tracker value by tracker ID and date with user ownership verification.

    Args:
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format

    Returns:
        200 OK: Value found and returned
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Value or tracker doesn't exist
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Validates: Requirements 3.1, 3.2, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
    """
    try:
        # Get SessionLocal from the module
        db = db_module.SessionLocal()
        try:
            # Get current user and verify authentication
            current_user, error_response = _get_current_database_user(db)
            if error_response:
                return error_response

            # Verify tracker ownership
            tracker_exists, user_owns_tracker, tracker = _verify_tracker_ownership(
                db, tracker_id, current_user.id
            )

            if not tracker_exists:
                raise ResourceNotFoundError("Tracker", tracker_id)
            elif not user_owns_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403

            # Get the value
            tracker_value = get_value(db, tracker_id, date)

            # Raise not found if value doesn't exist
            not_found_if_none(tracker_value, "TrackerValue", f"{tracker_id}/{date}")

            # Return value data
            return jsonify(
                {
                    "value": {
                        "id": tracker_value.id,
                        "tracker_id": tracker_value.tracker_id,
                        "date": tracker_value.date.isoformat(),
                        "value": tracker_value.value,
                        "created_at": tracker_value.created_at.isoformat(),
                        "updated_at": tracker_value.updated_at.isoformat(),
                    }
                }
            ), 200

        except (ResourceNotFoundError, ValidationError):
            raise
        except ValueError as e:
            # Invalid date format
            raise ValidationError(f"Invalid date format: {str(e)}")
        except Exception as e:
            # Log the error and raise a DatabaseError
            error_id = log_error(e, get_request_info())
            raise DatabaseError("Failed to retrieve value", e)
        finally:
            db.close()

    except (ValidationError, ResourceNotFoundError, DatabaseError):
        # These will be handled by centralized error handlers
        raise
    except Exception as e:
        # Log unexpected errors
        error_id = log_error(e, get_request_info())
        raise


@tracker_value_bp.route("/api/trackers/<int:tracker_id>/values", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_tracker_values_list(tracker_id):
    """
    Get all values for a tracker with user ownership verification, optionally filtered by date range.

    Args:
        tracker_id: ID of the tracker

    Query Parameters:
        start_date: Optional start date in YYYY-MM-DD format (inclusive)
        end_date: Optional end date in YYYY-MM-DD format (inclusive)

    Returns:
        200 OK: Values found and returned (may be empty array)
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Tracker doesn't exist
        400 Bad Request: Invalid date format
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Validates: Requirements 3.3, 3.4, 3.5, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
    """
    try:
        # Get query parameters
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")

        # Get SessionLocal from the module
        db = db_module.SessionLocal()
        try:
            # Get current user and verify authentication
            current_user, error_response = _get_current_database_user(db)
            if error_response:
                return error_response

            # Verify tracker ownership
            tracker_exists, user_owns_tracker, tracker = _verify_tracker_ownership(
                db, tracker_id, current_user.id
            )

            if not tracker_exists:
                raise ResourceNotFoundError("Tracker", tracker_id)
            elif not user_owns_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403

            # Get values with optional date range filtering
            tracker_values = get_tracker_values(db, tracker_id, start_date, end_date)

            # Convert to JSON array
            values_data = [
                {
                    "id": value.id,
                    "tracker_id": value.tracker_id,
                    "date": value.date.isoformat(),
                    "value": value.value,
                    "created_at": value.created_at.isoformat(),
                    "updated_at": value.updated_at.isoformat(),
                }
                for value in tracker_values
            ]

            return jsonify({"values": values_data}), 200

        except (ResourceNotFoundError, ValidationError):
            raise
        except ValueError as e:
            # Invalid date format in query parameters
            raise ValidationError(f"Invalid date format in query parameters: {str(e)}")
        except Exception as e:
            # Log the error and raise a DatabaseError
            error_id = log_error(e, get_request_info())
            raise DatabaseError("Failed to retrieve values", e)
        finally:
            db.close()

    except (ValidationError, ResourceNotFoundError, DatabaseError):
        # These will be handled by centralized error handlers
        raise
    except Exception as e:
        # Log unexpected errors
        error_id = log_error(e, get_request_info())
        raise


@tracker_value_bp.route("/api/trackers/<int:tracker_id>/values/<date>", methods=["PUT"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def update_tracker_value(tracker_id, date):
    """
    Update an existing tracker value with user ownership verification.

    Args:
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format

    Request Body:
        {
            "value": "string"
        }

    Returns:
        200 OK: Value updated successfully
        400 Bad Request: Validation errors
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Value or tracker doesn't exist
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Validates: Requirements 4.1, 4.2, 4.3, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
    """
    try:
        data = request.get_json()

        # Validate request data
        validation_errors = validate_update_data(data)
        if validation_errors:
            raise ValidationError(
                "Validation failed", details={"validation_errors": validation_errors}
            )

        # Get SessionLocal from the module
        db = db_module.SessionLocal()
        try:
            # Get current user and verify authentication
            current_user, error_response = _get_current_database_user(db)
            if error_response:
                return error_response

            # Verify tracker ownership
            tracker_exists, user_owns_tracker, tracker = _verify_tracker_ownership(
                db, tracker_id, current_user.id
            )

            if not tracker_exists:
                raise ResourceNotFoundError("Tracker", tracker_id)
            elif not user_owns_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403

            # Sanitize input
            sanitized_value = sanitize_value_input(data["value"])

            # Update value
            tracker_value = update_value(db, tracker_id, date, sanitized_value)

            # Raise not found if value doesn't exist
            not_found_if_none(tracker_value, "TrackerValue", f"{tracker_id}/{date}")

            db.commit()

            # Return updated value data
            return jsonify(
                {
                    "message": "Value updated successfully",
                    "value": {
                        "id": tracker_value.id,
                        "tracker_id": tracker_value.tracker_id,
                        "date": tracker_value.date.isoformat(),
                        "value": tracker_value.value,
                        "created_at": tracker_value.created_at.isoformat(),
                        "updated_at": tracker_value.updated_at.isoformat(),
                    },
                }
            ), 200

        except (ValidationError, ResourceNotFoundError):
            db.rollback()
            raise
        except ValueError as e:
            db.rollback()
            # Invalid date format
            raise ValidationError(f"Invalid date format: {str(e)}")
        except Exception as e:
            db.rollback()
            # Log the error and raise a DatabaseError
            error_id = log_error(e, get_request_info())
            raise DatabaseError("Failed to update value", e)
        finally:
            db.close()

    except (ValidationError, ResourceNotFoundError, DatabaseError):
        # These will be handled by centralized error handlers
        raise
    except Exception as e:
        # Log unexpected errors
        error_id = log_error(e, get_request_info())
        raise


@tracker_value_bp.route(
    "/api/trackers/<int:tracker_id>/values/<date>", methods=["DELETE"]
)
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def delete_tracker_value(tracker_id, date):
    """
    Delete a specific tracker value with user ownership verification.

    Args:
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format

    Returns:
        204 No Content: Value deleted successfully
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Value or tracker doesn't exist
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Validates: Requirements 5.1, 5.2, 5.3, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
    """
    try:
        # Get SessionLocal from the module
        db = db_module.SessionLocal()
        try:
            # Get current user and verify authentication
            current_user, error_response = _get_current_database_user(db)
            if error_response:
                return error_response

            # Verify tracker ownership
            tracker_exists, user_owns_tracker, tracker = _verify_tracker_ownership(
                db, tracker_id, current_user.id
            )

            if not tracker_exists:
                raise ResourceNotFoundError("Tracker", tracker_id)
            elif not user_owns_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403

            # Delete value
            deleted = delete_value(db, tracker_id, date)

            if not deleted:
                raise ResourceNotFoundError("TrackerValue", f"{tracker_id}/{date}")

            db.commit()

            # Return 204 No Content for successful deletion
            return "", 204

        except (ResourceNotFoundError, ValidationError):
            db.rollback()
            raise
        except ValueError as e:
            db.rollback()
            # Invalid date format
            raise ValidationError(f"Invalid date format: {str(e)}")
        except Exception as e:
            db.rollback()
            # Log the error and raise a DatabaseError
            error_id = log_error(e, get_request_info())
            raise DatabaseError("Failed to delete value", e)
        finally:
            db.close()

    except (ValidationError, ResourceNotFoundError, DatabaseError):
        # These will be handled by centralized error handlers
        raise
    except Exception as e:
        # Log unexpected errors
        error_id = log_error(e, get_request_info())
        raise


@tracker_value_bp.route("/api/trackers/<int:tracker_id>/values", methods=["DELETE"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def delete_all_tracker_values_endpoint(tracker_id):
    """
    Delete all values for a specific tracker with user ownership verification.

    Args:
        tracker_id: ID of the tracker

    Returns:
        200 OK: Values deleted successfully with count
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Tracker doesn't exist
        401 Unauthorized: User not authenticated
        500 Internal Server Error: Server error

    Validates: Requirements 5.4, 6.1, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5
    """
    try:
        # Get SessionLocal from the module
        db = db_module.SessionLocal()
        try:
            # Get current user and verify authentication
            current_user, error_response = _get_current_database_user(db)
            if error_response:
                return error_response

            # Verify tracker ownership
            tracker_exists, user_owns_tracker, tracker = _verify_tracker_ownership(
                db, tracker_id, current_user.id
            )

            if not tracker_exists:
                raise ResourceNotFoundError("Tracker", tracker_id)
            elif not user_owns_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403

            # Delete all values for the tracker
            deleted_count = delete_all_tracker_values(db, tracker_id)
            db.commit()

            # Return success with count
            return jsonify(
                {
                    "message": f"Deleted {deleted_count} values for tracker {tracker_id}",
                    "deleted_count": deleted_count,
                }
            ), 200

        except (ResourceNotFoundError, ValidationError):
            db.rollback()
            raise
        except Exception as e:
            db.rollback()
            # Log the error and raise a DatabaseError
            error_id = log_error(e, get_request_info())
            raise DatabaseError("Failed to delete values", e)
        finally:
            db.close()

    except (ValidationError, ResourceNotFoundError, DatabaseError):
        # These will be handled by centralized error handlers
        raise
    except Exception as e:
        # Log unexpected errors
        error_id = log_error(e, get_request_info())
        raise
