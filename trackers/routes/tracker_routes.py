# Endpoints which handle tracker-related operations

from flask import Blueprint, g, jsonify, request
from sqlalchemy.exc import IntegrityError

from trackers.auth.context import get_current_user
from trackers.auth.decorators import require_auth
from trackers.db import database as db_module
from trackers.db.trackerdb import (
    create_tracker,
    delete_user_tracker,
    get_all_trackers,
    get_user_tracker,
)
from trackers.services.user_service import UserService

tracker_bp = Blueprint("tracker", __name__)


@tracker_bp.route("/add_tracker", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def add_tracker():
    """
    Create a new tracker in the database with user ownership.

    This endpoint requires authentication and automatically assigns the tracker
    to the authenticated user.

    Validates: Requirements 6.1, 6.2
    """
    data = request.get_json()
    tracker_name = data.get("name")
    tracker_description = data.get("description")

    if not tracker_name:
        return jsonify({"error": "Tracker name is required"}), 400

    # Get SessionLocal from the module to ensure we use the current (possibly reinitialized) version
    db = db_module.SessionLocal()
    try:
        # Get current user from authentication context
        current_user_info = get_current_user()

        # Check if we're in public access mode (API key auth disabled)
        auth_context = getattr(g, "auth_context", None)
        is_public_access = auth_context and getattr(
            auth_context, "public_access", False
        )

        if not current_user_info and not is_public_access:
            return jsonify({"error": "User authentication required"}), 401

        # Handle user assignment based on authentication status
        user_id = None
        if current_user_info:
            # Get user's database record for authenticated users
            user_service = UserService(db)
            current_user = user_service.get_user_by_google_id(
                current_user_info.google_id
            )
            if not current_user:
                return jsonify({"error": "User not found in database"}), 401
            user_id = current_user.id
        elif is_public_access:
            # In public access mode, use the default system user
            user_service = UserService(db)
            default_user = user_service.get_or_create_default_system_user()
            if not default_user:
                return jsonify({"error": "Failed to create default system user"}), 500
            user_id = default_user.id

        # Create tracker with optional user ownership
        tracker = create_tracker(
            db,
            name=tracker_name,
            description=tracker_description,
            user_id=user_id,  # None for public access, user ID for authenticated users
        )
        db.commit()  # Commit the transaction

        # Return created tracker data
        return jsonify(
            {
                "message": "Tracker added successfully",
                "tracker": {
                    "id": tracker.id,
                    "name": tracker.name,
                    "description": tracker.description,
                    "user_id": tracker.user_id,
                },
            }
        ), 201
    except IntegrityError:
        db.rollback()
        return jsonify(
            {
                "error": f"Tracker with name '{tracker_name}' already exists for this user"
            }
        ), 409
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Failed to create tracker: {str(e)}"}), 500
    finally:
        db.close()


@tracker_bp.route("/trackers", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_trackers():
    """
    Retrieve all trackers belonging to the authenticated user.

    This endpoint requires authentication and filters results by user ownership.
    In public access mode, returns trackers belonging to the default system user.

    Validates: Requirements 6.1, 6.5
    """
    # Get SessionLocal from the module to ensure we use the current (possibly reinitialized) version
    db = db_module.SessionLocal()
    try:
        # Get current user from authentication context
        current_user_info = get_current_user()

        # Check if we're in public access mode (API key auth disabled)
        auth_context = getattr(g, "auth_context", None)
        is_public_access = auth_context and getattr(
            auth_context, "public_access", False
        )

        if not current_user_info and not is_public_access:
            return jsonify({"error": "User authentication required"}), 401

        # Handle user assignment based on authentication status
        user_id = None
        if current_user_info:
            # Get user's database record for authenticated users
            user_service = UserService(db)
            current_user = user_service.get_user_by_google_id(
                current_user_info.google_id
            )
            if not current_user:
                return jsonify({"error": "User not found in database"}), 401
            user_id = current_user.id
        elif is_public_access:
            # In public access mode, use the default system user
            user_service = UserService(db)
            default_user = user_service.get_or_create_default_system_user()
            if not default_user:
                return jsonify({"error": "Failed to create default system user"}), 500
            user_id = default_user.id

        # Query trackers filtered by user ownership
        trackers = get_all_trackers(db, user_id=user_id)

        # Convert to JSON array
        trackers_data = [
            {
                "id": tracker.id,
                "name": tracker.name,
                "description": tracker.description,
                "user_id": tracker.user_id,
            }
            for tracker in trackers
        ]

        return jsonify({"trackers": trackers_data}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve trackers: {str(e)}"}), 500
    finally:
        db.close()


@tracker_bp.route("/trackers/unified", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_trackers_unified():
    """
    Retrieve all trackers with unified authentication support.

    This endpoint demonstrates the new unified authentication system that
    accepts both API key and Google OAuth authentication.

    Validates: Requirements 5.3, 5.4
    """
    from trackers.auth.context import get_auth_method

    # Get SessionLocal from the module to ensure we use the current (possibly reinitialized) version
    db = db_module.SessionLocal()
    try:
        # Get current user from authentication context
        current_user_info = get_current_user()
        if not current_user_info:
            return jsonify({"error": "User authentication required"}), 401

        # Get user's database record
        user_service = UserService(db)
        current_user = user_service.get_user_by_google_id(current_user_info.google_id)
        if not current_user:
            return jsonify({"error": "User not found in database"}), 401

        # Query trackers filtered by user ownership
        trackers = get_all_trackers(db, user_id=current_user.id)

        # Convert to JSON array
        trackers_data = [
            {
                "id": tracker.id,
                "name": tracker.name,
                "description": tracker.description,
                "user_id": tracker.user_id,
            }
            for tracker in trackers
        ]

        # Include authentication context in response
        auth_method = get_auth_method()
        current_user_info = get_current_user()

        response_data = {
            "trackers": trackers_data,
            "auth_info": {
                "method": auth_method,
                "user": {
                    "email": current_user_info.email if current_user_info else None,
                    "name": current_user_info.name if current_user_info else None,
                }
                if current_user_info
                else None,
            },
        }

        return jsonify(response_data), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve trackers: {str(e)}"}), 500
    finally:
        db.close()


@tracker_bp.route("/trackers/<int:tracker_id>", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def get_tracker(tracker_id):
    """
    Retrieve a specific tracker by ID with user ownership verification.

    Args:
        tracker_id: ID of the tracker to retrieve

    Returns:
        200 OK: Tracker found and owned by user
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Tracker doesn't exist
        401 Unauthorized: User not authenticated

    Validates: Requirements 6.1, 6.3, 6.4
    """
    db = db_module.SessionLocal()
    try:
        # Get current user from authentication context
        current_user_info = get_current_user()
        if not current_user_info:
            return jsonify({"error": "User authentication required"}), 401

        # Get user's database record
        user_service = UserService(db)
        current_user = user_service.get_user_by_google_id(current_user_info.google_id)
        if not current_user:
            return jsonify({"error": "User not found in database"}), 401

        # Get tracker with user ownership verification
        tracker = get_user_tracker(db, tracker_id, current_user.id)
        if not tracker:
            # Check if tracker exists at all to distinguish between 404 and 403
            from trackers.db.trackerdb import get_tracker as get_any_tracker

            any_tracker = get_any_tracker(db, tracker_id)
            if any_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403
            else:
                return jsonify({"error": "Tracker not found"}), 404

        # Return tracker data
        return jsonify(
            {
                "tracker": {
                    "id": tracker.id,
                    "name": tracker.name,
                    "description": tracker.description,
                    "user_id": tracker.user_id,
                    "created_at": tracker.created_at.isoformat()
                    if tracker.created_at
                    else None,
                    "updated_at": tracker.updated_at.isoformat()
                    if tracker.updated_at
                    else None,
                }
            }
        ), 200

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve tracker: {str(e)}"}), 500
    finally:
        db.close()


@tracker_bp.route("/trackers/<int:tracker_id>", methods=["PUT"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def update_tracker(tracker_id):
    """
    Update a specific tracker with user ownership verification.

    Args:
        tracker_id: ID of the tracker to update

    Request Body:
        {
            "name": "string (optional)",
            "description": "string (optional)"
        }

    Returns:
        200 OK: Tracker updated successfully
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Tracker doesn't exist
        400 Bad Request: Invalid request data
        401 Unauthorized: User not authenticated

    Validates: Requirements 6.1, 6.3, 6.4
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body is required"}), 400

    name = data.get("name")
    description = data.get("description")

    if name is None and description is None:
        return jsonify(
            {"error": "At least one field (name or description) must be provided"}
        ), 400

    db = db_module.SessionLocal()
    try:
        # Get current user from authentication context
        current_user_info = get_current_user()
        if not current_user_info:
            return jsonify({"error": "User authentication required"}), 401

        # Get user's database record
        user_service = UserService(db)
        current_user = user_service.get_user_by_google_id(current_user_info.google_id)
        if not current_user:
            return jsonify({"error": "User not found in database"}), 401

        # Get tracker with user ownership verification
        tracker = get_user_tracker(db, tracker_id, current_user.id)
        if not tracker:
            # Check if tracker exists at all to distinguish between 404 and 403
            from trackers.db.trackerdb import get_tracker as get_any_tracker

            any_tracker = get_any_tracker(db, tracker_id)
            if any_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403
            else:
                return jsonify({"error": "Tracker not found"}), 404

        # Update tracker fields
        if name is not None:
            tracker.name = name
        if description is not None:
            tracker.description = description

        db.commit()

        # Return updated tracker data
        return jsonify(
            {
                "message": "Tracker updated successfully",
                "tracker": {
                    "id": tracker.id,
                    "name": tracker.name,
                    "description": tracker.description,
                    "user_id": tracker.user_id,
                    "created_at": tracker.created_at.isoformat()
                    if tracker.created_at
                    else None,
                    "updated_at": tracker.updated_at.isoformat()
                    if tracker.updated_at
                    else None,
                },
            }
        ), 200

    except IntegrityError:
        db.rollback()
        return jsonify(
            {"error": f"Tracker with name '{name}' already exists for this user"}
        ), 409
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Failed to update tracker: {str(e)}"}), 500
    finally:
        db.close()


@tracker_bp.route("/trackers/<int:tracker_id>", methods=["DELETE"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def delete_tracker(tracker_id):
    """
    Delete a specific tracker with user ownership verification.

    Args:
        tracker_id: ID of the tracker to delete

    Returns:
        204 No Content: Tracker deleted successfully
        403 Forbidden: Tracker exists but not owned by user
        404 Not Found: Tracker doesn't exist
        401 Unauthorized: User not authenticated

    Validates: Requirements 6.1, 6.3, 6.4
    """
    db = db_module.SessionLocal()
    try:
        # Get current user from authentication context
        current_user_info = get_current_user()
        if not current_user_info:
            return jsonify({"error": "User authentication required"}), 401

        # Get user's database record
        user_service = UserService(db)
        current_user = user_service.get_user_by_google_id(current_user_info.google_id)
        if not current_user:
            return jsonify({"error": "User not found in database"}), 401

        # Attempt to delete tracker with user ownership verification
        deleted = delete_user_tracker(db, tracker_id, current_user.id)
        if not deleted:
            # Check if tracker exists at all to distinguish between 404 and 403
            from trackers.db.trackerdb import get_tracker as get_any_tracker

            any_tracker = get_any_tracker(db, tracker_id)
            if any_tracker:
                return jsonify(
                    {"error": "Access denied: tracker not owned by user"}
                ), 403
            else:
                return jsonify({"error": "Tracker not found"}), 404

        db.commit()

        # Return 204 No Content for successful deletion
        return "", 204

    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Failed to delete tracker: {str(e)}"}), 500
    finally:
        db.close()
