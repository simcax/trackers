"""
Profile routes for user API key management.

This module provides Flask routes for the user profile interface, including:
- Profile page display with API key management
- API key creation and invalidation
- User-specific API key operations

Requirements: 2.1, 2.4, 3.1, 3.2, 3.3
"""

import logging
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from sqlalchemy.exc import SQLAlchemyError

from trackers.auth.decorators import require_auth
from trackers.db import database as db_module
from trackers.services.api_key_service import APIKeyService
from trackers.services.user_service import UserService

# Configure logging
logger = logging.getLogger(__name__)

# Import get_current_user with error handling
try:
    from trackers.auth.context import get_current_user

    GET_CURRENT_USER_AVAILABLE = True
except ImportError as e:
    logger.error(f"Failed to import get_current_user: {e}")
    GET_CURRENT_USER_AVAILABLE = False

    def get_current_user():
        """Fallback function when get_current_user is not available."""
        return None


# Create profile blueprint
profile_bp = Blueprint(
    "profile",
    __name__,
    url_prefix="/profile",
    template_folder="../../templates",
)


def get_current_user_safely():
    """
    Safely get the current user with proper error handling.

    Returns:
        UserInfo or None: Current user info or None if not available
    """
    try:
        return get_current_user()
    except Exception as e:
        logger.error(f"Error getting current user: {e}")
        return None


@profile_bp.route("/")
@require_auth(allow_api_key=False, allow_google_oauth=True, redirect_to_login=True)
def profile_page():
    """
    Display user profile with API key management interface.

    Shows the user's existing API keys and provides forms for creating new keys
    and invalidating existing ones. Only accessible via Google OAuth authentication.

    Returns:
        Rendered profile template with user's API key data

    Requirements: 2.1, 3.1, 3.2 - Profile page access and API key display
    """
    try:
        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # Try to create user from OAuth info
                current_user = get_current_user_safely()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        logger.error(f"Error creating database user: {e}")
                        db.rollback()
                        return render_template(
                            "profile.html",
                            error="Unable to access user data",
                            api_keys=[],
                            user=None,
                            min_expiration_date=(
                                datetime.now() + timedelta(days=1)
                            ).strftime("%Y-%m-%d"),
                        )

            if not database_user:
                min_expiration_date = (datetime.now() + timedelta(days=1)).strftime(
                    "%Y-%m-%d"
                )
                return render_template(
                    "profile.html",
                    error="User authentication required",
                    api_keys=[],
                    user=None,
                    min_expiration_date=min_expiration_date,
                )

            # Get user's API keys
            api_key_service = APIKeyService(db)
            api_keys = api_key_service.list_user_api_keys(database_user.id)

            # Get key count for display
            key_count = len(api_keys)

            # Calculate minimum expiration date (tomorrow)
            min_expiration_date = (datetime.now() + timedelta(days=1)).strftime(
                "%Y-%m-%d"
            )

            logger.info(f"Profile page accessed by user {database_user.id}")

            return render_template(
                "profile.html",
                api_keys=api_keys,
                user=database_user,
                key_count=key_count,
                max_keys=10,  # Reasonable limit for UI
                min_expiration_date=min_expiration_date,
                error=request.args.get("error"),
                success=request.args.get("success"),
            )

        except Exception as e:
            logger.error(f"Error loading profile page: {e}")
            min_expiration_date = (datetime.now() + timedelta(days=1)).strftime(
                "%Y-%m-%d"
            )
            return render_template(
                "profile.html",
                error="Unable to load profile data",
                api_keys=[],
                user=None,
                min_expiration_date=min_expiration_date,
            )
        finally:
            db.close()

    except Exception as e:
        logger.error(f"Profile page error: {e}")
        min_expiration_date = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        return render_template(
            "profile.html",
            error="Profile system temporarily unavailable",
            api_keys=[],
            user=None,
            min_expiration_date=min_expiration_date,
        )


@profile_bp.route("/api-keys", methods=["POST"])
@require_auth(allow_api_key=False, allow_google_oauth=True, redirect_to_login=True)
def create_api_key():
    """
    Create new API key for authenticated user.

    Processes form data to create a new API key with optional expiration date.
    Returns the key value once for copying, then redirects to profile page.

    Form Data:
        name: User-friendly name for the key (required)
        expires_at: Optional expiration date in YYYY-MM-DD format

    Returns:
        JSON response for AJAX calls or redirect for form submissions

    Requirements: 1.2, 1.3, 1.4, 1.5 - API key creation with expiration and display
    """
    try:
        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # Try to create user from OAuth info
                current_user = get_current_user_safely()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        logger.error(f"Error creating database user: {e}")
                        db.rollback()
                        if request.is_json:
                            return jsonify({"error": "Unable to access user data"}), 500
                        else:
                            return redirect(
                                url_for(
                                    "profile.profile_page", error="user_access_failed"
                                )
                            )

            if not database_user:
                if request.is_json:
                    return jsonify({"error": "User authentication required"}), 401
                else:
                    return redirect(
                        url_for("profile.profile_page", error="auth_required")
                    )

            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()

            # Validate required fields
            name = data.get("name", "").strip()
            if not name:
                if request.is_json:
                    return jsonify({"error": "API key name is required"}), 400
                else:
                    return redirect(
                        url_for("profile.profile_page", error="name_required")
                    )

            # Parse optional expiration date
            expires_at = None
            expires_at_str = data.get("expires_at", "").strip()
            if expires_at_str:
                try:
                    expires_at = datetime.strptime(expires_at_str, "%Y-%m-%d")
                    # Set to end of day for better UX
                    expires_at = expires_at.replace(hour=23, minute=59, second=59)
                except ValueError:
                    if request.is_json:
                        return jsonify(
                            {"error": "Invalid expiration date format. Use YYYY-MM-DD"}
                        ), 400
                    else:
                        return redirect(
                            url_for("profile.profile_page", error="invalid_date")
                        )

            # Check key count limit (reasonable limit for UI)
            api_key_service = APIKeyService(db)
            current_key_count = api_key_service.get_user_key_count(database_user.id)
            if current_key_count >= 10:
                if request.is_json:
                    return jsonify(
                        {"error": "Maximum number of API keys reached (10)"}
                    ), 400
                else:
                    return redirect(
                        url_for("profile.profile_page", error="max_keys_reached")
                    )

            # Create API key
            result = api_key_service.create_api_key(database_user.id, name, expires_at)

            if not result.success:
                if request.is_json:
                    return jsonify({"error": result.error_message}), 400
                else:
                    return redirect(
                        url_for("profile.profile_page", error="creation_failed")
                    )

            # Commit the transaction
            db.commit()

            logger.info(f"Created API key '{name}' for user {database_user.id}")

            # Return success response with one-time key value
            if request.is_json:
                return jsonify(
                    {
                        "success": True,
                        "message": "API key created successfully",
                        "api_key": {
                            "id": result.api_key_info.id,
                            "name": result.api_key_info.name,
                            "created_at": result.api_key_info.created_at.isoformat(),
                            "expires_at": result.api_key_info.expires_at.isoformat()
                            if result.api_key_info.expires_at
                            else None,
                            "is_near_expiration": result.api_key_info.is_near_expiration,
                            "key_value": result.key_value,  # Only provided once
                        },
                    }
                ), 201
            else:
                # For form submissions, we need to show the key value once
                # Store it in session or pass as URL parameter (not ideal for security)
                # For now, redirect with success message
                return redirect(
                    url_for(
                        "profile.profile_page", success="key_created", key_name=name
                    )
                )

        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Database error creating API key: {e}")
            if request.is_json:
                return jsonify({"error": "Database error occurred"}), 500
            else:
                return redirect(url_for("profile.profile_page", error="database_error"))
        except Exception as e:
            db.rollback()
            logger.error(f"Unexpected error creating API key: {e}")
            if request.is_json:
                return jsonify({"error": "Failed to create API key"}), 500
            else:
                return redirect(
                    url_for("profile.profile_page", error="creation_failed")
                )
        finally:
            db.close()

    except Exception as e:
        logger.error(f"API key creation error: {e}")
        if request.is_json:
            return jsonify(
                {"error": "API key creation system temporarily unavailable"}
            ), 500
        else:
            return redirect(url_for("profile.profile_page", error="system_error"))


@profile_bp.route("/api-keys/<int:key_id>/invalidate", methods=["POST"])
@require_auth(allow_api_key=False, allow_google_oauth=True, redirect_to_login=True)
def invalidate_api_key(key_id: int):
    """
    Invalidate specific API key for authenticated user.

    Disables the specified API key, making it unusable for future API requests.
    Users can only invalidate their own keys for security.

    Args:
        key_id: ID of the API key to invalidate

    Returns:
        JSON response for AJAX calls or redirect for form submissions

    Requirements: 2.4, 2.5 - Invalidate button and immediate key disabling
    """
    try:
        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # Try to create user from OAuth info
                current_user = get_current_user_safely()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        logger.error(f"Error creating database user: {e}")
                        db.rollback()
                        if request.is_json:
                            return jsonify({"error": "Unable to access user data"}), 500
                        else:
                            return redirect(
                                url_for(
                                    "profile.profile_page", error="user_access_failed"
                                )
                            )

            if not database_user:
                if request.is_json:
                    return jsonify({"error": "User authentication required"}), 401
                else:
                    return redirect(
                        url_for("profile.profile_page", error="auth_required")
                    )

            # Invalidate the API key
            api_key_service = APIKeyService(db)
            success = api_key_service.invalidate_api_key(database_user.id, key_id)

            if not success:
                if request.is_json:
                    return jsonify(
                        {"error": "API key not found or already invalidated"}
                    ), 404
                else:
                    return redirect(
                        url_for("profile.profile_page", error="key_not_found")
                    )

            # Commit the transaction
            db.commit()

            logger.info(f"Invalidated API key {key_id} for user {database_user.id}")

            # Return success response
            if request.is_json:
                return jsonify(
                    {"success": True, "message": "API key invalidated successfully"}
                ), 200
            else:
                return redirect(
                    url_for("profile.profile_page", success="key_invalidated")
                )

        except SQLAlchemyError as e:
            db.rollback()
            logger.error(f"Database error invalidating API key {key_id}: {e}")
            if request.is_json:
                return jsonify({"error": "Database error occurred"}), 500
            else:
                return redirect(url_for("profile.profile_page", error="database_error"))
        except Exception as e:
            db.rollback()
            logger.error(f"Unexpected error invalidating API key {key_id}: {e}")
            if request.is_json:
                return jsonify({"error": "Failed to invalidate API key"}), 500
            else:
                return redirect(
                    url_for("profile.profile_page", error="invalidation_failed")
                )
        finally:
            db.close()

    except Exception as e:
        logger.error(f"API key invalidation error: {e}")
        if request.is_json:
            return jsonify(
                {"error": "API key invalidation system temporarily unavailable"}
            ), 500
        else:
            return redirect(url_for("profile.profile_page", error="system_error"))


@profile_bp.route("/api-keys/<int:key_id>", methods=["GET"])
@require_auth(allow_api_key=False, allow_google_oauth=True, redirect_to_login=True)
def get_api_key_details(key_id: int):
    """
    Get details for a specific API key (JSON endpoint for AJAX).

    Returns detailed information about a specific API key owned by the user.
    Used for displaying key information in modals or detailed views.

    Args:
        key_id: ID of the API key to retrieve

    Returns:
        JSON response with API key details

    Requirements: Supporting functionality for key management UI
    """
    try:
        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Get API key details
            api_key_service = APIKeyService(db)
            api_key_info = api_key_service.get_api_key_by_id(database_user.id, key_id)

            if not api_key_info:
                return jsonify({"error": "API key not found"}), 404

            # Return key details (no sensitive data)
            return jsonify(
                {
                    "success": True,
                    "api_key": {
                        "id": api_key_info.id,
                        "name": api_key_info.name,
                        "created_at": api_key_info.created_at.isoformat(),
                        "expires_at": api_key_info.expires_at.isoformat()
                        if api_key_info.expires_at
                        else None,
                        "is_active": api_key_info.is_active,
                        "is_expired": api_key_info.is_expired,
                        "is_near_expiration": api_key_info.is_near_expiration,
                        "last_used_at": api_key_info.last_used_at.isoformat()
                        if api_key_info.last_used_at
                        else None,
                    },
                }
            ), 200

        except Exception as e:
            logger.error(f"Error getting API key {key_id} details: {e}")
            return jsonify({"error": "Failed to retrieve API key details"}), 500
        finally:
            db.close()

    except Exception as e:
        logger.error(f"API key details error: {e}")
        return jsonify({"error": "API key details system temporarily unavailable"}), 500
