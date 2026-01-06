"""
Web routes for the Tracker Web UI.

This module provides Flask routes for the web interface, including:
- Dashboard view for displaying trackers
- Tracker creation form handling
- Adding values to existing trackers
- Integrated authentication supporting both API key and Google OAuth

Validates: Requirements 5.1, 5.2, 5.3, 5.4
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from flask import (
    Blueprint,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy.exc import IntegrityError

from trackers.auth.admin import get_admin_status_info
from trackers.auth.admin_decorators import admin_required
from trackers.auth.context import get_current_user, is_authenticated
from trackers.auth.decorators import optional_auth, require_auth
from trackers.db import database as db_module
from trackers.db.tracker_values_db import get_tracker_values
from trackers.db.trackerdb import create_tracker, get_all_trackers

logger = logging.getLogger(__name__)

# Create web blueprint with template folder configuration
# Static files are handled by the main Flask app, not the blueprint
web_bp = Blueprint(
    "web",
    __name__,
    url_prefix="/web",
    template_folder="../../templates",
)


@dataclass
class TrackerDisplayData:
    """Data structure for tracker display in the web interface."""

    id: int
    name: str
    description: Optional[str]
    icon: str
    color: str
    current_value: str
    change: float
    change_text: str
    recent_values: List[str]
    recent_dates: List[str]
    trend_data: List[float]
    unit: Optional[str] = None
    total_change: float = 0.0
    total_change_text: str = "No data"
    # Job-related fields
    job_count: int = 0
    active_jobs: int = 0
    has_jobs: bool = False


def format_danish_number(number):
    """Format number using Danish conventions (. for thousands, , for decimals)."""
    try:
        if isinstance(number, str):
            number = float(number)

        # Format with Danish locale-like formatting
        if number == int(number):
            # Integer - use thousand separators
            return f"{int(number):,}".replace(",", ".")
        else:
            # Decimal - use comma for decimal separator and dot for thousands
            formatted = (
                f"{number:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
            )
            # Remove trailing zeros after decimal comma
            if "," in formatted:
                formatted = formatted.rstrip("0").rstrip(",")
            return formatted
    except (ValueError, TypeError):
        return str(number)


def format_tracker_for_display(
    tracker, recent_values: List = None
) -> TrackerDisplayData:
    """
    Format tracker data for display in the web interface.

    Args:
        tracker: TrackerModel instance
        recent_values: List of recent TrackerValueModel instances

    Returns:
        TrackerDisplayData instance formatted for template rendering
    """
    try:
        if recent_values is None:
            recent_values = []

        # Extract recent values for display (last 5)
        recent_value_strings = [
            format_danish_number(value.value) for value in recent_values[:5]
        ]
        recent_date_strings = [
            value.date.strftime("%d-%m-%Y")
            for value in recent_values[:5]  # Danish date format
        ]

        # Calculate current value and change
        current_value = recent_value_strings[0] if recent_value_strings else "No data"

        # Simple change calculation (current vs previous)
        change = 0.0
        change_text = "No change"
        if len(recent_values) >= 2:
            try:
                current = float(recent_values[0].value)
                previous = float(recent_values[1].value)
                change = current - previous
                if change > 0:
                    change_text = f"+{format_danish_number(change)}"
                elif change < 0:
                    change_text = format_danish_number(change)
                else:
                    change_text = "No change"
            except (ValueError, TypeError):
                change_text = "No change"

        # Calculate total change (first to most recent entry)
        total_change = 0.0
        total_change_text = "No data"
        if len(recent_values) >= 2:
            try:
                # Most recent is first in the list, oldest is last
                most_recent = float(recent_values[0].value)
                oldest = float(recent_values[-1].value)
                total_change = most_recent - oldest
                if total_change > 0:
                    total_change_text = f"+{format_danish_number(total_change)} total"
                elif total_change < 0:
                    total_change_text = f"{format_danish_number(total_change)} total"
                else:
                    total_change_text = "No change total"
            except (ValueError, TypeError):
                total_change_text = "No data"

        # Generate trend data for mini charts (normalized between 0 and 1)
        trend_data = []
        if recent_values:
            # Extract numeric values for trend calculation
            numeric_values = []
            for value in recent_values[:10]:  # Last 10 values for trend
                try:
                    numeric_values.append(float(value.value))
                except (ValueError, TypeError):
                    numeric_values.append(0.0)

            if numeric_values:
                # Reverse to get chronological order (oldest first for chart display)
                numeric_values.reverse()

                # Normalize values to 0-1 range for chart rendering
                min_val = min(numeric_values)
                max_val = max(numeric_values)
                value_range = max_val - min_val

                if value_range > 0:
                    # Normalize each value to 0-1 range
                    trend_data = [
                        (val - min_val) / value_range for val in numeric_values
                    ]
                else:
                    # All values are the same, put them in the middle (0.5)
                    trend_data = [0.5] * len(numeric_values)

        # Extract unit from description if available
        unit = None
        if tracker.description:
            # Look for "Unit: <value>" pattern in description
            import re

            unit_match = re.search(r"Unit:\s*([^|]+)", tracker.description)
            if unit_match:
                unit = unit_match.group(1).strip()

        # Get job information for this tracker
        job_count = 0
        active_jobs = 0
        has_jobs = False

        try:
            # Import here to avoid circular imports
            from trackers.db import database as db_module
            from trackers.models.job_model import JobModel

            # Get a database session to query jobs
            db = db_module.SessionLocal()
            try:
                jobs = (
                    db.query(JobModel)
                    .filter(
                        JobModel.tracker_id == tracker.id,
                        JobModel.user_id == tracker.user_id,
                    )
                    .all()
                )

                job_count = len(jobs)
                active_jobs = len([job for job in jobs if job.is_active])
                has_jobs = job_count > 0

            finally:
                db.close()

        except Exception as job_error:
            print(f"Warning: Error querying jobs for tracker {tracker.id}: {job_error}")
            # Use default values if job query fails

        return TrackerDisplayData(
            id=tracker.id,
            name=tracker.name,
            description=tracker.description,
            icon="📊",  # Default icon for now
            color="blue",  # Default color for now
            current_value=current_value,
            change=change,
            change_text=change_text,
            recent_values=recent_value_strings,
            recent_dates=recent_date_strings,
            trend_data=trend_data,
            unit=unit,
            total_change=total_change,
            total_change_text=total_change_text,
            job_count=job_count,
            active_jobs=active_jobs,
            has_jobs=has_jobs,
        )
    except Exception as e:
        print(f"Error in format_tracker_for_display for tracker {tracker.id}: {e}")
        # Return a safe default
        return TrackerDisplayData(
            id=tracker.id,
            name=tracker.name,
            description=tracker.description,
            icon="📊",
            color="blue",
            current_value="No data",
            change=0.0,
            change_text="No change",
            recent_values=[],
            recent_dates=[],
            trend_data=[],
            unit=None,
            total_change=0.0,
            total_change_text="No data",
            job_count=0,
            active_jobs=0,
            has_jobs=False,
        )


@web_bp.route("/")
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=True)
def dashboard():
    """
    Main dashboard view for the web interface.

    Fetches user's trackers and their recent values, then displays them
    in a card-based layout with dark theme styling. Uses Google OAuth
    authentication only (API keys are for API endpoints only).

    Returns:
        Rendered dashboard template with user's tracker data

    Validates: Requirements 6.5, 8.1
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = None

            # Get authentication context that was set up by the @require_auth decorator
            from trackers.auth.decorators import get_auth_context

            auth_context = get_auth_context()

            # The @require_auth decorator should have already validated authentication
            # Now we just need to get or create the database user record
            if auth_context.is_authenticated and auth_context.user_info:
                # User is authenticated via Google OAuth or email/password
                try:
                    if auth_context.user_info.google_id:
                        # Google OAuth user - get or create database record
                        database_user = user_service.get_user_by_google_id(
                            auth_context.user_info.google_id
                        )
                        if not database_user:
                            # Create user if doesn't exist
                            database_user = user_service.create_or_update_user(
                                auth_context.user_info
                            )
                            db.commit()
                    else:
                        # Email/password user - try session lookup
                        database_user = user_service.get_current_user_from_session()
                        if not database_user:
                            return render_template(
                                "dashboard.html",
                                trackers=[],
                                error="Session user not found",
                            )
                except Exception as user_error:
                    print(f"User lookup failed: {user_error}")
                    import traceback

                    traceback.print_exc()
                    database_user = None
            elif auth_context.api_key_valid:
                # API key authentication - use default system user
                try:
                    database_user = user_service.get_or_create_default_system_user()
                    if database_user:
                        db.commit()
                except Exception as default_error:
                    print(f"Default user creation failed: {default_error}")
                    database_user = None
            else:
                # This should not happen if @require_auth is working correctly
                return render_template(
                    "dashboard.html",
                    trackers=[],
                    error="Authentication required",
                )

            if not database_user:
                return render_template(
                    "dashboard.html",
                    trackers=[],
                    error="User authentication required",
                )

            # Fetch user's trackers
            trackers = get_all_trackers(db, user_id=database_user.id)

            # Format trackers for display with recent values
            display_data = []
            for tracker in trackers:
                # Get recent values for this tracker (last 10 for trend calculation)
                recent_values = get_tracker_values(db, tracker.id)[:10]
                formatted_tracker = format_tracker_for_display(tracker, recent_values)
                display_data.append(formatted_tracker)

            # Template context processor now handles authentication context
            return render_template(
                "dashboard.html",
                trackers=display_data,
                database_user=database_user,
            )

        except Exception as e:
            # Log error and show empty dashboard
            print(f"Error fetching tracker data: {e}")
            return render_template(
                "dashboard.html",
                trackers=[],
                error="Unable to load tracker data",
            )
        finally:
            db.close()

    except Exception as e:
        # Fallback to test page if dashboard fails
        print(f"Dashboard error: {e}")
        return render_template("test.html")


@web_bp.route("/tracker/create", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=True)
def create_tracker_web():
    """
    Handle tracker creation form submission from the web interface.

    Processes form data, validates inputs, and creates a new tracker
    using the existing API infrastructure. Now requires authentication
    and automatically assigns tracker to the current user.

    Request Form Data:
        name: Tracker name (required)
        description: Tracker description (optional)
        unit: Tracker unit (optional, stored in description for now)
        goal: Tracker goal (optional, stored in description for now)
        color: Tracker color theme (optional, not stored yet)

    Returns:
        JSON response for AJAX calls or redirect for form submissions

    Validates: Requirements 6.2, 6.5, 8.1
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for tracker assignment
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        if request.is_json:
                            return jsonify({"error": "Unable to access user data"}), 500
                        else:
                            return redirect(
                                url_for("web.dashboard", error="user_access_failed")
                            )

            if not database_user:
                if request.is_json:
                    return jsonify({"error": "User authentication required"}), 401
                else:
                    return redirect(url_for("web.dashboard", error="auth_required"))

            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()

            # Validate required fields
            tracker_name_raw = data.get("name")
            tracker_name = tracker_name_raw.strip() if tracker_name_raw else ""
            if not tracker_name:
                if request.is_json:
                    return jsonify({"error": "Tracker name is required"}), 400
                else:
                    # For form submissions, redirect back with error
                    return redirect(url_for("web.dashboard", error="name_required"))

            # Extract optional fields
            description_raw = data.get("description")
            unit_raw = data.get("unit")
            goal_raw = data.get("goal")

            description = description_raw.strip() if description_raw else ""
            unit = unit_raw.strip() if unit_raw else ""
            goal = goal_raw.strip() if goal_raw else ""
            color = data.get("color", "blue")

            # Combine unit and goal into description for now
            # TODO: Update database schema to support unit and goal fields
            description_parts = []
            if description:
                description_parts.append(description)
            if unit:
                description_parts.append(f"Unit: {unit}")
            if goal:
                description_parts.append(f"Goal: {goal}")

            final_description = (
                " | ".join(description_parts) if description_parts else None
            )

            # Create tracker using existing database functions with user assignment
            tracker = create_tracker(
                db,
                name=tracker_name,
                description=final_description,
                user_id=database_user.id,
            )
            db.commit()

            # Return success response
            tracker_data = {
                "id": tracker.id,
                "name": tracker.name,
                "description": tracker.description,
                "user_id": tracker.user_id,
            }

            if request.is_json:
                return jsonify(
                    {
                        "message": "Tracker created successfully",
                        "tracker": tracker_data,
                    }
                ), 201
            else:
                # For form submissions, redirect to dashboard
                return redirect(url_for("web.dashboard", success="tracker_created"))

        except IntegrityError:
            db.rollback()
            error_msg = (
                f"Tracker with name '{tracker_name}' already exists for your account"
            )
            if request.is_json:
                return jsonify({"error": error_msg}), 409
            else:
                return redirect(url_for("web.dashboard", error="name_exists"))

        except Exception as e:
            db.rollback()
            error_msg = f"Failed to create tracker: {str(e)}"
            if request.is_json:
                return jsonify({"error": error_msg}), 500
            else:
                return redirect(url_for("web.dashboard", error="creation_failed"))
        finally:
            db.close()

    except Exception as e:
        error_msg = f"Request processing error: {str(e)}"
        if request.is_json:
            return jsonify({"error": error_msg}), 500
        else:
            return redirect(url_for("web.dashboard", error="request_error"))


@web_bp.route("/tracker/<int:tracker_id>/value", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=True)
def add_tracker_value_web(tracker_id):
    """
    Handle adding values to existing trackers from the web interface.

    Processes form data and creates/updates tracker values using the
    existing API infrastructure. Now requires authentication and verifies
    that the tracker belongs to the current user.

    Args:
        tracker_id: ID of the tracker to add value to

    Request Form Data:
        date: Date in YYYY-MM-DD format (defaults to today)
        value: Value to add (required)

    Returns:
        JSON response for AJAX calls or redirect for form submissions

    Validates: Requirements 6.3, 6.4, 6.5, 8.1
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for ownership verification
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        if request.is_json:
                            return jsonify({"error": "Unable to access user data"}), 500
                        else:
                            return redirect(
                                url_for("web.dashboard", error="user_access_failed")
                            )

            if not database_user:
                if request.is_json:
                    return jsonify({"error": "User authentication required"}), 401
                else:
                    return redirect(url_for("web.dashboard", error="auth_required"))

            # Handle both JSON and form data
            if request.is_json:
                data = request.get_json()
            else:
                data = request.form.to_dict()

            # Validate required fields
            value = data.get("value", "").strip()
            if not value:
                if request.is_json:
                    return jsonify({"error": "Value is required"}), 400
                else:
                    return redirect(url_for("web.dashboard", error="value_required"))

            # Get date (default to today)
            date = data.get("date")
            if not date:
                date = datetime.now().strftime("%Y-%m-%d")

            # Check if tracker exists and belongs to user
            from trackers.db.trackerdb import get_user_tracker

            tracker = get_user_tracker(db, tracker_id, database_user.id)
            if not tracker:
                if request.is_json:
                    return jsonify({"error": "Tracker not found or access denied"}), 404
                else:
                    return redirect(url_for("web.dashboard", error="tracker_not_found"))

            # Import the tracker value creation function
            from trackers.db.tracker_values_db import create_or_update_value

            # Create or update the value
            tracker_value = create_or_update_value(db, tracker_id, date, value)
            db.commit()

            # Return success response
            value_data = {
                "id": tracker_value.id,
                "tracker_id": tracker_value.tracker_id,
                "date": tracker_value.date.isoformat(),
                "value": tracker_value.value,
            }

            if request.is_json:
                return jsonify(
                    {
                        "message": "Value added successfully",
                        "value": value_data,
                    }
                ), 201
            else:
                return redirect(url_for("web.dashboard", success="value_added"))

        except Exception as e:
            db.rollback()
            error_msg = f"Failed to add value: {str(e)}"
            if request.is_json:
                return jsonify({"error": error_msg}), 500
            else:
                return redirect(url_for("web.dashboard", error="value_add_failed"))
        finally:
            db.close()

    except Exception as e:
        error_msg = f"Request processing error: {str(e)}"
        if request.is_json:
            return jsonify({"error": error_msg}), 500
        else:
            return redirect(url_for("web.dashboard", error="request_error"))


@web_bp.route("/tracker/<int:tracker_id>/chart-data", methods=["GET"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=True)
def get_tracker_chart_data_web(tracker_id):
    """
    Get tracker chart data for the web interface.

    This endpoint provides chart data for authenticated users, ensuring
    they can only access their own tracker data.

    Args:
        tracker_id: ID of the tracker to get chart data for

    Returns:
        JSON response with tracker values for chart display

    Validates: Requirements 6.3, 6.4, 6.5
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for ownership verification
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return jsonify({"error": "Unable to access user data"}), 500

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Check if tracker exists and belongs to user
            from trackers.db.trackerdb import get_user_tracker

            tracker = get_user_tracker(db, tracker_id, database_user.id)
            if not tracker:
                return jsonify({"error": "Tracker not found or access denied"}), 404

            # Get tracker values for chart (last 30 values)
            tracker_values = get_tracker_values(db, tracker_id)[:30]

            # Format values for chart
            chart_values = []
            for value in tracker_values:
                chart_values.append(
                    {
                        "date": value.date.isoformat(),
                        "value": value.value,
                        "created_at": value.created_at.isoformat()
                        if value.created_at
                        else None,
                    }
                )

            return jsonify(
                {
                    "success": True,
                    "tracker": {
                        "id": tracker.id,
                        "name": tracker.name,
                        "description": tracker.description,
                        "user_id": tracker.user_id,
                    },
                    "values": chart_values,
                }
            ), 200

        except Exception as e:
            error_msg = f"Failed to fetch chart data: {str(e)}"
            return jsonify({"error": error_msg}), 500
        finally:
            db.close()

    except Exception as e:
        error_msg = f"Request processing error: {str(e)}"
        return jsonify({"error": error_msg}), 500


@web_bp.route("/systems")
@require_auth(allow_api_key=False, allow_google_oauth=True, redirect_to_login=True)
@admin_required
def systems_page():
    """
    Systems administration page - requires admin authorization.

    Shows administrative tools and system monitoring for admin users only.
    Admin users are configured via the ADMIN_USERS environment variable.
    """
    from flask import render_template_string

    from trackers.auth.context import get_current_user, is_authenticated
    from trackers.db.database import get_db_session
    from trackers.services.stats_service import StatsService

    # Get authentication context
    current_user = get_current_user()
    authenticated = is_authenticated()

    # Get admin status information
    admin_status = get_admin_status_info()

    # Get system statistics
    try:
        with get_db_session() as db:
            stats_service = StatsService(db)
            system_stats = stats_service.get_quick_stats()
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        system_stats = {
            "total_users": 0,
            "google_users": 0,
            "email_users": 0,
            "total_trackers": 0,
        }

    # Show systems administration page for admin users
    template = """
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Systems Administration - Tracker Application</title>
        <link href="{{ url_for('static', filename='css/dist/output.css') }}" rel="stylesheet">
        <style>
            body { font-family: system-ui, -apple-system, sans-serif; }
            .container { max-width: 1000px; margin: 0 auto; padding: 2rem; }
            .card { background: #1f2937; border-radius: 0.5rem; padding: 1.5rem; margin: 1rem 0; border: 1px solid #374151; }
            .btn { display: inline-block; background: #3b82f6; color: white; padding: 0.75rem 1.5rem; 
                   border-radius: 0.375rem; text-decoration: none; margin: 0.5rem 0.5rem 0.5rem 0; 
                   transition: background-color 0.2s; font-weight: 500; }
            .btn:hover { background: #2563eb; }
            .btn-secondary { background: #6b7280; }
            .btn-secondary:hover { background: #4b5563; }
            .btn-success { background: #059669; }
            .btn-success:hover { background: #047857; }
            .btn-warning { background: #d97706; }
            .btn-warning:hover { background: #b45309; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
            .user-info { background: #065f46; border: 1px solid #059669; }
            .admin-info { background: #7c2d12; border: 1px solid #ea580c; }
        </style>
    </head>
    <body class="bg-gray-900 text-white">
        <div class="container">
            <!-- Header with user info -->
            <div class="flex justify-between items-center mb-8">
                <div>
                    <h1 class="text-4xl font-bold">Systems Administration</h1>
                    <p class="text-gray-400 mt-2">Administrative tools and system monitoring</p>
                </div>
                <div class="text-right">
                    <a href="/web/" class="btn btn-success">← Back to Dashboard</a>
                </div>
            </div>
            
            {% if current_user %}
            <div class="card user-info mb-6">
                <h2 class="text-xl font-semibold mb-2 text-green-300">Authenticated User</h2>
                <p class="text-green-100"><strong>Name:</strong> {{ current_user.name or 'N/A' }}</p>
                <p class="text-green-100"><strong>Email:</strong> {{ current_user.email or 'N/A' }}</p>
                {% if current_user.google_id %}
                <p class="text-green-100"><strong>Google ID:</strong> {{ current_user.google_id }}</p>
                {% endif %}
            </div>
            {% endif %}
            
            <!-- Admin Status Information -->
            <div class="card admin-info mb-6">
                <h2 class="text-xl font-semibold mb-2 text-orange-300">Admin Authorization Status</h2>
                <p class="text-orange-100"><strong>Admin System Enabled:</strong> {{ 'Yes' if admin_status.admin_system_enabled else 'No' }}</p>
                <p class="text-orange-100"><strong>Admin Users Configured:</strong> {{ admin_status.admin_users_configured }}</p>
                <p class="text-orange-100"><strong>Current User Is Admin:</strong> {{ 'Yes' if admin_status.current_user_is_admin else 'No' }}</p>
                {% if admin_status.current_user_email %}
                <p class="text-orange-100"><strong>Current User Email:</strong> {{ admin_status.current_user_email }}</p>
                {% endif %}
            </div>
            
            <!-- System Statistics -->
            <div class="card mb-6" style="background: #1e293b; border: 1px solid #475569;">
                <h2 class="text-xl font-semibold mb-4 text-slate-300">📊 System Statistics</h2>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div class="text-center">
                        <div class="text-2xl font-bold text-blue-400">{{ system_stats.total_users }}</div>
                        <div class="text-sm text-gray-400">Total Users</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-green-400">{{ system_stats.google_users }}</div>
                        <div class="text-sm text-gray-400">Google Users</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-purple-400">{{ system_stats.email_users }}</div>
                        <div class="text-sm text-gray-400">Email Users</div>
                    </div>
                    <div class="text-center">
                        <div class="text-2xl font-bold text-yellow-400">{{ system_stats.total_trackers }}</div>
                        <div class="text-sm text-gray-400">Total Trackers</div>
                    </div>
                </div>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-blue-300">API Endpoints</h2>
                    <p class="text-gray-300 mb-4">
                        Access the REST API for programmatic integration. All API endpoints require authentication.
                    </p>
                    <a href="/api/trackers" class="btn btn-secondary">Trackers API</a>
                    <a href="/api/tracker-values" class="btn btn-secondary">Values API</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-green-300">Health Monitoring</h2>
                    <p class="text-gray-300 mb-4">
                        Monitor application health, database status, and system performance.
                    </p>
                    <a href="/health" class="btn btn-success">Basic Health</a>
                    <a href="/health/detailed" class="btn btn-success">Detailed Health</a>
                    <a href="/health/ready" class="btn btn-success">Readiness Check</a>
                    <a href="/health/live" class="btn btn-success">Liveness Check</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-yellow-300">Database Management</h2>
                    <p class="text-gray-300 mb-4">
                        Database migration status, schema information, and maintenance tools.
                    </p>
                    <a href="/health/migration" class="btn btn-warning">Migration Status</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-purple-300">Authentication Testing</h2>
                    <p class="text-gray-300 mb-4">
                        Test different authentication methods and view authentication context.
                    </p>
                    <a href="/web/auth-demo" class="btn" style="background: #7c3aed;">Unified Auth Demo</a>
                    <a href="/web/api-key-only-demo" class="btn" style="background: #7c3aed;">API Key Only</a>
                    <a href="/web/oauth-only-demo" class="btn" style="background: #7c3aed;">OAuth Only</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-red-300">Development Tools</h2>
                    <p class="text-gray-300 mb-4">
                        Development and testing utilities for debugging and validation.
                    </p>
                    <a href="/web/test" class="btn" style="background: #dc2626;">UI Test Page</a>
                    <a href="/static/test-danish-formatting.html" class="btn" style="background: #dc2626;">Danish Format Test</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-gray-300">System Information</h2>
                    <p class="text-gray-300 mb-4">
                        Application version, configuration, and runtime information.
                    </p>
                    <div class="text-sm text-gray-400 space-y-1">
                        <p><strong>Framework:</strong> Flask with TailwindCSS</p>
                        <p><strong>Database:</strong> PostgreSQL with SQLAlchemy</p>
                        <p><strong>Authentication:</strong> API Key + Google OAuth</p>
                        <p><strong>Deployment:</strong> Clever Cloud Platform</p>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-8 text-gray-500">
                <p>Systems Administration Panel - Admin Access Only</p>
            </div>
        </div>
    </body>
    </html>
    """

    return render_template_string(
        template,
        current_user=current_user,
        is_authenticated=authenticated,
        admin_status=admin_status,
        system_stats=system_stats,
    )


@web_bp.route("/learn-more")
def learn_more_page():
    """
    Public landing page explaining the tracker service.

    Shows information about the tracker service and login options for unauthenticated users.
    This page is publicly accessible and provides an overview of the application features.
    """
    from flask import render_template_string

    template = """
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>About Trackers - Personal Progress Tracking</title>
        <link href="{{ url_for('static', filename='css/dist/output.css') }}" rel="stylesheet">
        <style>
            body { font-family: system-ui, -apple-system, sans-serif; }
            .container { max-width: 1000px; margin: 0 auto; padding: 2rem; }
            .card { background: #1f2937; border-radius: 0.5rem; padding: 1.5rem; margin: 1rem 0; border: 1px solid #374151; }
            .btn { display: inline-flex; align-items: center; background: #3b82f6; color: white; padding: 0.75rem 1.5rem; 
                   border-radius: 0.375rem; text-decoration: none; margin: 0.5rem 0.5rem 0.5rem 0; 
                   transition: background-color 0.2s; font-weight: 500; }
            .btn:hover { background: #2563eb; }
            .btn-success { background: #059669; }
            .btn-success:hover { background: #047857; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
            .hero { background: linear-gradient(135deg, #1e3a8a 0%, #3730a3 100%); }
        </style>
    </head>
    <body class="bg-gray-900 text-white">
        <div class="container">
            <!-- Hero Section -->
            <div class="hero rounded-xl p-8 mb-8 text-center">
                <h1 class="text-4xl font-bold mb-4">Welcome to Trackers</h1>
                <p class="text-xl text-blue-100 mb-6 max-w-2xl mx-auto">
                    A simple and powerful personal tracking application to help you monitor your habits, 
                    track your progress, and achieve your goals. Sign in with Google or create an account with email and password.
                </p>
                <div class="space-y-3 sm:space-y-0 sm:space-x-4 sm:flex sm:justify-center">
                    <a href="/auth/login" 
                       class="btn btn-success inline-flex items-center space-x-2">
                        <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                        </svg>
                        <span>Sign In</span>
                    </a>
                    <a href="/web/" class="btn">View Dashboard</a>
                </div>
            </div>
            
            <!-- Features Grid -->
            <div class="grid mb-8">
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-blue-300">🎯 Easy Habit Tracking</h2>
                    <p class="text-gray-300 mb-4">
                        Create custom trackers for any habit or metric you want to monitor. Whether it's daily steps, 
                        water intake, reading time, or workout sessions - track anything that matters to you.
                    </p>
                    <ul class="text-gray-400 text-sm space-y-1">
                        <li>• Custom tracker names and descriptions</li>
                        <li>• Flexible value entry with date selection</li>
                        <li>• Support for any unit of measurement</li>
                    </ul>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-green-300">📈 Visual Progress</h2>
                    <p class="text-gray-300 mb-4">
                        See your progress at a glance with beautiful charts and trend visualizations. 
                    </p>
                    <ul class="text-gray-400 text-sm space-y-1">
                        <li>• Interactive charts and graphs</li>
                        <li>• Daily and total progress indicators</li>
                        <li>• Danish number formatting support</li>
                    </ul>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4 text-purple-300">🔒 Secure & Private</h2>
                    <p class="text-gray-300 mb-4">
                        Your data is secure and private. Sign in with your Google account or create an account with email and password for easy access. 
                        Your tracking data is only visible to you.
                    </p>
                    <ul class="text-gray-400 text-sm space-y-1">
                        <li>• Google OAuth and email/password authentication</li>
                        <li>• Personal data isolation</li>
                        <li>• Secure cloud storage</li>
                    </ul>
                </div>
            </div>
            
            <!-- Getting Started -->
            <div class="card text-center">
                <h2 class="text-2xl font-semibold mb-4 text-yellow-300">🚀 Get Started Today</h2>
                <p class="text-gray-300 mb-6 max-w-2xl mx-auto">
                    Create an account with email and password or sign in with your Google account to start tracking immediately. 
                    No complex setup, no subscription fees - just simple, effective progress tracking.
                </p>
                <a href="/auth/login" 
                   class="btn btn-success inline-flex items-center space-x-2 text-lg px-8 py-4">
                    <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                    <span>Start Tracking Now</span>
                </a>
            </div>
            
            <div class="text-center mt-8 text-gray-500">
                <p>Simple. Secure. Effective.</p>
            </div>
        </div>
    </body>
    </html>
    """
    return render_template_string(template)


@web_bp.route("/test")
@optional_auth()
def test_page():
    """
    Test page for verifying TailwindCSS and Flowbite integration.

    This route displays a test page with various UI components to ensure
    that TailwindCSS, Flowbite, and custom styles are working correctly.
    Now includes authentication context demonstration.
    """
    # Get authentication context for demonstration
    current_user = get_current_user()
    authenticated = is_authenticated()

    return render_template(
        "test.html", current_user=current_user, is_authenticated=authenticated
    )


@web_bp.route("/auth-demo")
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=True)
def auth_demo():
    """
    Demonstration route showing unified authentication in action.

    This route requires authentication via either API key or Google OAuth
    and displays the current authentication context.

    Returns:
        JSON response with authentication context information
    """
    from trackers.auth.decorators import get_auth_context

    auth_context = get_auth_context()
    current_user = get_current_user()

    return jsonify(
        {
            "message": "Authentication successful!",
            "auth_context": auth_context.to_dict(),
            "user_info": {
                "email": current_user.email if current_user else None,
                "name": current_user.name if current_user else None,
                "google_id": current_user.google_id if current_user else None,
            }
            if current_user
            else None,
            "demonstration": "This route accepts both API key and Google OAuth authentication",
        }
    )


@web_bp.route("/api-key-only-demo")
@require_auth(allow_api_key=True, allow_google_oauth=False, redirect_to_login=False)
def api_key_only_demo():
    """
    Demonstration route that only accepts API key authentication.

    Returns:
        JSON response confirming API key authentication
    """
    from trackers.auth.decorators import get_auth_context

    auth_context = get_auth_context()

    return jsonify(
        {
            "message": "API key authentication successful!",
            "auth_method": auth_context.auth_method,
            "api_key_valid": auth_context.api_key_valid,
            "demonstration": "This route only accepts API key authentication",
        }
    )


@web_bp.route("/oauth-only-demo")
@require_auth(allow_api_key=False, allow_google_oauth=True, redirect_to_login=True)
def oauth_only_demo():
    """
    Demonstration route that only accepts Google OAuth authentication.

    Returns:
        JSON response with Google OAuth user information
    """
    from trackers.auth.decorators import get_auth_context

    auth_context = get_auth_context()
    current_user = get_current_user()

    return jsonify(
        {
            "message": "Google OAuth authentication successful!",
            "auth_method": auth_context.auth_method,
            "user": {
                "email": current_user.email,
                "name": current_user.name,
                "google_id": current_user.google_id,
                "picture_url": current_user.picture_url,
                "verified_email": current_user.verified_email,
            },
            "demonstration": "This route only accepts Google OAuth authentication",
        }
    )


@web_bp.route("/jobs")
@require_auth(
    allow_api_key=True,  # Temporarily allow API key for testing
    allow_google_oauth=True,
    allow_email_password=True,
    redirect_to_login=True,
)
def jobs_dashboard():
    """
    Job management dashboard view for the web interface.

    Fetches user's automated jobs and displays them in a management interface
    with options to create, edit, test, and monitor job execution.

    Returns:
        Rendered jobs template with user's job data

    Requirements: 1.1, 1.2, 1.3, 1.4, 7.1, 7.2
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            # Only create database users for authenticated users
            if not database_user:
                # Check if we have authenticated user info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return render_template(
                            "jobs.html",
                            jobs=[],
                            error="Unable to access user data",
                        )

            # Fetch user's jobs
            jobs = []
            if database_user:
                from trackers.services.job_service import JobService

                # Get job scheduler from app context
                scheduler = getattr(current_app, "job_scheduler", None)
                job_service = JobService(db, scheduler)

                try:
                    jobs = job_service.get_user_jobs(database_user.id)
                    print(f"DEBUG: Found {len(jobs)} jobs for user {database_user.id}")
                    for job in jobs:
                        print(
                            f"DEBUG: Job {job.id}: {job.name} (active: {job.is_active})"
                        )
                except Exception as e:
                    print(f"Error fetching jobs: {e}")
                    jobs = []
            else:
                print("DEBUG: No database_user found")

            # Format jobs for display
            display_jobs = []
            for job in jobs:
                display_jobs.append(
                    {
                        "id": job.id,
                        "name": job.name,
                        "job_type": job.job_type,
                        "tracker_id": job.tracker_id,
                        "cron_schedule": job.cron_schedule,
                        "is_active": job.is_active,
                        "created_at": job.created_at,
                        "updated_at": job.updated_at,
                        "last_run_at": job.last_run_at,
                        "last_success_at": job.last_success_at,
                        "failure_count": job.failure_count,
                        "last_error": job.last_error,
                    }
                )

            print(f"DEBUG: Passing {len(display_jobs)} display_jobs to template")

            return render_template(
                "jobs.html",
                jobs=display_jobs,
                database_user=database_user,
            )

        except Exception as e:
            # Log error and show empty jobs dashboard
            print(f"Error fetching job data: {e}")
            return render_template(
                "jobs.html",
                jobs=[],
                error="Unable to load job data",
            )
        finally:
            db.close()

    except Exception as e:
        # Fallback to empty jobs page
        print(f"Jobs dashboard error: {e}")
        return render_template("jobs.html", jobs=[], error="Dashboard error")


@web_bp.route("/jobs/data")
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def jobs_data():
    """
    Get jobs data as JSON for AJAX updates.

    Returns:
        JSON response with user's job data

    Requirements: 1.1, 7.1
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Fetch user's jobs
            from trackers.services.job_service import JobService

            # Get job scheduler from app context
            scheduler = getattr(current_app, "job_scheduler", None)
            job_service = JobService(db, scheduler)

            jobs = job_service.get_user_jobs(database_user.id)

            # Format jobs for JSON response
            jobs_data = []
            for job in jobs:
                jobs_data.append(
                    {
                        "id": job.id,
                        "name": job.name,
                        "job_type": job.job_type,
                        "tracker_id": job.tracker_id,
                        "cron_schedule": job.cron_schedule,
                        "is_active": job.is_active,
                        "created_at": job.created_at.isoformat()
                        if job.created_at
                        else None,
                        "updated_at": job.updated_at.isoformat()
                        if job.updated_at
                        else None,
                        "last_run_at": job.last_run_at.isoformat()
                        if job.last_run_at
                        else None,
                        "last_success_at": job.last_success_at.isoformat()
                        if job.last_success_at
                        else None,
                        "failure_count": job.failure_count,
                        "last_error": job.last_error,
                    }
                )

            return jsonify(
                {
                    "jobs": jobs_data,
                    "total": len(jobs_data),
                    "active": len([j for j in jobs_data if j["is_active"]]),
                }
            ), 200

        finally:
            db.close()

    except Exception as e:
        print(f"Error fetching jobs data: {e}")
        return jsonify({"error": "Failed to fetch jobs data"}), 500


@web_bp.route("/trackers/data")
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def trackers_data():
    """
    Get user's trackers data as JSON for web interface AJAX calls.

    This endpoint uses session-based authentication (same as other web routes)
    and is specifically designed for the web interface to load tracker data
    for forms and dropdowns.

    Returns:
        JSON response with user's tracker data

    Requirements: 6.1, 6.5
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = None

            # Get authentication context to determine auth method
            from trackers.auth.decorators import get_auth_context

            auth_context = get_auth_context()

            # Handle different authentication methods
            if auth_context.is_authenticated and auth_context.user_info:
                # User is authenticated via Google OAuth or email/password
                try:
                    if auth_context.user_info.google_id:
                        # Google OAuth user
                        database_user = user_service.get_user_by_google_id(
                            auth_context.user_info.google_id
                        )
                        if not database_user:
                            # Create user if doesn't exist
                            database_user = user_service.create_or_update_user(
                                auth_context.user_info
                            )
                            db.commit()
                    else:
                        # Email/password user - try session lookup
                        database_user = user_service.get_current_user_from_session()
                        if not database_user:
                            return jsonify({"error": "Session user not found"}), 401
                except Exception as user_error:
                    print(f"User lookup failed: {user_error}")
                    import traceback

                    traceback.print_exc()
                    database_user = None
            elif auth_context.api_key_valid:
                # API key authentication - use default system user
                try:
                    database_user = user_service.get_or_create_default_system_user()
                    if database_user:
                        db.commit()
                except Exception as default_error:
                    print(f"Default user creation failed: {default_error}")
                    database_user = None
            else:
                # This should not happen if @require_auth is working correctly
                return jsonify({"error": "Authentication required"}), 401

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Fetch user's trackers
            trackers = get_all_trackers(db, user_id=database_user.id)

            # Format trackers for JSON response
            trackers_data = []
            for tracker in trackers:
                # Get job information for this tracker
                try:
                    from trackers.models.job_model import JobModel

                    jobs = (
                        db.query(JobModel)
                        .filter(
                            JobModel.tracker_id == tracker.id,
                            JobModel.user_id == database_user.id,
                        )
                        .all()
                    )

                    # Calculate job statistics
                    job_count = len(jobs)
                    active_jobs = len([job for job in jobs if job.is_active])
                    has_jobs = job_count > 0

                except Exception as job_error:
                    # If there's an error with job queries, provide default values
                    print(
                        f"Warning: Error querying jobs for tracker {tracker.id}: {job_error}"
                    )
                    job_count = 0
                    active_jobs = 0
                    has_jobs = False

                trackers_data.append(
                    {
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
                        "job_count": job_count,
                        "active_jobs": active_jobs,
                        "has_jobs": has_jobs,
                    }
                )

            return jsonify(
                {
                    "trackers": trackers_data,
                    "total": len(trackers_data),
                }
            ), 200

        finally:
            db.close()

    except Exception as e:
        print(f"Error fetching trackers data: {e}")
        import traceback

        traceback.print_exc()

        # Try to return a basic response without job information
        try:
            db = db_module.SessionLocal()
            try:
                from trackers.services.user_service import UserService

                user_service = UserService(db)
                database_user = user_service.get_current_user_from_session()

                if database_user:
                    trackers = get_all_trackers(db, user_id=database_user.id)
                    trackers_data = []
                    for tracker in trackers:
                        trackers_data.append(
                            {
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
                                "job_count": 0,
                                "active_jobs": 0,
                                "has_jobs": False,
                            }
                        )

                    return jsonify(
                        {
                            "trackers": trackers_data,
                            "total": len(trackers_data),
                            "warning": "Job information unavailable",
                        }
                    ), 200
            finally:
                db.close()
        except Exception as fallback_error:
            print(f"Fallback also failed: {fallback_error}")

        return jsonify({"error": "Failed to fetch trackers data"}), 500


@web_bp.route("/tracker/<int:tracker_id>", methods=["PUT"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def update_tracker_web(tracker_id):
    """
    Update tracker via web interface.

    Args:
        tracker_id: ID of the tracker to update

    Request Body:
        name: New tracker name (required)
        description: New tracker description (optional)

    Returns:
        JSON response with updated tracker data

    Requirements: 6.1, 6.5
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for ownership verification
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return jsonify({"error": "Unable to access user data"}), 500

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Verify user owns the tracker
            from trackers.db.trackerdb import get_user_tracker

            tracker = get_user_tracker(db, tracker_id, database_user.id)
            if not tracker:
                return jsonify({"error": "Tracker not found or access denied"}), 404

            # Get request data
            data = request.get_json()
            if not data:
                return jsonify({"error": "Request body is required"}), 400

            # Validate required fields
            name = data.get("name", "").strip()
            if not name:
                return jsonify({"error": "Tracker name is required"}), 400

            description = data.get("description", "").strip()

            # Update tracker
            tracker.name = name
            tracker.description = description if description else None

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
                    },
                }
            ), 200

        except IntegrityError:
            db.rollback()
            return jsonify(
                {"error": f"Tracker with name '{name}' already exists for your account"}
            ), 409

        except Exception as e:
            db.rollback()
            print(f"Error updating tracker: {e}")
            return jsonify({"error": "Failed to update tracker"}), 500

        finally:
            db.close()

    except Exception as e:
        print(f"Request processing error: {e}")
        return jsonify({"error": "Request processing error"}), 500


@web_bp.route("/tracker/<int:tracker_id>", methods=["DELETE"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def delete_tracker_web(tracker_id):
    """
    Delete tracker via web interface.

    Args:
        tracker_id: ID of the tracker to delete

    Returns:
        JSON response confirming deletion

    Requirements: 6.1, 6.5
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for ownership verification
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return jsonify({"error": "Unable to access user data"}), 500

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Verify user owns the tracker
            from trackers.db.trackerdb import get_user_tracker

            tracker = get_user_tracker(db, tracker_id, database_user.id)
            if not tracker:
                return jsonify({"error": "Tracker not found or access denied"}), 404

            # Store tracker name for response
            tracker_name = tracker.name

            # Delete associated tracker values first
            from trackers.models.tracker_value_model import TrackerValueModel

            db.query(TrackerValueModel).filter(
                TrackerValueModel.tracker_id == tracker_id
            ).delete()

            # Delete associated jobs
            from trackers.models.job_model import JobModel

            db.query(JobModel).filter(
                JobModel.tracker_id == tracker_id, JobModel.user_id == database_user.id
            ).delete()

            # Delete the tracker
            db.delete(tracker)
            db.commit()

            # Return success response
            return jsonify(
                {
                    "message": f"Tracker '{tracker_name}' deleted successfully",
                    "tracker_id": tracker_id,
                }
            ), 200

        except Exception as e:
            db.rollback()
            print(f"Error deleting tracker: {e}")
            return jsonify({"error": "Failed to delete tracker"}), 500

        finally:
            db.close()

    except Exception as e:
        print(f"Request processing error: {e}")
        return jsonify({"error": "Request processing error"}), 500


@web_bp.route("/trackers/<int:tracker_id>/jobs")
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def tracker_jobs(tracker_id):
    """
    Get jobs associated with a specific tracker.

    Args:
        tracker_id: ID of the tracker to get jobs for

    Returns:
        JSON response with jobs for the tracker

    Requirements: 6.1, 6.5
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return jsonify({"error": "Unable to access user data"}), 500

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Verify user owns the tracker
            from trackers.db.trackerdb import get_user_tracker

            tracker = get_user_tracker(db, tracker_id, database_user.id)
            if not tracker:
                return jsonify({"error": "Tracker not found or access denied"}), 404

            # Get jobs for this tracker
            from trackers.models.job_model import JobModel

            jobs = (
                db.query(JobModel)
                .filter(
                    JobModel.tracker_id == tracker_id,
                    JobModel.user_id == database_user.id,
                )
                .order_by(JobModel.created_at.desc())
                .all()
            )

            # Format jobs for JSON response
            jobs_data = []
            for job in jobs:
                jobs_data.append(
                    {
                        "id": job.id,
                        "name": job.name,
                        "job_type": job.job_type,
                        "is_active": job.is_active,
                        "cron_schedule": job.cron_schedule,
                        "created_at": job.created_at.isoformat()
                        if job.created_at
                        else None,
                        "updated_at": job.updated_at.isoformat()
                        if job.updated_at
                        else None,
                        "last_run_at": job.last_run_at.isoformat()
                        if job.last_run_at
                        else None,
                        "last_success_at": job.last_success_at.isoformat()
                        if job.last_success_at
                        else None,
                        "failure_count": job.failure_count,
                    }
                )

            return jsonify(
                {
                    "tracker": {
                        "id": tracker.id,
                        "name": tracker.name,
                        "description": tracker.description,
                    },
                    "jobs": jobs_data,
                    "total": len(jobs_data),
                }
            ), 200

        finally:
            db.close()

    except Exception as e:
        print(f"Error fetching tracker jobs: {e}")
        return jsonify({"error": "Failed to fetch tracker jobs"}), 500


@web_bp.route("/jobs/<int:job_id>/tracker")
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def job_tracker(job_id):
    """
    Get tracker information for a specific job.

    Args:
        job_id: ID of the job to get tracker for

    Returns:
        JSON response with tracker information for the job

    Requirements: 6.1, 6.5
    """
    try:
        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user:
                # If no database user found, try to create one from OAuth info
                current_user = get_current_user()
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return jsonify({"error": "Unable to access user data"}), 500

            if not database_user:
                return jsonify({"error": "User authentication required"}), 401

            # Get job and verify user owns it
            from trackers.models.job_model import JobModel

            job = (
                db.query(JobModel)
                .filter(JobModel.id == job_id, JobModel.user_id == database_user.id)
                .first()
            )

            if not job:
                return jsonify({"error": "Job not found or access denied"}), 404

            # Get the associated tracker
            from trackers.db.trackerdb import get_user_tracker

            tracker = get_user_tracker(db, job.tracker_id, database_user.id)
            if not tracker:
                return jsonify({"error": "Associated tracker not found"}), 404

            return jsonify(
                {
                    "job": {
                        "id": job.id,
                        "name": job.name,
                        "job_type": job.job_type,
                    },
                    "tracker": {
                        "id": tracker.id,
                        "name": tracker.name,
                        "description": tracker.description,
                    },
                }
            ), 200

        finally:
            db.close()

    except Exception as e:
        print(f"Error fetching job tracker: {e}")
        return jsonify({"error": "Failed to fetch job tracker"}), 500


@web_bp.route("/jobs/validate/cron", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def validate_cron_web():
    """
    Validate cron expression for web interface.

    This endpoint uses session-based authentication and is specifically designed
    for the web interface job creation form to validate cron expressions.

    Expected JSON payload:
    {
        "cron_expression": "0 9 * * *"
    }

    Returns:
        JSON response with validation results

    Requirements: 5.1, 5.4
    """
    try:
        data = request.get_json()
        if not data or "cron_expression" not in data:
            return jsonify(
                {
                    "valid": False,
                    "error": "Missing 'cron_expression' in request body",
                }
            ), 400

        from trackers.services.job_providers.job_testing_service import (
            JobTestingService,
        )

        testing_service = JobTestingService()
        validation_result = testing_service.validate_cron_expression(
            data["cron_expression"]
        )

        # Format response for web interface compatibility
        response = {
            "valid": validation_result.get("is_valid", False),
            "description": validation_result.get("description", ""),
            "error": "; ".join(validation_result.get("errors", []))
            if validation_result.get("errors")
            else None,
        }

        return jsonify(response), 200

    except Exception as e:
        print(f"Error validating cron expression: {e}")
        return jsonify(
            {
                "valid": False,
                "error": "Failed to validate cron expression",
            }
        ), 500


@web_bp.route("/jobs/test/config", methods=["POST"])
@require_auth(allow_api_key=True, allow_google_oauth=True, redirect_to_login=False)
def test_job_configuration_web():
    """
    Test job configuration for web interface.

    This endpoint uses session-based authentication and is specifically designed
    for the web interface job creation form to test job configurations.

    Expected JSON payload:
    {
        "job_type": "stock",
        "config": {...},
        "cron_schedule": "0 9 * * *",
        "use_mocks": true
    }

    Returns:
        JSON response with test results

    Requirements: 5.1, 5.4, 10.1, 10.2
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify(
                {
                    "overall_valid": False,
                    "config_validation": {
                        "is_valid": False,
                        "errors": ["Missing request body"],
                    },
                    "cron_validation": {"is_valid": False, "errors": []},
                    "execution_test": {
                        "success": False,
                        "error_message": "No data provided",
                    },
                    "recommendations": ["Provide job configuration data"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ), 400

        # Validate required fields
        required_fields = ["job_type", "config", "cron_schedule"]
        missing_fields = [field for field in required_fields if field not in data]

        if missing_fields:
            return jsonify(
                {
                    "overall_valid": False,
                    "config_validation": {
                        "is_valid": False,
                        "errors": [
                            f"Missing required fields: {', '.join(missing_fields)}"
                        ],
                    },
                    "cron_validation": {"is_valid": False, "errors": []},
                    "execution_test": {
                        "success": False,
                        "error_message": "Missing required fields",
                    },
                    "recommendations": ["Provide all required fields"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
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
                "overall_valid": False,
                "config_validation": {
                    "is_valid": False,
                    "errors": [f"Testing error: {str(e)}"],
                },
                "cron_validation": {"is_valid": False, "errors": []},
                "execution_test": {"success": False, "error_message": str(e)},
                "recommendations": ["Fix configuration errors and try again"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ), 500
