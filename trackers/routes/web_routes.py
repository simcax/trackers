"""
Web routes for the Tracker Web UI.

This module provides Flask routes for the web interface, including:
- Dashboard view for displaying trackers
- Tracker creation form handling
- Adding values to existing trackers
- Integrated authentication supporting both API key and Google OAuth

Validates: Requirements 5.1, 5.2, 5.3, 5.4
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError

from trackers.auth.admin import get_admin_status_info
from trackers.auth.admin_decorators import admin_required
from trackers.auth.context import get_current_user, is_authenticated
from trackers.auth.decorators import optional_auth, require_auth
from trackers.db import database as db_module
from trackers.db.tracker_values_db import get_tracker_values
from trackers.db.trackerdb import create_tracker, get_all_trackers

# Create web blueprint with template and static folder configuration
web_bp = Blueprint(
    "web",
    __name__,
    url_prefix="/web",
    template_folder="../../templates",
    static_folder="../../static",
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
        )


@web_bp.route("/")
@optional_auth()
def dashboard():
    """
    Main dashboard view for the web interface.

    Fetches user's trackers and their recent values, then displays them
    in a card-based layout with dark theme styling. Now requires authentication
    and shows only the authenticated user's trackers.

    Returns:
        Rendered dashboard template with user's tracker data

    Validates: Requirements 6.5, 8.1
    """
    try:
        # Get authentication context
        current_user = get_current_user()
        authenticated = is_authenticated()

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
                if current_user:
                    try:
                        database_user = user_service.create_or_update_user(current_user)
                        db.commit()
                    except Exception as e:
                        print(f"Error creating database user: {e}")
                        db.rollback()
                        return render_template(
                            "dashboard.html",
                            trackers=[],
                            current_user=current_user,
                            is_authenticated=authenticated,
                            error="Unable to access user data",
                        )

            # Fetch user's trackers only
            if database_user:
                trackers = get_all_trackers(db, user_id=database_user.id)
            else:
                trackers = []

            # Format trackers for display with recent values
            display_data = []
            for tracker in trackers:
                # Get recent values for this tracker (last 10 for trend calculation)
                recent_values = get_tracker_values(db, tracker.id)[:10]
                formatted_tracker = format_tracker_for_display(tracker, recent_values)
                display_data.append(formatted_tracker)

            # Pass authentication context and database user to template
            return render_template(
                "dashboard.html",
                trackers=display_data,
                current_user=current_user,
                database_user=database_user,
                is_authenticated=authenticated,
            )

        except Exception as e:
            # Log error and show empty dashboard
            print(f"Error fetching tracker data: {e}")
            return render_template(
                "dashboard.html",
                trackers=[],
                current_user=current_user,
                is_authenticated=authenticated,
                error="Unable to load tracker data",
            )
        finally:
            db.close()

    except Exception as e:
        # Fallback to test page if dashboard fails
        print(f"Dashboard error: {e}")
        return render_template("test.html")


@web_bp.route("/debug")
@optional_auth()
def debug_dashboard():
    """
    Debug route to help diagnose authentication and template issues.
    """
    try:
        # Get authentication context
        current_user = get_current_user()
        authenticated = is_authenticated()

        # Get current database user
        from trackers.services.user_service import UserService

        # Get database session
        db = db_module.SessionLocal()
        try:
            # Get current database user for filtering
            user_service = UserService(db)
            database_user = user_service.get_current_user_from_session()

            if not database_user and current_user:
                try:
                    database_user = user_service.create_or_update_user(current_user)
                    db.commit()
                except Exception as e:
                    print(f"Error creating database user: {e}")
                    db.rollback()

            # Fetch user's trackers only
            if database_user:
                trackers = get_all_trackers(db, user_id=database_user.id)
            else:
                trackers = []

            # Format trackers for display with recent values
            display_data = []
            for tracker in trackers:
                # Get recent values for this tracker (last 10 for trend calculation)
                recent_values = get_tracker_values(db, tracker.id)[:10]
                formatted_tracker = format_tracker_for_display(tracker, recent_values)
                display_data.append(formatted_tracker)

            # Pass authentication context and database user to template
            return render_template(
                "debug_dashboard.html",
                trackers=display_data,
                current_user=current_user,
                database_user=database_user,
                is_authenticated=authenticated,
            )

        finally:
            db.close()

    except Exception as e:
        # Show error information
        return render_template(
            "debug_dashboard.html",
            trackers=[],
            current_user=None,
            database_user=None,
            is_authenticated=False,
            error=str(e),
        )


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

    # Get authentication context
    current_user = get_current_user()
    authenticated = is_authenticated()

    # Get admin status information
    admin_status = get_admin_status_info()

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
            .btn { display: inline-block; background: #3b82f6; color: white; padding: 0.75rem 1.5rem; 
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
                    track your progress, and achieve your goals.
                </p>
                <div class="space-y-3 sm:space-y-0 sm:space-x-4 sm:flex sm:justify-center">
                    <a href="/auth/login" 
                       class="btn btn-success inline-flex items-center space-x-2">
                        <svg class="w-5 h-5" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                        </svg>
                        <span>Sign in with Google</span>
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
                        Your data is secure and private. Sign in with your Google account for easy access, 
                        and rest assured that your tracking data is only visible to you.
                    </p>
                    <ul class="text-gray-400 text-sm space-y-1">
                        <li>• Google OAuth authentication</li>
                        <li>• Personal data isolation</li>
                        <li>• Secure cloud storage</li>
                    </ul>
                </div>
            </div>
            
            <!-- Getting Started -->
            <div class="card text-center">
                <h2 class="text-2xl font-semibold mb-4 text-yellow-300">🚀 Get Started Today</h2>
                <p class="text-gray-300 mb-6 max-w-2xl mx-auto">
                    Anyone with a Google account can sign in and start creating trackers immediately. 
                    No complex setup, no subscription fees - just simple, effective progress tracking.
                </p>
                <a href="/auth/login" 
                   class="btn btn-success inline-flex items-center space-x-2 text-lg px-8 py-4">
                    <svg class="w-6 h-6" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
                        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
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
