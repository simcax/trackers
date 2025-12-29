"""
Web routes for the Tracker Web UI.

This module provides Flask routes for the web interface, including:
- Dashboard view for displaying trackers
- Tracker creation form handling
- Adding values to existing trackers
- Public access without authentication (API routes require authentication)

Validates: Requirements 5.1, 5.2, 5.3, 5.4
"""

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError

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
        recent_value_strings = [str(value.value) for value in recent_values[:5]]
        recent_date_strings = [
            value.date.strftime("%Y-%m-%d") for value in recent_values[:5]
        ]

        # Calculate current value and change
        current_value = recent_value_strings[0] if recent_value_strings else "No data"

        # Simple change calculation (current vs previous)
        change = 0.0
        change_text = "No change"
        if len(recent_value_strings) >= 2:
            try:
                current = float(recent_value_strings[0])
                previous = float(recent_value_strings[1])
                change = current - previous
                if change > 0:
                    change_text = f"+{change:.1f}"
                elif change < 0:
                    change_text = f"{change:.1f}"
                else:
                    change_text = "No change"
            except (ValueError, TypeError):
                change_text = "No change"

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
        )


@web_bp.route("/")
def dashboard():
    """
    Main dashboard view for the web interface.

    Fetches all user trackers and their recent values, then displays them
    in a card-based layout with dark theme styling.

    Returns:
        Rendered dashboard template with tracker data

    Validates: Requirements 5.1, 5.2
    """
    try:
        # Get database session
        db = db_module.SessionLocal()
        try:
            # Fetch all trackers
            trackers = get_all_trackers(db)

            # Format trackers for display with recent values
            display_data = []
            for tracker in trackers:
                # Get recent values for this tracker (last 10 for trend calculation)
                recent_values = get_tracker_values(db, tracker.id)[:10]
                formatted_tracker = format_tracker_for_display(tracker, recent_values)
                display_data.append(formatted_tracker)

            return render_template("dashboard.html", trackers=display_data)

        except Exception as e:
            # Log error and show empty dashboard
            print(f"Error fetching tracker data: {e}")
            return render_template("dashboard.html", trackers=[])
        finally:
            db.close()

    except Exception as e:
        # Fallback to test page if dashboard fails
        print(f"Dashboard error: {e}")
        return render_template("test.html")


@web_bp.route("/tracker/create", methods=["POST"])
def create_tracker_web():
    """
    Handle tracker creation form submission from the web interface.

    Processes form data, validates inputs, and creates a new tracker
    using the existing API infrastructure.

    Request Form Data:
        name: Tracker name (required)
        description: Tracker description (optional)
        unit: Tracker unit (optional, stored in description for now)
        goal: Tracker goal (optional, stored in description for now)
        color: Tracker color theme (optional, not stored yet)

    Returns:
        JSON response for AJAX calls or redirect for form submissions

    Validates: Requirements 5.3, 5.4
    """
    try:
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

        final_description = " | ".join(description_parts) if description_parts else None

        # Create tracker using existing database functions
        db = db_module.SessionLocal()
        try:
            tracker = create_tracker(
                db, name=tracker_name, description=final_description
            )
            db.commit()

            # Return success response
            tracker_data = {
                "id": tracker.id,
                "name": tracker.name,
                "description": tracker.description,
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
            error_msg = f"Tracker with name '{tracker_name}' already exists"
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
def add_tracker_value_web(tracker_id):
    """
    Handle adding values to existing trackers from the web interface.

    Processes form data and creates/updates tracker values using the
    existing API infrastructure.

    Args:
        tracker_id: ID of the tracker to add value to

    Request Form Data:
        date: Date in YYYY-MM-DD format (defaults to today)
        value: Value to add (required)

    Returns:
        JSON response for AJAX calls or redirect for form submissions

    Validates: Requirements 5.3, 5.4
    """
    try:
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

        # Import the tracker value creation function
        from trackers.db.tracker_values_db import create_or_update_value

        # Create/update tracker value using existing database functions
        db = db_module.SessionLocal()
        try:
            # Check if tracker exists
            from trackers.db.trackerdb import get_tracker

            tracker = get_tracker(db, tracker_id)
            if not tracker:
                if request.is_json:
                    return jsonify({"error": "Tracker not found"}), 404
                else:
                    return redirect(url_for("web.dashboard", error="tracker_not_found"))

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


@web_bp.route("/test")
def test_page():
    """
    Test page for verifying TailwindCSS and Flowbite integration.

    This route displays a test page with various UI components to ensure
    that TailwindCSS, Flowbite, and custom styles are working correctly.
    """
    return render_template("test.html")
