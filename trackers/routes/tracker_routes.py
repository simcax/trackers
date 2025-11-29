# Endpoints which handle tracker-related operations

from flask import Blueprint, jsonify, request
from sqlalchemy.exc import IntegrityError

from trackers.db import database as db_module
from trackers.db.trackerdb import create_tracker, get_all_trackers

tracker_bp = Blueprint("tracker", __name__)


@tracker_bp.route("/add_tracker", methods=["POST"])
def add_tracker():
    """
    Create a new tracker in the database.

    Validates: Requirements 5.1, 5.2
    """
    data = request.get_json()
    tracker_name = data.get("name")
    tracker_description = data.get("description")

    if not tracker_name:
        return jsonify({"error": "Tracker name is required"}), 400

    # Get SessionLocal from the module to ensure we use the current (possibly reinitialized) version
    db = db_module.SessionLocal()
    try:
        # Create tracker in database
        tracker = create_tracker(db, name=tracker_name, description=tracker_description)
        db.commit()  # Commit the transaction

        # Return created tracker data
        return jsonify(
            {
                "message": "Tracker added successfully",
                "tracker": {
                    "id": tracker.id,
                    "name": tracker.name,
                    "description": tracker.description,
                },
            }
        ), 201
    except IntegrityError:
        db.rollback()
        return jsonify(
            {"error": f"Tracker with name '{tracker_name}' already exists"}
        ), 409
    except Exception as e:
        db.rollback()
        return jsonify({"error": f"Failed to create tracker: {str(e)}"}), 500
    finally:
        db.close()


@tracker_bp.route("/trackers", methods=["GET"])
def get_trackers():
    """
    Retrieve all trackers from the database.

    Validates: Requirements 5.3
    """
    # Get SessionLocal from the module to ensure we use the current (possibly reinitialized) version
    db = db_module.SessionLocal()
    try:
        # Query all trackers from database
        trackers = get_all_trackers(db)

        # Convert to JSON array
        trackers_data = [
            {
                "id": tracker.id,
                "name": tracker.name,
                "description": tracker.description,
            }
            for tracker in trackers
        ]

        return jsonify({"trackers": trackers_data}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve trackers: {str(e)}"}), 500
    finally:
        db.close()
