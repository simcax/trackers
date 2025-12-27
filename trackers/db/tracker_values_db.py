"""
Tracker values repository operations for database CRUD functionality.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from trackers.models.tracker_value_model import TrackerValueModel


def create_or_update_value(
    db: Session, tracker_id: int, date: str, value: str
) -> TrackerValueModel:
    """
    Create a new tracker value or update existing one for the same tracker/date.

    This implements upsert logic - if a value already exists for the given
    tracker_id and date, it updates the existing record. Otherwise, it creates
    a new one.

    Args:
        db: Database session
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format
        value: Value to store

    Returns:
        TrackerValueModel instance (created or updated)

    Validates: Requirements 1.1, 1.2, 6.4
    """
    # Convert string date to date object
    date_obj = datetime.strptime(date, "%Y-%m-%d").date()

    # Check if value already exists for this tracker and date
    existing_value = (
        db.query(TrackerValueModel)
        .filter(
            TrackerValueModel.tracker_id == tracker_id,
            TrackerValueModel.date == date_obj,
        )
        .first()
    )

    if existing_value:
        # Update existing value
        existing_value.value = value
        existing_value.updated_at = datetime.utcnow()
        db.flush()
        db.refresh(existing_value)
        return existing_value
    else:
        # Create new value
        tracker_value = TrackerValueModel(
            tracker_id=tracker_id, date=date_obj, value=value
        )
        db.add(tracker_value)
        db.flush()
        db.refresh(tracker_value)
        return tracker_value


def get_value(db: Session, tracker_id: int, date: str) -> Optional[TrackerValueModel]:
    """
    Get a specific tracker value by tracker ID and date.

    Args:
        db: Database session
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format

    Returns:
        TrackerValueModel instance if found, None otherwise

    Validates: Requirements 3.1
    """
    # Convert string date to date object
    date_obj = datetime.strptime(date, "%Y-%m-%d").date()

    return (
        db.query(TrackerValueModel)
        .filter(
            TrackerValueModel.tracker_id == tracker_id,
            TrackerValueModel.date == date_obj,
        )
        .first()
    )


def get_tracker_values(
    db: Session,
    tracker_id: int,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> List[TrackerValueModel]:
    """
    Get all values for a tracker, optionally filtered by date range.

    Values are returned ordered by date in descending order (newest first).

    Args:
        db: Database session
        tracker_id: ID of the tracker
        start_date: Optional start date in YYYY-MM-DD format (inclusive)
        end_date: Optional end date in YYYY-MM-DD format (inclusive)

    Returns:
        List of TrackerValueModel instances ordered by date descending

    Validates: Requirements 3.3, 3.5
    """
    query = db.query(TrackerValueModel).filter(
        TrackerValueModel.tracker_id == tracker_id
    )

    # Apply date range filters if provided
    if start_date:
        start_date_obj = datetime.strptime(start_date, "%Y-%m-%d").date()
        query = query.filter(TrackerValueModel.date >= start_date_obj)

    if end_date:
        end_date_obj = datetime.strptime(end_date, "%Y-%m-%d").date()
        query = query.filter(TrackerValueModel.date <= end_date_obj)

    # Order by date descending (newest first)
    return query.order_by(TrackerValueModel.date.desc()).all()


def update_value(
    db: Session, tracker_id: int, date: str, new_value: str
) -> Optional[TrackerValueModel]:
    """
    Update an existing tracker value.

    Args:
        db: Database session
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format
        new_value: New value to set

    Returns:
        Updated TrackerValueModel instance if found, None if not found

    Validates: Requirements 4.1
    """
    # Convert string date to date object
    date_obj = datetime.strptime(date, "%Y-%m-%d").date()

    tracker_value = (
        db.query(TrackerValueModel)
        .filter(
            TrackerValueModel.tracker_id == tracker_id,
            TrackerValueModel.date == date_obj,
        )
        .first()
    )

    if tracker_value:
        tracker_value.value = new_value
        tracker_value.updated_at = datetime.utcnow()
        db.flush()
        db.refresh(tracker_value)
        return tracker_value

    return None


def delete_value(db: Session, tracker_id: int, date: str) -> bool:
    """
    Delete a specific tracker value.

    Args:
        db: Database session
        tracker_id: ID of the tracker
        date: Date in YYYY-MM-DD format

    Returns:
        True if value was deleted, False if value not found

    Validates: Requirements 5.1
    """
    # Convert string date to date object
    date_obj = datetime.strptime(date, "%Y-%m-%d").date()

    tracker_value = (
        db.query(TrackerValueModel)
        .filter(
            TrackerValueModel.tracker_id == tracker_id,
            TrackerValueModel.date == date_obj,
        )
        .first()
    )

    if tracker_value:
        db.delete(tracker_value)
        db.flush()
        return True

    return False


def delete_all_tracker_values(db: Session, tracker_id: int) -> int:
    """
    Delete all values for a specific tracker.

    Args:
        db: Database session
        tracker_id: ID of the tracker

    Returns:
        Number of values deleted

    Validates: Requirements 5.4
    """
    deleted_count = (
        db.query(TrackerValueModel)
        .filter(TrackerValueModel.tracker_id == tracker_id)
        .delete()
    )

    db.flush()
    return deleted_count
