"""
Tracker repository operations for database CRUD functionality.
"""

from typing import Optional

from sqlalchemy.orm import Session

from trackers.models.tracker_model import TrackerModel


def create_tracker(
    db: Session, name: str, description: Optional[str] = None
) -> TrackerModel:
    """
    Create a new tracker in the database.

    Args:
        db: Database session
        name: Tracker name (must be unique)
        description: Optional tracker description

    Returns:
        Created TrackerModel instance

    Validates: Requirements 4.1
    """
    tracker = TrackerModel(name=name, description=description)
    db.add(tracker)
    db.flush()  # Flush to get the ID without committing
    db.refresh(tracker)
    return tracker


def get_tracker(db: Session, tracker_id: int) -> Optional[TrackerModel]:
    """
    Retrieve a tracker by its ID.

    Args:
        db: Database session
        tracker_id: ID of the tracker to retrieve

    Returns:
        TrackerModel instance if found, None otherwise

    Validates: Requirements 4.2
    """
    return db.query(TrackerModel).filter(TrackerModel.id == tracker_id).first()


def get_all_trackers(db: Session) -> list[TrackerModel]:
    """
    Retrieve all trackers from the database.

    Args:
        db: Database session

    Returns:
        List of all TrackerModel instances

    Validates: Requirements 4.2
    """
    return db.query(TrackerModel).all()


def delete_tracker(db: Session, tracker_id: int) -> bool:
    """
    Delete a tracker from the database.

    Args:
        db: Database session
        tracker_id: ID of the tracker to delete

    Returns:
        True if tracker was deleted, False if tracker not found

    Validates: Requirements 4.4
    """
    tracker = db.query(TrackerModel).filter(TrackerModel.id == tracker_id).first()
    if tracker:
        db.delete(tracker)
        db.flush()  # Flush to execute delete without committing
        return True
    return False
