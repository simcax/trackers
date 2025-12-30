"""
Tracker repository operations for database CRUD functionality.
"""

from typing import Optional

from sqlalchemy.orm import Session

from trackers.models.tracker_model import TrackerModel


class TrackerDB:
    """
    Repository class for tracker database operations with user filtering.

    This class provides CRUD operations for trackers with automatic user context
    filtering to ensure data isolation between users.

    Requirements: 2.4, 2.5, 6.1, 6.2
    """

    def __init__(self, db_session: Session, user_id: Optional[int] = None):
        """
        Initialize TrackerDB with database session and optional user context.

        Args:
            db_session: SQLAlchemy database session
            user_id: Optional user ID for filtering operations

        Requirements: 2.4, 2.5, 6.1, 6.2
        """
        self.db = db_session
        self.user_id = user_id

    def create_tracker(
        self,
        name: str,
        description: Optional[str] = None,
        user_id: Optional[int] = None,
    ) -> TrackerModel:
        """
        Create a new tracker in the database.

        Args:
            name: Tracker name (must be unique per user)
            description: Optional tracker description
            user_id: ID of the user who owns this tracker (uses instance user_id if not provided)

        Returns:
            Created TrackerModel instance

        Raises:
            ValueError: If no user_id is provided and instance has no user context

        Validates: Requirements 2.1, 2.2, 2.5, 6.2
        """
        # Use provided user_id or fall back to instance user_id
        effective_user_id = user_id or self.user_id

        if effective_user_id is None:
            raise ValueError("User ID is required for tracker creation")

        tracker = TrackerModel(
            name=name, description=description, user_id=effective_user_id
        )
        self.db.add(tracker)
        self.db.flush()  # Flush to get the ID without committing
        self.db.refresh(tracker)
        return tracker

    def get_tracker(self, tracker_id: int) -> Optional[TrackerModel]:
        """
        Retrieve a tracker by its ID, filtered by user context.

        Args:
            tracker_id: ID of the tracker to retrieve

        Returns:
            TrackerModel instance if found and owned by user, None otherwise

        Validates: Requirements 6.1, 6.3
        """
        query = self.db.query(TrackerModel).filter(TrackerModel.id == tracker_id)

        # Apply user filtering if user context is available
        if self.user_id is not None:
            query = query.filter(TrackerModel.user_id == self.user_id)

        return query.first()

    def get_all_trackers(self) -> list[TrackerModel]:
        """
        Retrieve all trackers from the database, filtered by user context.

        Returns:
            List of TrackerModel instances belonging to the user (or all if no user context)

        Validates: Requirements 2.4, 6.1, 6.5
        """
        query = self.db.query(TrackerModel)

        # Apply user filtering if user context is available
        if self.user_id is not None:
            query = query.filter(TrackerModel.user_id == self.user_id)

        return query.all()

    def delete_tracker(self, tracker_id: int) -> bool:
        """
        Delete a tracker from the database, filtered by user context.

        Args:
            tracker_id: ID of the tracker to delete

        Returns:
            True if tracker was deleted, False if tracker not found or not owned by user

        Validates: Requirements 6.3, 6.4
        """
        query = self.db.query(TrackerModel).filter(TrackerModel.id == tracker_id)

        # Apply user filtering if user context is available
        if self.user_id is not None:
            query = query.filter(TrackerModel.user_id == self.user_id)

        tracker = query.first()
        if tracker:
            self.db.delete(tracker)
            self.db.flush()  # Flush to execute delete without committing
            return True
        return False

    def update_tracker(
        self,
        tracker_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[TrackerModel]:
        """
        Update a tracker's information, filtered by user context.

        Args:
            tracker_id: ID of the tracker to update
            name: New tracker name (optional)
            description: New tracker description (optional)

        Returns:
            Updated TrackerModel instance if found and owned by user, None otherwise

        Validates: Requirements 6.3, 6.4
        """
        query = self.db.query(TrackerModel).filter(TrackerModel.id == tracker_id)

        # Apply user filtering if user context is available
        if self.user_id is not None:
            query = query.filter(TrackerModel.user_id == self.user_id)

        tracker = query.first()
        if tracker:
            if name is not None:
                tracker.name = name
            if description is not None:
                tracker.description = description

            self.db.flush()
            self.db.refresh(tracker)
            return tracker

        return None

    def get_tracker_count(self) -> int:
        """
        Get the count of trackers, filtered by user context.

        Returns:
            Number of trackers belonging to the user (or total if no user context)

        Validates: Requirements 2.4, 6.1
        """
        query = self.db.query(TrackerModel)

        # Apply user filtering if user context is available
        if self.user_id is not None:
            query = query.filter(TrackerModel.user_id == self.user_id)

        return query.count()

    def tracker_exists(self, name: str) -> bool:
        """
        Check if a tracker with the given name exists for the user.

        Args:
            name: Tracker name to check

        Returns:
            True if tracker exists for the user, False otherwise

        Validates: Requirements 2.2, 6.1
        """
        query = self.db.query(TrackerModel).filter(TrackerModel.name == name)

        # Apply user filtering if user context is available
        if self.user_id is not None:
            query = query.filter(TrackerModel.user_id == self.user_id)

        return query.first() is not None

    def set_user_context(self, user_id: Optional[int]) -> None:
        """
        Set the user context for this repository instance.

        Args:
            user_id: User ID to set as context, or None to clear context

        Validates: Requirements 2.4, 6.1
        """
        self.user_id = user_id

    def get_user_context(self) -> Optional[int]:
        """
        Get the current user context for this repository instance.

        Returns:
            Current user ID context, or None if no context set

        Validates: Requirements 2.4, 6.1
        """
        return self.user_id


# Backward compatibility functions that maintain the original API
# These functions create a TrackerDB instance without user context for legacy use


def create_tracker(
    db: Session,
    name: str,
    description: Optional[str] = None,
    user_id: Optional[int] = None,
) -> TrackerModel:
    """
    Create a new tracker in the database.

    Args:
        db: Database session
        name: Tracker name (must be unique per user)
        description: Optional tracker description
        user_id: ID of the user who owns this tracker (required for user ownership)

    Returns:
        Created TrackerModel instance

    Validates: Requirements 2.1, 2.2, 2.5, 4.1
    """
    tracker_db = TrackerDB(db)
    return tracker_db.create_tracker(name, description, user_id)


def get_tracker(
    db: Session, tracker_id: int, user_id: Optional[int] = None
) -> Optional[TrackerModel]:
    """
    Retrieve a tracker by its ID, optionally verifying user ownership.

    Args:
        db: Database session
        tracker_id: ID of the tracker to retrieve
        user_id: Optional user ID to verify ownership

    Returns:
        TrackerModel instance if found (and owned by user if user_id provided), None otherwise

    Validates: Requirements 4.2, 6.3
    """
    tracker_db = TrackerDB(db, user_id)
    return tracker_db.get_tracker(tracker_id)


def get_user_tracker(
    db: Session, tracker_id: int, user_id: int
) -> Optional[TrackerModel]:
    """
    Retrieve a tracker by ID, ensuring it belongs to the specified user.

    Args:
        db: Database session
        tracker_id: ID of the tracker to retrieve
        user_id: ID of the user who should own the tracker

    Returns:
        TrackerModel instance if found and owned by user, None otherwise

    Validates: Requirements 6.3, 6.4
    """
    tracker_db = TrackerDB(db, user_id)
    return tracker_db.get_tracker(tracker_id)


def get_all_trackers(db: Session, user_id: Optional[int] = None) -> list[TrackerModel]:
    """
    Retrieve all trackers from the database, optionally filtered by user.

    Args:
        db: Database session
        user_id: Optional user ID to filter trackers by user ownership

    Returns:
        List of TrackerModel instances (filtered by user if user_id provided)

    Validates: Requirements 2.4, 4.2, 6.1
    """
    tracker_db = TrackerDB(db, user_id)
    return tracker_db.get_all_trackers()


def get_user_trackers(db: Session, user_id: int) -> list[TrackerModel]:
    """
    Retrieve all trackers belonging to a specific user.

    Args:
        db: Database session
        user_id: ID of the user whose trackers to retrieve

    Returns:
        List of TrackerModel instances belonging to the user

    Validates: Requirements 2.4, 6.1, 6.5
    """
    tracker_db = TrackerDB(db, user_id)
    return tracker_db.get_all_trackers()


def delete_tracker(db: Session, tracker_id: int, user_id: Optional[int] = None) -> bool:
    """
    Delete a tracker from the database, optionally verifying user ownership.

    Args:
        db: Database session
        tracker_id: ID of the tracker to delete
        user_id: Optional user ID to verify ownership before deletion

    Returns:
        True if tracker was deleted, False if tracker not found or not owned by user

    Validates: Requirements 4.4, 6.3, 6.4
    """
    tracker_db = TrackerDB(db, user_id)
    return tracker_db.delete_tracker(tracker_id)


def delete_user_tracker(db: Session, tracker_id: int, user_id: int) -> bool:
    """
    Delete a tracker belonging to a specific user.

    Args:
        db: Database session
        tracker_id: ID of the tracker to delete
        user_id: ID of the user who should own the tracker

    Returns:
        True if tracker was deleted, False if tracker not found or not owned by user

    Validates: Requirements 6.3, 6.4
    """
    tracker_db = TrackerDB(db, user_id)
    return tracker_db.delete_tracker(tracker_id)
