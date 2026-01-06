from datetime import datetime, timezone


def _utc_now():
    """Helper function to get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


from sqlalchemy import (
    Column,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class TrackerValueModel(Base):
    """
    Model for storing daily values associated with trackers.

    Each tracker can have one value per day, enforced by unique constraint.
    Timestamps are automatically managed for creation and updates.

    Validates: Requirements 1.1, 1.2, 1.5
    """

    __tablename__ = "tracker_values"

    id = Column(Integer, primary_key=True, index=True)
    tracker_id = Column(
        Integer, ForeignKey("trackers.id", ondelete="CASCADE"), nullable=False
    )
    date = Column(Date, nullable=False)
    value = Column(String, nullable=False)
    created_at = Column(DateTime, default=_utc_now, nullable=False)
    updated_at = Column(DateTime, default=_utc_now, onupdate=_utc_now, nullable=False)

    # Relationship to TrackerModel
    tracker = relationship("TrackerModel", back_populates="values")

    # Constraints and indexes
    __table_args__ = (
        UniqueConstraint("tracker_id", "date", name="unique_tracker_date"),
        Index("idx_tracker_date", "tracker_id", "date"),
    )
