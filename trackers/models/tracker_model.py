from datetime import datetime

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class TrackerModel(Base):
    __tablename__ = "trackers"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False, index=True)  # Remove unique constraint
    description = Column(String, nullable=True)

    # User ownership - Requirements: 2.1, 2.2
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # Timestamp fields for tracking creation and updates
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    # Relationships
    user = relationship("UserModel", back_populates="trackers")
    items = relationship("ItemModel", back_populates="tracker")
    logs = relationship("LogModel", back_populates="tracker")
    values = relationship(
        "TrackerValueModel",
        back_populates="tracker",
        cascade="all, delete-orphan",
        order_by="TrackerValueModel.date.desc()",
    )

    # Constraints and indexes - Requirements: 2.2, 2.3
    __table_args__ = (
        UniqueConstraint("user_id", "name", name="unique_user_tracker_name"),
        Index("idx_user_trackers", "user_id"),
        Index("idx_tracker_created", "created_at"),
    )


class ItemModel(Base):
    __tablename__ = "items"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    tracker_id = Column(Integer, ForeignKey("trackers.id"))
    date = Column(DateTime)

    tracker = relationship("TrackerModel", back_populates="items")


class LogModel(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    message = Column(String)
    tracker_id = Column(Integer, ForeignKey("trackers.id"))

    tracker = relationship("TrackerModel", back_populates="logs")
