"""
User Model for Google OAuth integration.

This module provides the UserModel class for storing user information
from Google OAuth authentication in the database.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
"""

from datetime import datetime

from sqlalchemy import Column, DateTime, Index, Integer, String
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class UserModel(Base):
    """
    Database model for storing user information from Google OAuth.

    This model stores essential user information obtained from Google OAuth
    authentication, including Google user ID, email, name, and profile picture.
    It also tracks user activity with timestamps for creation, updates, and last login.

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5
    """

    __tablename__ = "users"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Google OAuth fields - Requirements: 1.1, 1.2
    google_user_id = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    profile_picture_url = Column(String, nullable=True)

    # Timestamp fields - Requirements: 1.3, 1.4
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    last_login_at = Column(DateTime, nullable=True)

    # Relationships - Requirements: 2.1, 2.2
    trackers = relationship(
        "TrackerModel", back_populates="user", cascade="all, delete-orphan"
    )
    api_keys = relationship(
        "APIKeyModel", back_populates="user", cascade="all, delete-orphan"
    )

    # Indexes for performance
    __table_args__ = (
        Index("idx_users_google_id", "google_user_id"),
        Index("idx_users_email", "email"),
        Index("idx_users_last_login", "last_login_at"),
    )

    def __repr__(self) -> str:
        """String representation of the user model."""
        return f"<UserModel(id={self.id}, email='{self.email}', name='{self.name}')>"

    def update_last_login(self) -> None:
        """
        Update the last login timestamp to current time.

        Requirements: 1.4, 5.5
        """
        self.last_login_at = datetime.utcnow()

    def to_dict(self) -> dict:
        """
        Convert user model to dictionary representation.

        Returns:
            dict: User data as dictionary

        Requirements: 5.1, 5.2
        """
        return {
            "id": self.id,
            "google_user_id": self.google_user_id,
            "email": self.email,
            "name": self.name,
            "profile_picture_url": self.profile_picture_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login_at": (
                self.last_login_at.isoformat() if self.last_login_at else None
            ),
        }
