"""
API Key Model for User API Key Management.

This module provides the APIKeyModel class for storing user-created API keys
in the database with proper security, expiration, and relationship management.

Requirements: 4.1, 4.2, 4.3, 4.4
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class APIKeyModel(Base):
    """
    Database model for storing user-created API keys.

    This model stores API keys created by users for programmatic access to the API.
    It includes security features like key hashing, expiration dates, and activity tracking.

    Requirements: 4.1, 4.2, 4.3, 4.4
    """

    __tablename__ = "api_keys"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # User relationship - Requirements: 4.1
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    # API key metadata - Requirements: 4.2, 4.3
    name = Column(String(100), nullable=False)  # User-friendly name for the key
    key_hash = Column(String(255), nullable=False, unique=True)  # Hashed key value

    # Timestamps - Requirements: 4.3
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)  # Optional expiration date
    last_used_at = Column(DateTime, nullable=True)  # Track usage

    # Status management - Requirements: 4.4
    is_active = Column(Boolean, default=True, nullable=False)  # For manual invalidation

    # Relationships
    user = relationship("UserModel", back_populates="api_keys")

    # Indexes for performance - Requirements: 4.4
    __table_args__ = (
        Index("idx_api_keys_user_id", "user_id"),
        Index("idx_api_keys_hash", "key_hash"),
        Index("idx_api_keys_active", "is_active"),
        Index("idx_api_keys_expires", "expires_at"),
    )

    def __repr__(self) -> str:
        """String representation of the API key model."""
        return f"<APIKeyModel(id={self.id}, user_id={self.user_id}, name='{self.name}', active={self.is_active})>"

    def is_expired(self) -> bool:
        """
        Check if the API key has expired.

        Returns:
            True if the key has expired, False otherwise

        Requirements: 4.3
        """
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def is_near_expiration(self, days_threshold: int = 7) -> bool:
        """
        Check if the API key is near expiration.

        Args:
            days_threshold: Number of days before expiration to consider "near"

        Returns:
            True if the key expires within the threshold, False otherwise

        Requirements: 6.4 - Visual indicators for near expiration
        """
        if self.expires_at is None:
            return False

        # Already expired keys are not "near expiration", they are expired
        if self.is_expired():
            return False

        # Check if expiration is within the threshold
        time_until_expiration = self.expires_at - datetime.utcnow()
        return time_until_expiration.days <= days_threshold

    def is_valid(self) -> bool:
        """
        Check if the API key is valid for use.

        A key is valid if it is active and not expired.

        Returns:
            True if the key is valid, False otherwise

        Requirements: 4.4
        """
        return self.is_active and not self.is_expired()

    def invalidate(self) -> None:
        """
        Invalidate the API key by setting is_active to False.

        Requirements: 4.4
        """
        self.is_active = False

    def update_last_used(self) -> None:
        """
        Update the last used timestamp to current time.

        Requirements: 4.3
        """
        self.last_used_at = datetime.utcnow()

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """
        Convert API key model to dictionary representation.

        Args:
            include_sensitive: Whether to include sensitive data (key_hash)

        Returns:
            dict: API key data as dictionary

        Requirements: 4.2, 4.3
        """
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "name": self.name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat()
            if self.last_used_at
            else None,
            "is_active": self.is_active,
            "is_expired": self.is_expired(),
            "is_near_expiration": self.is_near_expiration(),
            "is_valid": self.is_valid(),
        }

        if include_sensitive:
            data["key_hash"] = self.key_hash

        return data
