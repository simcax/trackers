"""
User Model for multi-method authentication.

This module provides the UserModel class for storing user information
from multiple authentication methods including Google OAuth and email/password.

Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 7.1, 7.2, 7.3, 7.4, 7.5
"""

from datetime import datetime, timezone


def _utc_now():
    """Helper function to get current UTC time with timezone info."""
    return datetime.now(timezone.utc)


from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String
from sqlalchemy.orm import relationship

from trackers.db.database import Base


class UserModel(Base):
    """
    Database model for storing user information from multiple authentication methods.

    This model stores user information for both Google OAuth and email/password
    authentication methods. It supports backward compatibility by making
    Google OAuth fields optional while adding new password-related fields.

    Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 7.1, 7.2, 7.3, 7.4, 7.5
    """

    __tablename__ = "users"

    # Primary key
    id = Column(Integer, primary_key=True, index=True)

    # Google OAuth fields - Requirements: 1.1, 1.2, 7.2 (made nullable for backward compatibility)
    google_user_id = Column(String, unique=True, nullable=True, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    name = Column(String, nullable=False)
    profile_picture_url = Column(String, nullable=True)

    # Email/Password authentication fields - Requirements: 7.1
    password_hash = Column(String, nullable=True)  # bcrypt hash
    email_verified = Column(Boolean, default=False, nullable=False)
    password_changed_at = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)

    # Authentication method tracking - Requirements: 7.1
    auth_methods = Column(
        String, default="", nullable=False
    )  # Comma-separated: 'google,password'

    # Timestamp fields - Requirements: 1.3, 1.4
    created_at = Column(DateTime, default=_utc_now, nullable=False)
    updated_at = Column(DateTime, default=_utc_now, onupdate=_utc_now, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    # Relationships - Requirements: 2.1, 2.2
    trackers = relationship(
        "TrackerModel", back_populates="user", cascade="all, delete-orphan"
    )
    api_keys = relationship(
        "APIKeyModel", back_populates="user", cascade="all, delete-orphan"
    )
    jobs = relationship("JobModel", back_populates="user", cascade="all, delete-orphan")

    # Indexes for performance - Requirements: 7.5
    __table_args__ = (
        Index("idx_users_google_id", "google_user_id"),
        Index("idx_users_email", "email"),
        Index("idx_users_last_login", "last_login_at"),
        Index("idx_users_password_hash", "password_hash"),
        Index("idx_users_email_verified", "email_verified"),
        Index("idx_users_failed_attempts", "failed_login_attempts"),
        Index("idx_users_locked_until", "locked_until"),
    )

    def __repr__(self) -> str:
        """String representation of the user model."""
        return f"<UserModel(id={self.id}, email='{self.email}', name='{self.name}')>"

    def update_last_login(self) -> None:
        """
        Update the last login timestamp to current time.

        Requirements: 1.4, 5.5
        """
        self.last_login_at = datetime.now(timezone.utc)

    def has_google_auth(self) -> bool:
        """
        Check if user has Google OAuth authentication configured.

        Returns:
            True if user has Google OAuth, False otherwise

        Requirements: 7.1 - Multiple authentication method support
        """
        return self.google_user_id is not None

    def has_password_auth(self) -> bool:
        """
        Check if user has email/password authentication configured.

        Returns:
            True if user has password authentication, False otherwise

        Requirements: 7.1 - Multiple authentication method support
        """
        return self.password_hash is not None

    def get_auth_methods(self) -> list:
        """
        Get list of authentication methods available for this user.

        Returns:
            List of authentication method strings

        Requirements: 7.1 - Authentication method tracking
        """
        methods = []
        if self.has_google_auth():
            methods.append("google")
        if self.has_password_auth():
            methods.append("password")
        return methods

    def update_auth_methods(self) -> None:
        """
        Update the auth_methods field based on current authentication configuration.

        Requirements: 7.1 - Authentication method tracking
        """
        methods = self.get_auth_methods()
        self.auth_methods = ",".join(methods)

    def is_account_locked(self) -> bool:
        """
        Check if the account is currently locked due to failed login attempts.

        Returns:
            True if account is locked, False otherwise

        Requirements: 7.1 - Account security features
        """
        if self.locked_until is None:
            return False
        return datetime.now(timezone.utc) < self.locked_until

    def increment_failed_attempts(self) -> None:
        """
        Increment the failed login attempts counter.

        Requirements: 7.1 - Account security features
        """
        self.failed_login_attempts += 1

    def reset_failed_attempts(self) -> None:
        """
        Reset the failed login attempts counter.

        Requirements: 7.1 - Account security features
        """
        self.failed_login_attempts = 0
        self.locked_until = None

    def lock_account(self, duration_minutes: int = 30) -> None:
        """
        Lock the account for the specified duration.

        Args:
            duration_minutes: How long to lock the account (default: 30 minutes)

        Requirements: 7.1 - Account security features
        """
        from datetime import timedelta

        self.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=duration_minutes
        )

    def update_password_changed_timestamp(self) -> None:
        """
        Update the password changed timestamp to current time.

        Requirements: 7.1 - Password management tracking
        """
        self.password_changed_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict:
        """
        Convert user model to dictionary representation.

        Returns:
            dict: User data as dictionary

        Requirements: 5.1, 5.2, 7.1
        """
        return {
            "id": self.id,
            "google_user_id": self.google_user_id,
            "email": self.email,
            "name": self.name,
            "profile_picture_url": self.profile_picture_url,
            "email_verified": self.email_verified,
            "auth_methods": self.get_auth_methods(),
            "has_google_auth": self.has_google_auth(),
            "has_password_auth": self.has_password_auth(),
            "is_locked": self.is_account_locked(),
            "failed_login_attempts": self.failed_login_attempts,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login_at": (
                self.last_login_at.isoformat() if self.last_login_at else None
            ),
            "password_changed_at": (
                self.password_changed_at.isoformat()
                if self.password_changed_at
                else None
            ),
        }
