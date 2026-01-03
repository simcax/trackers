"""
User Service for managing user operations.

This module provides the UserService class for CRUD operations on users,
OAuth integration, and session management helpers.

Requirements: 5.1, 5.2, 5.3
"""

import logging
from datetime import datetime
from typing import Optional

from flask import session
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from trackers.auth.token_validator import UserInfo
from trackers.models.user_model import UserModel

logger = logging.getLogger(__name__)


class UserService:
    """
    Service class for user management operations.

    This class provides CRUD operations for users, methods for creating/updating
    users from Google OAuth data, and helper methods for getting current user
    from session.

    Requirements: 5.1, 5.2, 5.3
    """

    def __init__(self, db_session: Session):
        """
        Initialize User Service with database session.

        Args:
            db_session: SQLAlchemy database session

        Requirements: 5.1, 5.2, 5.3
        """
        self.db = db_session

    def create_or_update_user(self, google_user_info: UserInfo) -> UserModel:
        """
        Create new user or update existing user from Google OAuth info.

        Args:
            google_user_info: User information from Google OAuth

        Returns:
            UserModel: Created or updated user model

        Raises:
            ValueError: If user information is invalid
            IntegrityError: If database constraint violation occurs

        Requirements: 5.1 - Create or update user record when OAuth completes
        """
        if not google_user_info or not google_user_info.google_id:
            raise ValueError("Invalid Google user information provided")

        if not google_user_info.email:
            raise ValueError("User email is required")

        if not google_user_info.name:
            raise ValueError("User name is required")

        try:
            # Try to find existing user by Google ID first
            existing_user = self.get_user_by_google_id(google_user_info.google_id)

            if existing_user:
                # Update existing user with latest information
                existing_user.email = google_user_info.email
                existing_user.name = google_user_info.name
                existing_user.profile_picture_url = google_user_info.picture_url
                existing_user.updated_at = datetime.utcnow()

                self.db.flush()  # Flush to get any database errors
                self.db.refresh(existing_user)

                logger.info(f"Updated existing user: {existing_user.email}")
                return existing_user

            else:
                # Check if user exists with same email but different Google ID
                # This could happen if user changes Google accounts
                email_user = self.get_user_by_email(google_user_info.email)
                if email_user:
                    # Update the existing user's Google ID
                    email_user.google_user_id = google_user_info.google_id
                    email_user.name = google_user_info.name
                    email_user.profile_picture_url = google_user_info.picture_url
                    email_user.updated_at = datetime.utcnow()

                    self.db.flush()
                    self.db.refresh(email_user)

                    logger.info(f"Updated user Google ID for: {email_user.email}")
                    return email_user

                # Create new user
                new_user = UserModel(
                    google_user_id=google_user_info.google_id,
                    email=google_user_info.email,
                    name=google_user_info.name,
                    profile_picture_url=google_user_info.picture_url,
                )

                self.db.add(new_user)
                self.db.flush()  # Flush to get the ID and check constraints
                self.db.refresh(new_user)

                logger.info(f"Created new user: {new_user.email}")
                return new_user

        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"Database integrity error creating/updating user: {str(e)}")
            raise IntegrityError(
                f"Failed to create or update user due to database constraint: {str(e)}",
                params=None,
                orig=e.orig,
            )
        except Exception as e:
            self.db.rollback()
            logger.error(f"Unexpected error creating/updating user: {str(e)}")
            raise

    def get_user_by_google_id(self, google_user_id: str) -> Optional[UserModel]:
        """
        Get user by Google user ID.

        Args:
            google_user_id: Google user ID to search for

        Returns:
            Optional[UserModel]: User model if found, None otherwise

        Requirements: 5.2 - Provide methods to lookup users by Google ID
        """
        if not google_user_id:
            return None

        try:
            return (
                self.db.query(UserModel)
                .filter(UserModel.google_user_id == google_user_id)
                .first()
            )
        except Exception as e:
            logger.error(f"Error getting user by Google ID {google_user_id}: {str(e)}")
            return None

    def get_user_by_email(self, email: str) -> Optional[UserModel]:
        """
        Get user by email address.

        Args:
            email: Email address to search for

        Returns:
            Optional[UserModel]: User model if found, None otherwise

        Requirements: 5.2 - Provide methods to lookup users by email
        """
        if not email:
            return None

        try:
            return self.db.query(UserModel).filter(UserModel.email == email).first()
        except Exception as e:
            # Redact email from error logs for privacy
            redacted_email = (
                email.split("@")[0][:3] + "***@" + email.split("@")[1]
                if "@" in email
                else "***"
            )
            logger.error(f"Error getting user by email {redacted_email}: {str(e)}")
            return None

    def get_user_by_id(self, user_id: int) -> Optional[UserModel]:
        """
        Get user by database ID.

        Args:
            user_id: Database user ID to search for

        Returns:
            Optional[UserModel]: User model if found, None otherwise

        Requirements: 5.2 - Provide methods to lookup users by ID
        """
        if not user_id or user_id <= 0:
            return None

        try:
            return self.db.query(UserModel).filter(UserModel.id == user_id).first()
        except Exception as e:
            logger.error(f"Error getting user by ID {user_id}: {str(e)}")
            return None

    def update_last_login(self, user_id: int) -> bool:
        """
        Update user's last login timestamp.

        Args:
            user_id: Database user ID

        Returns:
            bool: True if update successful, False otherwise

        Requirements: 5.2 - Update user activity tracking
        """
        if not user_id or user_id <= 0:
            return False

        try:
            user = self.get_user_by_id(user_id)
            if user:
                user.update_last_login()
                self.db.flush()
                logger.debug(f"Updated last login for user {user_id}")
                return True
            else:
                logger.warning(f"User {user_id} not found for last login update")
                return False

        except Exception as e:
            logger.error(f"Error updating last login for user {user_id}: {str(e)}")
            return False

    def get_current_user_from_session(self) -> Optional[UserModel]:
        """
        Get current authenticated user from session.

        This method retrieves the current user's database record based on
        the authentication information stored in the Flask session.

        Returns:
            Optional[UserModel]: Current user model if authenticated, None otherwise

        Requirements: 5.3 - Provide helper methods to get current user from session
        """
        try:
            # Check if there's user session data
            session_user_data = session.get("google_auth_user")
            if not session_user_data:
                return None

            # Extract Google user ID from session
            user_info_data = session_user_data.get("user_info")
            if not user_info_data:
                return None

            google_user_id = user_info_data.get("google_id")
            if not google_user_id:
                return None

            # Look up user in database
            user = self.get_user_by_google_id(google_user_id)
            if user:
                logger.debug(f"Retrieved current user from session: {user.email}")
                return user
            else:
                logger.warning(
                    f"User with Google ID {google_user_id} not found in database"
                )
                return None

        except Exception as e:
            logger.error(f"Error getting current user from session: {str(e)}")
            return None

    def require_authenticated_user(self) -> UserModel:
        """
        Get current authenticated user, raising exception if not authenticated.

        Returns:
            UserModel: Current authenticated user

        Raises:
            ValueError: If user is not authenticated or not found

        Requirements: 5.3 - Provide helper methods for authentication requirements
        """
        current_user = self.get_current_user_from_session()
        if not current_user:
            raise ValueError("User authentication required")

        return current_user

    def is_user_authenticated(self) -> bool:
        """
        Check if a user is currently authenticated.

        Returns:
            bool: True if user is authenticated, False otherwise

        Requirements: 5.3 - Provide authentication status checking
        """
        return self.get_current_user_from_session() is not None

    def get_user_session_info(self) -> dict:
        """
        Get information about the current user session for debugging/monitoring.

        Returns:
            dict: User session information including database user data

        Requirements: 5.3 - Provide session information for monitoring
        """
        try:
            current_user = self.get_current_user_from_session()
            if current_user:
                return {
                    "authenticated": True,
                    "user_id": current_user.id,
                    "email": current_user.email,
                    "name": current_user.name,
                    "google_user_id": current_user.google_user_id,
                    "created_at": current_user.created_at.isoformat()
                    if current_user.created_at
                    else None,
                    "last_login_at": current_user.last_login_at.isoformat()
                    if current_user.last_login_at
                    else None,
                }
            else:
                return {
                    "authenticated": False,
                    "user_id": None,
                    "email": None,
                    "name": None,
                }

        except Exception as e:
            logger.error(f"Error getting user session info: {str(e)}")
            return {
                "authenticated": False,
                "error": str(e),
            }

    def delete_user(self, user_id: int) -> bool:
        """
        Delete a user and all associated data.

        Args:
            user_id: Database user ID to delete

        Returns:
            bool: True if user was deleted, False if user not found

        Note: This will cascade delete all user's trackers and tracker values
        due to the database relationship configuration.

        Requirements: 5.2 - Provide user management operations
        """
        if not user_id or user_id <= 0:
            return False

        try:
            user = self.get_user_by_id(user_id)
            if user:
                self.db.delete(user)
                self.db.flush()
                logger.info(f"Deleted user {user_id} ({user.email})")
                return True
            else:
                logger.warning(f"User {user_id} not found for deletion")
                return False

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            return False

    def update_user_profile(
        self,
        user_id: int,
        name: Optional[str] = None,
        profile_picture_url: Optional[str] = None,
    ) -> Optional[UserModel]:
        """
        Update user profile information.

        Args:
            user_id: Database user ID
            name: New name (optional)
            profile_picture_url: New profile picture URL (optional)

        Returns:
            Optional[UserModel]: Updated user model if successful, None otherwise

        Requirements: 5.2 - Provide user management operations
        """
        if not user_id or user_id <= 0:
            return None

        try:
            user = self.get_user_by_id(user_id)
            if not user:
                logger.warning(f"User {user_id} not found for profile update")
                return None

            # Update provided fields
            if name is not None:
                user.name = name

            if profile_picture_url is not None:
                user.profile_picture_url = profile_picture_url

            # Update timestamp
            user.updated_at = datetime.utcnow()

            self.db.flush()
            self.db.refresh(user)

            logger.info(f"Updated profile for user {user_id}")
            return user

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error updating profile for user {user_id}: {str(e)}")
            return None

    def get_all_users(
        self, limit: Optional[int] = None, offset: Optional[int] = None
    ) -> list[UserModel]:
        """
        Get all users with optional pagination.

        Args:
            limit: Maximum number of users to return (optional)
            offset: Number of users to skip (optional)

        Returns:
            list[UserModel]: List of user models

        Requirements: 5.2 - Provide user management operations
        """
        try:
            query = self.db.query(UserModel).order_by(UserModel.created_at.desc())

            if offset:
                query = query.offset(offset)

            if limit:
                query = query.limit(limit)

            return query.all()

        except Exception as e:
            logger.error(f"Error getting all users: {str(e)}")
            return []

    def get_user_count(self) -> int:
        """
        Get total number of users in the system.

        Returns:
            int: Total user count

        Requirements: 5.2 - Provide user management operations
        """
        try:
            return self.db.query(UserModel).count()
        except Exception as e:
            logger.error(f"Error getting user count: {str(e)}")
            return 0

    def get_or_create_default_system_user(self) -> Optional[UserModel]:
        """
        Get or create the default system user for public access mode.

        This user is used when creating trackers in public access mode
        (when API key authentication is disabled).

        Returns:
            UserModel: The default system user, or None if creation failed

        Requirements: 2.4 - Create default system user for existing trackers
        """
        try:
            # First try to get existing default system user
            existing_user = (
                self.db.query(UserModel)
                .filter_by(email="system@trackers.local")
                .first()
            )

            if existing_user:
                logger.debug(
                    f"Found existing default system user with ID: {existing_user.id}"
                )
                return existing_user

            # Create new default system user
            logger.info("Creating default system user for public access mode")
            default_user = UserModel(
                google_user_id="system-default-user",
                email="system@trackers.local",
                name="System Default User",
                profile_picture_url=None,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )

            self.db.add(default_user)
            self.db.flush()  # Get the ID without committing
            self.db.refresh(default_user)

            logger.info(f"Created default system user with ID: {default_user.id}")
            return default_user

        except Exception as e:
            logger.error(f"Error getting or creating default system user: {str(e)}")
            return None
