"""
Authentication User Integration Service.

This module provides the AuthUserIntegration class that bridges Google OAuth
authentication with database user management, handling successful login
processing and user record management.

Requirements: 5.1, 5.2, 5.4
"""

import logging
from typing import Optional

from flask import session
from sqlalchemy.orm import Session

from trackers.auth.auth_service import GoogleAuthService
from trackers.auth.token_validator import UserInfo
from trackers.models.user_model import UserModel
from trackers.services.user_service import UserService

logger = logging.getLogger(__name__)


class AuthUserIntegration:
    """
    Integration service that bridges OAuth authentication with database user management.

    This class coordinates between the GoogleAuthService and UserService to ensure
    that successful OAuth authentication results in proper user record creation
    and session management.

    Requirements: 5.1, 5.2, 5.4
    """

    def __init__(
        self,
        user_service: UserService,
        auth_service: GoogleAuthService,
        db_session: Optional[Session] = None,
    ):
        """
        Initialize Authentication User Integration service.

        Args:
            user_service: UserService instance for database operations
            auth_service: GoogleAuthService instance for OAuth operations
            db_session: Optional database session (for transaction management)

        Requirements: 5.1, 5.2, 5.4
        """
        self.user_service = user_service
        self.auth_service = auth_service
        self.db_session = db_session

    def handle_successful_login(self, user_info: UserInfo) -> UserModel:
        """
        Handle successful Google OAuth login and create/update user record.

        This method is called after successful OAuth authentication to ensure
        the user exists in the database and their information is up to date.

        Args:
            user_info: User information from Google OAuth

        Returns:
            UserModel: Created or updated user database record

        Raises:
            ValueError: If user information is invalid
            Exception: If database operations fail

        Requirements: 5.1 - Create or update user record when OAuth completes
        """
        if not user_info:
            raise ValueError("User information is required")

        try:
            logger.info(f"Processing successful login for user: {user_info.email}")

            # Create or update user record in database
            user_model = self.user_service.create_or_update_user(user_info)

            # Update last login timestamp
            self.user_service.update_last_login(user_model.id)

            # Commit the transaction if we have a session
            if self.db_session:
                self.db_session.commit()

            logger.info(
                f"Successfully processed login for user {user_model.id} ({user_model.email})"
            )

            return user_model

        except Exception as e:
            # Rollback transaction on error
            if self.db_session:
                self.db_session.rollback()

            logger.error(
                f"Failed to handle successful login for {user_info.email}: {str(e)}"
            )
            raise

    def get_current_database_user(self) -> Optional[UserModel]:
        """
        Get current user's database record.

        This method retrieves the current authenticated user's database record
        by coordinating between the OAuth session and database lookup.

        Returns:
            Optional[UserModel]: Current user's database record or None if not authenticated

        Requirements: 5.2 - Link authenticated Google user to database record
        """
        try:
            # First check if user is authenticated via OAuth
            if not self.auth_service.is_authenticated():
                logger.debug("User is not authenticated via OAuth")
                return None

            # Get OAuth user information
            oauth_user_info = self.auth_service.get_current_user()
            if not oauth_user_info:
                logger.debug("No OAuth user information available")
                return None

            # Look up user in database by Google ID
            database_user = self.user_service.get_user_by_google_id(
                oauth_user_info.google_id
            )

            if database_user:
                logger.debug(f"Found database user: {database_user.email}")
                return database_user
            else:
                logger.warning(
                    f"OAuth user {oauth_user_info.email} not found in database"
                )
                return None

        except Exception as e:
            logger.error(f"Error getting current database user: {str(e)}")
            return None

    def require_authenticated_user(self) -> UserModel:
        """
        Get current authenticated user, raising exception if not authenticated.

        This method ensures that a user is both OAuth authenticated and has
        a corresponding database record.

        Returns:
            UserModel: Current authenticated user's database record

        Raises:
            ValueError: If user is not authenticated or database record not found

        Requirements: 5.4 - Provide helper methods for authentication requirements
        """
        # Check OAuth authentication first
        if not self.auth_service.is_authenticated():
            raise ValueError("User is not authenticated via OAuth")

        # Get database user record
        database_user = self.get_current_database_user()
        if not database_user:
            raise ValueError("Authenticated user not found in database")

        return database_user

    def sync_user_data(self, force_update: bool = False) -> Optional[UserModel]:
        """
        Synchronize current OAuth user data with database record.

        This method updates the database user record with the latest information
        from the OAuth session, useful for keeping user data current.

        Args:
            force_update: Whether to force update even if data appears current

        Returns:
            Optional[UserModel]: Updated user record or None if not authenticated

        Requirements: 5.1, 5.2 - Keep user data synchronized
        """
        try:
            # Get current OAuth user info
            oauth_user_info = self.auth_service.get_current_user()
            if not oauth_user_info:
                logger.debug("No OAuth user information available for sync")
                return None

            # Get current database user
            database_user = self.get_current_database_user()
            if not database_user:
                logger.info("Creating new database user during sync")
                return self.handle_successful_login(oauth_user_info)

            # Check if update is needed
            needs_update = force_update or self._user_data_needs_update(
                database_user, oauth_user_info
            )

            if needs_update:
                logger.info(f"Synchronizing user data for {database_user.email}")
                updated_user = self.user_service.create_or_update_user(oauth_user_info)

                # Commit the transaction if we have a session
                if self.db_session:
                    self.db_session.commit()

                return updated_user
            else:
                logger.debug(f"User data is current for {database_user.email}")
                return database_user

        except Exception as e:
            # Rollback transaction on error
            if self.db_session:
                self.db_session.rollback()

            logger.error(f"Error synchronizing user data: {str(e)}")
            return None

    def is_user_authenticated(self) -> bool:
        """
        Check if user is authenticated and has valid database record.

        Returns:
            bool: True if user is fully authenticated, False otherwise

        Requirements: 5.4 - Provide authentication status checking
        """
        try:
            return (
                self.auth_service.is_authenticated()
                and self.get_current_database_user() is not None
            )
        except Exception as e:
            logger.error(f"Error checking authentication status: {str(e)}")
            return False

    def get_user_session_info(self) -> dict:
        """
        Get comprehensive user session information.

        Returns:
            dict: Combined OAuth and database user session information

        Requirements: 5.4 - Provide session information for monitoring
        """
        try:
            # Get OAuth session info
            oauth_session_info = self.auth_service.get_session_info()

            # Get database user info
            database_user = self.get_current_database_user()
            database_info = {}
            if database_user:
                database_info = {
                    "database_user_id": database_user.id,
                    "database_email": database_user.email,
                    "database_name": database_user.name,
                    "created_at": database_user.created_at.isoformat()
                    if database_user.created_at
                    else None,
                    "last_login_at": database_user.last_login_at.isoformat()
                    if database_user.last_login_at
                    else None,
                }

            return {
                "oauth_session": oauth_session_info,
                "database_user": database_info,
                "fully_authenticated": self.is_user_authenticated(),
            }

        except Exception as e:
            logger.error(f"Error getting user session info: {str(e)}")
            return {
                "oauth_session": {},
                "database_user": {},
                "fully_authenticated": False,
                "error": str(e),
            }

    def logout_user(self, redirect_to_google: bool = False) -> str:
        """
        Log out user from both OAuth and clear database session context.

        Args:
            redirect_to_google: Whether to also redirect to Google's logout

        Returns:
            str: URL to redirect to after logout

        Requirements: 5.4 - Handle logout with session cleanup
        """
        try:
            # Get current user info for logging
            current_user = self.get_current_database_user()
            user_email = current_user.email if current_user else "unknown"

            logger.info(f"Logging out user: {user_email}")

            # Perform OAuth logout (this clears the OAuth session)
            logout_url = self.auth_service.logout(redirect_to_google)

            # Clear any additional database-related session data
            self._clear_database_session_context()

            logger.info(f"Successfully logged out user: {user_email}")

            return logout_url

        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")
            # Still try to clear sessions even if there's an error
            try:
                self.auth_service.logout(redirect_to_google)
                self._clear_database_session_context()
            except Exception:
                pass  # Ignore errors during cleanup

            # Return a safe logout URL
            return "/?logged_out=true"

    def _user_data_needs_update(
        self, database_user: UserModel, oauth_user_info: UserInfo
    ) -> bool:
        """
        Check if database user data needs to be updated with OAuth information.

        Args:
            database_user: Current database user record
            oauth_user_info: Current OAuth user information

        Returns:
            bool: True if update is needed, False otherwise
        """
        try:
            # Check if key fields have changed
            if database_user.email != oauth_user_info.email:
                return True

            if database_user.name != oauth_user_info.name:
                return True

            if database_user.profile_picture_url != oauth_user_info.picture_url:
                return True

            # Check if Google user ID has changed (shouldn't happen but be safe)
            if database_user.google_user_id != oauth_user_info.google_id:
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking if user data needs update: {str(e)}")
            # When in doubt, update
            return True

    def _clear_database_session_context(self) -> None:
        """
        Clear any database-related session context.

        This method clears any additional session data that might be stored
        for database user context beyond what the OAuth service handles.
        """
        try:
            # Clear any custom session keys we might have added
            # (Currently we rely on OAuth session, but this is here for future use)
            session_keys_to_clear = [
                "database_user_id",
                "user_preferences",
                "user_context",
            ]

            for key in session_keys_to_clear:
                session.pop(key, None)

            logger.debug("Cleared database session context")

        except Exception as e:
            logger.error(f"Error clearing database session context: {str(e)}")

    def refresh_authentication(self) -> bool:
        """
        Refresh the current authentication session and sync user data.

        Returns:
            bool: True if session was refreshed successfully, False otherwise

        Requirements: 5.4 - Provide session management
        """
        try:
            # Refresh OAuth session first
            oauth_refreshed = self.auth_service.refresh_authentication()

            if oauth_refreshed:
                # Sync user data to ensure database is current
                synced_user = self.sync_user_data()
                return synced_user is not None
            else:
                return False

        except Exception as e:
            logger.error(f"Error refreshing authentication: {str(e)}")
            return False

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with transaction handling."""
        if exc_type is not None and self.db_session:
            # Rollback on exception
            try:
                self.db_session.rollback()
            except Exception as e:
                logger.error(f"Error rolling back transaction: {str(e)}")
        elif self.db_session:
            # Commit on success
            try:
                self.db_session.commit()
            except Exception as e:
                logger.error(f"Error committing transaction: {str(e)}")
                self.db_session.rollback()
