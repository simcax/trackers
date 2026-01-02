"""
Email/Password Authentication Service.

This module provides the EmailPasswordAuthService class for email and password
authentication, integrating with the existing unified authentication system.
It handles user registration, authentication, password changes, and rate limiting.
"""

import logging
from datetime import datetime
from typing import Optional

from flask import request
from sqlalchemy.exc import IntegrityError

from trackers.auth.error_handling import (
    AccountLockedError,
    AuthLogger,
    DuplicateEmailError,
    EmailPasswordAuthError,
    EmailPasswordRateLimiter,
    EmailPasswordRateLimitError,
    InvalidCredentialsError,
    PasswordValidationError,
    get_client_ip,
)
from trackers.auth.password_hasher import PasswordHasher
from trackers.auth.session_manager import SessionManager
from trackers.auth.token_validator import UserInfo
from trackers.models.user_model import UserModel
from trackers.services.user_service import UserService

logger = logging.getLogger(__name__)


class AuthResult:
    """Authentication result from registration or login."""

    def __init__(
        self,
        success: bool,
        user_info: Optional[UserInfo] = None,
        user_model: Optional[UserModel] = None,
        error_message: Optional[str] = None,
        redirect_url: Optional[str] = None,
    ):
        """
        Initialize authentication result.

        Args:
            success: Whether authentication succeeded
            user_info: User information if successful (for session compatibility)
            user_model: Database user model if successful
            error_message: Error message if failed
            redirect_url: URL to redirect to after processing
        """
        self.success = success
        self.user_info = user_info
        self.user_model = user_model
        self.error_message = error_message
        self.redirect_url = redirect_url


class EmailPasswordAuthService:
    """
    Email/Password authentication service.

    This service handles user registration, authentication, and password management
    for email/password authentication, integrating with the existing unified
    authentication system and session management.

    Requirements: 1.1, 1.2, 1.6, 2.1, 2.2, 2.3, 6.1, 6.2
    """

    def __init__(
        self,
        session_manager: Optional[SessionManager] = None,
        user_service: Optional[UserService] = None,
        password_hasher: Optional[PasswordHasher] = None,
        rate_limiter: Optional[EmailPasswordRateLimiter] = None,
    ):
        """
        Initialize Email/Password Authentication Service.

        Args:
            session_manager: Session manager instance (creates default if None)
            user_service: User service instance (creates default if None)
            password_hasher: Password hasher instance (creates default if None)
            rate_limiter: Email/password rate limiter instance (creates default if None)

        Requirements: 1.1, 1.2, 1.6, 2.1, 2.2, 2.3, 6.1, 6.2
        """
        self.session_manager = session_manager or SessionManager()
        self.password_hasher = password_hasher or PasswordHasher()
        self.rate_limiter = rate_limiter or EmailPasswordRateLimiter()

        # Configure logging
        self.logger = AuthLogger()
        self.flask_logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        # Note: user_service and db sessions will be created as needed using get_db_session()

    def register_user(self, email: str, password: str, name: str) -> AuthResult:
        """
        Register a new user with email/password credentials.

        Args:
            email: User's email address
            password: User's password
            name: User's display name

        Returns:
            AuthResult: Registration result with user info or error

        Raises:
            EmailPasswordRateLimitError: If too many registration attempts
            PasswordValidationError: If password doesn't meet requirements
            DuplicateEmailError: If email already exists
            EmailPasswordAuthError: For other registration errors

        Requirements: 1.1, 1.2, 1.6
        """
        from trackers.db.database import get_db_session
        from trackers.services.user_service import UserService

        client_ip = get_client_ip()

        # Apply rate limiting for registration attempts
        is_limited, retry_after = self.rate_limiter.is_rate_limited(
            client_ip, "registration"
        )
        if is_limited:
            raise EmailPasswordRateLimitError(
                f"Too many registration attempts from {client_ip}",
                retry_after=retry_after,
                attempt_type="registration",
            )

        try:
            with get_db_session() as db:
                user_service = UserService(db)

                # Validate input parameters
                if not email or not email.strip():
                    raise EmailPasswordAuthError(
                        "Email is required", error_code="missing_email"
                    )

                if not password:
                    raise EmailPasswordAuthError(
                        "Password is required", error_code="missing_password"
                    )

                if not name or not name.strip():
                    raise EmailPasswordAuthError(
                        "Name is required", error_code="missing_name"
                    )

                # Normalize email
                email = email.strip().lower()
                name = name.strip()

                # Validate password strength
                password_errors = self.password_hasher.validate_password_strength(
                    password
                )
                if password_errors:
                    raise PasswordValidationError(password_errors)

                # Check if email already exists
                existing_user = user_service.get_user_by_email(email)
                if existing_user:
                    # If user exists but only has Google auth, allow adding password auth
                    if (
                        existing_user.has_google_auth()
                        and not existing_user.has_password_auth()
                    ):
                        # Add password authentication to existing Google user
                        password_hash = self.password_hasher.hash_password(password)
                        existing_user.password_hash = password_hash
                        existing_user.name = name  # Update name if provided
                        existing_user.update_auth_methods()
                        existing_user.update_last_login()
                        db.flush()

                        # Create UserInfo for session compatibility
                        user_info = UserInfo(
                            google_id=existing_user.google_user_id,
                            email=existing_user.email,
                            name=existing_user.name,
                            picture_url=existing_user.profile_picture_url,
                            verified_email=existing_user.email_verified,
                        )

                        # Store user session (auto-login after registration)
                        self._store_email_password_session(user_info, existing_user)

                        # Log successful registration
                        self.logger.log_email_password_registration(
                            existing_user.email, client_ip, True
                        )
                        self.rate_limiter.record_attempt(
                            client_ip, "registration", success=True
                        )

                        self.flask_logger.info(
                            f"Added password auth to existing Google user: {email}"
                        )

                        return AuthResult(
                            success=True,
                            user_info=user_info,
                            user_model=existing_user,
                            redirect_url=self._get_success_redirect_url(),
                        )
                    else:
                        # User already has password auth or other conflict
                        self.rate_limiter.record_attempt(
                            client_ip, "registration", success=False
                        )
                        # Log the attempt but don't reveal the email exists
                        self.logger.log_email_password_registration(
                            "[REDACTED]", client_ip, False, "Email already exists"
                        )
                        raise DuplicateEmailError(email)

                # Hash password
                password_hash = self.password_hasher.hash_password(password)

                # Create new user
                new_user = UserModel(
                    email=email,
                    name=name,
                    password_hash=password_hash,
                    email_verified=False,  # TODO: Implement email verification
                    auth_methods="password",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )

                db.add(new_user)
                db.flush()  # Get the ID and check constraints
                db.refresh(new_user)

                # Create UserInfo for session compatibility
                user_info = UserInfo(
                    google_id=None,  # No Google ID for email/password users
                    email=new_user.email,
                    name=new_user.name,
                    picture_url=new_user.profile_picture_url,
                    verified_email=new_user.email_verified,
                )

                # Store user session (auto-login after registration)
                self._store_email_password_session(user_info, new_user)

                # Update last login
                new_user.update_last_login()
                db.flush()

                # Log successful registration
                self.logger.log_email_password_registration(
                    new_user.email, client_ip, True
                )
                self.rate_limiter.record_attempt(
                    client_ip, "registration", success=True
                )

                self.flask_logger.info(f"Successfully registered new user: {email}")

                return AuthResult(
                    success=True,
                    user_info=user_info,
                    user_model=new_user,
                    redirect_url=self._get_success_redirect_url(),
                )

        except (
            PasswordValidationError,
            DuplicateEmailError,
            EmailPasswordAuthError,
            EmailPasswordRateLimitError,
        ) as e:
            # These are expected registration errors
            self.rate_limiter.record_attempt(client_ip, "registration", success=False)
            raise e
        except IntegrityError as e:
            self.logger.log_email_password_registration(
                "[REDACTED]", client_ip, False, f"Database integrity error: {str(e)}"
            )
            self.rate_limiter.record_attempt(client_ip, "registration", success=False)
            raise EmailPasswordAuthError(
                f"Registration failed due to database constraint: {str(e)}",
                error_code="database_error",
                status_code=500,
            )
        except Exception as e:
            error_msg = f"Registration failed: {str(e)}"
            self.logger.log_email_password_registration(
                "[REDACTED]", client_ip, False, error_msg
            )
            self.rate_limiter.record_attempt(client_ip, "registration", success=False)
            raise EmailPasswordAuthError(
                error_msg,
                error_code="registration_failed",
                status_code=500,
            )

    def authenticate_user(self, email: str, password: str) -> AuthResult:
        """
        Authenticate user with email/password credentials.

        Args:
            email: User's email address
            password: User's password

        Returns:
            AuthResult: Authentication result with user info or error

        Raises:
            EmailPasswordRateLimitError: If too many authentication attempts
            InvalidCredentialsError: If credentials are invalid
            AccountLockedError: If account is locked
            EmailPasswordAuthError: For other authentication errors

        Requirements: 2.1, 2.2, 2.3
        """
        from trackers.db.database import get_db_session
        from trackers.services.user_service import UserService

        client_ip = get_client_ip()

        # Apply rate limiting for login attempts
        is_limited, retry_after = self.rate_limiter.is_rate_limited(client_ip, "login")
        if is_limited:
            raise EmailPasswordRateLimitError(
                f"Too many authentication attempts from {client_ip}",
                retry_after=retry_after,
                attempt_type="login",
            )

        try:
            with get_db_session() as db:
                user_service = UserService(db)

                # Validate input parameters
                if not email or not email.strip():
                    raise InvalidCredentialsError()

                if not password:
                    raise InvalidCredentialsError()

                # Normalize email
                email = email.strip().lower()

                # Get user by email
                user = user_service.get_user_by_email(email)
                if not user or not user.password_hash:
                    # User doesn't exist or doesn't have password auth
                    # Use constant-time operation to prevent timing attacks
                    self.password_hasher.verify_password("dummy", "dummy_hash")
                    self.rate_limiter.record_attempt(client_ip, "login", success=False)
                    # Log failed attempt without revealing email
                    self.logger.log_email_password_login(
                        "[REDACTED]", client_ip, False, "Invalid credentials"
                    )
                    raise InvalidCredentialsError()

                # Check if account is locked
                if user.is_account_locked():
                    self.rate_limiter.record_attempt(client_ip, "login", success=False)
                    # Log account lockout attempt
                    self.logger.log_suspicious_activity(
                        "locked_account_access",
                        user.email,
                        client_ip,
                        {
                            "locked_until": user.locked_until.isoformat()
                            if user.locked_until
                            else None
                        },
                    )
                    raise AccountLockedError(user.locked_until)

                # Verify password
                if not self.password_hasher.verify_password(
                    password, user.password_hash
                ):
                    # Increment failed attempts
                    user.increment_failed_attempts()

                    # Check if this should trigger account lockout
                    if user.failed_login_attempts >= 5:
                        user.lock_account(duration_minutes=30)
                        db.flush()

                        # Log account lockout
                        self.logger.log_account_lockout(
                            user.email, client_ip, user.failed_login_attempts, 30
                        )
                        self.rate_limiter.record_attempt(
                            client_ip, "login", success=False
                        )
                        raise AccountLockedError(user.locked_until)

                    db.flush()
                    self.rate_limiter.record_attempt(client_ip, "login", success=False)
                    # Log failed login without revealing email
                    self.logger.log_email_password_login(
                        "[REDACTED]", client_ip, False, "Invalid credentials"
                    )
                    raise InvalidCredentialsError()

                # Authentication successful - reset failed attempts
                user.reset_failed_attempts()
                user.update_last_login()
                db.flush()

                # Create UserInfo for session compatibility
                user_info = UserInfo(
                    google_id=user.google_user_id,  # May be None for email-only users
                    email=user.email,
                    name=user.name,
                    picture_url=user.profile_picture_url,
                    verified_email=user.email_verified,
                )

                # Store user session
                self._store_email_password_session(user_info, user)

                # Log successful authentication
                self.logger.log_email_password_login(user.email, client_ip, True)
                self.rate_limiter.record_attempt(client_ip, "login", success=True)

                self.flask_logger.info(f"Successfully authenticated user: {email}")

                return AuthResult(
                    success=True,
                    user_info=user_info,
                    user_model=user,
                    redirect_url=self._get_success_redirect_url(),
                )

        except (
            InvalidCredentialsError,
            AccountLockedError,
            EmailPasswordAuthError,
            EmailPasswordRateLimitError,
        ) as e:
            # These are expected authentication errors
            raise e
        except Exception as e:
            error_msg = f"Authentication failed: {str(e)}"
            self.logger.log_email_password_login(
                "[REDACTED]", client_ip, False, error_msg
            )
            self.rate_limiter.record_attempt(client_ip, "login", success=False)
            raise EmailPasswordAuthError(
                error_msg,
                error_code="authentication_failed",
                status_code=500,
            )

    def change_password(
        self, user_id: int, current_password: str, new_password: str
    ) -> bool:
        """
        Change user's password after verifying current password.

        Args:
            user_id: Database user ID
            current_password: Current password for verification
            new_password: New password to set

        Returns:
            True if password was changed successfully

        Raises:
            InvalidCredentialsError: If current password is incorrect
            PasswordValidationError: If new password doesn't meet requirements
            EmailPasswordAuthError: For other password change errors

        Requirements: 6.1, 6.2
        """
        from trackers.db.database import get_db_session
        from trackers.services.user_service import UserService

        client_ip = get_client_ip()

        # Apply rate limiting for password change attempts
        is_limited, retry_after = self.rate_limiter.is_rate_limited(
            client_ip, "password_change"
        )
        if is_limited:
            raise EmailPasswordRateLimitError(
                f"Too many password change attempts from {client_ip}",
                retry_after=retry_after,
                attempt_type="password_change",
            )

        try:
            with get_db_session() as db:
                user_service = UserService(db)

                # Validate input parameters
                if not user_id or user_id <= 0:
                    raise EmailPasswordAuthError(
                        "Invalid user ID", error_code="invalid_user_id"
                    )

                if not current_password:
                    raise InvalidCredentialsError("Current password is required")

                if not new_password:
                    raise EmailPasswordAuthError(
                        "New password is required", error_code="missing_new_password"
                    )

                # Get user
                user = user_service.get_user_by_id(user_id)
                if not user or not user.password_hash:
                    raise EmailPasswordAuthError(
                        "User not found or password authentication not enabled",
                        error_code="user_not_found",
                    )

                # Verify current password
                if not self.password_hasher.verify_password(
                    current_password, user.password_hash
                ):
                    self.rate_limiter.record_attempt(
                        client_ip, "password_change", success=False
                    )
                    self.logger.log_password_change(
                        user.email, client_ip, False, "Invalid current password"
                    )
                    raise InvalidCredentialsError("Current password is incorrect")

                # Validate new password strength
                password_errors = self.password_hasher.validate_password_strength(
                    new_password
                )
                if password_errors:
                    self.rate_limiter.record_attempt(
                        client_ip, "password_change", success=False
                    )
                    raise PasswordValidationError(password_errors)

                # Hash new password
                new_password_hash = self.password_hasher.hash_password(new_password)

                # Update password
                user.password_hash = new_password_hash
                user.update_password_changed_timestamp()
                user.reset_failed_attempts()  # Reset any failed attempts
                db.flush()

                # Log successful password change
                self.logger.log_password_change(user.email, client_ip, True)
                self.rate_limiter.record_attempt(
                    client_ip, "password_change", success=True
                )

                self.flask_logger.info(
                    f"Password changed successfully for user: {user.email}"
                )

                return True

        except (
            InvalidCredentialsError,
            PasswordValidationError,
            EmailPasswordAuthError,
            EmailPasswordRateLimitError,
        ) as e:
            # These are expected password change errors
            raise e
        except Exception as e:
            error_msg = f"Password change failed: {str(e)}"
            # Note: user variable might not be defined if error occurred early
            try:
                if "user" in locals() and user:
                    self.logger.log_password_change(
                        user.email, client_ip, False, error_msg
                    )
            except:
                pass
            self.rate_limiter.record_attempt(
                client_ip, "password_change", success=False
            )
            raise EmailPasswordAuthError(
                error_msg,
                error_code="password_change_failed",
                status_code=500,
            )

    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated with valid session.

        Returns:
            True if user is authenticated, False otherwise

        Requirements: 2.4, 4.5, 5.5
        """
        return self.session_manager.is_authenticated()

    def get_current_user(self) -> Optional[UserInfo]:
        """
        Get current authenticated user information.

        Returns:
            UserInfo or None if not authenticated

        Requirements: 2.4, 4.5, 5.5
        """
        return self.session_manager.get_current_user()

    def logout(self) -> str:
        """
        Logout user and clear session.

        Returns:
            URL to redirect to after logout

        Requirements: 2.4, 4.5, 5.5
        """
        client_ip = get_client_ip()

        try:
            # Get current user info for logging
            current_user = self.get_current_user()
            user_email = current_user.email if current_user else "unknown"

            # Clear session
            self.session_manager.clear_session()

            self.logger.log_logout(user_email, client_ip)

            return self._get_logout_redirect_url()

        except Exception as e:
            self.flask_logger.error(f"Error during logout: {str(e)}")
            # Even if logout fails, clear the session and redirect
            self.session_manager.clear_session()
            return self._get_logout_redirect_url()

    def _store_email_password_session(
        self, user_info: UserInfo, user_model: UserModel
    ) -> None:
        """
        Store user session for email/password authentication.

        This method creates a session compatible with the existing SessionManager
        by providing dummy OAuth token data since email/password auth doesn't
        use OAuth tokens.

        Args:
            user_info: User information for session
            user_model: Database user model
        """
        # For email/password auth, we don't have real OAuth tokens
        # Create dummy token data for session compatibility
        dummy_access_token = (
            f"email_password_session_{user_model.id}_{datetime.utcnow().timestamp()}"
        )

        # Set token expiration to 24 hours (same as session timeout)
        token_expires_in = 24 * 60 * 60  # 24 hours in seconds

        self.session_manager.store_user_session(
            user_info=user_info,
            access_token=dummy_access_token,
            token_expires_in=token_expires_in,
        )

    def _get_success_redirect_url(self) -> str:
        """
        Get URL to redirect to after successful authentication.

        Returns:
            Redirect URL
        """
        from flask import session, url_for

        # Check for stored post-login redirect
        redirect_url = session.pop("post_login_redirect", None)
        if redirect_url:
            return redirect_url

        # Default to dashboard or home page
        try:
            return url_for("web.dashboard")
        except Exception:
            # Fallback if route doesn't exist
            return "/"

    def _get_logout_redirect_url(self) -> str:
        """
        Get URL to redirect to after logout.

        Returns:
            Redirect URL
        """
        from flask import url_for

        try:
            return url_for("auth.login")
        except Exception:
            # Fallback if route doesn't exist
            return "/?logged_out=true"

    def get_session_info(self) -> dict:
        """
        Get information about the current session for debugging/monitoring.

        Returns:
            Session information including authentication method
        """
        session_info = self.session_manager.get_session_info()
        session_info["auth_method"] = "email_password"
        return session_info

    def require_authentication(self, redirect_url: Optional[str] = None):
        """
        Helper to require authentication for routes.

        Args:
            redirect_url: URL to redirect to after successful login

        Returns:
            Flask redirect response if not authenticated, None if authenticated
        """
        from flask import redirect, url_for

        if not self.is_authenticated():
            # Store the current URL for post-login redirect
            if not redirect_url:
                redirect_url = request.url

            # Store redirect URL in session
            from flask import session

            session["post_login_redirect"] = redirect_url

            # Redirect to login page
            try:
                return redirect(url_for("auth.login"))
            except Exception:
                return redirect("/login")

        return None
