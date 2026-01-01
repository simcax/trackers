"""
API Key Service for User API Key Management.

This module provides the APIKeyService class for creating, managing, and validating
user-created API keys with proper security, expiration handling, and database operations.

Requirements: 1.2, 1.5, 2.5, 5.1, 5.2, 5.3
"""

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from trackers.models.api_key_model import APIKeyModel

logger = logging.getLogger(__name__)


@dataclass
class APIKeyInfo:
    """Public API key information (no sensitive data)."""

    id: int
    name: str
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    last_used_at: Optional[datetime]
    is_expired: bool  # Computed property
    is_near_expiration: bool  # Computed property for near expiration warning


@dataclass
class APIKeyResult:
    """Result of API key creation (includes one-time key value)."""

    success: bool
    api_key_info: Optional[APIKeyInfo]
    key_value: Optional[str]  # Only provided once during creation
    error_message: Optional[str]


@dataclass
class APIKeyValidationResult:
    """Result of API key validation."""

    is_valid: bool
    user_id: Optional[int]
    key_info: Optional[APIKeyInfo]
    validation_error: Optional[str]


class APIKeyService:
    """
    Service class for user API key management operations.

    This class provides CRUD operations for user API keys, secure key generation,
    validation, and expiration management with proper security practices.

    Requirements: 1.2, 1.5, 2.5, 5.1, 5.2, 5.3
    """

    def __init__(self, db_session: Session):
        """
        Initialize API Key Service with database session.

        Args:
            db_session: SQLAlchemy database session

        Requirements: 1.2, 1.5, 2.5, 5.1, 5.2, 5.3
        """
        self.db = db_session

    def generate_secure_api_key(self) -> str:
        """
        Generate cryptographically secure API key with uk_ prefix.

        Generates a 32-byte (256-bit) cryptographically secure random key,
        encodes it as URL-safe base64, and adds the "uk_" prefix for user keys.

        Returns:
            str: Secure API key in format "uk_<base64_encoded_random_bytes>"

        Requirements: 1.2 - Generate unique, secure token
        """
        # Generate 32 bytes (256 bits) of cryptographically secure random data
        random_bytes = secrets.token_bytes(32)

        # Encode as URL-safe base64 (no padding needed for 32 bytes)
        encoded_key = base64.urlsafe_b64encode(random_bytes).decode("ascii").rstrip("=")

        # Add user key prefix
        return f"uk_{encoded_key}"

    def hash_api_key(self, api_key: str) -> str:
        """
        Hash API key using SHA-256 for secure storage.

        Args:
            api_key: Plain text API key to hash

        Returns:
            str: Hexadecimal hash of the API key

        Requirements: 1.5 - Store key associated with user account (securely hashed)
        """
        # Use SHA-256 for hashing (consistent with existing security patterns)
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

    def create_api_key(
        self, user_id: int, name: str, expires_at: Optional[datetime] = None
    ) -> APIKeyResult:
        """
        Create new API key for a user.

        Args:
            user_id: Database user ID
            name: User-friendly name for the key
            expires_at: Optional expiration date

        Returns:
            APIKeyResult: Result containing success status, key info, and one-time key value

        Requirements: 1.2, 1.5 - Generate unique secure token and store with user account
        """
        if not user_id or user_id <= 0:
            return APIKeyResult(
                success=False,
                api_key_info=None,
                key_value=None,
                error_message="Invalid user ID",
            )

        if not name or not name.strip():
            return APIKeyResult(
                success=False,
                api_key_info=None,
                key_value=None,
                error_message="API key name is required",
            )

        # Validate expiration date
        if expires_at and expires_at <= datetime.utcnow():
            return APIKeyResult(
                success=False,
                api_key_info=None,
                key_value=None,
                error_message="Expiration date must be in the future",
            )

        try:
            # Generate secure API key
            api_key = self.generate_secure_api_key()
            key_hash = self.hash_api_key(api_key)

            # Create database record
            api_key_model = APIKeyModel(
                user_id=user_id,
                name=name.strip(),
                key_hash=key_hash,
                expires_at=expires_at,
                created_at=datetime.utcnow(),
                is_active=True,
            )

            self.db.add(api_key_model)
            self.db.flush()  # Get the ID without committing
            self.db.refresh(api_key_model)

            # Convert to APIKeyInfo
            api_key_info = self._model_to_info(api_key_model)

            logger.info(f"Created API key '{name}' for user {user_id}")

            return APIKeyResult(
                success=True,
                api_key_info=api_key_info,
                key_value=api_key,  # Only provided once during creation
                error_message=None,
            )

        except IntegrityError as e:
            self.db.rollback()
            logger.error(f"Database integrity error creating API key: {str(e)}")
            return APIKeyResult(
                success=False,
                api_key_info=None,
                key_value=None,
                error_message="Failed to create API key due to database constraint",
            )
        except Exception as e:
            self.db.rollback()
            logger.error(f"Unexpected error creating API key: {str(e)}")
            return APIKeyResult(
                success=False,
                api_key_info=None,
                key_value=None,
                error_message="Failed to create API key",
            )

    def list_user_api_keys(self, user_id: int) -> List[APIKeyInfo]:
        """
        List all API keys for a user.

        Args:
            user_id: Database user ID

        Returns:
            List[APIKeyInfo]: List of user's API keys (no sensitive data)

        Requirements: 2.1 - Display list of existing API keys
        """
        if not user_id or user_id <= 0:
            return []

        try:
            api_keys = (
                self.db.query(APIKeyModel)
                .filter(APIKeyModel.user_id == user_id)
                .order_by(APIKeyModel.created_at.desc())
                .all()
            )

            return [self._model_to_info(key) for key in api_keys]

        except Exception as e:
            logger.error(f"Error listing API keys for user {user_id}: {str(e)}")
            return []

    def invalidate_api_key(self, user_id: int, key_id: int) -> bool:
        """
        Invalidate (disable) an API key for a user.

        Args:
            user_id: Database user ID (for security - users can only invalidate their own keys)
            key_id: API key ID to invalidate

        Returns:
            bool: True if key was invalidated, False otherwise

        Requirements: 2.5 - Immediately disable key for API access
        """
        if not user_id or user_id <= 0 or not key_id or key_id <= 0:
            return False

        try:
            api_key = (
                self.db.query(APIKeyModel)
                .filter(
                    APIKeyModel.id == key_id,
                    APIKeyModel.user_id
                    == user_id,  # Security: users can only invalidate their own keys
                )
                .first()
            )

            if not api_key:
                logger.warning(f"API key {key_id} not found for user {user_id}")
                return False

            if not api_key.is_active:
                logger.info(f"API key {key_id} already inactive")
                return True  # Already inactive, consider it success

            # Invalidate the key
            api_key.invalidate()
            self.db.flush()

            logger.info(f"Invalidated API key {key_id} for user {user_id}")
            return True

        except Exception as e:
            self.db.rollback()
            logger.error(
                f"Error invalidating API key {key_id} for user {user_id}: {str(e)}"
            )
            return False

    def validate_user_api_key(self, key_value: str) -> Optional[APIKeyValidationResult]:
        """
        Validate a user-created API key.

        Args:
            key_value: Plain text API key to validate

        Returns:
            Optional[APIKeyValidationResult]: Validation result if key exists, None otherwise

        Requirements: 5.1, 5.2, 5.3 - Validate against database, check expiration and active status
        """
        if not key_value or not key_value.startswith("uk_"):
            return None

        try:
            # Hash the provided key for database lookup
            key_hash = self.hash_api_key(key_value)

            # Find the API key in database
            api_key = (
                self.db.query(APIKeyModel)
                .filter(APIKeyModel.key_hash == key_hash)
                .first()
            )

            if not api_key:
                return APIKeyValidationResult(
                    is_valid=False,
                    user_id=None,
                    key_info=None,
                    validation_error="API key not found",
                )

            # Check if key is active
            if not api_key.is_active:
                return APIKeyValidationResult(
                    is_valid=False,
                    user_id=api_key.user_id,
                    key_info=self._model_to_info(api_key),
                    validation_error="API key has been invalidated",
                )

            # Check if key is expired
            if api_key.is_expired():
                return APIKeyValidationResult(
                    is_valid=False,
                    user_id=api_key.user_id,
                    key_info=self._model_to_info(api_key),
                    validation_error="API key has expired",
                )

            # Key is valid - update last used timestamp
            api_key.update_last_used()
            self.db.flush()

            return APIKeyValidationResult(
                is_valid=True,
                user_id=api_key.user_id,
                key_info=self._model_to_info(api_key),
                validation_error=None,
            )

        except Exception as e:
            logger.error(f"Error validating API key: {str(e)}")
            return APIKeyValidationResult(
                is_valid=False,
                user_id=None,
                key_info=None,
                validation_error="Validation system error",
            )

    def cleanup_expired_keys(self) -> int:
        """
        Clean up expired API keys (optional background task).

        This method can be used to periodically remove expired keys from the database
        to keep the table size manageable.

        Returns:
            int: Number of keys cleaned up

        Requirements: Supporting functionality for key management
        """
        try:
            # Find expired keys
            expired_keys = (
                self.db.query(APIKeyModel)
                .filter(
                    APIKeyModel.expires_at.isnot(None),
                    APIKeyModel.expires_at <= datetime.utcnow(),
                )
                .all()
            )

            count = len(expired_keys)

            if count > 0:
                # Delete expired keys
                for key in expired_keys:
                    self.db.delete(key)

                self.db.flush()
                logger.info(f"Cleaned up {count} expired API keys")

            return count

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error cleaning up expired keys: {str(e)}")
            return 0

    def get_api_key_by_id(self, user_id: int, key_id: int) -> Optional[APIKeyInfo]:
        """
        Get specific API key information for a user.

        Args:
            user_id: Database user ID (for security)
            key_id: API key ID

        Returns:
            Optional[APIKeyInfo]: API key info if found and owned by user, None otherwise

        Requirements: Supporting functionality for key management
        """
        if not user_id or user_id <= 0 or not key_id or key_id <= 0:
            return None

        try:
            api_key = (
                self.db.query(APIKeyModel)
                .filter(APIKeyModel.id == key_id, APIKeyModel.user_id == user_id)
                .first()
            )

            if api_key:
                return self._model_to_info(api_key)

            return None

        except Exception as e:
            logger.error(f"Error getting API key {key_id} for user {user_id}: {str(e)}")
            return None

    def get_user_key_count(self, user_id: int) -> int:
        """
        Get count of API keys for a user.

        Args:
            user_id: Database user ID

        Returns:
            int: Number of API keys for the user

        Requirements: Supporting functionality for key management
        """
        if not user_id or user_id <= 0:
            return 0

        try:
            return (
                self.db.query(APIKeyModel)
                .filter(APIKeyModel.user_id == user_id)
                .count()
            )

        except Exception as e:
            logger.error(f"Error getting key count for user {user_id}: {str(e)}")
            return 0

    def _model_to_info(self, api_key_model: APIKeyModel) -> APIKeyInfo:
        """
        Convert APIKeyModel to APIKeyInfo (no sensitive data).

        Args:
            api_key_model: Database model

        Returns:
            APIKeyInfo: Public API key information

        Requirements: 2.3 - Do not show actual key value for security
        """
        return APIKeyInfo(
            id=api_key_model.id,
            name=api_key_model.name,
            created_at=api_key_model.created_at,
            expires_at=api_key_model.expires_at,
            is_active=api_key_model.is_active,
            last_used_at=api_key_model.last_used_at,
            is_expired=api_key_model.is_expired(),
            is_near_expiration=api_key_model.is_near_expiration(),
        )
