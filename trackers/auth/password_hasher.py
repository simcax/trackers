"""
Password hashing and validation utilities for email/password authentication.

This module provides secure password hashing using bcrypt and comprehensive
password strength validation according to security requirements.
"""

import re
import secrets
import time
from typing import List

import bcrypt


class PasswordHasher:
    """
    Secure password hashing and validation using bcrypt.

    Implements security requirements:
    - Minimum 12 salt rounds for bcrypt
    - Constant-time password verification
    - Comprehensive password strength validation
    """

    def __init__(self, rounds: int = 12):
        """
        Initialize password hasher with specified bcrypt rounds.

        Args:
            rounds: Number of bcrypt salt rounds (minimum 12 for security)

        Raises:
            ValueError: If rounds is less than 12
        """
        if rounds < 12:
            raise ValueError("Bcrypt rounds must be at least 12 for security")
        self.rounds = rounds

    def hash_password(self, password: str) -> str:
        """
        Hash password using bcrypt with salt.

        Args:
            password: Plain text password to hash

        Returns:
            Bcrypt hash string suitable for database storage

        Raises:
            ValueError: If password is empty or None
        """
        if not password:
            raise ValueError("Password cannot be empty")

        # Convert password to bytes and generate salt
        password_bytes = password.encode("utf-8")
        salt = bcrypt.gensalt(rounds=self.rounds)

        # Generate hash
        hashed = bcrypt.hashpw(password_bytes, salt)

        # Return as string for database storage
        return hashed.decode("utf-8")

    def verify_password(self, password: str, hashed: str) -> bool:
        """
        Verify password against hash using constant-time comparison.

        This method uses bcrypt's built-in constant-time comparison to prevent
        timing attacks. It also includes additional timing normalization.

        Args:
            password: Plain text password to verify
            hashed: Stored bcrypt hash to verify against

        Returns:
            True if password matches hash, False otherwise
        """
        if not password or not hashed:
            # Perform dummy operation to normalize timing
            self._dummy_hash_operation()
            return False

        try:
            password_bytes = password.encode("utf-8")
            hashed_bytes = hashed.encode("utf-8")

            # bcrypt.checkpw uses constant-time comparison internally
            result = bcrypt.checkpw(password_bytes, hashed_bytes)

            # Add small random delay to further normalize timing
            self._normalize_timing()

            return result

        except (ValueError, TypeError):
            # Perform dummy operation to normalize timing on error
            self._dummy_hash_operation()
            return False

    def validate_password_strength(self, password: str) -> List[str]:
        """
        Validate password meets security requirements.

        Requirements:
        - At least 8 characters long
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character

        Args:
            password: Password to validate

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        if not password:
            errors.append("Password is required")
            return errors

        # Check minimum length
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")

        # Check for uppercase letter
        if not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        # Check for lowercase letter
        if not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        # Check for number
        if not re.search(r"\d", password):
            errors.append("Password must contain at least one number")

        # Check for special character
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append(
                'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)'
            )

        return errors

    def is_password_valid(self, password: str) -> bool:
        """
        Check if password meets all security requirements.

        Args:
            password: Password to validate

        Returns:
            True if password is valid, False otherwise
        """
        return len(self.validate_password_strength(password)) == 0

    def _dummy_hash_operation(self) -> None:
        """
        Perform dummy bcrypt operation to normalize timing.

        This helps prevent timing attacks by ensuring failed verifications
        take similar time as successful ones.
        """
        dummy_password = secrets.token_urlsafe(16)
        dummy_salt = bcrypt.gensalt(rounds=self.rounds)
        bcrypt.hashpw(dummy_password.encode("utf-8"), dummy_salt)

    def _normalize_timing(self) -> None:
        """
        Add small random delay to normalize timing across operations.
        """
        # Add 0-5ms random delay
        delay = secrets.randbelow(5) / 1000.0
        time.sleep(delay)


class PasswordValidationError(Exception):
    """Exception raised when password validation fails."""

    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(f"Password validation failed: {', '.join(errors)}")


def create_password_hasher() -> PasswordHasher:
    """
    Factory function to create a PasswordHasher with default settings.

    Returns:
        PasswordHasher instance with secure defaults
    """
    return PasswordHasher(rounds=12)
