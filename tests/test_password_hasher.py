"""
Tests for password hashing and validation functionality.
"""

import time

import pytest

from trackers.auth.password_hasher import (
    PasswordHasher,
    PasswordValidationError,
    create_password_hasher,
)


class TestPasswordHasher:
    """Test cases for PasswordHasher class."""

    def test_initialization_with_valid_rounds(self):
        """Test PasswordHasher initializes with valid rounds."""
        hasher = PasswordHasher(rounds=12)
        assert hasher.rounds == 12

        hasher = PasswordHasher(rounds=15)
        assert hasher.rounds == 15

    def test_initialization_with_invalid_rounds(self):
        """Test PasswordHasher raises error with invalid rounds."""
        with pytest.raises(ValueError, match="Bcrypt rounds must be at least 12"):
            PasswordHasher(rounds=10)

        with pytest.raises(ValueError, match="Bcrypt rounds must be at least 12"):
            PasswordHasher(rounds=5)

    def test_hash_password_success(self):
        """Test password hashing produces valid bcrypt hash."""
        hasher = PasswordHasher()
        password = "TestPassword123!"

        hashed = hasher.hash_password(password)

        # Bcrypt hashes start with $2b$ and are 60 characters long
        assert hashed.startswith("$2b$")
        assert len(hashed) == 60
        assert isinstance(hashed, str)

    def test_hash_password_empty_input(self):
        """Test hash_password raises error for empty input."""
        hasher = PasswordHasher()

        with pytest.raises(ValueError, match="Password cannot be empty"):
            hasher.hash_password("")

        with pytest.raises(ValueError, match="Password cannot be empty"):
            hasher.hash_password(None)

    def test_verify_password_success(self):
        """Test password verification with correct password."""
        hasher = PasswordHasher()
        password = "TestPassword123!"

        hashed = hasher.hash_password(password)
        assert hasher.verify_password(password, hashed) is True

    def test_verify_password_failure(self):
        """Test password verification with incorrect password."""
        hasher = PasswordHasher()
        password = "TestPassword123!"
        wrong_password = "WrongPassword123!"

        hashed = hasher.hash_password(password)
        assert hasher.verify_password(wrong_password, hashed) is False

    def test_verify_password_empty_inputs(self):
        """Test password verification with empty inputs."""
        hasher = PasswordHasher()

        assert hasher.verify_password("", "hash") is False
        assert hasher.verify_password("password", "") is False
        assert hasher.verify_password(None, "hash") is False
        assert hasher.verify_password("password", None) is False

    def test_verify_password_invalid_hash(self):
        """Test password verification with invalid hash."""
        hasher = PasswordHasher()

        assert hasher.verify_password("password", "invalid_hash") is False
        assert hasher.verify_password("password", "not_a_bcrypt_hash") is False

    def test_validate_password_strength_valid_password(self):
        """Test password strength validation with valid password."""
        hasher = PasswordHasher()

        valid_passwords = [
            "TestPass123!",
            "MySecure@Password1",
            "Complex#Pass99",
            "Strong$Password2024",
        ]

        for password in valid_passwords:
            errors = hasher.validate_password_strength(password)
            assert errors == [], (
                f"Password '{password}' should be valid but got errors: {errors}"
            )

    def test_validate_password_strength_invalid_passwords(self):
        """Test password strength validation with invalid passwords."""
        hasher = PasswordHasher()

        test_cases = [
            ("", ["Password is required"]),
            (
                "short",
                [
                    "Password must be at least 8 characters long",
                    "Password must contain at least one uppercase letter",
                    "Password must contain at least one number",
                    'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)',
                ],
            ),
            (
                "toolongbutnouppercaseornumberorspecial",
                [
                    "Password must contain at least one uppercase letter",
                    "Password must contain at least one number",
                    'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)',
                ],
            ),
            (
                "NOLOWERCASE123!",
                ["Password must contain at least one lowercase letter"],
            ),
            ("NoNumbers!", ["Password must contain at least one number"]),
            (
                "NoSpecialChar123",
                [
                    'Password must contain at least one special character (!@#$%^&*(),.?":{}|<>)'
                ],
            ),
        ]

        for password, expected_errors in test_cases:
            errors = hasher.validate_password_strength(password)
            for expected_error in expected_errors:
                assert expected_error in errors, (
                    f"Expected error '{expected_error}' not found in {errors}"
                )

    def test_is_password_valid(self):
        """Test is_password_valid convenience method."""
        hasher = PasswordHasher()

        assert hasher.is_password_valid("ValidPass123!") is True
        assert hasher.is_password_valid("invalid") is False
        assert hasher.is_password_valid("") is False

    def test_different_passwords_produce_different_hashes(self):
        """Test that different passwords produce different hashes."""
        hasher = PasswordHasher()

        password1 = "TestPassword123!"
        password2 = "DifferentPassword456@"

        hash1 = hasher.hash_password(password1)
        hash2 = hasher.hash_password(password2)

        assert hash1 != hash2

    def test_same_password_produces_different_hashes(self):
        """Test that same password produces different hashes due to salt."""
        hasher = PasswordHasher()
        password = "TestPassword123!"

        hash1 = hasher.hash_password(password)
        hash2 = hasher.hash_password(password)

        # Different hashes due to different salts
        assert hash1 != hash2

        # But both should verify correctly
        assert hasher.verify_password(password, hash1) is True
        assert hasher.verify_password(password, hash2) is True

    def test_timing_normalization(self):
        """Test that verification timing is normalized for security."""
        hasher = PasswordHasher()
        password = "TestPassword123!"
        hashed = hasher.hash_password(password)

        # Test multiple verifications to ensure timing consistency
        times = []
        for _ in range(5):
            start = time.time()
            hasher.verify_password("wrong_password", hashed)
            end = time.time()
            times.append(end - start)

        # All times should be reasonably similar (within 50ms variance)
        # This is a basic timing test - in production, more sophisticated timing analysis would be needed
        max_time = max(times)
        min_time = min(times)
        assert (max_time - min_time) < 0.05, (
            "Timing variance too high, potential timing attack vulnerability"
        )


class TestPasswordValidationError:
    """Test cases for PasswordValidationError exception."""

    def test_password_validation_error_creation(self):
        """Test PasswordValidationError creation with error list."""
        errors = ["Error 1", "Error 2"]
        exception = PasswordValidationError(errors)

        assert exception.errors == errors
        assert "Password validation failed: Error 1, Error 2" in str(exception)


class TestFactoryFunction:
    """Test cases for factory function."""

    def test_create_password_hasher(self):
        """Test factory function creates hasher with correct defaults."""
        hasher = create_password_hasher()

        assert isinstance(hasher, PasswordHasher)
        assert hasher.rounds == 12
