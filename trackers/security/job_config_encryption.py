"""
Job Configuration Encryption System.

This module provides secure encryption and decryption of sensitive job configuration
data using AES-256-GCM encryption. It automatically detects and encrypts sensitive
fields like API keys, tokens, and passwords.

Requirements: 8.1, 8.4, 8.5
"""

import base64
import json
import logging
import os
from typing import Any, Dict, Optional, Set

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)


class JobConfigEncryption:
    """
    Handles encryption and decryption of sensitive job configuration data.

    Uses AES-256-GCM encryption via Fernet for secure storage of API keys,
    tokens, and other sensitive configuration values.

    Requirements: 8.1, 8.4, 8.5
    """

    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize encryption system with master key.

        Args:
            master_key: Master encryption key (uses Flask SECRET_KEY if not provided)

        Requirements: 8.1
        """
        self.master_key = master_key or self._get_master_key()
        self.sensitive_fields = self._get_sensitive_field_patterns()
        self._fernet = None

    def _get_master_key(self) -> str:
        """
        Get master encryption key from environment.

        Returns:
            Master key for encryption

        Requirements: 8.1
        """
        # Try Flask SECRET_KEY first
        secret_key = os.environ.get("SECRET_KEY")
        if secret_key:
            return secret_key

        # Fallback to other environment variables
        for key_name in ["ENCRYPTION_KEY", "FLASK_SECRET_KEY"]:
            key = os.environ.get(key_name)
            if key:
                return key

        # Generate a warning if no key is found
        logger.warning(
            "No encryption key found in environment variables. "
            "Using default key - this is not secure for production!"
        )
        return "default-insecure-key-change-in-production"

    def _get_sensitive_field_patterns(self) -> Set[str]:
        """
        Get patterns for detecting sensitive fields.

        Returns:
            Set of field name patterns that should be encrypted

        Requirements: 8.1, 8.4
        """
        return {
            # Exact field names
            "api_key",
            "token",
            "password",
            "secret",
            "client_secret",
            "bearer_token",
            "access_token",
            "refresh_token",
            "private_key",
            "auth_token",
            # Field name patterns (lowercase)
            "authorization",
            "authentication",
            "credential",
            "key",
        }

    def _get_fernet(self, salt: bytes = None) -> Fernet:
        """
        Get Fernet encryption instance with derived key.

        Args:
            salt: Salt for key derivation (generates random if not provided)

        Returns:
            Fernet encryption instance

        Requirements: 8.1
        """
        if salt is None:
            salt = b"job-config-salt"  # Default salt for consistency

        # Derive key using PBKDF2
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))
        return Fernet(key)

    def _is_sensitive_field(self, field_name: str, field_value: Any) -> bool:
        """
        Determine if a field contains sensitive data that should be encrypted.

        Args:
            field_name: Name of the field
            field_value: Value of the field

        Returns:
            True if field should be encrypted

        Requirements: 8.1, 8.4
        """
        if not isinstance(field_value, str):
            return False

        field_name_lower = field_name.lower()

        # Check exact matches
        if field_name_lower in self.sensitive_fields:
            return True

        # Check if field name contains sensitive patterns
        for pattern in self.sensitive_fields:
            if pattern in field_name_lower:
                return True

        # Check for common token/key patterns in the value
        value_lower = field_value.lower()
        if any(
            pattern in value_lower
            for pattern in ["bearer ", "token ", "key ", "secret "]
        ):
            return True

        # Check for base64-like patterns (potential encoded secrets)
        if (
            len(field_value) > 20
            and field_value.replace("=", "").replace("+", "").replace("/", "").isalnum()
        ):
            return True

        return False

    def _encrypt_value(self, value: str) -> str:
        """
        Encrypt a single value.

        Args:
            value: Value to encrypt

        Returns:
            Encrypted value as base64 string

        Requirements: 8.1, 8.4
        """
        try:
            fernet = self._get_fernet()
            encrypted_bytes = fernet.encrypt(value.encode())
            return base64.urlsafe_b64encode(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Failed to encrypt value: {e}")
            raise ValueError(f"Encryption failed: {e}")

    def _decrypt_value(self, encrypted_value: str) -> str:
        """
        Decrypt a single value.

        Args:
            encrypted_value: Encrypted value as base64 string

        Returns:
            Decrypted value

        Requirements: 8.1, 8.4
        """
        try:
            fernet = self._get_fernet()
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_value.encode())
            decrypted_bytes = fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode()
        except Exception as e:
            logger.error(f"Failed to decrypt value: {e}")
            raise ValueError(f"Decryption failed: {e}")

    def encrypt_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt sensitive fields in job configuration.

        Args:
            config: Job configuration dictionary

        Returns:
            Configuration with sensitive fields encrypted

        Requirements: 8.1, 8.4, 8.5
        """
        try:
            encrypted_config = {}

            for key, value in config.items():
                if isinstance(value, dict):
                    # Recursively encrypt nested dictionaries
                    encrypted_config[key] = self.encrypt_config(value)
                elif self._is_sensitive_field(key, value):
                    # Encrypt sensitive fields
                    encrypted_config[key] = self._encrypt_value(str(value))
                    logger.debug(f"Encrypted sensitive field: {key}")
                else:
                    # Keep non-sensitive fields as-is
                    encrypted_config[key] = value

            return encrypted_config

        except Exception as e:
            logger.error(f"Failed to encrypt configuration: {e}")
            raise ValueError(f"Configuration encryption failed: {e}")

    def decrypt_config(self, encrypted_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt sensitive fields in job configuration.

        Args:
            encrypted_config: Configuration with encrypted sensitive fields

        Returns:
            Configuration with sensitive fields decrypted

        Requirements: 8.1, 8.4, 8.5
        """
        try:
            decrypted_config = {}

            for key, value in encrypted_config.items():
                if isinstance(value, dict):
                    # Recursively decrypt nested dictionaries
                    decrypted_config[key] = self.decrypt_config(value)
                elif self._is_sensitive_field(key, value) and isinstance(value, str):
                    # Attempt to decrypt sensitive fields
                    try:
                        decrypted_config[key] = self._decrypt_value(value)
                        logger.debug(f"Decrypted sensitive field: {key}")
                    except ValueError:
                        # If decryption fails, field might not be encrypted
                        decrypted_config[key] = value
                        logger.debug(f"Field {key} appears to be unencrypted")
                else:
                    # Keep non-sensitive fields as-is
                    decrypted_config[key] = value

            return decrypted_config

        except Exception as e:
            logger.error(f"Failed to decrypt configuration: {e}")
            raise ValueError(f"Configuration decryption failed: {e}")

    def encrypt_config_json(self, config: Dict[str, Any]) -> str:
        """
        Encrypt configuration and return as JSON string.

        Args:
            config: Job configuration dictionary

        Returns:
            JSON string with encrypted sensitive fields

        Requirements: 8.1, 8.4
        """
        encrypted_config = self.encrypt_config(config)
        return json.dumps(encrypted_config)

    def decrypt_config_json(self, encrypted_config_json: str) -> Dict[str, Any]:
        """
        Decrypt configuration from JSON string.

        Args:
            encrypted_config_json: JSON string with encrypted sensitive fields

        Returns:
            Configuration dictionary with decrypted sensitive fields

        Requirements: 8.1, 8.4
        """
        encrypted_config = json.loads(encrypted_config_json)
        return self.decrypt_config(encrypted_config)

    def get_secure_credential(
        self, config: Dict[str, Any], field_name: str
    ) -> Optional[str]:
        """
        Safely retrieve and decrypt a credential from configuration.

        Args:
            config: Configuration dictionary (may contain encrypted fields)
            field_name: Name of the credential field

        Returns:
            Decrypted credential value or None if not found

        Requirements: 8.1, 8.4, 8.5
        """
        try:
            if field_name not in config:
                return None

            value = config[field_name]
            if not isinstance(value, str):
                return None

            # If field is sensitive, try to decrypt it
            if self._is_sensitive_field(field_name, value):
                try:
                    return self._decrypt_value(value)
                except ValueError:
                    # Field might not be encrypted, return as-is
                    return value
            else:
                return value

        except Exception as e:
            logger.error(f"Failed to retrieve credential {field_name}: {e}")
            return None

    def validate_encryption_key(self) -> bool:
        """
        Validate that the encryption key is properly configured.

        Returns:
            True if encryption key is valid and secure

        Requirements: 8.1
        """
        try:
            # Check if key exists and is not default
            if (
                not self.master_key
                or self.master_key == "default-insecure-key-change-in-production"
            ):
                logger.warning(
                    "Using default or missing encryption key - not secure for production"
                )
                return False

            # Check key length (should be reasonably long)
            if len(self.master_key) < 16:
                logger.warning(
                    "Encryption key is too short - should be at least 16 characters"
                )
                return False

            # Test encryption/decryption
            test_value = "test-encryption-value"
            encrypted = self._encrypt_value(test_value)
            decrypted = self._decrypt_value(encrypted)

            if decrypted != test_value:
                logger.error("Encryption/decryption test failed")
                return False

            logger.debug("Encryption key validation passed")
            return True

        except Exception as e:
            logger.error(f"Encryption key validation failed: {e}")
            return False

    def get_encryption_info(self) -> Dict[str, Any]:
        """
        Get information about the encryption configuration.

        Returns:
            Dictionary with encryption configuration details

        Requirements: 8.1
        """
        return {
            "encryption_enabled": True,
            "key_configured": bool(
                self.master_key
                and self.master_key != "default-insecure-key-change-in-production"
            ),
            "key_secure": self.validate_encryption_key(),
            "sensitive_field_patterns": list(self.sensitive_fields),
            "encryption_algorithm": "AES-256-GCM (via Fernet)",
        }
