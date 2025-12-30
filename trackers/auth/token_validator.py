"""
JWT Token Validator for Google OAuth 2.0.

This module provides the TokenValidator class for handling JWT token verification,
signature validation, and user information extraction from Google ID tokens.
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import jwt
import requests

from .error_handling import AuthLogger, NetworkRetryHandler, TokenValidationError


@dataclass
class UserInfo:
    """User information extracted from Google ID token."""

    google_id: str
    email: str
    name: str
    picture_url: Optional[str]
    verified_email: bool


class TokenValidator:
    """
    JWT Token Validator for Google OAuth 2.0 ID tokens.

    This class handles JWT signature verification using Google's public keys,
    ID token payload extraction and validation, and user information extraction
    from token claims.
    """

    # Google's JSON Web Key Set endpoint
    JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs"

    # Valid Google OAuth issuers
    VALID_ISSUERS = ["https://accounts.google.com", "accounts.google.com"]

    def __init__(self, client_id: str):
        """
        Initialize Token Validator with OAuth client ID.

        Args:
            client_id: Google OAuth client ID for audience validation

        Requirements: 3.4, 4.1, 4.2, 4.3, 4.4
        """
        self.client_id = client_id
        self._session = requests.Session()
        self._session.verify = True  # Always verify SSL certificates
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._jwks_cache_time: float = 0
        self._jwks_cache_ttl: float = 3600  # Cache for 1 hour

        # Initialize error handling components
        self._logger = AuthLogger()
        self._retry_handler = NetworkRetryHandler()

    def validate_and_decode_token(self, id_token: str) -> Dict[str, Any]:
        """
        Validate and decode Google ID token, returning the full payload.

        Args:
            id_token: JWT ID token from Google

        Returns:
            dict: Full decoded and validated token payload

        Raises:
            TokenValidationError: If token validation fails

        Requirements: 3.4, 4.1, 4.3, 4.4 - Validate ID token signature and claims
        """
        try:
            # Decode and validate the token, returning the full payload
            return self._decode_and_verify_token(id_token)
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(
                f"Invalid ID token: {str(e)}", token_error=str(e)
            )
        except requests.RequestException as e:
            # NetworkError will be raised by the @with_error_handling decorator
            raise e

    def validate_id_token(self, id_token: str) -> UserInfo:
        """
        Validate and decode Google ID token.

        Args:
            id_token: JWT ID token from Google

        Returns:
            UserInfo: Validated user information from token

        Raises:
            TokenValidationError: If token validation fails

        Requirements: 3.4, 4.1, 4.3, 4.4 - Validate ID token signature and claims
        """
        try:
            # Decode and validate the token
            payload = self._decode_and_verify_token(id_token)

            # Extract user information from validated payload
            return self.extract_user_info(payload)

        except jwt.InvalidTokenError as e:
            raise TokenValidationError(
                f"Invalid ID token: {str(e)}", token_error=str(e)
            )
        except requests.RequestException as e:
            raise TokenValidationError(
                f"Failed to validate token: {str(e)}", token_error=str(e)
            )

    def extract_user_info(self, token_payload: Dict[str, Any]) -> UserInfo:
        """
        Extract user information from validated ID token payload.

        Args:
            token_payload: Decoded and validated JWT payload

        Returns:
            UserInfo: User information extracted from token claims

        Raises:
            TokenValidationError: If required claims are missing

        Requirements: 4.2 - Extract user email, name, and Google ID from token
        """
        # Validate required claims are present
        required_claims = ["sub", "email", "name"]
        missing_claims = [
            claim
            for claim in required_claims
            if claim not in token_payload or not token_payload[claim]
        ]

        if missing_claims:
            raise TokenValidationError(
                f"Token missing required claims: {missing_claims}",
                token_error=f"missing_claims: {missing_claims}",
            )

        # Extract user information
        return UserInfo(
            google_id=token_payload["sub"],
            email=token_payload["email"],
            name=token_payload["name"],
            picture_url=token_payload.get("picture"),
            verified_email=token_payload.get("email_verified", False),
        )

    def verify_token_signature(self, id_token: str) -> bool:
        """
        Verify JWT token signature using Google's public keys.

        Args:
            id_token: JWT ID token to verify

        Returns:
            bool: True if signature is valid, False otherwise

        Requirements: 3.4 - Implement JWT signature verification using Google's public keys
        """
        try:
            self._decode_and_verify_token(id_token)
            return True
        except (jwt.InvalidTokenError, TokenValidationError, requests.RequestException):
            return False

    def check_token_expiry(self, token_payload: Dict[str, Any]) -> bool:
        """
        Check if token has expired.

        Args:
            token_payload: Decoded JWT payload

        Returns:
            bool: True if token is still valid, False if expired

        Requirements: 4.3 - Validate token expiration
        """
        current_time = int(time.time())
        exp_time = token_payload.get("exp", 0)

        return exp_time > current_time

    def _decode_and_verify_token(self, id_token: str) -> Dict[str, Any]:
        """
        Decode and verify JWT token with full validation.

        Args:
            id_token: JWT ID token to decode and verify

        Returns:
            dict: Decoded and validated token payload

        Raises:
            TokenValidationError: If token validation fails
            jwt.InvalidTokenError: If JWT processing fails
            requests.RequestException: If network request fails
        """
        # First decode without verification to get the header
        try:
            unverified_header = jwt.get_unverified_header(id_token)
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(
                f"Invalid token header: {str(e)}", token_error=str(e)
            )

        # Get the key ID from the token header
        kid = unverified_header.get("kid")
        if not kid:
            raise TokenValidationError(
                "ID token missing key ID in header", token_error="missing_kid"
            )

        # Get the public key for verification
        public_key = self._get_public_key(kid)

        # Verify and decode the token with full validation
        try:
            payload = jwt.decode(
                id_token,
                public_key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=self.VALID_ISSUERS,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.InvalidTokenError as e:
            raise TokenValidationError(
                f"Token validation failed: {str(e)}", token_error=str(e)
            )

        # Additional validation checks
        self._validate_token_claims(payload)

        return payload

    def _get_public_key(self, kid: str) -> Any:
        """
        Get Google's public key for token verification.

        Args:
            kid: Key ID from token header

        Returns:
            Public key for signature verification

        Raises:
            TokenValidationError: If public key cannot be found or retrieved
            requests.RequestException: If network request fails
        """
        # Check if we need to refresh the JWKS cache
        current_time = time.time()
        if (
            self._jwks_cache is None
            or current_time - self._jwks_cache_time > self._jwks_cache_ttl
        ):
            self._refresh_jwks_cache()

        # Find the matching public key
        if self._jwks_cache:
            for key in self._jwks_cache.get("keys", []):
                if key.get("kid") == kid:
                    try:
                        # Convert JWK to PEM format
                        return jwt.algorithms.RSAAlgorithm.from_jwk(key)
                    except Exception as e:
                        raise TokenValidationError(
                            f"Failed to convert JWK to public key: {str(e)}",
                            token_error=f"jwk_conversion_error: {str(e)}",
                        )

        raise TokenValidationError(
            f"Public key not found for key ID: {kid}",
            token_error=f"key_not_found: {kid}",
        )

    def _refresh_jwks_cache(self) -> None:
        """
        Refresh the JWKS cache from Google's endpoint.

        Raises:
            requests.RequestException: If network request fails
        """

        def _make_jwks_request():
            """Internal function for JWKS request with retry logic."""
            response = self._session.get(self.JWKS_URI, timeout=10)
            response.raise_for_status()
            return response

        try:
            response = self._retry_handler.retry_with_backoff(_make_jwks_request)
            self._jwks_cache = response.json()
            self._jwks_cache_time = time.time()
        except requests.RequestException as e:
            # NetworkError will be raised by the calling code's @with_error_handling decorator
            raise e

    def _validate_token_claims(self, payload: Dict[str, Any]) -> None:
        """
        Validate additional token claims beyond standard JWT validation.

        Args:
            payload: Decoded JWT payload

        Raises:
            TokenValidationError: If token claims are invalid

        Requirements: 4.4 - Verify token audience matches OAuth client ID
        """
        current_time = int(time.time())

        # Check issued at time (not too far in the future)
        iat = payload.get("iat", 0)
        if iat > current_time + 300:  # 5 minute tolerance
            raise TokenValidationError(
                "Token issued too far in the future", token_error="invalid_iat"
            )

        # Validate audience matches our client ID
        aud = payload.get("aud")
        if aud != self.client_id:
            raise TokenValidationError(
                f"Token audience mismatch: expected {self.client_id}, got {aud}",
                token_error="audience_mismatch",
            )

        # Validate issuer is from Google
        iss = payload.get("iss")
        if iss not in self.VALID_ISSUERS:
            raise TokenValidationError(
                f"Invalid token issuer: {iss}", token_error="invalid_issuer"
            )

        # Validate subject (user ID) is present
        sub = payload.get("sub")
        if not sub:
            raise TokenValidationError(
                "Token missing subject (user ID)", token_error="missing_subject"
            )

        # Validate email is present and marked as verified
        email = payload.get("email")
        if not email:
            raise TokenValidationError(
                "Token missing email claim", token_error="missing_email"
            )

        # Note: We don't require email_verified to be True here as some Google accounts
        # may not have verified emails, but we extract this information for the caller to decide

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - close session."""
        self._session.close()
