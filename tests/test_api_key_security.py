"""
Comprehensive test suite for API key security system.

This module provides complete test coverage for the API key authentication system,
including unit tests for individual components, integration tests with Flask,
and tests for various authentication scenarios and edge cases.
"""

import os
from unittest.mock import Mock, patch

import pytest
from flask import Flask, jsonify

from trackers.security.api_key_auth import (
    AuthErrorHandler,
    KeyValidator,
    SecurityConfig,
    SecurityLogger,
    api_key_required,
    create_auth_error_response,
    get_request_info,
    init_security,
    validate_authorization_header,
)


class TestSecurityConfig:
    """Test SecurityConfig class functionality."""

    def test_load_api_keys_from_environment(self):
        """Test loading API keys from environment variables."""
        with patch.dict(
            os.environ,
            {
                "API_KEYS": "valid-key-1234567890,another-key-0987654321,third-key-1122334455"
            },
        ):
            config = SecurityConfig()

            assert len(config.api_keys) == 3
            assert "valid-key-1234567890" in config.api_keys
            assert "another-key-0987654321" in config.api_keys
            assert "third-key-1122334455" in config.api_keys
            assert config.authentication_enabled is True

    def test_empty_api_keys_disables_authentication(self):
        """Test that empty API keys disable authentication."""
        with patch.dict(os.environ, {}, clear=True):
            config = SecurityConfig()

            assert len(config.api_keys) == 0
            assert config.authentication_enabled is False

    def test_api_keys_with_whitespace_handling(self):
        """Test API key parsing handles whitespace correctly."""
        with patch.dict(
            os.environ,
            {
                "API_KEYS": " valid-key-1234567890 , another-key-0987654321 ,  third-key-1122334455  "
            },
        ):
            config = SecurityConfig()

            assert len(config.api_keys) == 3
            assert "valid-key-1234567890" in config.api_keys
            assert "another-key-0987654321" in config.api_keys
            assert "third-key-1122334455" in config.api_keys

    def test_validate_key_security_minimum_length(self):
        """Test API key security validation for minimum length."""
        config = SecurityConfig()

        # Valid keys (16+ characters)
        assert config.validate_key_security("1234567890123456") is True
        assert config.validate_key_security("very-long-secure-api-key") is True

        # Invalid keys (< 16 characters)
        assert config.validate_key_security("short") is False
        assert config.validate_key_security("123456789012345") is False

    def test_validate_key_security_whitespace_only(self):
        """Test API key security validation rejects whitespace-only keys."""
        config = SecurityConfig()

        assert config.validate_key_security("") is False
        assert config.validate_key_security("   ") is False
        assert config.validate_key_security("\t\n") is False

    def test_route_protection_default_patterns(self):
        """Test default route protection patterns."""
        with patch.dict(os.environ, {}, clear=True):
            config = SecurityConfig()

            protected_routes = config.get_protected_routes()
            public_routes = config.get_public_routes()

            assert "/api/*" in protected_routes
            assert "/trackers/*" in protected_routes
            assert "/tracker-values/*" in protected_routes

            assert "/health" in public_routes
            assert "/health/*" in public_routes
            assert "/status" in public_routes

    def test_is_route_protected_logic(self):
        """Test route protection logic with various patterns."""
        config = SecurityConfig()

        # Protected routes
        assert config.is_route_protected("/api/trackers") is True
        assert config.is_route_protected("/trackers/123") is True
        assert config.is_route_protected("/tracker-values/456") is True

        # Public routes
        assert config.is_route_protected("/health") is False
        assert config.is_route_protected("/health/detailed") is False
        assert config.is_route_protected("/status") is False
        assert config.is_route_protected("/hello") is False

    def test_custom_route_patterns_from_environment(self):
        """Test custom route patterns from environment variables."""
        with patch.dict(
            os.environ,
            {
                "PROTECTED_ROUTES": "/custom/*,/admin/*",
                "PUBLIC_ROUTES": "/public/*,/docs/*",
            },
        ):
            config = SecurityConfig()

            assert "/custom/*" in config.get_protected_routes()
            assert "/admin/*" in config.get_protected_routes()
            assert "/public/*" in config.get_public_routes()
            assert "/docs/*" in config.get_public_routes()


class TestKeyValidator:
    """Test KeyValidator class functionality."""

    def test_valid_key_validation(self):
        """Test validation of valid API keys."""
        with patch.dict(
            os.environ, {"API_KEYS": "valid-key-1234567890,another-valid-key-123456"}
        ):
            config = SecurityConfig()
            validator = KeyValidator(config)

            assert validator.is_valid_key("valid-key-1234567890") is True
            assert validator.is_valid_key("another-valid-key-123456") is True

    def test_invalid_key_validation(self):
        """Test validation of invalid API keys."""
        with patch.dict(os.environ, {"API_KEYS": "valid-key-1234567890"}):
            config = SecurityConfig()
            validator = KeyValidator(config)

            assert validator.is_valid_key("invalid-key") is False
            assert validator.is_valid_key("wrong-key-1234567890") is False
            assert validator.is_valid_key("") is False
            assert validator.is_valid_key(None) is False

    def test_authentication_enabled_status(self):
        """Test authentication enabled status based on configuration."""
        # With valid keys
        with patch.dict(os.environ, {"API_KEYS": "test-key-1234567890"}):
            config = SecurityConfig()
            validator = KeyValidator(config)
            assert validator.is_authentication_enabled() is True

        # Without keys
        with patch.dict(os.environ, {}, clear=True):
            config = SecurityConfig()
            validator = KeyValidator(config)
            assert validator.is_authentication_enabled() is False

    def test_constant_time_comparison(self):
        """Test constant-time string comparison for security."""
        with patch.dict(os.environ, {"API_KEYS": "test-key-1234567890"}):
            config = SecurityConfig()
            validator = KeyValidator(config)

            # Test that comparison works correctly
            assert validator._constant_time_compare("test", "test") is True
            assert validator._constant_time_compare("test", "different") is False
            assert validator._constant_time_compare("", "") is True
            assert validator._constant_time_compare("test", "") is False

    def test_user_key_validation_with_api_service(self):
        """Test validation of user-created API keys through API key service."""
        from trackers.services.api_key_service import APIKeyValidationResult

        # Create mock API key service
        mock_api_service = Mock()

        # Set up mock to return valid result for uk_ prefixed keys
        mock_validation_result = APIKeyValidationResult(
            is_valid=True, user_id=123, key_info=None, validation_error=None
        )
        mock_api_service.validate_user_api_key.return_value = mock_validation_result

        with patch.dict(os.environ, {"API_KEYS": "env-key-1234567890123456"}):
            config = SecurityConfig()
            validator = KeyValidator(config, mock_api_service)

            # Test environment key validation (should work as before)
            assert validator.is_valid_key("env-key-1234567890123456") is True

            # Test user key validation (should use API key service)
            assert (
                validator.is_valid_key("uk_test123456789012345678901234567890") is True
            )

            # Verify the API key service was called for user keys
            mock_api_service.validate_user_api_key.assert_called_with(
                "uk_test123456789012345678901234567890"
            )

    def test_user_key_validation_invalid_key(self):
        """Test validation of invalid user-created API keys."""
        from trackers.services.api_key_service import APIKeyValidationResult

        # Create mock API key service
        mock_api_service = Mock()

        # Set up mock to return invalid result
        mock_validation_result = APIKeyValidationResult(
            is_valid=False, user_id=None, key_info=None, validation_error="Invalid key"
        )
        mock_api_service.validate_user_api_key.return_value = mock_validation_result

        with patch.dict(os.environ, {"API_KEYS": "env-key-1234567890123456"}):
            config = SecurityConfig()
            validator = KeyValidator(config, mock_api_service)

            # Test invalid user key
            assert validator.is_valid_key("uk_invalid_key") is False

    def test_user_key_validation_without_api_service(self):
        """Test that user keys fail gracefully when no API service is provided."""
        with patch.dict(os.environ, {"API_KEYS": "env-key-1234567890123456"}):
            config = SecurityConfig()
            validator = KeyValidator(config, None)  # No API service

            # Test environment key validation (should work as before)
            assert validator.is_valid_key("env-key-1234567890123456") is True

            # Test user key validation (should fail gracefully)
            assert (
                validator.is_valid_key("uk_test123456789012345678901234567890") is False
            )

    def test_user_key_validation_api_service_exception(self):
        """Test that API service exceptions are handled gracefully."""
        # Create mock API key service that raises an exception
        mock_api_service = Mock()
        mock_api_service.validate_user_api_key.side_effect = Exception("Database error")

        with patch.dict(os.environ, {"API_KEYS": "env-key-1234567890123456"}):
            config = SecurityConfig()
            validator = KeyValidator(config, mock_api_service)

            # Test that exception is caught and key is treated as invalid
            assert (
                validator.is_valid_key("uk_test123456789012345678901234567890") is False
            )

            # Environment keys should still work
            assert validator.is_valid_key("env-key-1234567890123456") is True


class TestSecurityLogger:
    """Test SecurityLogger class functionality."""

    def test_log_successful_auth(self):
        """Test logging of successful authentication attempts."""
        mock_logger = Mock()
        security_logger = SecurityLogger(mock_logger)

        request_info = {
            "endpoint": "/api/trackers",
            "method": "GET",
            "ip_address": "192.168.1.1",
        }

        security_logger.log_successful_auth(request_info)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "API authentication successful" in call_args
        assert "/api/trackers" in call_args
        assert "GET" in call_args
        assert "192.168.1.1" in call_args

    def test_log_failed_auth(self):
        """Test logging of failed authentication attempts."""
        mock_logger = Mock()
        security_logger = SecurityLogger(mock_logger)

        request_info = {
            "endpoint": "/api/trackers",
            "method": "POST",
            "ip_address": "192.168.1.2",
        }

        security_logger.log_failed_auth(request_info, "Invalid API key")

        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        assert "API authentication failed" in call_args
        assert "Invalid API key" in call_args
        assert "/api/trackers" in call_args
        assert "POST" in call_args
        assert "192.168.1.2" in call_args

    def test_log_missing_auth(self):
        """Test logging of missing authentication attempts."""
        mock_logger = Mock()
        security_logger = SecurityLogger(mock_logger)

        request_info = {
            "endpoint": "/api/trackers",
            "method": "DELETE",
            "ip_address": "192.168.1.3",
        }

        security_logger.log_missing_auth(request_info)

        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        assert "API authentication missing" in call_args
        assert "/api/trackers" in call_args
        assert "DELETE" in call_args
        assert "192.168.1.3" in call_args

    def test_log_config_loaded(self):
        """Test logging of configuration loading."""
        mock_logger = Mock()
        security_logger = SecurityLogger(mock_logger)

        # Test with keys enabled
        security_logger.log_config_loaded(3)
        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "API key authentication enabled" in call_args
        assert "3 valid keys" in call_args

        # Test with no keys
        mock_logger.reset_mock()
        security_logger.log_config_loaded(0)
        mock_logger.warning.assert_called_once()
        call_args = mock_logger.warning.call_args[0][0]
        assert "API key authentication disabled" in call_args


class TestAuthErrorHandler:
    """Test AuthErrorHandler class functionality."""

    def test_create_error_response_standard_messages(self):
        """Test creating error responses with standard messages."""
        app = Flask(__name__)
        with app.app_context():
            response, status_code = AuthErrorHandler.create_error_response(
                "missing_key"
            )

            assert status_code == 401
            response_data = response.get_json()
            assert response_data["error"] == "Unauthorized"
            assert response_data["message"] == "API key required"
            assert response_data["status_code"] == 401

    def test_create_error_response_custom_message(self):
        """Test creating error responses with custom messages."""
        app = Flask(__name__)
        with app.app_context():
            custom_message = "Custom error message"
            response, status_code = AuthErrorHandler.create_error_response(
                "invalid_key", custom_message
            )

            assert status_code == 401
            response_data = response.get_json()
            assert response_data["message"] == custom_message

    def test_handle_missing_header(self):
        """Test handling missing Authorization header."""
        app = Flask(__name__)
        with app.app_context():
            response, status_code = AuthErrorHandler.handle_missing_header()

            assert status_code == 401
            response_data = response.get_json()
            assert response_data["message"] == "API key required"

    def test_handle_invalid_format(self):
        """Test handling invalid Authorization header format."""
        app = Flask(__name__)
        with app.app_context():
            response, status_code = AuthErrorHandler.handle_invalid_format()

            assert status_code == 401
            response_data = response.get_json()
            assert response_data["message"] == "Invalid authorization header format"

    def test_handle_invalid_key(self):
        """Test handling invalid API key."""
        app = Flask(__name__)
        with app.app_context():
            response, status_code = AuthErrorHandler.handle_invalid_key()

            assert status_code == 401
            response_data = response.get_json()
            assert response_data["message"] == "Invalid API key"


class TestAuthorizationHeaderValidation:
    """Test authorization header validation functionality."""

    def test_valid_bearer_token(self):
        """Test validation of valid Bearer token format."""
        is_valid, api_key, error_message = validate_authorization_header(
            "Bearer test-key-1234567890"
        )

        assert is_valid is True
        assert api_key == "test-key-1234567890"
        assert error_message is None

    def test_missing_header(self):
        """Test validation of missing authorization header."""
        is_valid, api_key, error_message = validate_authorization_header(None)

        assert is_valid is False
        assert api_key is None
        assert error_message == "API key required"

    def test_empty_header(self):
        """Test validation of empty authorization header."""
        is_valid, api_key, error_message = validate_authorization_header("")

        assert is_valid is False
        assert api_key is None
        assert error_message == "API key required"

    def test_whitespace_only_header(self):
        """Test validation of whitespace-only authorization header."""
        is_valid, api_key, error_message = validate_authorization_header("   ")

        assert is_valid is False
        assert api_key is None
        assert error_message == "API key required"

    def test_invalid_format_no_bearer(self):
        """Test validation of header without Bearer prefix."""
        is_valid, api_key, error_message = validate_authorization_header(
            "test-key-1234567890"
        )

        assert is_valid is False
        assert api_key is None
        assert error_message == "Invalid authorization header format"

    def test_bearer_without_key(self):
        """Test validation of Bearer without actual key."""
        is_valid, api_key, error_message = validate_authorization_header("Bearer ")

        assert is_valid is False
        assert api_key is None
        assert error_message == "API key required"

    def test_bearer_with_whitespace_key(self):
        """Test validation of Bearer with whitespace-only key."""
        is_valid, api_key, error_message = validate_authorization_header("Bearer   ")

        assert is_valid is False
        assert api_key is None
        assert error_message == "API key required"

    def test_bearer_with_key_and_whitespace(self):
        """Test validation of Bearer with key containing whitespace."""
        is_valid, api_key, error_message = validate_authorization_header(
            "Bearer  test-key-1234567890  "
        )

        assert is_valid is True
        assert api_key == "test-key-1234567890"  # Should be trimmed
        assert error_message is None


class TestApiKeyDecorator:
    """Test @api_key_required decorator functionality."""

    def _check_response(
        self, result, expected_status, expected_message_key=None, expected_message=None
    ):
        """Helper method to check response from decorator (handles tuple returns)."""
        if isinstance(result, tuple):
            response, status_code = result
            assert status_code == expected_status
            if expected_message_key:
                assert response.get_json()[expected_message_key] == expected_message
            return response.get_json()
        else:
            assert result.status_code == expected_status
            if expected_message_key:
                assert result.get_json()[expected_message_key] == expected_message
            return result.get_json()

    def test_decorator_with_valid_key(self):
        """Test decorator allows access with valid API key."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-test-key-123456"}):
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                with app.test_request_context(
                    "/api/test",  # Use protected route pattern
                    headers={"Authorization": "Bearer valid-test-key-123456"},
                ):
                    response = test_endpoint()
                    data = self._check_response(response, 200, "message", "success")

    def test_decorator_with_invalid_key(self):
        """Test decorator rejects access with invalid API key."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-test-key-123456"}):
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                with app.test_request_context(
                    "/api/test",  # Use protected route pattern
                    headers={"Authorization": "Bearer invalid-key"},
                ):
                    response = test_endpoint()
                    data = self._check_response(response, 401, "error", "Unauthorized")

    def test_decorator_with_missing_header(self):
        """Test decorator rejects access with missing Authorization header."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-test-key-123456"}):
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                with app.test_request_context(
                    "/api/test"
                ):  # Use protected route pattern
                    response = test_endpoint()
                    data = self._check_response(
                        response, 401, "message", "API key required"
                    )

    def test_decorator_with_malformed_header(self):
        """Test decorator rejects access with malformed Authorization header."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-test-key-123456"}):
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                with app.test_request_context(
                    "/api/test",  # Use protected route pattern
                    headers={"Authorization": "InvalidFormat valid-test-key-123456"},
                ):
                    response = test_endpoint()
                    data = self._check_response(
                        response, 401, "message", "Invalid authorization header format"
                    )

    def test_decorator_when_authentication_disabled(self):
        """Test decorator allows access when authentication is disabled."""
        app = Flask(__name__)

        with patch.dict(os.environ, {}, clear=True):  # No API keys
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                with app.test_request_context(
                    "/api/test"
                ):  # Use protected route pattern
                    response = test_endpoint()
                    data = self._check_response(response, 200, "message", "success")

    def test_decorator_with_public_route(self):
        """Test decorator allows access to public routes without authentication."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-test-key-123456"}):
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                # Test with a public route path
                with app.test_request_context("/health"):
                    response = test_endpoint()
                    data = self._check_response(response, 200, "message", "success")


class TestFlaskIntegration:
    """Test Flask application integration with API key security."""

    def test_security_initialization(self):
        """Test security system initialization with Flask app."""
        app = Flask(__name__)

        with patch.dict(
            os.environ, {"API_KEYS": "test-key-1234567890,another-key-0987654321"}
        ):
            with app.app_context():
                security_config = init_security(app)

                # Verify all components are initialized
                assert hasattr(app, "security_config")
                assert hasattr(app, "key_validator")
                assert hasattr(app, "security_logger")
                assert hasattr(app, "production_enforcer")

                # Verify configuration
                assert security_config.authentication_enabled is True
                assert len(security_config.api_keys) == 2

    def test_before_request_handler_with_valid_key(self):
        """Test before_request handler allows valid API keys."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-integration-key-123456"}):
            init_security(app)

            @app.route("/api/test")
            def test_route():
                return jsonify({"message": "success"})

            with app.test_client() as client:
                response = client.get(
                    "/api/test",
                    headers={"Authorization": "Bearer valid-integration-key-123456"},
                )

                assert response.status_code == 200
                assert response.get_json()["message"] == "success"

    def test_before_request_handler_with_invalid_key(self):
        """Test before_request handler rejects invalid API keys."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-integration-key-123456"}):
            init_security(app)

            @app.route("/api/test")
            def test_route():
                return jsonify({"message": "success"})

            with app.test_client() as client:
                response = client.get(
                    "/api/test", headers={"Authorization": "Bearer invalid-key"}
                )

                assert response.status_code == 401
                assert response.get_json()["error"] == "Unauthorized"

    def test_before_request_handler_public_routes(self):
        """Test before_request handler allows public routes without authentication."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "valid-integration-key-123456"}):
            init_security(app)

            @app.route("/health")
            def health_route():
                return jsonify({"status": "healthy"})

            with app.test_client() as client:
                response = client.get("/health")

                assert response.status_code == 200
                assert response.get_json()["status"] == "healthy"

    def test_before_request_handler_when_disabled(self):
        """Test before_request handler when authentication is disabled."""
        app = Flask(__name__)

        with patch.dict(os.environ, {}, clear=True):  # No API keys
            init_security(app)

            @app.route("/api/test")
            def test_route():
                return jsonify({"message": "success"})

            with app.test_client() as client:
                response = client.get("/api/test")

                assert response.status_code == 200
                assert response.get_json()["message"] == "success"


class TestErrorHandlingAndEdgeCases:
    """Test error handling and edge cases."""

    def test_get_request_info_with_missing_attributes(self):
        """Test get_request_info handles missing request attributes gracefully."""
        app = Flask(__name__)

        with app.test_request_context("/test"):
            request_info = get_request_info()

            assert "endpoint" in request_info
            assert "method" in request_info
            assert "ip_address" in request_info
            assert "timestamp" in request_info
            assert "user_agent" in request_info

    def test_create_auth_error_response_format(self):
        """Test auth error response format consistency."""
        app = Flask(__name__)
        with app.app_context():
            response, status_code = create_auth_error_response(
                "test_error", "Test error message"
            )

            assert status_code == 401
            response_data = response.get_json()
            assert response_data["error"] == "Unauthorized"
            assert response_data["message"] == "Test error message"
            assert response_data["status_code"] == 401

    def test_decorator_exception_handling(self):
        """Test decorator handles unexpected exceptions gracefully."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "test-key-1234567890"}):
            with app.app_context():
                init_security(app)

                # Mock key_validator to raise an exception
                app.key_validator.is_valid_key = Mock(
                    side_effect=Exception("Test error")
                )

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                with app.test_request_context(
                    "/api/test",  # Use protected route pattern
                    headers={"Authorization": "Bearer test-key-1234567890"},
                ):
                    result = test_endpoint()
                    # Handle tuple return from decorator
                    if isinstance(result, tuple):
                        response, status_code = result
                        assert status_code == 401
                        assert (
                            "Authentication system temporarily unavailable"
                            in response.get_json()["message"]
                        )
                    else:
                        assert result.status_code == 401
                        assert (
                            "Authentication system temporarily unavailable"
                            in result.get_json()["message"]
                        )

    def test_security_config_with_invalid_keys_filtered(self):
        """Test that invalid keys are filtered out during configuration."""
        with patch.dict(
            os.environ,
            {"API_KEYS": "short,valid-key-1234567890,   ,another-valid-key-123456"},
        ):
            config = SecurityConfig()

            # Should only contain valid keys (16+ chars, not whitespace-only)
            assert len(config.api_keys) == 2
            assert "valid-key-1234567890" in config.api_keys
            assert "another-valid-key-123456" in config.api_keys
            assert "short" not in config.api_keys

    def test_multiple_authentication_scenarios(self):
        """Test various authentication scenarios in sequence."""
        app = Flask(__name__)

        with patch.dict(
            os.environ,
            {"API_KEYS": "scenario-test-key-123456,another-scenario-key-789012"},
        ):
            init_security(app)

            @app.route("/api/test")
            def test_route():
                return jsonify({"message": "success"})

            with app.test_client() as client:
                # Valid key 1
                response = client.get(
                    "/api/test",
                    headers={"Authorization": "Bearer scenario-test-key-123456"},
                )
                assert response.status_code == 200

                # Valid key 2
                response = client.get(
                    "/api/test",
                    headers={"Authorization": "Bearer another-scenario-key-789012"},
                )
                assert response.status_code == 200

                # Invalid key
                response = client.get(
                    "/api/test", headers={"Authorization": "Bearer invalid-key"}
                )
                assert response.status_code == 401

                # Missing header
                response = client.get("/api/test")
                assert response.status_code == 401

                # Malformed header
                response = client.get(
                    "/api/test", headers={"Authorization": "InvalidFormat key"}
                )
                assert response.status_code == 401

    def test_case_sensitive_key_validation(self):
        """Test that API key validation is case-sensitive."""
        app = Flask(__name__)

        with patch.dict(os.environ, {"API_KEYS": "CaseSensitiveKey123456"}):
            with app.app_context():
                init_security(app)

                @api_key_required
                def test_endpoint():
                    return jsonify({"message": "success"})

                # Correct case
                with app.test_request_context(
                    "/api/test",  # Use protected route pattern
                    headers={"Authorization": "Bearer CaseSensitiveKey123456"},
                ):
                    result = test_endpoint()
                    if isinstance(result, tuple):
                        response, status_code = result
                        assert status_code == 200
                    else:
                        assert result.status_code == 200

                # Wrong case
                with app.test_request_context(
                    "/api/test",  # Use protected route pattern
                    headers={"Authorization": "Bearer casesensitivekey123456"},
                ):
                    result = test_endpoint()
                    if isinstance(result, tuple):
                        response, status_code = result
                        assert status_code == 401
                    else:
                        assert result.status_code == 401


if __name__ == "__main__":
    pytest.main([__file__])
