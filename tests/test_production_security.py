"""
Tests for production environment security features.

This module tests the enhanced security features for production environments,
including environment-specific configuration, proxy header support, key rotation,
and HTTPS enforcement.
"""

import os
import time
from unittest.mock import Mock, patch

import pytest
from flask import Flask

from trackers.security.api_key_auth import (
    ProductionConfig,
    ProductionSecurityEnforcer,
    SecurityConfig,
    init_security,
)


class TestProductionConfig:
    """Test production configuration functionality."""

    def test_production_config_from_environment(self):
        """Test creating production config from environment variables."""
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "production",
                "ENABLE_API_KEY_ROTATION": "true",
                "API_KEY_RELOAD_INTERVAL": "600",
                "TRUST_PROXY_HEADERS": "true",
                "REQUIRE_HTTPS": "true",
            },
        ):
            config = ProductionConfig.from_environment()

            assert config.environment == "production"
            assert config.enable_key_rotation is True
            assert config.key_reload_interval == 600.0
            assert config.trust_proxy_headers is True
            assert config.require_https is True

    def test_development_config_defaults(self):
        """Test development environment defaults."""
        with patch.dict(os.environ, {}, clear=True):
            config = ProductionConfig.from_environment()

            assert config.environment == "development"
            assert config.enable_key_rotation is True  # Default enabled
            assert config.key_reload_interval == 300.0  # 5 minutes default
            assert config.trust_proxy_headers is False  # Not auto-enabled in dev
            assert config.require_https is False  # Not required in dev

    def test_staging_environment_auto_proxy_trust(self):
        """Test that staging environment automatically trusts proxy headers."""
        with patch.dict(os.environ, {"FLASK_ENV": "staging"}):
            config = ProductionConfig.from_environment()

            assert config.environment == "staging"
            assert config.trust_proxy_headers is True  # Auto-enabled in staging


class TestSecurityConfigEnhancements:
    """Test enhanced security configuration for production."""

    def test_environment_specific_api_keys(self):
        """Test loading environment-specific API keys."""
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "production",
                "API_KEYS": "general-key-1234567890,general-key-0987654321",
                "API_KEYS_PRODUCTION": "prod-key-1234567890,prod-key-0987654321",
                "API_KEYS_DEVELOPMENT": "dev-key-12345678901,dev-key-10987654321",
            },
        ):
            config = SecurityConfig()

            # Should load production-specific keys, not general ones
            assert len(config.api_keys) == 2
            assert "prod-key-1234567890" in config.api_keys
            assert "prod-key-0987654321" in config.api_keys
            assert "general-key-1234567890" not in config.api_keys

    def test_alternative_environment_key_format(self):
        """Test alternative environment key format (ENVIRONMENT_API_KEYS)."""
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "staging",
                "STAGING_API_KEYS": "staging-key-1234567890,staging-key-0987654321",
            },
        ):
            config = SecurityConfig()

            assert len(config.api_keys) == 2
            assert "staging-key-1234567890" in config.api_keys
            assert "staging-key-0987654321" in config.api_keys

    def test_fallback_to_general_keys(self):
        """Test fallback to general API_KEYS when no environment-specific keys."""
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "production",
                "API_KEYS": "fallback-key-1234567890,fallback-key-0987654321",
            },
        ):
            config = SecurityConfig()

            assert len(config.api_keys) == 2
            assert "fallback-key-1234567890" in config.api_keys
            assert "fallback-key-0987654321" in config.api_keys

    def test_key_rotation_reload(self):
        """Test automatic key reloading for rotation support."""
        with patch.dict(
            os.environ,
            {
                "API_KEYS": "initial-key-1234567890,initial-key-0987654321",
                "API_KEY_RELOAD_INTERVAL": "1",  # 1 second for testing
            },
        ):
            config = SecurityConfig()

            # Initial keys
            assert len(config.api_keys) == 2
            assert "initial-key-1234567890" in config.api_keys

            # Simulate environment change
            with patch.dict(
                os.environ,
                {
                    "API_KEYS": "updated-key-1234567890,updated-key-0987654321",
                    "API_KEY_RELOAD_INTERVAL": "1",
                },
            ):
                # Wait for reload interval
                time.sleep(1.1)

                # Trigger reload
                reloaded = config.reload_keys_if_needed()

                assert reloaded is True
                assert len(config.api_keys) == 2
                assert "updated-key-1234567890" in config.api_keys
                assert "initial-key-1" not in config.api_keys

    def test_client_ip_extraction_with_proxy_headers(self):
        """Test client IP extraction with various proxy headers."""
        with patch.dict(os.environ, {"TRUST_PROXY_HEADERS": "true"}):
            config = SecurityConfig()

            # Mock request with X-Forwarded-For
            mock_request = Mock()
            mock_request.remote_addr = "127.0.0.1"
            mock_request.headers = {
                "X-Forwarded-For": "192.168.1.100, 10.0.0.1",
                "X-Real-IP": "192.168.1.200",
            }

            ip = config.get_client_ip(mock_request)
            assert ip == "192.168.1.100"  # First IP from X-Forwarded-For

    def test_client_ip_extraction_without_proxy_trust(self):
        """Test client IP extraction when proxy headers are not trusted."""
        with patch.dict(os.environ, {"TRUST_PROXY_HEADERS": "false"}):
            config = SecurityConfig()

            # Mock request with proxy headers
            mock_request = Mock()
            mock_request.remote_addr = "127.0.0.1"
            mock_request.headers = {
                "X-Forwarded-For": "192.168.1.100",
                "X-Real-IP": "192.168.1.200",
            }

            ip = config.get_client_ip(mock_request)
            assert ip == "127.0.0.1"  # Should use direct connection IP

    def test_ip_validation(self):
        """Test IP address validation."""
        config = SecurityConfig()

        # Valid IPv4
        assert config._is_valid_ip("192.168.1.1") is True
        assert config._is_valid_ip("10.0.0.1") is True
        assert config._is_valid_ip("127.0.0.1") is True

        # Valid IPv6 (basic check)
        assert config._is_valid_ip("2001:db8::1") is True
        assert config._is_valid_ip("::1") is True

        # Invalid IPs
        assert config._is_valid_ip("256.256.256.256") is False
        assert config._is_valid_ip("invalid") is False
        assert config._is_valid_ip("") is False
        assert config._is_valid_ip("unknown") is False


class TestProductionSecurityEnforcer:
    """Test production security enforcement."""

    def test_production_readiness_validation(self):
        """Test production readiness validation."""
        # Production config with issues
        config = ProductionConfig(
            environment="production",
            enable_key_rotation=False,  # Issue: should be enabled
            key_reload_interval=7200,  # Issue: too long (>1 hour)
            trust_proxy_headers=False,  # Issue: should be enabled
            max_key_age_hours=None,
            require_https=True,
        )

        enforcer = ProductionSecurityEnforcer(config, Mock())
        issues = enforcer.validate_production_readiness()

        assert len(issues) == 3
        assert any("proxy headers" in issue for issue in issues)
        assert any("Key rotation" in issue for issue in issues)
        assert any("reload interval" in issue for issue in issues)

    def test_https_enforcement(self):
        """Test HTTPS requirement enforcement."""
        config = ProductionConfig(
            environment="production",
            enable_key_rotation=True,
            key_reload_interval=300,
            trust_proxy_headers=True,
            max_key_age_hours=None,
            require_https=True,
        )

        enforcer = ProductionSecurityEnforcer(config, Mock())

        # Create Flask app for context
        app = Flask(__name__)

        with app.app_context():
            # Mock HTTP request
            mock_request = Mock()
            mock_request.is_secure = False
            mock_request.headers = {}
            mock_request.remote_addr = "192.168.1.1"

            response = enforcer.enforce_https_requirement(mock_request)

            assert response is not None
            json_response, status_code = response
            assert status_code == 426  # Upgrade Required

            # Mock HTTPS request
            mock_request.is_secure = True
            response = enforcer.enforce_https_requirement(mock_request)
            assert response is None  # No error

    def test_https_enforcement_with_proxy_headers(self):
        """Test HTTPS enforcement with proxy headers."""
        config = ProductionConfig(
            environment="production",
            enable_key_rotation=True,
            key_reload_interval=300,
            trust_proxy_headers=True,
            max_key_age_hours=None,
            require_https=True,
        )

        enforcer = ProductionSecurityEnforcer(config, Mock())

        # Mock request with X-Forwarded-Proto: https
        mock_request = Mock()
        mock_request.is_secure = False  # Direct connection is HTTP
        mock_request.headers = {"X-Forwarded-Proto": "https"}
        mock_request.remote_addr = "192.168.1.1"

        response = enforcer.enforce_https_requirement(mock_request)
        assert response is None  # Should be allowed due to proxy header


class TestProductionIntegration:
    """Test production security integration with Flask app."""

    def test_production_security_initialization(self):
        """Test security system initialization in production mode."""
        with patch.dict(
            os.environ,
            {
                "FLASK_ENV": "production",
                "API_KEYS_PRODUCTION": "prod-key-1234567890,prod-key-0987654321",
                "TRUST_PROXY_HEADERS": "true",
                "REQUIRE_HTTPS": "true",
            },
        ):
            app = Flask(__name__)

            with app.app_context():
                security_config = init_security(app)

                # Verify production components are initialized
                assert hasattr(app, "security_config")
                assert hasattr(app, "key_validator")
                assert hasattr(app, "security_logger")
                assert hasattr(app, "production_enforcer")

                # Verify production configuration
                assert security_config.environment == "production"
                assert security_config.trust_proxy_headers is True
                assert len(security_config.api_keys) == 2

    def test_stateless_authentication_across_instances(self):
        """Test that authentication is stateless and works across multiple instances."""
        # This test verifies that authentication doesn't rely on server-side state
        with patch.dict(os.environ, {"API_KEYS": "test-key-for-stateless-auth"}):
            # Create two separate app instances (simulating multiple servers)
            app1 = Flask(__name__ + "1")
            app2 = Flask(__name__ + "2")

            with app1.app_context():
                init_security(app1)
                validator1 = app1.key_validator

            with app2.app_context():
                init_security(app2)
                validator2 = app2.key_validator

            # Both instances should validate the same key identically
            test_key = "test-key-for-stateless-auth"
            assert validator1.is_valid_key(test_key) is True
            assert validator2.is_valid_key(test_key) is True

            # Both instances should reject invalid keys identically
            invalid_key = "invalid-key"
            assert validator1.is_valid_key(invalid_key) is False
            assert validator2.is_valid_key(invalid_key) is False

    def test_thread_safety_of_key_reloading(self):
        """Test that key reloading is thread-safe."""
        import threading

        with patch.dict(
            os.environ,
            {
                "API_KEYS": "thread-test-key-1234567890,thread-test-key-0987654321",
                "API_KEY_RELOAD_INTERVAL": "0.1",  # Very short for testing
            },
        ):
            config = SecurityConfig()

            # Function to reload keys in multiple threads
            def reload_keys():
                for _ in range(10):
                    config.reload_keys_if_needed()
                    time.sleep(0.01)

            # Start multiple threads
            threads = []
            for _ in range(5):
                thread = threading.Thread(target=reload_keys)
                threads.append(thread)
                thread.start()

            # Wait for all threads to complete
            for thread in threads:
                thread.join()

            # Configuration should still be valid
            assert len(config.api_keys) >= 2
            assert config.authentication_enabled is True


class TestReverseProxyCompatibility:
    """Test compatibility with reverse proxies and load balancers."""

    def test_cloudflare_headers(self):
        """Test compatibility with Cloudflare proxy headers."""
        with patch.dict(os.environ, {"TRUST_PROXY_HEADERS": "true"}):
            config = SecurityConfig()

            mock_request = Mock()
            mock_request.remote_addr = "127.0.0.1"
            mock_request.headers = {
                "CF-Connecting-IP": "203.0.113.1",  # Cloudflare header
                "X-Forwarded-For": "203.0.113.1, 198.51.100.1",
            }

            ip = config.get_client_ip(mock_request)
            assert ip == "203.0.113.1"  # Should prefer X-Forwarded-For

    def test_aws_alb_headers(self):
        """Test compatibility with AWS Application Load Balancer headers."""
        with patch.dict(os.environ, {"TRUST_PROXY_HEADERS": "true"}):
            config = SecurityConfig()

            mock_request = Mock()
            mock_request.remote_addr = "10.0.0.1"
            mock_request.headers = {
                "X-Forwarded-For": "203.0.113.1",
                "X-Forwarded-Proto": "https",
                "X-Forwarded-Port": "443",
            }

            ip = config.get_client_ip(mock_request)
            assert ip == "203.0.113.1"

    def test_nginx_headers(self):
        """Test compatibility with nginx proxy headers."""
        with patch.dict(os.environ, {"TRUST_PROXY_HEADERS": "true"}):
            config = SecurityConfig()

            mock_request = Mock()
            mock_request.remote_addr = "127.0.0.1"
            mock_request.headers = {
                "X-Real-IP": "203.0.113.1",
                "X-Forwarded-Host": "api.example.com",
            }

            ip = config.get_client_ip(mock_request)
            assert ip == "203.0.113.1"

    def test_multiple_proxy_hops(self):
        """Test handling of multiple proxy hops in X-Forwarded-For."""
        with patch.dict(os.environ, {"TRUST_PROXY_HEADERS": "true"}):
            config = SecurityConfig()

            mock_request = Mock()
            mock_request.remote_addr = "127.0.0.1"
            mock_request.headers = {
                # Client -> Proxy1 -> Proxy2 -> Server
                "X-Forwarded-For": "203.0.113.1, 198.51.100.1, 192.0.2.1"
            }

            ip = config.get_client_ip(mock_request)
            assert ip == "203.0.113.1"  # Should extract original client IP


if __name__ == "__main__":
    pytest.main([__file__])
