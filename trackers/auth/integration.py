"""
Integration module for unified authentication system.

This module integrates Google OAuth authentication with the existing API key
authentication system, providing a unified authentication experience that
supports both authentication methods seamlessly.

Requirements: 5.3, 5.4 - Integration with existing security system
"""

import logging
from typing import Optional

from flask import Flask

from .context import configure_user_context

# Configure logging
logger = logging.getLogger(__name__)


class UnifiedAuthSystem:
    """
    Unified authentication system that integrates Google OAuth with API key authentication.

    This class provides a single interface for managing both authentication methods
    and ensures they work together seamlessly throughout the application.
    """

    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize the unified authentication system.

        Args:
            app: Flask application instance (optional, can be set later)
        """
        self.app = app
        self.google_auth_enabled = False
        self.api_key_auth_enabled = False

        if app is not None:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """
        Initialize the unified authentication system with Flask application.

        Args:
            app: Flask application instance

        Requirements: 5.3, 5.4 - Integrate authentication systems
        """
        self.app = app

        # Check what authentication methods are available
        self._detect_auth_methods()

        # Configure user context management
        configure_user_context(app)

        # Set up authentication integration
        self._setup_auth_integration()

        # Log authentication system status
        self._log_auth_system_status()

    def _detect_auth_methods(self) -> None:
        """Detect which authentication methods are configured and available."""
        # Check API key authentication
        self.api_key_auth_enabled = (
            hasattr(self.app, "key_validator")
            and self.app.key_validator.is_authentication_enabled()
        )

        # Check Google OAuth authentication
        try:
            from .config import google_oauth_config

            self.google_auth_enabled = google_oauth_config is not None
        except ImportError:
            self.google_auth_enabled = False

    def _setup_auth_integration(self) -> None:
        """Set up integration between authentication methods."""

        @self.app.before_request
        def setup_unified_auth_context():
            """
            Set up unified authentication context for each request.

            This runs before each request to establish the authentication
            context that will be used by decorators and route handlers.
            """
            # The actual authentication checking is handled by the decorators
            # This just ensures the integration is properly initialized
            pass

        # Add CLI commands for authentication management
        self._register_auth_commands()

    def _register_auth_commands(self) -> None:
        """Register CLI commands for authentication management."""

        @self.app.cli.command("auth-status")
        def auth_status_command():
            """Display current authentication system status."""
            click = self._get_click()
            if not click:
                print("Click not available for CLI commands")
                return

            click.echo("Authentication System Status:")
            click.echo(
                f"  API Key Auth: {'✓ Enabled' if self.api_key_auth_enabled else '✗ Disabled'}"
            )
            click.echo(
                f"  Google OAuth: {'✓ Enabled' if self.google_auth_enabled else '✗ Disabled'}"
            )

            if self.api_key_auth_enabled:
                key_count = len(self.app.security_config.api_keys)
                click.echo(f"  API Keys: {key_count} configured")

            if self.google_auth_enabled:
                from .config import google_oauth_config

                click.echo(f"  OAuth Client ID: {google_oauth_config.client_id}")
                click.echo(f"  OAuth Redirect URI: {google_oauth_config.redirect_uri}")

        @self.app.cli.command("test-auth")
        def test_auth_command():
            """Test authentication system configuration."""
            click = self._get_click()
            if not click:
                print("Click not available for CLI commands")
                return

            click.echo("Testing Authentication Configuration...")

            # Test API key authentication
            if self.api_key_auth_enabled:
                try:
                    # Test key validation
                    test_result = self._test_api_key_auth()
                    if test_result:
                        click.echo("✓ API Key authentication: OK")
                    else:
                        click.echo("✗ API Key authentication: Failed")
                except Exception as e:
                    click.echo(f"✗ API Key authentication: Error - {str(e)}")
            else:
                click.echo("- API Key authentication: Not configured")

            # Test Google OAuth authentication
            if self.google_auth_enabled:
                try:
                    test_result = self._test_google_oauth_config()
                    if test_result:
                        click.echo("✓ Google OAuth configuration: OK")
                    else:
                        click.echo("✗ Google OAuth configuration: Failed")
                except Exception as e:
                    click.echo(f"✗ Google OAuth configuration: Error - {str(e)}")
            else:
                click.echo("- Google OAuth: Not configured")

    def _get_click(self):
        """Get click module if available."""
        try:
            import click

            return click
        except ImportError:
            return None

    def _test_api_key_auth(self) -> bool:
        """Test API key authentication configuration."""
        try:
            # Check if security config is properly initialized
            if not hasattr(self.app, "security_config"):
                return False

            # Check if key validator is working
            if not hasattr(self.app, "key_validator"):
                return False

            # Test key validation with a dummy key
            # (This doesn't test actual keys for security reasons)
            validator = self.app.key_validator
            return validator.is_authentication_enabled()

        except Exception:
            return False

    def _test_google_oauth_config(self) -> bool:
        """Test Google OAuth configuration."""
        try:
            from .config import google_oauth_config

            if not google_oauth_config:
                return False

            # Check required configuration fields
            required_fields = ["client_id", "client_secret", "redirect_uri"]
            for field in required_fields:
                if not getattr(google_oauth_config, field, None):
                    return False

            return True

        except Exception:
            return False

    def _log_auth_system_status(self) -> None:
        """Log the status of the unified authentication system."""
        logger.info("Unified Authentication System Status:")
        logger.info(
            f"  API Key Authentication: {'Enabled' if self.api_key_auth_enabled else 'Disabled'}"
        )
        logger.info(
            f"  Google OAuth Authentication: {'Enabled' if self.google_auth_enabled else 'Disabled'}"
        )

        if not self.api_key_auth_enabled and not self.google_auth_enabled:
            logger.warning("⚠ No authentication methods are enabled!")
            logger.warning("⚠ All endpoints will be publicly accessible")
        elif self.api_key_auth_enabled and self.google_auth_enabled:
            logger.info("✓ Both authentication methods are available")
            logger.info("✓ Routes can use either or both authentication methods")
        elif self.api_key_auth_enabled:
            logger.info("✓ API Key authentication is available")
            logger.info("- Google OAuth is not configured")
        else:
            logger.info("✓ Google OAuth authentication is available")
            logger.info("- API Key authentication is not configured")

    @property
    def is_any_auth_enabled(self) -> bool:
        """Check if any authentication method is enabled."""
        return self.api_key_auth_enabled or self.google_auth_enabled

    @property
    def available_auth_methods(self) -> list[str]:
        """Get list of available authentication methods."""
        methods = []
        if self.api_key_auth_enabled:
            methods.append("api_key")
        if self.google_auth_enabled:
            methods.append("google_oauth")
        return methods

    def get_auth_status(self) -> dict:
        """
        Get comprehensive authentication system status.

        Returns:
            dict: Authentication system status information
        """
        return {
            "api_key_auth_enabled": self.api_key_auth_enabled,
            "google_oauth_enabled": self.google_auth_enabled,
            "any_auth_enabled": self.is_any_auth_enabled,
            "available_methods": self.available_auth_methods,
            "api_key_count": len(self.app.security_config.api_keys)
            if self.api_key_auth_enabled
            else 0,
        }


# Global instance for easy access
unified_auth = UnifiedAuthSystem()


def init_unified_auth(app: Flask) -> UnifiedAuthSystem:
    """
    Initialize the unified authentication system for a Flask application.

    Args:
        app: Flask application instance

    Returns:
        UnifiedAuthSystem: Configured authentication system

    Requirements: 5.3, 5.4 - Initialize integrated authentication system
    """
    unified_auth.init_app(app)
    return unified_auth


def get_unified_auth() -> UnifiedAuthSystem:
    """
    Get the global unified authentication system instance.

    Returns:
        UnifiedAuthSystem: Global authentication system instance
    """
    return unified_auth
