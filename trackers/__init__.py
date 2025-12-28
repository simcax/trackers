import os

from flask import Flask

from trackers.error_handling import register_error_handlers
from trackers.routes.health_routes import health_bp
from trackers.routes.tracker_routes import tracker_bp
from trackers.routes.tracker_value_routes import tracker_value_bp
from trackers.security.api_key_auth import init_security


def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY="dev",
        DATABASE=os.path.join(app.instance_path, "flaskr.sqlite"),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Run database migration before registering blueprints (Requirements: 4.1, 4.2)
    if not test_config:  # Skip migration during testing (Requirements: 4.3)
        _run_migration(app)

    # Initialize security system with comprehensive logging and validation (Requirements: 3.1, 3.2, 4.1)
    _initialize_security_system(app)

    # register error handlers
    register_error_handlers(app)

    # register health check blueprint
    app.register_blueprint(health_bp)

    # register tracker blueprint
    app.register_blueprint(tracker_bp)

    # register tracker value blueprint
    app.register_blueprint(tracker_value_bp)

    # a simple page that says hello
    @app.route("/hello")
    def hello():
        return "Hello, World!"

    return app


def _initialize_security_system(app):
    """
    Initialize and integrate the security system with Flask application.

    This function provides comprehensive security system integration by:
    - Loading and validating security configuration at startup
    - Integrating key validator and security logger with Flask app context
    - Adding detailed startup logging for security configuration status
    - Ensuring proper error handling during security initialization

    Requirements: 3.1, 3.2, 4.1
    """
    try:
        app.logger.info("Initializing API key security system...")

        # Initialize security system using the existing init_security function
        security_config = init_security(app)

        # Validate security system components are properly initialized
        if not hasattr(app, "security_config"):
            app.logger.error("Security configuration failed to initialize")
            raise RuntimeError("Security configuration initialization failed")

        if not hasattr(app, "key_validator"):
            app.logger.error("Key validator failed to initialize")
            raise RuntimeError("Key validator initialization failed")

        if not hasattr(app, "security_logger"):
            app.logger.error("Security logger failed to initialize")
            raise RuntimeError("Security logger initialization failed")

        # Log detailed security configuration status
        if security_config.authentication_enabled:
            app.logger.info("✓ API key authentication is ENABLED")
            app.logger.info(f"✓ Loaded {len(security_config.api_keys)} valid API keys")
            app.logger.info(
                f"✓ Protected routes: {len(security_config.get_protected_routes())} patterns"
            )
            app.logger.info(
                f"✓ Public routes: {len(security_config.get_public_routes())} patterns"
            )

            # Log route protection details for debugging
            app.logger.debug(
                f"Protected route patterns: {', '.join(security_config.get_protected_routes())}"
            )
            app.logger.debug(
                f"Public route patterns: {', '.join(security_config.get_public_routes())}"
            )

            # Validate key security requirements
            valid_keys = 0
            for key in security_config.api_keys:
                if security_config.validate_key_security(key):
                    valid_keys += 1

            if valid_keys != len(security_config.api_keys):
                app.logger.warning(
                    f"Some API keys failed security validation ({valid_keys}/{len(security_config.api_keys)} valid)"
                )
            else:
                app.logger.info("✓ All API keys meet security requirements")

        else:
            app.logger.warning("⚠ API key authentication is DISABLED")
            app.logger.warning(
                "⚠ No valid API keys configured - all endpoints are publicly accessible"
            )
            app.logger.info(
                "To enable authentication, set the API_KEYS environment variable"
            )

        # Log security system readiness
        app.logger.info("API key security system initialization completed successfully")

        return security_config

    except Exception as e:
        # Ensure security initialization failures are properly logged and handled
        app.logger.error(f"Failed to initialize security system: {e}")
        app.logger.error(
            "Application will continue startup but security may not function properly"
        )

        # Try to initialize a minimal security system to prevent crashes
        try:
            from trackers.security.api_key_auth import (
                KeyValidator,
                SecurityConfig,
                SecurityLogger,
            )

            # Create minimal security configuration
            minimal_config = SecurityConfig()
            app.security_config = minimal_config
            app.key_validator = KeyValidator(minimal_config)
            app.security_logger = SecurityLogger(app.logger)

            app.logger.warning("Minimal security system initialized as fallback")

        except Exception as fallback_error:
            app.logger.error(
                f"Failed to initialize fallback security system: {fallback_error}"
            )
            app.logger.error(
                "Security system is not available - authentication will not work"
            )


def _run_migration(app):
    """
    Run automatic database migration during Flask application startup.

    This function implements automatic schema creation functionality by:
    - Importing all models to register them with Base.metadata
    - Running the migration engine to detect and create missing tables
    - Ensuring proper timing so migration completes before routes are available

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 4.1, 4.2, 4.3, 4.4
    """
    try:
        # Import all models to ensure they are registered with Base.metadata
        # This must happen before migration runs (Requirements: 2.1, 2.2, 2.3)
        from trackers.db.database import Base, engine
        from trackers.db.migration import MigrationEngine
        from trackers.models.tracker_model import ItemModel, LogModel, TrackerModel
        from trackers.models.tracker_value_model import TrackerValueModel

        # Create migration engine with all registered models
        migration_engine = MigrationEngine(engine, Base.metadata, app.logger)

        # Run automatic schema creation (Requirements: 2.1, 2.4, 2.5)
        app.logger.info("Starting automatic database migration...")
        migration_result = migration_engine.run_migration()

        # Handle migration results (Requirements: 4.4, 4.5)
        if migration_result.success:
            app.logger.info(
                f"Database migration completed successfully in {migration_result.duration_seconds:.2f}s"
            )
            if migration_result.tables_created:
                app.logger.info(
                    f"Created tables: {', '.join(migration_result.tables_created)}"
                )
        else:
            # Migration failure should not prevent application startup (Requirements: 4.4)
            app.logger.error(f"Database migration failed: {migration_result.message}")
            for error in migration_result.errors:
                app.logger.error(f"Migration error: {error}")
            app.logger.warning(
                "Application will continue startup despite migration failure"
            )

    except Exception as e:
        # Ensure migration failures don't prevent application startup (Requirements: 4.4)
        app.logger.error(f"Migration system failed to initialize: {e}")
        app.logger.warning("Application will continue startup without migration")
