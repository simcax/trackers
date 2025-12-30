import os

from flask import Flask

from trackers.error_handling import register_error_handlers
from trackers.routes.health_routes import health_bp
from trackers.routes.tracker_routes import tracker_bp
from trackers.routes.tracker_value_routes import tracker_value_bp
from trackers.routes.web_routes import web_bp
from trackers.security.api_key_auth import init_security


def create_app(test_config=None):
    # create and configure the app with static folder configuration
    app = Flask(
        __name__,
        instance_relative_config=True,
        static_folder="../static",
        static_url_path="/static",
    )
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

    # Initialize Google OAuth authentication if configured
    _initialize_google_auth(app)

    # Initialize unified authentication system
    _initialize_unified_auth(app)

    # register error handlers
    register_error_handlers(app)

    # register health check blueprint
    app.register_blueprint(health_bp)

    # register tracker blueprint
    app.register_blueprint(tracker_bp)

    # register tracker value blueprint
    app.register_blueprint(tracker_value_bp)

    # register web UI blueprint
    app.register_blueprint(web_bp)

    # Root route that provides navigation to the web interface
    @app.route("/")
    def index():
        """
        Root route that provides navigation to the web interface and API documentation.

        This serves as the main entry point for users accessing the application,
        providing links to both the web UI and API endpoints.

        Validates: Requirements 5.1, 5.5
        """
        from flask import render_template_string

        # Simple HTML template with navigation links
        template = """
        <!DOCTYPE html>
        <html lang="en" class="dark">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Tracker Application</title>
            <link href="{{ url_for('static', filename='css/dist/output.css') }}" rel="stylesheet">
            <style>
                body { font-family: system-ui, -apple-system, sans-serif; }
                .container { max-width: 800px; margin: 0 auto; padding: 2rem; }
                .card { background: #1f2937; border-radius: 0.5rem; padding: 1.5rem; margin: 1rem 0; }
                .btn { display: inline-block; background: #3b82f6; color: white; padding: 0.75rem 1.5rem; 
                       border-radius: 0.375rem; text-decoration: none; margin: 0.5rem 0.5rem 0.5rem 0; 
                       transition: background-color 0.2s; }
                .btn:hover { background: #2563eb; }
                .btn-secondary { background: #6b7280; }
                .btn-secondary:hover { background: #4b5563; }
            </style>
        </head>
        <body class="bg-gray-900 text-white">
            <div class="container">
                <h1 class="text-4xl font-bold mb-8 text-center">Tracker Application</h1>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4">Web Interface</h2>
                    <p class="text-gray-300 mb-4">
                        Access the modern web interface to manage your trackers with an intuitive dashboard,
                        data visualization, and easy-to-use forms.
                    </p>
                    <a href="/web/" class="btn">Open Web Dashboard</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4">API Endpoints</h2>
                    <p class="text-gray-300 mb-4">
                        Access the REST API for programmatic integration. All API endpoints require authentication.
                    </p>
                    <a href="/trackers" class="btn btn-secondary">View Trackers API</a>
                    <a href="/health" class="btn btn-secondary">Health Check</a>
                    <a href="/health/detailed" class="btn btn-secondary">Detailed Health</a>
                </div>
                
                <div class="card">
                    <h2 class="text-2xl font-semibold mb-4">System Status</h2>
                    <p class="text-gray-300 mb-4">
                        Monitor application health, database status, and migration information.
                    </p>
                    <a href="/health/migration" class="btn btn-secondary">Migration Status</a>
                    <a href="/health/ready" class="btn btn-secondary">Readiness Check</a>
                </div>
                
                <div class="text-center mt-8 text-gray-400">
                    <p>Built with Flask, TailwindCSS, and Flowbite</p>
                </div>
            </div>
        </body>
        </html>
        """

        return render_template_string(template)

    # a simple page that says hello
    @app.route("/hello")
    def hello():
        return "Hello, World!"

    return app


def _initialize_unified_auth(app):
    """
    Initialize the unified authentication system.

    This function integrates Google OAuth authentication with the existing
    API key authentication system, providing a unified authentication
    experience that supports both methods.

    Requirements: 5.3, 5.4 - Integration with existing security system
    """
    try:
        from trackers.auth.integration import init_unified_auth

        # Initialize the unified authentication system
        unified_auth = init_unified_auth(app)

        app.logger.info("✓ Unified authentication system initialized")
        app.logger.info(
            f"✓ Available auth methods: {', '.join(unified_auth.available_auth_methods)}"
        )

        # Store reference in app for access in routes
        app.unified_auth = unified_auth

    except Exception as e:
        app.logger.warning(f"Failed to initialize unified authentication: {e}")
        app.logger.info(
            "Application will continue with individual authentication systems"
        )


def _initialize_google_auth(app):
    """
    Initialize Google OAuth authentication if configured.

    This function conditionally enables Google OAuth authentication based on
    environment variable configuration. If Google OAuth credentials are not
    configured, the application continues without OAuth functionality.

    Requirements: 8.1, 8.2, 8.3 - Security hardening for OAuth
    """
    try:
        # Try to import and initialize Google OAuth configuration
        from trackers.auth.config import google_oauth_config

        if google_oauth_config is not None:
            # Import auth routes and initialize
            from trackers.auth.auth_routes import init_auth_routes

            # Initialize auth routes with configuration
            auth_bp = init_auth_routes(google_oauth_config)

            # Register auth blueprint
            app.register_blueprint(auth_bp)

            app.logger.info("✓ Google OAuth authentication enabled")
            app.logger.info(f"✓ OAuth client ID: {google_oauth_config.client_id}")
            app.logger.info(f"✓ OAuth redirect URI: {google_oauth_config.redirect_uri}")

            # Configure session security for OAuth
            from trackers.auth.session_manager import SessionManager

            session_manager = SessionManager()
            session_manager.configure_flask_session_security(app)

            app.logger.info("✓ Session security configured for OAuth")

        else:
            app.logger.info(
                "Google OAuth not configured - OAuth endpoints will not be available"
            )
            app.logger.info(
                "To enable OAuth, set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI"
            )

    except Exception as e:
        app.logger.warning(f"Failed to initialize Google OAuth: {e}")
        app.logger.info("Application will continue without OAuth authentication")


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
    - Running the enhanced migration engine with integrated user migration
    - Providing comprehensive error handling and reporting
    - Ensuring proper timing so migration completes before routes are available

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 4.1, 4.2, 4.3, 4.4
    """
    try:
        # Import all models to ensure they are registered with Base.metadata
        # This must happen before migration runs (Requirements: 2.1, 2.2, 2.3)
        from trackers.db.database import Base, engine
        from trackers.db.migration import MigrationEngine
        from trackers.models.tracker_model import ItemModel, LogModel, TrackerModel
        from trackers.models.tracker_value_model import TrackerValueModel
        from trackers.models.user_model import UserModel  # Import UserModel

        # Create enhanced migration engine with integrated user migration
        # Requirements: 3.1, 3.2, 3.3, 3.4, 3.5
        migration_engine = MigrationEngine(
            engine=engine,
            metadata=Base.metadata,
            logger=app.logger,
            timeout_seconds=60,  # Increased timeout for user migration
            enable_user_migration=True,
        )

        # Run complete migration process (schema + user migration)
        # Requirements: 2.1, 2.4, 2.5, 3.1, 3.2, 3.3
        app.logger.info("Starting comprehensive database migration...")
        migration_result = migration_engine.run_complete_migration()

        # Handle migration results with comprehensive reporting
        # Requirements: 4.4, 4.5, 3.5
        if migration_result.success:
            app.logger.info(
                f"Database migration completed successfully in {migration_result.duration_seconds:.2f}s"
            )
            if migration_result.tables_created:
                app.logger.info(
                    f"Created tables: {', '.join(migration_result.tables_created)}"
                )

            # Report user migration results if available
            if migration_result.user_migration_result:
                user_result = migration_result.user_migration_result
                if user_result.success:
                    app.logger.info(
                        f"User migration completed successfully in {user_result.duration_seconds:.2f}s"
                    )
                    if user_result.orphaned_trackers_migrated > 0:
                        app.logger.info(
                            f"Migrated {user_result.orphaned_trackers_migrated} existing trackers to default user"
                        )
                    if user_result.users_table_created:
                        app.logger.info("Created users table for user ownership")
                    if user_result.trackers_table_modified:
                        app.logger.info("Modified trackers table for user ownership")
                else:
                    app.logger.error(f"User migration failed: {user_result.message}")
                    for error in user_result.errors:
                        app.logger.error(f"User migration error: {error}")
        else:
            # Migration failure should not prevent application startup (Requirements: 4.4)
            app.logger.error(f"Database migration failed: {migration_result.message}")
            for error in migration_result.errors:
                app.logger.error(f"Migration error: {error}")
            app.logger.warning(
                "Application will continue startup despite migration failure"
            )

        # Generate and log migration report for monitoring
        # Requirements: 3.5
        try:
            migration_report = migration_engine.get_migration_report()
            app.logger.info(
                f"Migration health status: {migration_report.get('health', 'unknown')}"
            )
            if migration_report.get("health_message"):
                app.logger.info(
                    f"Migration status: {migration_report['health_message']}"
                )
        except Exception as e:
            app.logger.warning(f"Failed to generate migration report: {e}")

    except Exception as e:
        # Ensure migration failures don't prevent application startup (Requirements: 4.4)
        app.logger.error(f"Migration system failed to initialize: {e}")
        app.logger.warning("Application will continue startup without migration")
