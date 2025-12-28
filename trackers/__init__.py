import os

from flask import Flask

from trackers.error_handling import register_error_handlers
from trackers.routes.health_routes import health_bp
from trackers.routes.tracker_routes import tracker_bp
from trackers.routes.tracker_value_routes import tracker_value_bp


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
