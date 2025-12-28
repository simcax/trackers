import os

from dotenv import load_dotenv

# Load environment variables from .env file BEFORE importing trackers
load_dotenv()

from trackers import create_app

# Create the Flask application instance for WSGI deployment
app = create_app()


def main():
    """Main entry point for local development."""
    # Get configuration from environment variables
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "true").lower() in ("true", "1", "yes")

    print(f"Starting Flask app on {host}:{port} (debug={debug})")

    # Run the Flask development server
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
