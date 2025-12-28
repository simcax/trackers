import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from trackers import create_app


def main():
    """Main entry point for the Flask application."""
    app = create_app()

    # Get configuration from environment variables
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "9000"))
    debug = os.getenv("FLASK_DEBUG", "true").lower() in ("true", "1", "yes")

    print(f"Starting Flask app on {host}:{port} (debug={debug})")

    # Run the Flask development server
    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
