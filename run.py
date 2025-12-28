#!/usr/bin/env python3
"""
Simple script to run the Flask application.
Usage: uv run python run.py
"""

import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from trackers import create_app


def main():
    """Run the Flask development server."""
    app = create_app()

    # Get configuration from environment variables
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "true").lower() in ("true", "1", "yes")

    print(f"Starting Flask app on {host}:{port} (debug={debug})")

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
