"""
WSGI entry point for production deployment.

This module provides the WSGI application object that production servers
(like uWSGI, Gunicorn, or Clever Cloud) can use to serve the Flask application.
"""

import os

from dotenv import load_dotenv

# Load environment variables from .env file (if it exists)
# In production, environment variables are typically set by the platform
if os.path.exists(".env"):
    load_dotenv()

from trackers import create_app

# Create the Flask application instance
# This is the WSGI application object that production servers will use
application = create_app()

# For compatibility with some WSGI servers that expect 'app'
app = application

if __name__ == "__main__":
    # This allows running the WSGI file directly for testing
    # In production, this won't be executed
    port = int(os.environ.get("FLASK_PORT", 8080))
    application.run(host="0.0.0.0", port=port)
