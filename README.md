# Trackers

A Flask application for managing trackers with PostgreSQL database support.

## Development Setup

### Prerequisites

- Python 3.13+
- PostgreSQL 12+ (or Docker for containerized setup)
- uv (Python package manager)

### Installation

1. Install dependencies:
```bash
uv sync
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your database credentials
```

### Database Setup

You have several options for setting up the database:

#### Option 1: Automated Setup (Recommended)

Use the initialization script to create a new database user and set up the schema:

```bash
# Set your database credentials
export DB_HOST=localhost
export DB_USER=trackers_user
export DB_PASSWORD=your_secure_password
export DB_NAME=trackers

# Run the initialization script
./scripts/init-db.sh

# Or with sample data
./scripts/init-db.sh --sample-data
```

#### Option 2: Docker Setup for Testing

Use Docker Compose for a quick test environment:

```bash
# Start test database
docker compose -f docker-compose.test.yml up -d

# Or use the helper script
./scripts/test-db.sh start
```

#### Option 3: Manual SQL Setup

If you prefer manual setup, use the SQL script:

```bash
# Edit scripts/init-db.sql with your credentials first
psql -U postgres -f scripts/init-db.sql

# Then apply the schema
python -c "
from trackers.db.database import Base
from trackers.models.tracker_model import *
from sqlalchemy import create_engine
engine = create_engine('postgresql://your_user:your_pass@localhost/your_db')
Base.metadata.create_all(engine)
"
```

### Running the Flask Application

The Flask application can be started in several ways:

#### Option 1: Using uv run with script entry point (Recommended)

```bash
# Start the Flask app (default: http://0.0.0.0:5000)
uv run trackers-app

# With custom port
FLASK_PORT=8000 uv run trackers-app

# With custom host and port
FLASK_HOST=127.0.0.1 FLASK_PORT=8000 uv run trackers-app
```

#### Option 2: Using uv run with Python files

```bash
# Using main.py
uv run python main.py

# Using run.py (with more configuration options)
uv run python run.py
```

#### Option 3: Direct Python execution

```bash
# Make sure environment is activated and dependencies installed
python main.py
```

### Flask Configuration

You can configure the Flask application using environment variables in your `.env` file:

```bash
# Flask server configuration
FLASK_HOST=0.0.0.0      # Server host (default: 0.0.0.0)
FLASK_PORT=5000         # Server port (default: 5000)
FLASK_DEBUG=true        # Debug mode (default: true)
```

### Health Check Endpoints

The application provides comprehensive health check endpoints for monitoring and deployment:

#### Basic Health Check
```bash
curl http://localhost:5000/health
```
Returns basic application status - lightweight check suitable for load balancers.

#### Detailed Health Check
```bash
curl http://localhost:5000/health/detailed
```
Performs comprehensive checks including database connectivity. Returns HTTP 503 if any component is unhealthy.

#### Kubernetes Probes
```bash
# Readiness probe - checks if app is ready to serve traffic
curl http://localhost:5000/health/ready

# Liveness probe - checks if app is alive and shouldn't be restarted
curl http://localhost:5000/health/live
```

**Example Kubernetes Configuration:**
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 5000
  initialDelaySeconds: 30
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health/ready
    port: 5000
  initialDelaySeconds: 5
  periodSeconds: 5
```

Once the Flask app is running, you can access:

**Health Check Endpoints:**
- **Basic Health**: `GET /health` - Simple health status check
- **Detailed Health**: `GET /health/detailed` - Comprehensive health check with database connectivity
- **Readiness Check**: `GET /health/ready` - Kubernetes readiness probe endpoint
- **Liveness Check**: `GET /health/live` - Kubernetes liveness probe endpoint

**Application Endpoints:**
- **Health check**: `GET /hello` - Simple health check endpoint (legacy)

**Trackers API:**
- `GET /trackers` - List all trackers
- `POST /add_tracker` - Create a new tracker

**Tracker Values API:**
- `POST /api/trackers/{id}/values` - Create/update tracker values
- `GET /api/trackers/{id}/values` - List tracker values
- `GET /api/trackers/{id}/values/{date}` - Get specific value
- `PUT /api/trackers/{id}/values/{date}` - Update specific value
- `DELETE /api/trackers/{id}/values/{date}` - Delete specific value

### Running Tests

The project uses automated test database setup with PostgreSQL.

1. Ensure your environment variables are set (or use Docker setup)
2. Run tests:
```bash
pytest
```

The test infrastructure automatically:
- Creates a test database (`{DB_NAME}_test`)
- Applies all schema definitions
- Provides isolated sessions for each test
- Rolls back changes after each test

### Database Management Scripts

The project includes several database management scripts:

#### `scripts/init-db.sh` - Database Initialization
- Creates database user with appropriate privileges
- Creates the main database
- Applies SQLAlchemy schema
- Optionally creates sample data

```bash
./scripts/init-db.sh --help           # Show usage
./scripts/init-db.sh                  # Basic setup
./scripts/init-db.sh --sample-data    # Setup with sample data
./scripts/init-db.sh --force          # Force recreation
```

#### `scripts/test-db.sh` - Test Database Management
- Manages Docker-based test database
- Useful for development and CI

```bash
./scripts/test-db.sh start     # Start test database
./scripts/test-db.sh stop      # Stop test database
./scripts/test-db.sh restart   # Restart test database
./scripts/test-db.sh clean     # Remove test database and data
./scripts/test-db.sh logs      # Show database logs
```

## Project Structure

```
trackers/
├── trackers/
│   ├── db/
│   │   ├── database.py           # Database engine and session setup
│   │   ├── settings.py           # Configuration management
│   │   ├── trackerdb.py          # Repository operations (CRUD)
│   │   └── tracker_values_db.py  # Tracker values repository
│   ├── models/
│   │   ├── tracker_model.py      # SQLAlchemy models
│   │   └── tracker_value_model.py # Tracker values model
│   ├── routes/
│   │   ├── health_routes.py      # Health check endpoints
│   │   ├── tracker_routes.py     # Tracker API endpoints
│   │   └── tracker_value_routes.py # Tracker values API endpoints
│   └── validation/
│       └── tracker_value_validation.py # Input validation
├── tests/
│   ├── conftest.py               # Test fixtures and database setup
│   ├── test_db.py                # Database tests
│   ├── test_endpoints.py         # API endpoint tests
│   ├── test_health_endpoints.py  # Health check endpoint tests
│   ├── test_settings.py          # Configuration tests (property-based)
│   ├── test_trackerdb.py         # Repository tests
│   ├── test_error_handling.py    # Error handling tests
│   └── test_tracker_value_integration.py # Integration tests
├── scripts/
│   ├── init-db.sh                # Database initialization script
│   ├── init-db.py                # Python database setup
│   ├── init-db.sql               # Manual SQL setup
│   ├── test-db.sh                # Test database management
│   └── migrate-tracker-values.py # Database migration script
├── main.py                       # Main Flask application entry point
├── run.py                        # Alternative Flask runner with more config
└── docker-compose.test.yml       # Test database configuration
```

## Environment Variables

Required environment variables for database connection:

**Clever Cloud PostgreSQL Addon (Production):**
- `POSTGRESQL_ADDON_HOST` - PostgreSQL server host (automatically set by Clever Cloud)
- `POSTGRESQL_ADDON_USER` - Database username (automatically set by Clever Cloud)
- `POSTGRESQL_ADDON_PASSWORD` - Database password (automatically set by Clever Cloud)
- `POSTGRESQL_ADDON_DB` - Database name (automatically set by Clever Cloud)
- `POSTGRESQL_ADDON_PORT` - Database port (automatically set by Clever Cloud)

**Local Development (Fallback):**
- `DB_HOST` - PostgreSQL server host (default: localhost)
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name (test database will append `_test`)
- `DB_PORT` - Database port (optional, defaults to 5432)

**Flask Application:**
- `FLASK_HOST` - Flask server host (default: 0.0.0.0)
- `FLASK_PORT` - Flask server port (default: 5000)
- `FLASK_DEBUG` - Flask debug mode (default: true)

**Legacy (for initialization scripts):**
- `POSTGRES_USER` - PostgreSQL superuser for initialization (default: postgres)
- `POSTGRES_PASSWORD` - PostgreSQL superuser password (default: postgres)

## Deployment

### Production Deployment (Clever Cloud)

The application is configured for deployment on Clever Cloud with proper WSGI support:

**WSGI Entry Point:** `wsgi:application`

The `wsgi.py` file provides the production WSGI application object that Clever Cloud (and other WSGI servers) can use. It automatically loads environment variables and creates the Flask application instance.

**Environment Variables:** Clever Cloud automatically sets the PostgreSQL addon environment variables (`POSTGRESQL_ADDON_*`) when you add a PostgreSQL addon to your application.

### Local Development

For local development, you can run the application using:

```bash
# Using uv (recommended)
uv run trackers-app

# Or directly with Python
python main.py

# Or using the run script
python run.py
```

The `main.py` file provides a development server with hot reloading and debug mode enabled by default.

## Database Schema

The application uses these main tables:

- **trackers** - Main tracker entities with name and description
- **tracker_values** - Daily values associated with trackers
- **items** - Items associated with trackers, with timestamps
- **logs** - Log entries for tracking events and changes

All tables are automatically created by the SQLAlchemy models when you run the initialization scripts.
