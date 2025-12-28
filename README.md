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
# Edit .env with your database credentials and API key configuration
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

### API Key Authentication

The application includes comprehensive API key authentication to secure all API endpoints. Authentication is configured through environment variables and can be enabled or disabled as needed.

#### Quick Start

1. **Generate API Keys:**
```bash
# Generate a single secure API key
python scripts/generate-api-key.py

# Generate multiple keys
python scripts/generate-api-key.py --count 3

# Generate keys with custom length
python scripts/generate-api-key.py --length 32
```

2. **Configure API Keys:**
```bash
# Add to your .env file
API_KEYS=your-generated-key-here,another-key-here

# Or use environment-specific keys (recommended for production)
API_KEYS_DEVELOPMENT=dev-key-1,dev-key-2
API_KEYS_PRODUCTION=prod-key-1,prod-key-2
```

3. **Test Authentication:**
```bash
# Without authentication (will fail with 401)
curl http://localhost:5000/api/trackers

# With valid API key
curl -H "Authorization: Bearer your-generated-key-here" http://localhost:5000/api/trackers
```

#### Authentication Configuration

**Basic Configuration:**
```bash
# Single API key
API_KEYS=your-secret-api-key-here

# Multiple API keys (comma-separated)
API_KEYS=key1,key2,key3

# Disable authentication for development
# (leave API_KEYS empty or unset)
```

**Environment-Specific Configuration (Recommended):**
```bash
# Development keys
API_KEYS_DEVELOPMENT=dev-key-1,dev-key-2

# Staging keys  
API_KEYS_STAGING=staging-key-1,staging-key-2

# Production keys
API_KEYS_PRODUCTION=prod-key-1,prod-key-2
```

**Advanced Security Settings:**
```bash
# Enable automatic key rotation (default: true)
ENABLE_API_KEY_ROTATION=true

# Key reload interval in seconds (default: 300)
API_KEY_RELOAD_INTERVAL=300

# Trust proxy headers for accurate IP logging
TRUST_PROXY_HEADERS=true

# Require HTTPS in production (auto-enabled)
REQUIRE_HTTPS=true
```

#### Using API Keys

**Authorization Header Format:**
```bash
Authorization: Bearer your-api-key-here
```

**Example API Calls:**
```bash
# List all trackers
curl -H "Authorization: Bearer your-key" http://localhost:5000/api/trackers

# Create a new tracker
curl -X POST \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Tracker", "description": "Track something"}' \
  http://localhost:5000/add_tracker

# Get tracker values
curl -H "Authorization: Bearer your-key" \
  http://localhost:5000/api/trackers/1/values

# Create tracker value
curl -X POST \
  -H "Authorization: Bearer your-key" \
  -H "Content-Type: application/json" \
  -d '{"date": "2024-01-15", "value": 42}' \
  http://localhost:5000/api/trackers/1/values
```

#### Protected vs Public Endpoints

**Protected Endpoints (require API key):**
- All `/api/*` endpoints
- All `/trackers/*` endpoints  
- All `/tracker-values/*` endpoints
- `/add_tracker` endpoint

**Public Endpoints (no API key required):**
- `/health` - Basic health check
- `/health/*` - All health check endpoints
- `/status` - Application status
- `/ping` - Simple ping endpoint
- `/hello` - Legacy health check

#### Route Protection Configuration

You can customize which routes require authentication:

```bash
# Custom protected routes (comma-separated patterns)
PROTECTED_ROUTES=/api/*,/custom/*,/admin/*

# Custom public routes (comma-separated patterns)
PUBLIC_ROUTES=/health,/status,/public/*
```

#### Security Best Practices

**API Key Requirements:**
- Minimum 16 characters length
- Use cryptographically secure random generation
- Avoid predictable patterns or dictionary words
- Rotate keys regularly (especially in production)

**Key Management:**
- Store keys in environment variables, never in code
- Use different keys for different environments
- Implement key rotation policies
- Monitor authentication logs for suspicious activity

**Production Security:**
- Always use HTTPS in production
- Enable proxy header trust for accurate IP logging
- Set up monitoring and alerting for failed authentication attempts
- Use environment-specific keys (API_KEYS_PRODUCTION)
- Enable automatic key rotation

**Client Implementation:**
```python
# Python example
import requests

headers = {
    'Authorization': 'Bearer your-api-key-here',
    'Content-Type': 'application/json'
}

response = requests.get('http://localhost:5000/api/trackers', headers=headers)
```

```javascript
// JavaScript example
const headers = {
    'Authorization': 'Bearer your-api-key-here',
    'Content-Type': 'application/json'
};

fetch('http://localhost:5000/api/trackers', { headers })
    .then(response => response.json())
    .then(data => console.log(data));
```

```bash
# cURL example
curl -H "Authorization: Bearer your-api-key-here" \
     -H "Content-Type: application/json" \
     http://localhost:5000/api/trackers
```

#### Authentication Errors

**Common Error Responses:**

**Missing API Key (401):**
```json
{
    "error": "Unauthorized",
    "message": "API key required",
    "status_code": 401
}
```

**Invalid API Key (401):**
```json
{
    "error": "Unauthorized", 
    "message": "Invalid API key",
    "status_code": 401
}
```

**Malformed Header (401):**
```json
{
    "error": "Unauthorized",
    "message": "Invalid authorization header format",
    "status_code": 401
}
```

#### Troubleshooting Authentication

**Authentication Not Working:**
1. Verify API_KEYS environment variable is set
2. Check that keys meet minimum requirements (16+ characters)
3. Ensure Authorization header format: `Bearer your-key`
4. Check application logs for security system initialization
5. Test with a simple endpoint first

**Key Generation Issues:**
```bash
# Verify the key generator works
python scripts/generate-api-key.py --test

# Generate and test a key immediately
KEY=$(python scripts/generate-api-key.py)
curl -H "Authorization: Bearer $KEY" http://localhost:5000/health
```

**Environment-Specific Keys:**
```bash
# Check which environment is detected
curl http://localhost:5000/health/detailed

# Verify correct keys are loaded for your environment
# Check application startup logs for key count
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
- **Health check**: `GET /hello` - Simple health check endpoint (legacy, public)

**Trackers API (requires API key):**
- `GET /trackers` - List all trackers
- `POST /add_tracker` - Create a new tracker

**Tracker Values API (requires API key):**
- `POST /api/trackers/{id}/values` - Create/update tracker values
- `GET /api/trackers/{id}/values` - List tracker values
- `GET /api/trackers/{id}/values/{date}` - Get specific value
- `PUT /api/trackers/{id}/values/{date}` - Update specific value
- `DELETE /api/trackers/{id}/values/{date}` - Delete specific value

**Authentication:**
All API endpoints (except health checks) require a valid API key in the Authorization header:
```bash
Authorization: Bearer your-api-key-here
```

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
│   ├── security/
│   │   └── api_key_auth.py       # API key authentication system
│   └── validation/
│       └── tracker_value_validation.py # Input validation
├── tests/
│   ├── conftest.py               # Test fixtures and database setup
│   ├── test_api_key_security.py  # API key authentication tests
│   ├── test_db.py                # Database tests
│   ├── test_endpoints.py         # API endpoint tests
│   ├── test_health_endpoints.py  # Health check endpoint tests
│   ├── test_production_security.py # Production security tests
│   ├── test_settings.py          # Configuration tests (property-based)
│   ├── test_trackerdb.py         # Repository tests
│   ├── test_error_handling.py    # Error handling tests
│   └── test_tracker_value_integration.py # Integration tests
├── scripts/
│   ├── generate-api-key.py       # API key generation utility
│   ├── init-db.sh                # Database initialization script
│   ├── init-db.py                # Python database setup
│   ├── init-db.sql               # Manual SQL setup
│   ├── test-db.sh                # Test database management
│   └── migrate-tracker-values.py # Database migration script
├── docs/
│   ├── migration-system.md       # Database migration documentation
│   └── production-security.md    # Production security guide
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
- `FLASK_ENV` - Flask environment (development, staging, production)

**API Key Authentication:**
- `API_KEYS` - Comma-separated list of valid API keys
- `API_KEYS_DEVELOPMENT` - Development environment API keys
- `API_KEYS_STAGING` - Staging environment API keys  
- `API_KEYS_PRODUCTION` - Production environment API keys
- `ENABLE_API_KEY_ROTATION` - Enable automatic key rotation (default: true)
- `API_KEY_RELOAD_INTERVAL` - Key reload interval in seconds (default: 300)
- `TRUST_PROXY_HEADERS` - Trust proxy headers for IP extraction (default: false)
- `REQUIRE_HTTPS` - Require HTTPS connections (auto-enabled in production)
- `PROTECTED_ROUTES` - Custom protected route patterns (comma-separated)
- `PUBLIC_ROUTES` - Custom public route patterns (comma-separated)

**Legacy (for initialization scripts):**
- `POSTGRES_USER` - PostgreSQL superuser for initialization (default: postgres)
- `POSTGRES_PASSWORD` - PostgreSQL superuser password (default: postgres)

## Deployment

### Production Deployment (Clever Cloud)

The application is configured for deployment on Clever Cloud with proper WSGI support:

**WSGI Entry Point:** `wsgi:application`

The `wsgi.py` file provides the production WSGI application object that Clever Cloud (and other WSGI servers) can use. It automatically loads environment variables and creates the Flask application instance.

**Environment Variables:** 
- Clever Cloud automatically sets the PostgreSQL addon environment variables (`POSTGRESQL_ADDON_*`) when you add a PostgreSQL addon to your application.
- **API Key Configuration:** Set `API_KEYS_PRODUCTION` in Clever Cloud environment variables for secure API authentication.

**Production Security Setup:**
1. **Add PostgreSQL Addon** in Clever Cloud console
2. **Set API Keys** in environment variables:
   ```bash
   API_KEYS_PRODUCTION=your-secure-production-key-1,your-secure-production-key-2
   ```
3. **Optional Security Settings:**
   ```bash
   REQUIRE_HTTPS=true
   TRUST_PROXY_HEADERS=true
   ENABLE_API_KEY_ROTATION=true
   ```

**Production Features:**
- Automatic HTTPS requirement enforcement
- Proxy header trust for accurate IP logging  
- Enhanced security metrics logging
- Automatic key rotation support
- Production readiness validation

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
