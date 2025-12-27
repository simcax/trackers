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
│   │   ├── database.py      # Database engine and session setup
│   │   ├── settings.py      # Configuration management
│   │   └── trackerdb.py     # Repository operations (CRUD)
│   ├── models/
│   │   └── tracker_model.py # SQLAlchemy models
│   └── routes/
│       └── tracker_routes.py # API endpoints
├── tests/
│   ├── conftest.py          # Test fixtures and database setup
│   ├── test_db.py           # Database tests
│   ├── test_trackerdb.py    # Repository tests
│   ├── test_endpoints.py    # API endpoint tests
│   ├── test_settings.py     # Configuration tests (property-based)
│   └── test_error_handling.py # Error handling tests
├── scripts/
│   ├── init-db.sh           # Database initialization script
│   ├── init-db.py           # Python database setup
│   ├── init-db.sql          # Manual SQL setup
│   └── test-db.sh           # Test database management
└── docker-compose.test.yml  # Test database configuration
```

## Environment Variables

Required environment variables:

- `DB_HOST` - PostgreSQL server host (default: localhost)
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name (test database will append `_test`)

Optional environment variables:

- `POSTGRES_USER` - PostgreSQL superuser for initialization (default: postgres)
- `POSTGRES_PASSWORD` - PostgreSQL superuser password (default: postgres)

## Database Schema

The application uses three main tables:

- **trackers** - Main tracker entities with name and description
- **items** - Items associated with trackers, with timestamps
- **logs** - Log entries for tracking events and changes

All tables are automatically created by the SQLAlchemy models when you run the initialization scripts.
