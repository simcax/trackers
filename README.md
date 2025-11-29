# Trackers

A Flask application for managing trackers with PostgreSQL database support.

## Development Setup

### Prerequisites

- Python 3.13+
- Docker and Docker Compose
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

### Running Tests

The project uses Docker Compose to provide a PostgreSQL database for testing.

1. Start the test database:
```bash
docker compose -f docker-compose.test.yml up -d
```

Or use the helper script:
```bash
./scripts/test-db.sh start
```

2. Run tests:
```bash
pytest
```

3. Stop the test database:
```bash
docker compose -f docker-compose.test.yml down
```

Or use the helper script:
```bash
./scripts/test-db.sh stop
```

### Test Database Management

The `scripts/test-db.sh` script provides convenient commands:

- `./scripts/test-db.sh start` - Start the test database
- `./scripts/test-db.sh stop` - Stop the test database
- `./scripts/test-db.sh restart` - Restart the test database
- `./scripts/test-db.sh clean` - Stop and remove the test database (including data)
- `./scripts/test-db.sh logs` - Show database logs

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
│   ├── conftest.py          # Test fixtures
│   ├── test_db.py           # Database tests
│   ├── test_trackerdb.py    # Repository tests
│   └── test_endpoints.py    # API endpoint tests
└── docker-compose.test.yml  # Test database configuration
```

## Environment Variables

Required environment variables:

- `DB_HOST` - PostgreSQL server host (default: localhost)
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `DB_NAME` - Database name (test database will append `_test`)
