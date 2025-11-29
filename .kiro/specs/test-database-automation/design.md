# Design Document: Test Database Automation

## Overview

This design establishes a comprehensive automated testing infrastructure for the trackers Flask application. The system uses pytest fixtures to manage test database lifecycle, SQLAlchemy for ORM operations, and Flask's test client for endpoint testing. The architecture ensures complete isolation between test runs while maintaining simplicity and debuggability.

## Architecture

The testing infrastructure follows a layered approach:

1. **Configuration Layer**: Settings module that manages environment-specific database configuration
2. **Database Layer**: SQLAlchemy engine and session management with test-specific database
3. **Fixture Layer**: pytest fixtures that orchestrate database setup, teardown, and session management
4. **Test Layer**: Individual test functions that use fixtures to interact with the test database

### Component Interaction Flow

```
Test Session Start
    ↓
Load Settings (environment variables)
    ↓
Create Test Database (drop old, create new)
    ↓
Apply Schema (SQLAlchemy metadata)
    ↓
Test Function Starts
    ↓
Create Database Session (fixture)
    ↓
Run Test (interact with database)
    ↓
Rollback & Close Session
    ↓
Next Test or Session End
```

## Components and Interfaces

### 1. Settings Module (`trackers/db/settings.py`)

**Purpose**: Centralized configuration management for database connections

**Interface**:
```python
class Settings:
    db_host: str
    db_user: str
    db_password: str
    db_name: str
    db_url: str
    
    def init() -> None:
        """Load configuration from environment variables"""
    
    def get_test_db_url(test_db_name: str) -> str:
        """Generate test database URL"""
```

**Responsibilities**:
- Load database credentials from environment variables
- Construct PostgreSQL connection URLs
- Provide test-specific database URLs
- Validate required environment variables are present

### 2. Database Module (`trackers/db/database.py`)

**Purpose**: SQLAlchemy engine and session factory

**Interface**:
```python
engine: Engine  # SQLAlchemy engine instance
SessionLocal: sessionmaker  # Session factory
Base: DeclarativeMeta  # Base class for ORM models

def get_db() -> Generator[Session, None, None]:
    """Dependency injection for database sessions"""
```

**Responsibilities**:
- Create and manage SQLAlchemy engine
- Provide session factory for creating database sessions
- Export Base for model definitions

### 3. Test Configuration (`tests/conftest.py`)

**Purpose**: pytest configuration and fixture definitions

**Fixtures**:

#### `fake_db` (session scope, autouse)
- Drops existing test database
- Creates fresh test database
- Creates database user and grants privileges
- Applies all schema definitions
- Runs once per test session

#### `db_session` (function scope)
- Creates a new database session for each test
- Yields session to test function
- Rolls back any changes after test
- Closes session to prevent connection leaks

#### `app` (function scope)
- Creates Flask application in test mode
- Configures test-specific settings
- Returns configured app instance

#### `client` (function scope)
- Creates Flask test client from app fixture
- Enables HTTP request simulation

### 4. Model Integration

**Existing Models**:
- `TrackerModel`: Main tracker entity
- `ItemModel`: Items associated with trackers
- `LogModel`: Log entries for trackers

**Requirements**:
- All models must use the same `Base` from `database.py`
- Models must be imported before `Base.metadata.create_all()` is called
- Foreign key relationships must be properly defined

## Data Models

The existing data models remain unchanged but must be properly integrated:

```python
TrackerModel
├── id: Integer (PK)
├── name: String (unique, indexed)
├── description: String (nullable)
├── items: relationship → ItemModel
└── logs: relationship → LogModel

ItemModel
├── id: Integer (PK)
├── name: String (unique, indexed)
├── tracker_id: Integer (FK → trackers.id)
├── date: DateTime
└── tracker: relationship → TrackerModel

LogModel
├── id: Integer (PK)
├── message: String
├── tracker_id: Integer (FK → trackers.id)
└── tracker: relationship → TrackerModel
```

**Key Consideration**: All models currently define their own `Base` instance. This must be consolidated to use a single `Base` from `database.py` to ensure proper schema creation.


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Configuration Properties

**Property 1: Environment variable loading**
*For any* set of valid environment variables (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME), when the settings module initializes, it should correctly load all values into the corresponding settings fields.
**Validates: Requirements 1.1**

**Property 2: Test URL generation**
*For any* test database name string, the generated test database URL should contain that exact name and follow valid PostgreSQL connection string format.
**Validates: Requirements 1.2**

**Property 3: Connection string validity**
*For any* valid settings configuration, the generated database URL should match the PostgreSQL connection string pattern: `postgresql://user:password@host/database`.
**Validates: Requirements 1.3**

### Database Lifecycle Properties

**Property 4: Schema creation completeness**
*For any* set of ORM models registered with Base, after database creation and schema application, the test database should contain tables for all registered models.
**Validates: Requirements 2.3**

### Session Management Properties

**Property 5: Session validity**
*For any* test function, the db_session fixture should provide a session object that can successfully execute queries.
**Validates: Requirements 3.1**

**Property 6: Transaction isolation**
*For any* test function that creates data, when that test completes and a new test starts, the new test should not see the data from the previous test.
**Validates: Requirements 3.2, 3.4**

**Property 7: Session cleanup**
*For any* test function, after the test completes, the database session should be closed and not hold any active connections.
**Validates: Requirements 3.3**

### Data Persistence Properties

**Property 8: Tracker round-trip**
*For any* valid tracker with name and optional description, creating the tracker in the database and then querying for it should return a tracker with identical field values.
**Validates: Requirements 4.1, 4.2**

**Property 9: Relationship integrity**
*For any* tracker with associated items and logs, navigating the relationships in both directions (tracker→items, items→tracker) should maintain referential integrity and return the correct related objects.
**Validates: Requirements 4.3**

### Endpoint Integration Properties

**Property 10: Endpoint database persistence**
*For any* valid tracker data sent to the add_tracker endpoint, querying the database directly should return a tracker with matching data.
**Validates: Requirements 5.1**

**Property 11: Endpoint response completeness**
*For any* successful tracker creation via the add_tracker endpoint, the response should include all tracker fields that were provided in the request.
**Validates: Requirements 5.2**

**Property 12: Query endpoint accuracy**
*For any* tracker data in the test database, calling a query endpoint should return data that matches what's in the database.
**Validates: Requirements 5.3**

### Observability Properties

**Property 13: Setup logging**
*For any* test session, the database setup process should produce log messages indicating database creation and schema application steps.
**Validates: Requirements 6.3**

## Error Handling

The testing infrastructure must handle several error scenarios gracefully:

### 1. Missing Environment Variables
- **Scenario**: Required database configuration variables are not set
- **Handling**: Raise clear error message listing missing variables
- **Recovery**: User must set environment variables before running tests

### 2. Database Connection Failures
- **Scenario**: Cannot connect to PostgreSQL server
- **Handling**: Display connection error with host/port details and suggest checking if PostgreSQL is running
- **Recovery**: User must start PostgreSQL service

### 3. Active Database Connections
- **Scenario**: Cannot drop test database due to active connections
- **Handling**: Log warning message suggesting closing other connections (e.g., psql prompts)
- **Recovery**: Attempt to terminate connections or skip drop and proceed with existing database

### 4. Permission Errors
- **Scenario**: Database user lacks privileges to create databases or tables
- **Handling**: Display permission error with specific privilege requirements
- **Recovery**: User must grant appropriate privileges to database user

### 5. Schema Migration Conflicts
- **Scenario**: Existing test database schema doesn't match current models
- **Handling**: Drop and recreate database to ensure clean schema
- **Recovery**: Automatic via database recreation

## Testing Strategy

### Dual Testing Approach

This feature requires both unit tests and property-based tests to ensure comprehensive coverage:

- **Unit tests** verify specific scenarios, edge cases, and error conditions
- **Property tests** verify universal properties that should hold across all inputs
- Together they provide complete coverage: unit tests catch concrete bugs, property tests verify general correctness

### Unit Testing

Unit tests will cover:

1. **Specific setup scenarios**:
   - Database creation with existing database
   - Database creation with no existing database
   - User creation when user already exists
   - Schema application with empty models
   - Schema application with multiple related models

2. **Error conditions**:
   - Missing environment variables
   - Invalid database credentials
   - Connection failures
   - Permission errors

3. **Integration points**:
   - Flask app initialization with test config
   - Test client creation
   - Fixture interaction (app → client → db_session)

### Property-Based Testing

Property-based tests will use **Hypothesis** (Python's leading property-based testing library) to verify universal properties.

**Configuration**:
- Each property test will run a minimum of 100 iterations
- Tests will use Hypothesis strategies to generate varied test data
- Each property test will be tagged with a comment referencing the design document property

**Tag Format**: `# Feature: test-database-automation, Property {number}: {property_text}`

**Property Test Coverage**:

1. **Configuration properties** (Properties 1-3):
   - Generate random valid environment variable combinations
   - Generate random test database names
   - Verify URL format and content

2. **Session management properties** (Properties 5-7):
   - Generate random database operations
   - Verify session state after operations
   - Verify isolation between test runs

3. **Data persistence properties** (Properties 8-9):
   - Generate random tracker data (names, descriptions)
   - Generate random related items and logs
   - Verify round-trip consistency
   - Verify relationship navigation

4. **Endpoint properties** (Properties 10-12):
   - Generate random valid tracker payloads
   - Verify database state matches requests
   - Verify response completeness

**Property Test Implementation**:
- Each correctness property (1-13) will be implemented by a SINGLE property-based test
- Tests will be placed in appropriate test files based on the component being tested
- Property tests will be implemented alongside the components they test, not as a separate final step

### Test Organization

```
tests/
├── conftest.py              # Fixtures and test configuration
├── test_settings.py         # Settings module tests (Properties 1-3)
├── test_db_lifecycle.py     # Database setup/teardown tests (Property 4)
├── test_db_session.py       # Session management tests (Properties 5-7)
├── test_models.py           # Model persistence tests (Properties 8-9)
├── test_endpoints.py        # Endpoint integration tests (Properties 10-12)
└── test_observability.py    # Logging tests (Property 13)
```

## Implementation Considerations

### 1. Import Order
Models must be imported before `Base.metadata.create_all()` is called. The recommended approach:
```python
# In conftest.py, before create_all
from trackers.models.tracker_model import TrackerModel, ItemModel, LogModel
```

### 2. Base Consolidation
Currently `tracker_model.py` defines its own `Base`. This must be changed to import from `database.py`:
```python
# Change from:
Base = declarative_base()

# To:
from trackers.db.database import Base
```

### 3. Environment Variables
Required environment variables:
- `DB_HOST`: PostgreSQL server host (default: localhost)
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_NAME`: Base database name (test database will append `_test`)

### 4. Test Database Naming
Test database name format: `{DB_NAME}_test`
This ensures clear separation from development database.

### 5. Connection Pooling
For tests, disable connection pooling to avoid connection leaks:
```python
engine = create_engine(url, poolclass=NullPool)
```

### 6. Transaction Management
Each test should run in a transaction that's rolled back:
- Faster than recreating database for each test
- Ensures complete isolation
- Preserves database structure

## Dependencies

- **pytest**: Test framework (already installed)
- **hypothesis**: Property-based testing library (needs installation)
- **python-dotenv**: Environment variable loading (already installed)
- **SQLAlchemy**: ORM and database toolkit (already installed)
- **Flask**: Web framework with test client (already installed)
- **psycopg2-binary**: PostgreSQL adapter for Python (needs installation)

## Success Criteria

The implementation is complete when:

1. All tests can run with `pytest` command
2. Test database is automatically created and destroyed
3. Tests run in isolation without interfering with each other
4. All 13 correctness properties are verified by property-based tests
5. Error messages clearly indicate problems and suggest fixes
6. No manual database setup is required to run tests
7. Tests pass consistently on clean runs
