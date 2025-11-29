# Implementation Plan

- [x] 1. Create settings module for database configuration
  - Create `trackers/db/settings.py` with Settings class
  - Implement environment variable loading (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
  - Implement database URL construction for both regular and test databases
  - Add validation for required environment variables
  - _Requirements: 1.1, 1.2, 1.3_

- [x] 1.1 Write property test for environment variable loading
  - **Property 1: Environment variable loading**
  - **Validates: Requirements 1.1**

- [ ]* 1.2 Write property test for test URL generation
  - **Property 2: Test URL generation**
  - **Validates: Requirements 1.2**

- [ ]* 1.3 Write property test for connection string validity
  - **Property 3: Connection string validity**
  - **Validates: Requirements 1.3**

- [x] 2. Fix model Base consolidation
  - Update `trackers/models/tracker_model.py` to import Base from `trackers.db.database`
  - Remove local `Base = declarative_base()` definition
  - Verify all models use the shared Base
  - _Requirements: 2.3_

- [x] 3. Install missing dependencies
  - Add `hypothesis` to dev dependencies for property-based testing
  - Add `psycopg2-binary` to main dependencies for PostgreSQL support
  - Update `pyproject.toml` with new dependencies
  - Run dependency installation
  - _Requirements: All (infrastructure)_

- [x] 4. Implement database lifecycle fixtures
  - Fix syntax error in `tests/conftest.py` (missing `@pytest.fixture` decorator before `fake_db`)
  - Update `fake_db` fixture to properly import models before schema creation
  - Implement proper error handling for database drop failures
  - Add logging for database creation and teardown steps
  - Ensure test database naming follows `{DB_NAME}_test` pattern
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 6.1, 6.3_

- [ ]* 4.1 Write property test for schema creation completeness
  - **Property 4: Schema creation completeness**
  - **Validates: Requirements 2.3**

- [x] 5. Implement database session fixture
  - Create `db_session` fixture in `tests/conftest.py` with function scope
  - Implement session creation using SessionLocal
  - Implement transaction rollback after each test
  - Implement session close to prevent connection leaks
  - Ensure proper cleanup even when tests fail
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [ ]* 5.1 Write property test for session validity
  - **Property 5: Session validity**
  - **Validates: Requirements 3.1**

- [ ]* 5.2 Write property test for transaction isolation
  - **Property 6: Transaction isolation**
  - **Validates: Requirements 3.2, 3.4**

- [ ]* 5.3 Write property test for session cleanup
  - **Property 7: Session cleanup**
  - **Validates: Requirements 3.3**

- [x] 6. Update existing test files to use new fixtures
  - Update `tests/test_db.py` to use `db_session` fixture
  - Update test to create and query actual tracker data
  - Remove placeholder test
  - _Requirements: 4.1, 4.2_

- [ ]* 6.1 Write property test for tracker round-trip
  - **Property 8: Tracker round-trip**
  - **Validates: Requirements 4.1, 4.2**

- [ ]* 6.2 Write property test for relationship integrity
  - **Property 9: Relationship integrity**
  - **Validates: Requirements 4.3**

- [ ]* 6.3 Write unit test for cascade delete behavior
  - Test deleting tracker with related items and logs
  - Verify cascade behavior matches model definitions
  - _Requirements: 4.4_

- [x] 7. Implement tracker repository operations
  - Create `trackers/db/trackerdb.py` with CRUD operations
  - Implement `create_tracker(db, name, description)` function
  - Implement `get_tracker(db, tracker_id)` function
  - Implement `get_all_trackers(db)` function
  - Implement `delete_tracker(db, tracker_id)` function
  - _Requirements: 4.1, 4.2, 4.4_

- [x] 8. Update add_tracker endpoint to use database
  - Modify `trackers/routes/tracker_routes.py` to import database functions
  - Update `add_tracker` endpoint to create tracker in database
  - Return created tracker data in response
  - Add error handling for duplicate tracker names
  - _Requirements: 5.1, 5.2_

- [x] 9. Create query endpoint for trackers
  - Add `get_trackers` endpoint to `trackers/routes/tracker_routes.py`
  - Implement endpoint to return all trackers from database
  - Return JSON array of tracker objects
  - _Requirements: 5.3_

- [x] 10. Update endpoint tests
  - Update `tests/test_endpoints.py` to verify database persistence
  - Add test for querying trackers after creation
  - Verify response data matches database state
  - Test error cases (duplicate names, invalid data)
  - _Requirements: 5.1, 5.2, 5.3_

- [ ]* 10.1 Write property test for endpoint database persistence
  - **Property 10: Endpoint database persistence**
  - **Validates: Requirements 5.1**

- [ ]* 10.2 Write property test for endpoint response completeness
  - **Property 11: Endpoint response completeness**
  - **Validates: Requirements 5.2**

- [ ]* 10.3 Write property test for query endpoint accuracy
  - **Property 12: Query endpoint accuracy**
  - **Validates: Requirements 5.3**

- [x] 11. Implement error handling and logging
  - Add connection error handling with helpful messages
  - Add permission error handling with privilege suggestions
  - Ensure database state is preserved on test failures
  - _Requirements: 6.1, 6.2, 6.4_

- [ ]* 11.1 Write property test for setup logging
  - **Property 13: Setup logging**
  - **Validates: Requirements 6.3**

- [x] 12. Create .env.example file
  - Document required environment variables
  - Provide example values for local development
  - Add instructions for setting up test database
  - _Requirements: 1.1_

- [x] 13. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
