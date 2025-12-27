# Database Migration: Tracker Values

This directory contains the migration script for adding the `tracker_values` table to the trackers database.

## Migration Script

**File**: `migrate-tracker-values.py`

### Purpose

Adds the `tracker_values` table to an existing trackers database with:
- Proper foreign key constraints to the `trackers` table
- Unique constraint on `(tracker_id, date)` to ensure one value per tracker per day
- Optimized indexes for efficient queries
- Automatic timestamp management

### Usage

#### Apply Migration
```bash
python scripts/migrate-tracker-values.py
```

#### Rollback Migration
```bash
python scripts/migrate-tracker-values.py --rollback
```

### Requirements

- PostgreSQL database with existing `trackers` table
- Environment variables set (DB_HOST, DB_USER, DB_PASSWORD, DB_NAME)
- Python dependencies: sqlalchemy, psycopg2, python-dotenv

### Table Schema

The migration creates the following table:

```sql
CREATE TABLE tracker_values (
    id SERIAL PRIMARY KEY,
    tracker_id INTEGER NOT NULL REFERENCES trackers(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW() NOT NULL,
    CONSTRAINT unique_tracker_date UNIQUE(tracker_id, date)
);

CREATE INDEX idx_tracker_date ON tracker_values(tracker_id, date);
```

### Features

- **Idempotent**: Safe to run multiple times
- **Verification**: Automatically verifies migration success
- **Rollback**: Complete rollback capability
- **Error Handling**: Comprehensive error messages and validation
- **Clean Database Testing**: Verified to work on clean databases

### Validation

The migration script includes comprehensive validation:
- Checks table existence before creation
- Verifies all columns are created correctly
- Confirms constraints and indexes are in place
- Validates foreign key relationships

### Testing

The migration has been tested on:
- Existing databases with tracker data
- Clean databases without existing data
- Rollback and re-application scenarios

All existing tests continue to pass after migration.