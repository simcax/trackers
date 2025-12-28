# Database Migration System

## Overview

The automatic database migration system provides seamless database schema management for the trackers Flask application. The system detects missing or incomplete database schemas during application startup and automatically applies the necessary changes using SQLAlchemy metadata.

## Features

- **Automatic Schema Detection**: Detects missing database tables and schema inconsistencies
- **Safe Migration Execution**: Uses SQLAlchemy metadata to create tables with proper constraints and relationships
- **Idempotent Operations**: Safe to run multiple times without data corruption
- **Concurrent Safety**: Handles multiple application instances deploying simultaneously
- **Comprehensive Logging**: Detailed logging for monitoring and troubleshooting
- **Production Ready**: Designed for cloud platforms like Clever Cloud
- **Configuration Options**: Flexible configuration via environment variables
- **Manual Triggers**: API endpoints for manual migration control
- **Status Monitoring**: Health check endpoints for deployment monitoring

## Configuration

### Environment Variables

The migration system can be configured using the following environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `MIGRATION_ENABLED` | `true` | Enable/disable automatic migration |
| `MIGRATION_TIMEOUT` | `30` | Migration timeout in seconds |
| `MIGRATION_LOCK_TIMEOUT` | `30` | Lock acquisition timeout in seconds |
| `MIGRATION_LOGGING` | `true` | Enable detailed migration logging |
| `MIGRATION_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARN/ERROR) |
| `MIGRATION_SKIP_VALIDATION` | `false` | Skip post-migration validation |
| `MIGRATION_CONCURRENT_SAFETY` | `true` | Enable concurrent migration safety |

### Database Environment Variables

The system supports both Clever Cloud and local development environments:

**Clever Cloud (Priority)**:
- `POSTGRESQL_ADDON_HOST`
- `POSTGRESQL_ADDON_USER`
- `POSTGRESQL_ADDON_PASSWORD`
- `POSTGRESQL_ADDON_DB`
- `POSTGRESQL_ADDON_PORT` (optional, defaults to 5432)

**Local Development (Fallback)**:
- `DB_HOST`
- `DB_USER`
- `DB_PASSWORD`
- `DB_NAME`
- `DB_PORT`

## Usage

### Automatic Migration

Migration runs automatically during Flask application startup:

```python
from trackers import create_app

# Migration runs automatically when app is created
app = create_app()
```

### Manual Migration

You can trigger migration manually using the utility functions:

```python
from trackers.db.database import Base, engine
from trackers.db.migration_utils import trigger_manual_migration

# Trigger manual migration
result = trigger_manual_migration(engine, Base.metadata)

if result.success:
    print(f"Migration completed: {result.message}")
    print(f"Tables created: {result.tables_created}")
else:
    print(f"Migration failed: {result.message}")
    print(f"Errors: {result.errors}")
```

### API Endpoints

#### Migration Status

Get comprehensive migration status information:

```bash
GET /health/migration
```

Response:
```json
{
  "health": "healthy",
  "health_message": "Database is healthy and up to date",
  "migration_status": {
    "database_exists": true,
    "connection_healthy": true,
    "migration_needed": false,
    "existing_tables": ["trackers", "items", "logs", "tracker_values"],
    "missing_tables": [],
    "total_expected_tables": 4,
    "total_existing_tables": 4
  },
  "configuration": {
    "enabled": true,
    "timeout_seconds": 30,
    "lock_timeout_seconds": 30,
    "enable_logging": true,
    "log_level": "INFO",
    "concurrent_safety": true
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "trackers-api"
}
```

#### Manual Migration Trigger

Trigger migration manually:

```bash
POST /health/migration/trigger
```

Response:
```json
{
  "success": true,
  "message": "Migration completed successfully",
  "tables_created": ["new_table"],
  "errors": [],
  "duration_seconds": 1.23,
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "trackers-api"
}
```

## Deployment

### Clever Cloud

The migration system is designed to work seamlessly with Clever Cloud PostgreSQL addons:

1. **Attach PostgreSQL addon** to your application
2. **Deploy your application** - migration runs automatically
3. **Monitor deployment** using `/health/migration` endpoint

The system automatically uses `POSTGRESQL_ADDON_*` environment variables provided by Clever Cloud.

### Local Development

For local development:

1. **Set up local PostgreSQL** database
2. **Configure environment variables**:
   ```bash
   export DB_HOST=localhost
   export DB_USER=your_user
   export DB_PASSWORD=your_password
   export DB_NAME=trackers_dev
   export DB_PORT=5432
   ```
3. **Run the application** - migration runs automatically

### Docker

For Docker deployments:

```dockerfile
# Set migration configuration
ENV MIGRATION_ENABLED=true
ENV MIGRATION_TIMEOUT=60
ENV MIGRATION_LOG_LEVEL=INFO

# Database configuration
ENV DB_HOST=postgres
ENV DB_USER=trackers
ENV DB_PASSWORD=your_password
ENV DB_NAME=trackers
```

## Monitoring

### Health Checks

Use the health check endpoints to monitor migration status:

- `/health/migration` - Comprehensive migration status
- `/health/detailed` - Overall application health including database
- `/health/ready` - Kubernetes readiness probe
- `/health/live` - Kubernetes liveness probe

### Logging

Migration operations are logged with appropriate levels:

- **INFO**: Normal operations, successful migrations
- **WARN**: Non-critical issues, fallback behaviors
- **ERROR**: Migration failures, critical issues
- **DEBUG**: Detailed troubleshooting information

Example log output:
```
[INFO] ============================================================
[INFO] STARTING DATABASE MIGRATION
[INFO] ============================================================
[INFO] Database connection healthy: True
[INFO] Existing tables: 2
[INFO] Found tables: trackers, items
[INFO] Missing tables: 2
[INFO] Tables to create: logs, tracker_values
[INFO] Migration needed: True
[INFO] ----------------------------------------
[INFO] STARTING SCHEMA CREATION
[INFO] ----------------------------------------
[INFO] Creating 2 missing tables...
[INFO] ✓ Created table: logs
[INFO] ✓ Created table: tracker_values
[INFO] ✓ Successfully created all 2 tables
[INFO] ============================================================
[INFO] MIGRATION COMPLETED SUCCESSFULLY
[INFO] ============================================================
[INFO] Duration: 1.23 seconds
[INFO] Tables created: 2
[INFO] Created: logs, tracker_values
[INFO] Result: Created 2 tables successfully
[INFO] ============================================================
```

## Troubleshooting

### Common Issues

#### Connection Errors

**Symptoms**: `Database connection failed`, `Connection refused`

**Solutions**:
- Check database server is running
- Verify connection parameters (host, port, database name)
- Check network connectivity and firewall settings
- For Clever Cloud: Check PostgreSQL addon status in console

#### Permission Errors

**Symptoms**: `Permission denied`, `Insufficient privileges`

**Solutions**:
- Verify database user has CREATE TABLE privileges
- Check user has necessary schema modification permissions
- For Clever Cloud: Database user should have full privileges automatically

#### Timeout Errors

**Symptoms**: `Operation timed out`, `Migration timeout`

**Solutions**:
- Increase `MIGRATION_TIMEOUT` environment variable
- Check network latency and database performance
- For production: Consider increasing timeout for cloud deployments

#### Concurrent Migration Issues

**Symptoms**: `Migration lock acquisition failed`, `Another migration in progress`

**Solutions**:
- This is normal for zero-downtime deployments
- Wait for concurrent migration to complete
- Check for stale lock files if issue persists

### Environment Validation

Use the validation utility to check your environment:

```python
from trackers.db.migration_utils import validate_migration_environment

validation = validate_migration_environment()

if validation["valid"]:
    print("Environment is ready for migration")
else:
    print("Environment issues found:")
    for error in validation["errors"]:
        print(f"  ERROR: {error}")
    for warning in validation["warnings"]:
        print(f"  WARNING: {warning}")
```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
export MIGRATION_LOG_LEVEL=DEBUG
```

This provides detailed information about:
- Database connection attempts
- Table detection logic
- Schema validation steps
- Migration execution details

## Development

### Adding New Models

When adding new SQLAlchemy models:

1. **Create the model** in `trackers/models/`
2. **Import the model** in `trackers/__init__.py` (in the `_run_migration` function)
3. **Migration will automatically detect** and create the new table

Example:
```python
# In trackers/models/new_model.py
from trackers.db.database import Base

class NewModel(Base):
    __tablename__ = 'new_table'
    id = Column(Integer, primary_key=True)
    name = Column(String(100))

# In trackers/__init__.py, add to _run_migration function:
from trackers.models.new_model import NewModel
```

### Testing

The migration system includes comprehensive tests:

- **Property-based tests**: Validate correctness across many scenarios
- **Unit tests**: Test specific functionality
- **Integration tests**: Test end-to-end migration process

Run tests:
```bash
pytest tests/test_migration*.py -v
```

### Configuration Testing

Test different configuration scenarios:

```python
from trackers.db.migration_config import MigrationConfig

# Test custom configuration
config = MigrationConfig(
    enabled=True,
    timeout_seconds=60,
    log_level="DEBUG"
)

config.validate()  # Raises ValueError if invalid
```

## Security Considerations

- **Database Credentials**: Never log database passwords
- **Environment Variables**: Use secure methods to set environment variables in production
- **Network Security**: Ensure database connections use appropriate security (SSL/TLS)
- **Access Control**: Limit database user permissions to minimum required
- **Monitoring**: Monitor migration logs for security-related issues

## Performance

### Optimization Tips

- **Concurrent Safety**: Enable for production deployments
- **Timeout Settings**: Adjust based on database size and network latency
- **Logging Level**: Use INFO or WARN in production, DEBUG only for troubleshooting
- **Validation**: Enable post-migration validation for safety

### Scaling Considerations

- **Large Schemas**: Increase timeout for databases with many tables
- **High Latency**: Adjust timeouts for cloud deployments
- **Multiple Instances**: Concurrent safety handles multiple deployments automatically
- **Database Performance**: Monitor database performance during migration

## Support

For issues and questions:

1. **Check logs** for detailed error information
2. **Use health endpoints** to get current status
3. **Validate environment** using utility functions
4. **Review configuration** for common issues
5. **Check database connectivity** and permissions

The migration system is designed to be robust and provide clear error messages with recovery suggestions for common issues.