#!/bin/bash

# Script to manage the test database container

case "$1" in
  start)
    echo "Starting test database..."
    docker-compose -f docker-compose.test.yml up -d
    echo "Waiting for database to be ready..."
    sleep 3
    docker-compose -f docker-compose.test.yml exec -T postgres-test pg_isready -U postgres
    echo "Test database is ready!"
    ;;
  stop)
    echo "Stopping test database..."
    docker-compose -f docker-compose.test.yml down
    ;;
  restart)
    echo "Restarting test database..."
    docker-compose -f docker-compose.test.yml restart
    ;;
  clean)
    echo "Stopping and removing test database (including volumes)..."
    docker-compose -f docker-compose.test.yml down -v
    ;;
  logs)
    docker-compose -f docker-compose.test.yml logs -f postgres-test
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|clean|logs}"
    echo ""
    echo "Commands:"
    echo "  start   - Start the test database container"
    echo "  stop    - Stop the test database container"
    echo "  restart - Restart the test database container"
    echo "  clean   - Stop and remove the test database (including data)"
    echo "  logs    - Show database logs"
    exit 1
    ;;
esac
