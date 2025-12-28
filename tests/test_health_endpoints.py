"""
Tests for health check endpoints.

Verifies that health check endpoints return correct status information
and properly detect application and database health.
"""

from unittest.mock import patch

from sqlalchemy.exc import SQLAlchemyError


def test_basic_health_check(client):
    """Test the basic health check endpoint."""
    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "trackers-api"
    assert "timestamp" in data

    # Verify timestamp format (ISO 8601)
    from datetime import datetime

    datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))


def test_detailed_health_check_healthy(client, db_session):
    """Test detailed health check when all systems are healthy."""
    response = client.get("/health/detailed")

    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["service"] == "trackers-api"
    assert "timestamp" in data

    # Check application status
    assert data["checks"]["application"]["status"] == "healthy"

    # Check database status
    assert data["checks"]["database"]["status"] == "healthy"
    assert "Database connection successful" in data["checks"]["database"]["message"]


def test_detailed_health_check_database_failure(client):
    """Test detailed health check when database is unavailable."""
    # Mock database session to raise an exception
    with patch("trackers.routes.health_routes.SessionLocal") as mock_session_local:
        mock_session_local.side_effect = SQLAlchemyError("Connection failed")

        response = client.get("/health/detailed")

        assert response.status_code == 503

        data = response.get_json()
        assert data["status"] == "unhealthy"
        assert data["service"] == "trackers-api"

        # Check application status (should still be healthy)
        assert data["checks"]["application"]["status"] == "healthy"

        # Check database status (should be unhealthy)
        assert data["checks"]["database"]["status"] == "unhealthy"
        assert "Connection failed" in data["checks"]["database"]["message"]


def test_detailed_health_check_database_query_failure(client):
    """Test detailed health check when database connection works but queries fail."""
    # Mock database session to connect but fail on query
    with patch("trackers.routes.health_routes.SessionLocal") as mock_session_local:
        mock_session = mock_session_local.return_value
        mock_session.execute.side_effect = SQLAlchemyError("Query failed")

        response = client.get("/health/detailed")

        assert response.status_code == 503

        data = response.get_json()
        assert data["status"] == "unhealthy"

        # Check database status
        assert data["checks"]["database"]["status"] == "unhealthy"
        assert "Query failed" in data["checks"]["database"]["message"]

        # Verify session was closed
        mock_session.close.assert_called_once()


def test_readiness_check_ready(client, db_session):
    """Test readiness check when application is ready."""
    response = client.get("/health/ready")

    assert response.status_code == 200

    data = response.get_json()
    assert data["ready"] is True
    assert data["service"] == "trackers-api"
    assert "timestamp" in data

    # Check database readiness
    assert data["checks"]["database"]["ready"] is True
    assert "Database ready" in data["checks"]["database"]["message"]


def test_readiness_check_not_ready(client):
    """Test readiness check when database is not ready."""
    with patch("trackers.routes.health_routes.SessionLocal") as mock_session_local:
        mock_session_local.side_effect = Exception("Database not available")

        response = client.get("/health/ready")

        assert response.status_code == 503

        data = response.get_json()
        assert data["ready"] is False
        assert data["service"] == "trackers-api"

        # Check database readiness
        assert data["checks"]["database"]["ready"] is False
        assert "Database not available" in data["checks"]["database"]["message"]


def test_readiness_check_database_query_failure(client):
    """Test readiness check when database connects but queries fail."""
    with patch("trackers.routes.health_routes.SessionLocal") as mock_session_local:
        mock_session = mock_session_local.return_value
        mock_session.execute.side_effect = Exception("Query timeout")

        response = client.get("/health/ready")

        assert response.status_code == 503

        data = response.get_json()
        assert data["ready"] is False

        # Check database readiness
        assert data["checks"]["database"]["ready"] is False
        assert "Query timeout" in data["checks"]["database"]["message"]

        # Verify session was closed
        mock_session.close.assert_called_once()


def test_liveness_check(client):
    """Test liveness check endpoint."""
    response = client.get("/health/live")

    assert response.status_code == 200

    data = response.get_json()
    assert data["alive"] is True
    assert data["service"] == "trackers-api"
    assert "timestamp" in data

    # Verify timestamp format
    from datetime import datetime

    datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00"))


def test_health_endpoints_json_format(client):
    """Test that all health endpoints return valid JSON."""
    endpoints = ["/health", "/health/detailed", "/health/ready", "/health/live"]

    for endpoint in endpoints:
        response = client.get(endpoint)

        # Should be able to parse as JSON
        data = response.get_json()
        assert data is not None

        # Should have required fields
        assert "service" in data
        assert "timestamp" in data
        assert data["service"] == "trackers-api"


def test_health_endpoints_cors_headers(client):
    """Test that health endpoints can be accessed from different origins."""
    response = client.get("/health")

    # Health endpoints should be accessible (no CORS restrictions for monitoring)
    assert response.status_code == 200


def test_health_check_performance(client):
    """Test that basic health check responds quickly."""
    import time

    start_time = time.time()
    response = client.get("/health")
    end_time = time.time()

    # Basic health check should be very fast (under 100ms)
    assert (end_time - start_time) < 0.1
    assert response.status_code == 200


def test_detailed_health_check_with_database_session(client, db_session):
    """Test detailed health check with an active database session."""
    # This test ensures the health check works even when there are active sessions
    response = client.get("/health/detailed")

    assert response.status_code == 200

    data = response.get_json()
    assert data["status"] == "healthy"
    assert data["checks"]["database"]["status"] == "healthy"
