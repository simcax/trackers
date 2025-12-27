# Testing endpoints of the application

from trackers.db.trackerdb import get_all_trackers, get_tracker


def test_add_tracker_endpoint_database_persistence(client, db_session):
    """
    Test adding a tracker via the endpoint and verify database persistence.

    Validates: Requirements 5.1
    """
    response = client.post(
        "/add_tracker",
        json={"name": "Test Tracker Endpoint", "description": "Test Description"},
    )
    assert response.status_code == 201
    assert response.json["message"] == "Tracker added successfully"
    assert "tracker" in response.json
    assert response.json["tracker"]["name"] == "Test Tracker Endpoint"
    assert response.json["tracker"]["description"] == "Test Description"
    assert response.json["tracker"]["id"] is not None

    # Verify database persistence by querying directly
    tracker_id = response.json["tracker"]["id"]
    db_tracker = get_tracker(db_session, tracker_id)
    assert db_tracker is not None
    assert db_tracker.name == "Test Tracker Endpoint"
    assert db_tracker.description == "Test Description"
    assert db_tracker.id == tracker_id


def test_add_tracker_endpoint_response_completeness(client, db_session):
    """
    Test that the add_tracker endpoint response includes all provided fields.

    Validates: Requirements 5.2
    """
    tracker_data = {"name": "Complete Tracker", "description": "A complete description"}
    response = client.post("/add_tracker", json=tracker_data)
    assert response.status_code == 201

    # Verify response contains all fields from request
    response_tracker = response.json["tracker"]
    assert response_tracker["name"] == tracker_data["name"]
    assert response_tracker["description"] == tracker_data["description"]
    assert "id" in response_tracker


def test_add_tracker_endpoint_without_description(client, db_session):
    """
    Test adding a tracker without description.

    Validates: Requirements 5.2
    """
    response = client.post("/add_tracker", json={"name": "Minimal Tracker"})
    assert response.status_code == 201
    assert response.json["tracker"]["name"] == "Minimal Tracker"
    assert response.json["tracker"]["description"] is None


def test_query_trackers_after_creation(client, db_session):
    """
    Test querying trackers after creating them via the endpoint.

    Validates: Requirements 5.3
    """
    # Create multiple trackers
    tracker1_response = client.post(
        "/add_tracker", json={"name": "Endpoint Tracker 1", "description": "First"}
    )
    tracker2_response = client.post(
        "/add_tracker", json={"name": "Endpoint Tracker 2", "description": "Second"}
    )

    assert tracker1_response.status_code == 201
    assert tracker2_response.status_code == 201

    # Query all trackers
    response = client.get("/trackers")
    assert response.status_code == 200
    assert "trackers" in response.json

    trackers = response.json["trackers"]
    assert len(trackers) >= 2

    # Verify the created trackers are in the response
    tracker_names = [t["name"] for t in trackers]
    assert "Endpoint Tracker 1" in tracker_names
    assert "Endpoint Tracker 2" in tracker_names


def test_query_endpoint_matches_database_state(client, db_session):
    """
    Test that the query endpoint returns data matching the database state.

    Validates: Requirements 5.3
    """
    # Create a tracker via endpoint
    create_response = client.post(
        "/add_tracker", json={"name": "DB State Tracker", "description": "State Test"}
    )
    assert create_response.status_code == 201

    # Query via endpoint
    query_response = client.get("/trackers")
    assert query_response.status_code == 200

    # Query database directly
    db_trackers = get_all_trackers(db_session)

    # Verify counts match
    assert len(query_response.json["trackers"]) == len(db_trackers)

    # Verify data matches for our created tracker
    endpoint_tracker = next(
        (t for t in query_response.json["trackers"] if t["name"] == "DB State Tracker"),
        None,
    )
    db_tracker = next((t for t in db_trackers if t.name == "DB State Tracker"), None)

    assert endpoint_tracker is not None
    assert db_tracker is not None
    assert endpoint_tracker["id"] == db_tracker.id
    assert endpoint_tracker["name"] == db_tracker.name
    assert endpoint_tracker["description"] == db_tracker.description


def test_add_tracker_duplicate_name_error(client, db_session):
    """
    Test that adding a tracker with a duplicate name returns an error.

    Validates: Requirements 5.1
    """
    # Create first tracker
    response1 = client.post("/add_tracker", json={"name": "Duplicate Tracker"})
    assert response1.status_code == 201

    # Attempt to create tracker with same name
    response2 = client.post("/add_tracker", json={"name": "Duplicate Tracker"})
    assert response2.status_code == 409
    assert "error" in response2.json
    assert "already exists" in response2.json["error"].lower()


def test_add_tracker_missing_name_error(client, db_session):
    """
    Test that adding a tracker without a name returns an error.

    Validates: Requirements 5.1
    """
    response = client.post("/add_tracker", json={"description": "No name provided"})
    assert response.status_code == 400
    assert "error" in response.json
    assert "required" in response.json["error"].lower()


def test_add_tracker_empty_name_error(client, db_session):
    """
    Test that adding a tracker with an empty name returns an error.

    Validates: Requirements 5.1
    """
    response = client.post("/add_tracker", json={"name": ""})
    assert response.status_code == 400
    assert "error" in response.json


def test_add_tracker_invalid_json(client, db_session):
    """
    Test that sending invalid JSON returns an error.

    Validates: Requirements 5.1
    """
    response = client.post(
        "/add_tracker", data="not json", content_type="application/json"
    )
    assert response.status_code in [
        400,
        500,
    ]  # Either bad request or server error is acceptable


def test_tracker_value_routes_registered(client, db_session):
    """
    Test that tracker value routes are properly registered and accessible.

    This test verifies basic route registration and connectivity without
    requiring a full database setup.

    Validates: All API requirements - route registration
    """
    # First create a tracker to use for testing
    tracker_response = client.post(
        "/add_tracker",
        json={"name": "Route Test Tracker", "description": "For testing routes"},
    )
    assert tracker_response.status_code == 201
    tracker_id = tracker_response.json["tracker"]["id"]

    # Test POST /api/trackers/{tracker_id}/values (should fail validation but route should exist)
    response = client.post(f"/api/trackers/{tracker_id}/values", json={})
    assert (
        response.status_code == 400
    )  # Bad request due to missing data, but route exists
    assert "error" in response.json

    # Test GET /api/trackers/{tracker_id}/values/{date} (should return 404 for non-existent value)
    response = client.get(f"/api/trackers/{tracker_id}/values/2024-01-01")
    assert response.status_code == 404  # Not found, but route exists
    assert "error" in response.json

    # Test GET /api/trackers/{tracker_id}/values (should return empty array)
    response = client.get(f"/api/trackers/{tracker_id}/values")
    assert response.status_code == 200  # Should work and return empty array
    assert "values" in response.json
    assert response.json["values"] == []

    # Test PUT /api/trackers/{tracker_id}/values/{date} (should fail validation but route should exist)
    response = client.put(f"/api/trackers/{tracker_id}/values/2024-01-01", json={})
    assert (
        response.status_code == 400
    )  # Bad request due to missing data, but route exists
    assert "error" in response.json

    # Test DELETE /api/trackers/{tracker_id}/values/{date} (should return 404 for non-existent value)
    response = client.delete(f"/api/trackers/{tracker_id}/values/2024-01-01")
    assert response.status_code == 404  # Not found, but route exists
    assert "error" in response.json

    # Test DELETE /api/trackers/{tracker_id}/values (should work and return 0 deleted)
    response = client.delete(f"/api/trackers/{tracker_id}/values")
    assert response.status_code == 200  # Should work
    assert "deleted_count" in response.json
    assert response.json["deleted_count"] == 0


def test_tracker_value_routes_error_handling(client, db_session):
    """
    Test that tracker value routes have proper error handling for non-existent trackers.

    Validates: Requirements 2.2, 3.2, 4.2, 5.2 - error handling
    """
    non_existent_tracker_id = 99999

    # Test all routes with non-existent tracker ID
    routes_to_test = [
        (
            "POST",
            f"/api/trackers/{non_existent_tracker_id}/values",
            {"date": "2024-01-01", "value": "test"},
        ),
        ("GET", f"/api/trackers/{non_existent_tracker_id}/values/2024-01-01", None),
        ("GET", f"/api/trackers/{non_existent_tracker_id}/values", None),
        (
            "PUT",
            f"/api/trackers/{non_existent_tracker_id}/values/2024-01-01",
            {"value": "test"},
        ),
        ("DELETE", f"/api/trackers/{non_existent_tracker_id}/values/2024-01-01", None),
        ("DELETE", f"/api/trackers/{non_existent_tracker_id}/values", None),
    ]

    for method, url, json_data in routes_to_test:
        if method == "POST":
            response = client.post(url, json=json_data)
        elif method == "GET":
            response = client.get(url)
        elif method == "PUT":
            response = client.put(url, json=json_data)
        elif method == "DELETE":
            response = client.delete(url)

        # All should return 404 for non-existent tracker
        assert response.status_code == 404, (
            f"Route {method} {url} should return 404 for non-existent tracker"
        )
        assert "error" in response.json
        assert "not found" in response.json["error"]["message"].lower()
