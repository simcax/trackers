def test_app_initialisation(client):
    response = client.get("/hello")
    assert response.data == b"Hello, World!"
