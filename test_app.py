import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_home(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PhishNet API is running!" in response.data

def test_detect_phishing(client):
    response = client.post("/detect", json={"url": "http://example.com"})
    assert response.status_code == 200
    assert "is_phishing" in response.json

def test_submit_report(client):
    response = client.post("/report", json={"url": "http://example.com", "reason": "Test reason"})
    assert response.status_code == 200
    assert response.json["status"] == "success"
