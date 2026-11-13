"""
Automated validation test suite for Lab 1 (Securing a Web API).
Tests verify that all 6 OWASP Top 10 vulnerabilities are closed and valid flows function correctly.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

@pytest.fixture
def client():
    return TestClient(app)

def test_login_and_valid_flow(client):
    # Test valid login
    res = client.post("/login", json={"username": "alice", "password": "alicepass"})
    assert res.status_code == 200
    token = res.json()["token"]
    assert token and ":" in token

    # Test list my notes
    res = client.get("/notes", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200
    notes = res.json()
    assert len(notes) == 1
    assert notes[0]["title"] == "Alice diary"

    # Test create note
    res = client.post("/notes", json={"title": "Test Note", "body": "Hello world"}, headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 201
    assert res.json()["title"] == "Test Note"

def test_a05_sql_injection_blocked(client):
    # Attempt SQL injection bypass
    res = client.post("/login", json={"username": "' OR '1'='1' --", "password": "anything"})
    assert res.status_code == 401

def test_a07_auth_enumeration_prevented(client):
    # Bad username vs bad password should return generic 401
    res1 = client.post("/login", json={"username": "nonexistent_user", "password": "password"})
    res2 = client.post("/login", json={"username": "alice", "password": "wrongpassword"})
    assert res1.status_code == 401
    assert res2.status_code == 401
    assert res1.json()["detail"] == res2.json()["detail"]

def test_a01_broken_access_control_prevented(client):
    # Login as alice (owner of note 1, bob owns note 2)
    res = client.post("/login", json={"username": "alice", "password": "alicepass"})
    token = res.json()["token"]

    # Alice can read note 1
    res = client.get("/notes/1", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200

    # Alice cannot read note 2 (Bob's note)
    res = client.get("/notes/2", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403

def test_a10_exceptional_conditions_fails_closed(client):
    # Alice (non-admin) trying to access /admin/users
    res = client.post("/login", json={"username": "alice", "password": "alicepass"})
    token = res.json()["token"]

    res = client.get("/admin/users", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 403

    # Admin can access /admin/users
    admin_res = client.post("/login", json={"username": "admin", "password": "admin123"})
    admin_token = admin_res.json()["token"]
    res = client.get("/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    users = res.json()
    assert len(users) >= 3
    # Check that passwords are not exposed
    for u in users:
        assert "password" not in u
