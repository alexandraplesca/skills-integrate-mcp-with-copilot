from fastapi.testclient import TestClient

from src.app import app

client = TestClient(app)


def test_login_success_for_student():
    response = client.post(
        "/auth/login",
        json={"email": "student@mergington.edu", "password": "student123"},
    )

    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["user"]["email"] == "student@mergington.edu"
    assert body["user"]["role"] == "student"


def test_login_rejects_invalid_password():
    response = client.post(
        "/auth/login",
        json={"email": "student@mergington.edu", "password": "wrong-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


def test_me_requires_authentication():
    response = client.get("/me")

    assert response.status_code == 401


def test_admin_route_restricts_non_admin_users():
    login_response = client.post(
        "/auth/login",
        json={"email": "student@mergington.edu", "password": "student123"},
    )
    token = login_response.json()["access_token"]

    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Admin access required"


def test_admin_user_can_access_admin_route():
    login_response = client.post(
        "/auth/login",
        json={"email": "admin@mergington.edu", "password": "admin123"},
    )
    token = login_response.json()["access_token"]

    response = client.get(
        "/admin",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["role"] == "admin"
