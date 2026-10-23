import pytest

from app.auth.passwords import hash_password
from app.extensions import db
from app.models import User


def sign_in_as(app, client, role, division="D01"):
    email = f"{role}@example.test"
    password = "R8-test-password-123!"

    with app.app_context():
        user = User(
            email=email,
            password_hash=hash_password(password),
            role=role,
            division=division,
        )
        db.session.add(user)
        db.session.commit()

    response = client.post(
        "/auth/login",
        data={"email": email, "password": password},
    )
    assert response.status_code == 302, (
        f"Login failed: HTTP {response.status_code}"
    )
    return response


def test_unauthenticated_user_is_redirected_to_login(client):
    response = client.get("/admin/")

    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


@pytest.mark.parametrize("role", ["voter", "officer", "delegate"])
def test_non_admin_user_cannot_access_real_admin_route(
    app, client, role
):
    sign_in_as(app, client, role)

    response = client.get("/admin/")

    assert response.status_code == 403


def test_admin_can_access_real_admin_route(app, client):
    sign_in_as(app, client, "admin")

    response = client.get("/admin/")

    assert response.status_code == 200
    assert b"Admin module coming soon." in response.data


def test_unclassified_route_is_denied(app, client):
    @app.route("/r5-test-unclassified")
    def unclassified_route():
        return "This route should be blocked"

    response = client.get("/r5-test-unclassified")

    assert response.status_code == 403