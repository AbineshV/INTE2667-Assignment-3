import pytest

from app.extensions import db
from app.models import User


def sign_in_as(app, client, role, division="D01"):
    """Create a test user and establish a Flask-Login session."""

    with app.app_context():
        user = User(
            email=f"{role}@example.test",
            password_hash="unused-test-password-hash",
            role=role,
            division=division,
        )
        db.session.add(user)
        db.session.commit()
        user_id = str(user.id)

    with client.session_transaction() as session:
        session["_user_id"] = user_id
        session["_fresh"] = True


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