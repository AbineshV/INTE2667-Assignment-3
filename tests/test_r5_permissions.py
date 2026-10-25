import pytest
from flask import Flask
from flask_login import LoginManager, UserMixin

from app.access.permissions import require_roles, require_division_access


class DummyUser(UserMixin):
    """A lightweight user for testing permissions."""

    def __init__(self, user_id, role, division="D01"):
        self.id = str(user_id)
        self.role = role
        self.division = division


@pytest.fixture
def permission_client():
    app = Flask(__name__)
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-only-secret",
    )

    login_manager = LoginManager()
    login_manager.init_app(app)

    users = {}

    @login_manager.user_loader
    def load_user(user_id):
        return users.get(user_id)

    @app.route("/admin")
    @require_roles("admin")
    def admin_page():
        return "Admin page", 200

    @app.route("/officer")
    @require_roles("officer")
    def officer_page():
        return "Officer page", 200

    @app.route("/divisions/<division>")
    @require_division_access("officer", "admin")
    def division_page(division):
        return f"Division {division}", 200

    return app.test_client(), users


def sign_in(client, users, role, division="D01"):
    user = DummyUser(user_id="1", role=role, division=division)
    users[user.get_id()] = user

    with client.session_transaction() as session:
        session["_user_id"] = user.get_id()
        session["_fresh"] = True


def test_admin_can_access_admin_route(permission_client):
    client, users = permission_client
    sign_in(client, users, "admin")

    response = client.get("/admin")

    assert response.status_code == 200


@pytest.mark.parametrize("role", ["voter", "officer", "delegate", None])
def test_non_admin_roles_are_denied(permission_client, role):
    client, users = permission_client
    sign_in(client, users, role)

    response = client.get("/admin")

    assert response.status_code == 403


def test_officer_can_access_officer_route(permission_client):
    client, users = permission_client
    sign_in(client, users, "officer")

    response = client.get("/officer")

    assert response.status_code == 200


def test_permission_decorator_requires_a_role():
    with pytest.raises(ValueError):
        require_roles()


def test_officer_can_access_own_division(permission_client):
    client, users = permission_client
    sign_in(client, users, "officer", division="D01")

    response = client.get("/divisions/D01")

    assert response.status_code == 200


def test_officer_cannot_access_another_division(permission_client):
    client, users = permission_client
    sign_in(client, users, "officer", division="D01")

    response = client.get("/divisions/D02")

    assert response.status_code == 403


def test_admin_can_access_another_division(permission_client):
    client, users = permission_client
    sign_in(client, users, "admin", division="D01")

    response = client.get("/divisions/D02")

    assert response.status_code == 200


def test_officer_without_division_is_denied(permission_client):
    client, users = permission_client
    sign_in(client, users, "officer", division=None)

    response = client.get("/divisions/D01")

    assert response.status_code == 403


def test_voter_cannot_access_division_admin_route(permission_client):
    client, users = permission_client
    sign_in(client, users, "voter", division="D01")

    response = client.get("/divisions/D01")

    assert response.status_code == 403