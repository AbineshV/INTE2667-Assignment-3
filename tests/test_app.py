import pytest

from app import create_app
from app.config import TestingConfig


def test_app_uses_testing_config(app):
    assert app.config["TESTING"] is True


def test_login_page_loads(client):
    response = client.get("/auth/login")
    assert response.status_code == 200
    assert b"Log in" in response.data


def test_unknown_page_returns_404(client):
    response = client.get("/does-not-exist")
    assert response.status_code == 404


def test_app_refuses_to_start_without_secret_key():
    class NoSecretKeyConfig(TestingConfig):
        SECRET_KEY = None

    with pytest.raises(RuntimeError):
        create_app(NoSecretKeyConfig)