from datetime import date

import pytest

from app.auth.passwords import hash_password
from app.extensions import db
from app.models import User
from app.security.headers import SECURITY_HEADERS


@pytest.mark.parametrize("path", ["/auth/login", "/auth/register", "/results/", "/results/track",
                                  "/results/api/public-key", "/static/css/style.css",
                                  "/does-not-exist"])
def test_every_response_has_security_headers(client, path):
    response = client.get(path)
    for name, value in SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, name


def test_csp_blocks_framing_and_outside_scripts(client):
    csp = client.get("/auth/login").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "script-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "unsafe-inline" not in csp


def test_csp_allows_the_mfa_qr_image(client):
    assert "img-src 'self' data:" in client.get("/auth/login").headers["Content-Security-Policy"]


def test_hsts_only_over_https(client):
    assert "Strict-Transport-Security" not in client.get("/auth/login").headers
    secure = client.get("/auth/login", base_url="https://localhost")
    assert secure.headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"


def test_logged_out_pages_are_not_marked_no_store(client):
    assert client.get("/auth/login").headers.get("Cache-Control") != "no-store"


def test_logged_in_pages_are_not_cached(app, client):
    with app.app_context():
        db.session.add(User(email="v@example.com", password_hash=hash_password("Correct-Horse-9-Battery"),
                            role="voter", is_citizen=True, is_enrolled=True, division="Melbourne",
                            date_of_birth=date(2000, 1, 1)))
        db.session.commit()
    response = client.post("/auth/login", data={"email": "v@example.com",
                                                "password": "Correct-Horse-9-Battery"})
    assert response.headers["Cache-Control"] == "no-store"
