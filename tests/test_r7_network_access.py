from app.security.network_access import require_diplomatic_terminal_ip
from app.access.permissions import public_endpoint

def _register_terminal_route(app):
    @app.get("/test-diplomatic-terminal")
    @public_endpoint
    @require_diplomatic_terminal_ip
    def test_terminal():
        return "terminal-access-granted"


def test_allowlisted_ip_is_permitted(app, client):
    app.config["DIPLOMATIC_TERMINAL_ALLOWED_CIDRS"] = [
        "192.0.2.16/28"
    ]
    _register_terminal_route(app)

    response = client.get(
        "/test-diplomatic-terminal",
        environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
    )

    assert response.status_code == 200
    assert response.get_data(as_text=True) == "terminal-access-granted"


def test_unlisted_ip_is_blocked(app, client):
    app.config["DIPLOMATIC_TERMINAL_ALLOWED_CIDRS"] = [
        "192.0.2.16/28"
    ]
    _register_terminal_route(app)

    response = client.get(
        "/test-diplomatic-terminal",
        environ_overrides={"REMOTE_ADDR": "198.51.100.10"},
    )

    assert response.status_code == 403


def test_empty_allowlist_denies_everyone(app, client):
    app.config["DIPLOMATIC_TERMINAL_ALLOWED_CIDRS"] = []
    _register_terminal_route(app)

    response = client.get(
        "/test-diplomatic-terminal",
        environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
        headers={"X-Forwarded-For": "192.0.2.20"},
    )

    assert response.status_code == 403


def test_malformed_allowlist_denies_access(app, client):
    app.config["DIPLOMATIC_TERMINAL_ALLOWED_CIDRS"] = [
        "not-an-ip-network"
    ]
    _register_terminal_route(app)

    response = client.get(
        "/test-diplomatic-terminal",
        environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
    )

    assert response.status_code == 403

def test_real_terminal_route_denies_by_default(app, client):
    app.config["DIPLOMATIC_TERMINAL_ALLOWED_CIDRS"] = []

    response = client.get(
        "/vote/diplomatic-terminal",
        environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
    )

    assert response.status_code == 403


def test_real_terminal_route_allows_configured_ip(app, client):
    app.config["DIPLOMATIC_TERMINAL_ALLOWED_CIDRS"] = [
        "192.0.2.20/32"
    ]

    response = client.get(
        "/vote/diplomatic-terminal",
        environ_overrides={"REMOTE_ADDR": "192.0.2.20"},
    )

    assert response.status_code == 200
    assert response.get_data(as_text=True) == (
        "Diplomatic terminal access permitted."
    )