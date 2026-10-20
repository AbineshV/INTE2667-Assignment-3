from app.models import User

GOOD_PASSWORD = "correct horse battery staple"


def register(client, email="voter@example.com", password=GOOD_PASSWORD, confirm=None):
    return client.post("/auth/register", data={
        "email": email,
        "password": password,
        "confirm_password": confirm if confirm is not None else password,
        "date_of_birth": "1990-05-01",
        "division": "Melbourne",
    })


def login(client, email="voter@example.com", password=GOOD_PASSWORD):
    return client.post("/auth/login", data={"email": email, "password": password})


def get_user(app, email):
    with app.app_context():
        return User.query.filter_by(email=email).first()


def test_register_stores_argon2id_hash(client, app):
    response = register(client)
    assert response.status_code == 302

    user = get_user(app, "voter@example.com")
    assert user is not None
    assert user.password_hash != GOOD_PASSWORD
    assert user.password_hash.startswith("$argon2id$")


def test_register_rejects_mismatched_passwords(client, app):
    response = register(client, confirm="a different password here")
    assert response.status_code == 400
    assert b"Passwords do not match" in response.data
    assert get_user(app, "voter@example.com") is None


def test_register_rejects_weak_password(client):
    response = register(client, password="short")
    assert response.status_code == 400


def test_register_rejects_duplicate_email(client):
    register(client)
    response = register(client)
    assert response.status_code == 400
    assert b"could not be completed" in response.data


def test_login_success_redirects_to_vote(client):
    register(client)
    response = login(client)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/vote/")


def test_login_wrong_password(client):
    register(client)
    response = login(client, password="not the right password")
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_login_unknown_email(client):
    response = login(client, email="nobody@example.com")
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data


def test_logout_clears_session(client):
    register(client)
    login(client)
    with client.session_transaction() as sess:
        assert "_user_id" in sess

    client.post("/auth/logout")
    with client.session_transaction() as sess:
        assert "_user_id" not in sess