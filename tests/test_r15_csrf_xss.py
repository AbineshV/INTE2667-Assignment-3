"""
S4 - R15: CSRF and XSS Protection
Verifies that CSRF protection is enabled in the production config and
that Jinja2 autoescaping prevents cross-site scripting in templates.
"""
import pytest
from flask import render_template_string

from app.config import Config, TestingConfig


# ---------------------------------------------------------------------------
# CSRF configuration
# ---------------------------------------------------------------------------

class TestCsrfConfig:
    """R15: CSRF is on by default; test config safely opts out."""

    def test_csrf_not_disabled_in_base_config(self):
        """Config must not explicitly set WTF_CSRF_ENABLED = False."""
        assert getattr(Config, "WTF_CSRF_ENABLED", True) is not False

    def test_csrf_disabled_in_testing_config(self):
        """TestingConfig turns CSRF off so test clients can POST freely."""
        assert TestingConfig.WTF_CSRF_ENABLED is False

    def test_secret_key_present_in_testing(self):
        """CSRF tokens are signed with SECRET_KEY; it must be non-empty."""
        assert TestingConfig.SECRET_KEY
        assert len(TestingConfig.SECRET_KEY) >= 16

    def test_session_cookie_httponly(self):
        """R15: HttpOnly flag prevents JavaScript from reading the session cookie."""
        assert Config.SESSION_COOKIE_HTTPONLY is True

    def test_session_cookie_samesite(self):
        """R15: SameSite=Lax (or Strict) limits cross-origin request forgery."""
        assert Config.SESSION_COOKIE_SAMESITE in ("Lax", "Strict")


class TestCsrfEnforcement:
    """R15: state-changing POST without a CSRF token is rejected."""

    @pytest.fixture
    def csrf_client(self):
        from app import create_app

        class CsrfConfig(TestingConfig):
            WTF_CSRF_ENABLED = True
            WTF_CSRF_CHECK_DEFAULT = True

        return create_app(CsrfConfig).test_client()

    def test_post_without_token_is_rejected(self, csrf_client):
        rv = csrf_client.post(
            "/auth/login",
            data={"email": "x@x.com", "password": "hunter2"},
            content_type="application/x-www-form-urlencoded",
        )
        assert rv.status_code in (400, 403), (
            f"Expected 400 or 403 for missing CSRF token, got {rv.status_code}"
        )


# ---------------------------------------------------------------------------
# XSS / Jinja2 autoescaping
# ---------------------------------------------------------------------------

class TestXssProtection:
    """R15: Jinja2 autoescaping prevents reflected XSS in rendered templates."""

    def test_script_tag_is_escaped(self, app):
        with app.app_context():
            out = render_template_string("{{ v }}", v="<script>alert('xss')</script>")
            assert "<script>" not in out
            assert "&lt;script&gt;" in out

    def test_angle_brackets_are_escaped(self, app):
        with app.app_context():
            out = render_template_string("{{ v }}", v="<b>bold</b>")
            assert "<b>" not in out
            assert "&lt;b&gt;" in out

    def test_double_quote_event_handler_is_escaped(self, app):
        with app.app_context():
            out = render_template_string("{{ v }}", v='"onload=alert(1)')
            assert '"onload' not in out

    def test_ampersand_is_escaped(self, app):
        with app.app_context():
            out = render_template_string("{{ v }}", v="cats&dogs")
            assert "&amp;" in out

    def test_jinja_autoescape_is_active(self, app):
        """Flask enables autoescaping for .html templates by default."""
        with app.app_context():
            env = app.jinja_env
            assert env.autoescape or callable(env.autoescape)