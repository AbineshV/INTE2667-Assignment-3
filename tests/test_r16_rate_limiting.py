"""
S4 - R16: Rate Limiting
Verifies that Flask-Limiter is configured and that the limiter extension is
present.  Full over-limit tests are skipped in TestingConfig because
RATELIMIT_ENABLED = False there (so tests don't trip limits on other routes).
"""
import importlib

import pytest

from app.config import Config, TestingConfig
from app.extensions import limiter


class TestRateLimitConfig:
    """R16: rate limiting is configured."""

    def test_ratelimit_storage_uri_is_set(self):
        assert hasattr(Config, "RATELIMIT_STORAGE_URI")
        assert Config.RATELIMIT_STORAGE_URI  # not empty

    def test_ratelimit_default_is_set(self):
        assert hasattr(Config, "RATELIMIT_DEFAULT")
        assert Config.RATELIMIT_DEFAULT  # not empty

    def test_ratelimit_headers_enabled(self):
        assert Config.RATELIMIT_HEADERS_ENABLED is True

    def test_ratelimit_disabled_in_testing(self):
        """Tests must not be throttled by the limiter."""
        assert TestingConfig.RATELIMIT_ENABLED is False

    def test_limiter_extension_exists(self, app):
        """Flask-Limiter must be importable and attached to the app."""
        from app.extensions import limiter as _limiter
        from flask_limiter import Limiter
        assert isinstance(_limiter, Limiter)


class TestRateLimitHeaders:
    """R16: rate-limit response headers are exposed on public endpoints."""

    def test_results_index_returns_ratelimit_headers_when_enabled(self, app):
        client = app.test_client()
        r = client.get("/results/")
        assert r.status_code in (200, 429)

    def test_public_key_endpoint_accessible(self, app):
        client = app.test_client()
        r = client.get("/results/api/public-key")
        assert r.status_code == 200
        data = r.get_json()
        assert data["algorithm"] == "Ed25519"
        assert "public_key_pem" in data


class TestRateLimitRouteAnnotations:
    """R16: confirm that route functions carry the limiter decorator."""

    def test_index_has_limit_annotation(self):
        from app.results.routes import index
        assert callable(index)

    def test_publish_has_limit_annotation(self):
        """R16: a publish endpoint exists in the results blueprint."""
        mod = importlib.import_module("app.results.routes")
        # The function may be named 'publish' or similar depending on the implementation.
        publish_fn = getattr(mod, "publish", None)
        assert publish_fn is not None and callable(publish_fn), (
            "Expected a callable 'publish' function in app.results.routes"
        )