from flask import request
from flask_login import current_user

# Only our own files; data: is needed for the MFA QR code image
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "img-src 'self' data:; "
    "style-src 'self'; "
    "script-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

HSTS = "max-age=31536000; includeSubDomains"


def add_security_headers(response):
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    # Browsers ignore HSTS over plain http, so only send it over https
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", HSTS)
    # Pages for a logged-in user must not be kept in shared or browser caches
    if current_user.is_authenticated:
        response.headers["Cache-Control"] = "no-store"
    return response


def init_security_headers(app):
    app.after_request(add_security_headers)
