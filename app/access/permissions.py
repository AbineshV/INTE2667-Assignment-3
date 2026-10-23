from functools import wraps

from flask import abort
from flask_login import current_user, login_required


def require_roles(*allowed_roles):
    """Allow access only to logged-in users with an explicitly allowed role."""

    if not allowed_roles:
        raise ValueError("At least one allowed role must be specified.")

    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped_view(*args, **kwargs):
            user_role = getattr(current_user, "role", None)

            if user_role not in allowed_roles:
                abort(403)

            return view_func(*args, **kwargs)

        # Record the policy so we can inspect it for default-deny enforcement.
        wrapped_view.allowed_roles = frozenset(allowed_roles)

        return wrapped_view

    return decorator
def require_division_access(*allowed_roles):
    """Require an allowed role and restrict access to the user's division.

    Admin users may access any division. Other allowed roles must match
    the division assigned to their account.
    """
    if not allowed_roles:
        raise ValueError("At least one allowed role must be specified.")
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def wrapped_view(*args, **kwargs):
            user_role = getattr(current_user, "role", None)

            # Deny roles that have not been explicitly authorised.
            if user_role not in allowed_roles:
                abort(403)

            # Administrators have cross-division access.
            if user_role == "admin":
                return view_func(*args, **kwargs)

            # Division-specific routes must provide a division argument.
            requested_division = kwargs.get("division")
            user_division = getattr(current_user, "division", None)

            if not requested_division or not user_division:
                abort(403)

            if user_division != requested_division:
                abort(403)

            return view_func(*args, **kwargs)

        wrapped_view.allowed_roles = frozenset(allowed_roles)
        return wrapped_view

    return decorator

def public_endpoint(view_func):
    """Mark a route as intentionally accessible without authentication."""
    view_func.is_public_endpoint = True
    return view_func