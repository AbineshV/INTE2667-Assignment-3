import ipaddress
from functools import wraps

from flask import abort, current_app, request


def require_diplomatic_terminal_ip(view_func):
    """Allow access only from configured diplomatic-terminal IP ranges."""

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        remote_ip = request.remote_addr

        if not remote_ip:
            abort(403)

        try:
            client_ip = ipaddress.ip_address(remote_ip)
        except (TypeError, ValueError):
            abort(403)

        configured = current_app.config.get(
            "DIPLOMATIC_TERMINAL_ALLOWED_CIDRS", []
        )

        if configured is None:
            configured = []
        elif isinstance(configured, str):
            configured = configured.split(",")
        elif not isinstance(configured, (list, tuple, set)):
            current_app.logger.error(
                "Invalid diplomatic-terminal IP allowlist configuration."
            )
            abort(403)

        networks = []

        try:
            for entry in configured:
                if not isinstance(entry, str):
                    raise ValueError("CIDR entries must be strings.")

                entry = entry.strip()
                if entry:
                    networks.append(
                        ipaddress.ip_network(entry, strict=False)
                    )

        except (TypeError, ValueError):
            current_app.logger.error(
                "Invalid diplomatic-terminal IP allowlist configuration."
            )
            abort(403)

        allowed = any(
            client_ip.version == network.version
            and client_ip in network
            for network in networks
        )

        if not allowed:
            abort(403)

        return view_func(*args, **kwargs)

    return wrapped_view