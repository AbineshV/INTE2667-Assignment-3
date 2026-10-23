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
        except ValueError:
            abort(403)

        configured = current_app.config.get(
            "DIPLOMATIC_TERMINAL_ALLOWED_CIDRS", []
        )

        if isinstance(configured, str):
            configured = configured.split(",")

        networks = []
        try:
            for entry in configured or []:
                entry = str(entry).strip()
                if entry:
                    networks.append(
                        ipaddress.ip_network(entry, strict=False)
                    )
        except ValueError:
            current_app.logger.error(
                "Invalid diplomatic-terminal IP allowlist configuration."
            )
            abort(403)

        # An empty allowlist denies everyone.
        allowed = any(
            client_ip.version == network.version
            and client_ip in network
            for network in networks
        )

        if not allowed:
            abort(403)

        return view_func(*args, **kwargs)

    return wrapped_view