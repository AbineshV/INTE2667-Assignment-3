from flask import Flask, abort, request

from app.config import Config
from app.extensions import db, login_manager, csrf


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Refuse to start without a secret key
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is not set. Add it to your .env file.")

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)

    # Audit log signing key (R18)
    from app.audit import init_audit
    init_audit(app)

    # Election definition signing key (R19)
    from app.elections import init_elections
    init_elections(app)

    # Blueprints
    from app.auth.routes import bp as auth_bp
    from app.enrolment.routes import bp as enrolment_bp
    from app.voting.routes import bp as voting_bp
    from app.admin.routes import bp as admin_bp
    from app.results.routes import bp as results_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(enrolment_bp)
    app.register_blueprint(voting_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(results_bp)

    @app.before_request
    def enforce_explicit_access_policy():
        endpoint = request.endpoint

        # Let Flask return its normal 404 for unknown URLs.
        if endpoint is None:
            return

        # Static assets are public.
        if endpoint == "static":
            return

        view_func = app.view_functions.get(endpoint)

        # Deny if the route cannot be identified.
        if view_func is None:
            abort(403)

        # Permit routes explicitly marked public.
        if getattr(view_func, "is_public_endpoint", False):
            return

        # Routes with explicit role policies are checked by their decorators.
        if getattr(view_func, "allowed_roles", None):
            return

        # Secure default: no declared policy means no access.
        abort(403)

    # Create tables for local development
    with app.app_context():
        from app import models  # noqa: F401  (registers the models)
        from app.audit import models as audit_models  # noqa: F401
        from app.elections import models as election_models  # noqa: F401
        from app.ledger import models as ledger_models  # noqa: F401
        db.create_all()

    return app