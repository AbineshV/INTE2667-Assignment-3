from flask import Flask

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

    # Create tables for local development
    with app.app_context():
        from app import models  # noqa: F401  (registers the models)
        from app.audit import models as audit_models  # noqa: F401
        db.create_all()

    return app