from app.audit.logger import AuditVerification, log_event, verify_audit_log
from app.audit.signing import load_signing_key


def init_audit(app):
    app.extensions["audit_signing_key"] = load_signing_key(app)


__all__ = ["AuditVerification", "init_audit", "log_event", "verify_audit_log"]
