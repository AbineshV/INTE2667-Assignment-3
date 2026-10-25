from datetime import date

import pyotp
from cryptography.fernet import InvalidToken
from flask import (
    Blueprint,
    flash,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_user, logout_user
from sqlalchemy.exc import IntegrityError

from app.access.permissions import public_endpoint, require_roles
from app.auth.lockout import (
    is_locked,
    record_failed_login,
    reset_failed_logins,
    utc_now,
)
from app.auth.mfa import (
    check_code,
    decrypt_secret,
    encrypt_secret,
    generate_secret,
    qr_data_uri,
)
from app.auth.passwords import (
    hash_password,
    needs_rehash,
    validate_password,
    verify_password,
)
from app.extensions import db
from app.models import User


bp = Blueprint("auth", __name__, url_prefix="/auth")

# Hash of a random value, used so unknown emails take as long
# as wrong passwords.
_DUMMY_HASH = hash_password("dummy-password-for-timing-only")

MFA_TIMEOUT_SECONDS = 300  # Five minutes to enter the code.


@bp.route("/login", methods=["GET", "POST"])
@public_endpoint
def login():
    if request.method == "GET":
        return render_template("auth/login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user = User.query.filter_by(email=email).first()
    now = utc_now()

    if user is None:
        verify_password(_DUMMY_HASH, password)
        flash("Invalid email or password.", "error")
        return render_template("auth/login.html"), 401

    if is_locked(user, now):
        verify_password(_DUMMY_HASH, password)
        # TODO: audit log via S5's logger.
        flash("Invalid email or password.", "error")
        return render_template("auth/login.html"), 401

    if not verify_password(user.password_hash, password):
        record_failed_login(user, now)
        db.session.commit()
        flash("Invalid email or password.", "error")
        return render_template("auth/login.html"), 401

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)

    if user.totp_secret:
        # Password is correct, but login is not completed until MFA passes.
        # Failed login counts are not reset until successful MFA verification.
        db.session.commit()
        session.clear()
        session["mfa_user_id"] = user.id
        session["mfa_started"] = int(now.timestamp())
        return redirect(url_for("auth.mfa_verify"))

    reset_failed_logins(user)
    db.session.commit()

    # Discard pre-login session state before establishing authentication.
    session.clear()
    login_user(user, fresh=True)
    session.permanent = True

    # R8: initialise the inactivity timer after successful authentication.
    session["last_activity"] = int(now.timestamp())

    flash("Logged in. Please set up two-factor authentication.", "success")
    return redirect(url_for("auth.mfa_setup"))


@bp.route("/logout", methods=["POST"])
@require_roles("voter", "officer", "delegate", "admin")
def logout():
    logout_user()
    session.clear()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))


def _render_mfa_setup(secret, status=200):
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.email,
        issuer_name="E-Voting Prototype",
    )

    response = make_response(
        render_template(
            "auth/mfa_setup.html",
            qr=qr_data_uri(uri),
            secret=secret,
        ),
        status,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/mfa/setup", methods=["GET", "POST"])
@require_roles("voter", "officer", "delegate", "admin")
def mfa_setup():
    if current_user.totp_secret:
        flash("Two-factor authentication is already enabled.", "info")
        return redirect(url_for("voting.index"))

    if "pending_totp_secret" not in session:
        session["pending_totp_secret"] = encrypt_secret(generate_secret())

    secret = decrypt_secret(session["pending_totp_secret"])

    if request.method == "GET":
        return _render_mfa_setup(secret)

    step = check_code(
        secret,
        request.form.get("code", ""),
        utc_now(),
        None,
    )

    if step is None:
        flash("Invalid code.", "error")
        return _render_mfa_setup(secret, 400)

    current_user.totp_secret = encrypt_secret(secret)
    current_user.totp_last_used_step = step
    db.session.commit()
    session.pop("pending_totp_secret", None)

    flash("Two-factor authentication enabled.", "success")
    return redirect(url_for("voting.index"))


def _clear_mfa_session():
    session.pop("mfa_user_id", None)
    session.pop("mfa_started", None)


def _restart_login():
    _clear_mfa_session()
    flash("Please log in again.", "error")
    return redirect(url_for("auth.login"))


@bp.route("/mfa/verify", methods=["GET", "POST"])
@public_endpoint
def mfa_verify():
    user_id = session.get("mfa_user_id")
    started = session.get("mfa_started")
    now = utc_now()

    if user_id is None or started is None:
        return _restart_login()

    if int(now.timestamp()) - started > MFA_TIMEOUT_SECONDS:
        return _restart_login()

    user = db.session.get(User, user_id)

    if user is None:
        return _restart_login()

    if not user.totp_secret:
        return _restart_login()

    if is_locked(user, now):
        # TODO: audit log via S5's logger.
        flash("Invalid email or password.", "error")
        return render_template("auth/mfa_verify.html"), 401

    if request.method == "GET":
        return render_template("auth/mfa_verify.html")

    try:
        secret = decrypt_secret(user.totp_secret)
        step = check_code(
            secret,
            request.form.get("code", ""),
            now,
            user.totp_last_used_step,
        )
    except InvalidToken:
        # The stored secret could not be decrypted.
        # TODO: audit log via S5's logger.
        step = None

    if step is None:
        record_failed_login(user, now)
        db.session.commit()
        flash("Invalid code.", "error")
        return render_template("auth/mfa_verify.html"), 401

    user.totp_last_used_step = step
    reset_failed_logins(user)
    db.session.commit()

    # Establish a clean authenticated session only after MFA succeeds.
    session.clear()
    login_user(user, fresh=True)
    session.permanent = True

    # R8: initialise the inactivity timer after successful MFA.
    session["last_activity"] = int(now.timestamp())

    flash("Logged in.", "success")
    return redirect(url_for("voting.index"))


@bp.route("/register", methods=["GET", "POST"])
@public_endpoint
def register():
    if request.method == "GET":
        return render_template("auth/register.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")
    dob_text = request.form.get("date_of_birth", "")
    division = request.form.get("division", "").strip()

    errors = []

    if not email or "@" not in email or len(email) > 255:
        errors.append("Enter a valid email address.")

    if password != confirm:
        errors.append("Passwords do not match.")

    errors.extend(validate_password(password))

    try:
        date_of_birth = date.fromisoformat(dob_text)

        if date_of_birth > date.today():
            errors.append("Date of birth cannot be in the future.")

    except ValueError:
        errors.append("Enter a valid date of birth.")

    if not division or len(division) > 100:
        errors.append("Enter your electoral division.")

    if errors:
        for message in errors:
            flash(message, "error")

        return render_template("auth/register.html"), 400

    user = User(
        email=email,
        password_hash=hash_password(password),
        date_of_birth=date_of_birth,
        division=division,
    )
    db.session.add(user)

    try:
        db.session.commit()

    except IntegrityError:
        db.session.rollback()
        flash(
            "Registration could not be completed. Try again or log in.",
            "error",
        )
        return render_template("auth/register.html"), 400

    flash("Registration successful. Please log in.", "success")
    return redirect(url_for("auth.login"))