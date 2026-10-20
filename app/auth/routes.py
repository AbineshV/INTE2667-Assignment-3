from datetime import date

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import login_user, logout_user
from sqlalchemy.exc import IntegrityError

from app.auth.passwords import hash_password, validate_password
from app.extensions import db
from app.models import User

bp = Blueprint("auth", __name__, url_prefix="/auth")


# Hash of a random value, used so unknown emails take as long as wrong passwords
_DUMMY_HASH = hash_password("dummy-password-for-timing-only")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("auth/login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    user = User.query.filter_by(email=email).first()

    # R4: lockout check goes here, before the password is verified

    if user is None:
        verify_password(_DUMMY_HASH, password)
        flash("Invalid email or password.", "error")
        return render_template("auth/login.html"), 401

    if not verify_password(user.password_hash, password):
        flash("Invalid email or password.", "error")
        return render_template("auth/login.html"), 401

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(password)
        db.session.commit()

    login_user(user)
    flash("Logged in.", "success")
    return redirect(url_for("voting.index"))


@bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    flash("Logged out.", "success")
    return redirect(url_for("auth.login"))

@bp.route("/register", methods=["GET", "POST"])
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
        flash("Registration could not be completed. Try again or log in.", "error")
        return render_template("auth/register.html"), 400

    flash("Registration successful. Please log in.", "success")
    return redirect(url_for("auth.login"))