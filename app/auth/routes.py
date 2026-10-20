from datetime import date

from flask import Blueprint, flash, redirect, render_template, request, url_for
from sqlalchemy.exc import IntegrityError

from app.auth.passwords import hash_password, validate_password
from app.extensions import db
from app.models import User

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/login", methods=["GET"])
def login():
    return render_template("auth/login.html")


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