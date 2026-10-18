from flask import Blueprint, render_template

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/login", methods=["GET"])
def login():
    return render_template("auth/login.html")


@bp.route("/register", methods=["GET"])
def register():
    return render_template("auth/register.html")