import re
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from extensions import db
from models import User

auth = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,32}$")


def validate_email(email):
    """Return error string or None."""
    if not email:
        return "Email is required."
    if not EMAIL_RE.match(email):
        return "Enter a valid email address."
    return None


def validate_username(username):
    if not username:
        return "Username is required."
    if not USERNAME_RE.match(username):
        return "Username must be 3-32 characters: letters, numbers, underscores only."
    return None


def validate_password(password):
    if not password or len(password) < 8:
        return "Password must be at least 8 characters."
    return None


@auth.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Validate fields
        errors = []
        err = validate_username(username)
        if err: errors.append(err)
        err = validate_email(email)
        if err: errors.append(err)
        err = validate_password(password)
        if err: errors.append(err)
        if password and confirm != password:
            errors.append("Passwords do not match.")

        if not errors:
            # Check uniqueness
            if User.query.filter_by(username=username).first():
                errors.append("Username is already taken.")
            if User.query.filter_by(email=email).first():
                errors.append("An account with that email already exists.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("auth/signup.html",
                                   username=username, email=email)

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        flash("Account created! Welcome.", "success")
        return redirect(url_for("main.index"))

    return render_template("auth/signup.html", username="", email="")


@auth.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password   = request.form.get("password", "")
        remember   = bool(request.form.get("remember"))

        # Allow login with username OR email
        user = (User.query.filter_by(username=identifier).first() or
                User.query.filter_by(email=identifier.lower()).first())

        if not user or not user.check_password(password):
            flash("Invalid username/email or password.", "danger")
            return render_template("auth/login.html", identifier=identifier)

        login_user(user, remember=remember)
        next_page = request.args.get("next")
        return redirect(next_page or url_for("main.index"))

    return render_template("auth/login.html", identifier="")


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))
