from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash

from models import db, User

auth_bp = Blueprint("auth", __name__)

def ensure_demo_user():
    email = "demo@cybersecure.local"
    existing = User.query.filter_by(email=email).first()
    if existing:
        return

    user = User(
        email=email,
        password_hash=generate_password_hash("demo1234")
    )
    db.session.add(user)
    db.session.commit()

@auth_bp.get("/login")
def login_get():
    return render_template("login.html")

@auth_bp.post("/login")
def login_post():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        flash("Invalid email or password")
        return redirect(url_for("auth.login_get"))

    login_user(user)
    return redirect(url_for("pages.dashboard"))

@auth_bp.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login_get"))
