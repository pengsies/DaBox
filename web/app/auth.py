"""Signed-session authentication and the intentional remember-cookie flaw."""

from __future__ import annotations

import base64
import binascii
import hmac
import pickle
import re
import secrets
import time
from functools import wraps

import psycopg2
from flask import (
    abort,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

import prefs

from . import db


USERNAME_RE = re.compile(r"[a-z][a-z0-9_-]{2,31}\Z")
REMEMBER_COOKIE = "remember_prefs"


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> None:
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
    if not isinstance(expected, str) or not expected or not hmac.compare_digest(expected, supplied):
        if request.path.startswith("/api/"):
            response = jsonify(error="invalid CSRF token")
            response.status_code = 400
            abort(response)
        abort(400, description="Form expired. Reload the page and try again.")


def current_username() -> str | None:
    username = session.get("username")
    if isinstance(username, str) and USERNAME_RE.fullmatch(username):
        return username
    return None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_username() is None:
            if request.path.startswith("/api/"):
                return jsonify(error="authentication required"), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def remembered_username() -> str:
    raw = request.cookies.get(REMEMBER_COOKIE, "")
    if not raw or len(raw) > 8192:
        return ""
    try:
        serialized = base64.b64decode(raw, validate=True)
        if len(serialized) > 6144:
            return ""
        # INTENTIONAL-VULNERABILITY RF-WEB-02: client-controlled pickle
        # reconstruction. The allowlist contains a trusted gadget pair whose
        # __setstate__ methods compose into shell command execution.
        restored = prefs.loads_restricted(serialized)
        username = getattr(restored, "username", "")
        return username if isinstance(username, str) else ""
    except (binascii.Error, EOFError, pickle.PickleError, AttributeError, ValueError):
        return ""


def set_remember_cookie(response, username: str):
    encoded = base64.b64encode(pickle.dumps(prefs.RememberedPrefs(username))).decode("ascii")
    response.set_cookie(
        REMEMBER_COOKIE,
        encoded,
        max_age=1800,
        secure=True,
        httponly=True,
        samesite="Strict",
        path="/",
    )
    return response


def login_view():
    if current_username() is not None:
        return redirect(url_for("dashboard"))

    error = ""
    username = ""
    if request.method == "POST":
        validate_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        authenticated = False
        if USERNAME_RE.fullmatch(username) and 1 <= len(password.encode("utf-8")) <= 256:
            try:
                authenticated = db.authenticate(username, password)
            except psycopg2.Error:
                current_app.logger.exception("authentication backend unavailable")
                return render_template("login.html", error="Authentication service unavailable.", username=username), 503
        if authenticated:
            session.clear()
            session["username"] = username
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            return set_remember_cookie(redirect(url_for("dashboard")), username)
        time.sleep(0.35)
        error = "Incorrect username or password."
    return render_template("login.html", error=error, username=username), (401 if error else 200)


@login_required
def logout_view():
    validate_csrf()
    session.clear()
    response = redirect(url_for("login"))
    response.delete_cookie(REMEMBER_COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
    return response

