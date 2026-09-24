"""RelayForge Flask application."""

from __future__ import annotations

import os
import re
import stat
import uuid
from datetime import date, datetime
from functools import wraps
from typing import Any
from urllib.parse import urlsplit

import psycopg2
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db
from .auth import (
    csrf_token,
    current_username,
    login_required,
    login_view,
    logout_view,
    remembered_username,
    validate_csrf,
)
from .config import Config


TARGET_RE = re.compile(r"[a-z][a-z0-9-]{2,31}\Z")
RESULT_RE = re.compile(r"[0-9a-f]{32}\.txt\Z")
TOKEN_RE = re.compile(r"[0-9a-f]{48}\Z")
PUBLIC_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z")


def _api_database_errors(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        try:
            return view(*args, **kwargs)
        except psycopg2.Error as exc:
            current_app.logger.exception("Web database RPC failed")
            if (exc.pgcode or "").startswith(("22", "23", "P0")):
                return jsonify(error="request rejected"), 400
            return jsonify(error="database service unavailable"), 503

    return wrapped


def _request_value(name: str, default: Any = None) -> Any:
    if request.is_json:
        body = request.get_json(silent=True)
        if isinstance(body, dict):
            return body.get(name, default)
    return request.form.get(name, default)


def _uuid4(value: Any) -> str | None:
    try:
        parsed = uuid.UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None
    if parsed.version != 4 or str(parsed) != str(value).lower():
        return None
    return str(parsed)


def _json_value(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _safe_request_fields() -> tuple[str, str, int] | None:
    target = str(_request_value("target", ""))
    service = str(_request_value("service", ""))
    try:
        duration = int(_request_value("duration", 420))
    except (TypeError, ValueError):
        return None
    if TARGET_RE.fullmatch(target) is None or service != "echo" or not 30 <= duration <= 420:
        return None
    return target, service, duration


def _browser_worker_url(status: dict[str, Any]) -> str | None:
    if status.get("job_state") != "running":
        return None
    port = status.get("endpoint_port")
    token = status.get("session_token")
    if type(port) is not int or not 25_000 <= port <= 25_099:
        return None
    if type(token) is not str or TOKEN_RE.fullmatch(token) is None:
        return None
    hostname = urlsplit(f"//{request.host}").hostname
    if hostname is None or PUBLIC_HOST_RE.fullmatch(hostname) is None:
        return None
    return f"http://{hostname}:{port}/relay/{token}/"


def _read_one_shot_result(app: Flask, name: str) -> str | None:
    if RESULT_RE.fullmatch(name) is None:
        return None
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(app.config["RESULT_DIRECTORY"], directory_flags)
    except OSError:
        return None
    try:
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            result_fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError:
            return None
        try:
            details = os.fstat(result_fd)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_size > app.config["MAX_RESULT_BYTES"]
            ):
                return None
            chunks: list[bytes] = []
            remaining = app.config["MAX_RESULT_BYTES"] + 1
            while remaining:
                chunk = os.read(result_fd, min(remaining, 8192))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > app.config["MAX_RESULT_BYTES"]:
                return None
        finally:
            os.close(result_fd)
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            return None
        return data.decode("utf-8", errors="replace")
    finally:
        os.close(directory_fd)


def create_app() -> Flask:
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(Config)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    os.makedirs(app.config["RESULT_DIRECTORY"], mode=0o700, exist_ok=True)
    os.chmod(app.config["RESULT_DIRECTORY"], 0o700)

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.after_request
    def response_headers(response):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.get("/healthz")
    def healthz():
        return Response("ok\n", content_type="text/plain; charset=utf-8")

    app.add_url_rule("/login", "login", login_view, methods=["GET", "POST"])
    app.add_url_rule("/logout", "logout", logout_view, methods=["POST"])

    @app.get("/")
    def index():
        return redirect(url_for("dashboard" if current_username() else "login"))

    @app.get("/dashboard")
    @login_required
    def dashboard():
        # Authenticated processing of the remember cookie is the intended
        # Stage 1 entrypoint. The return value is cosmetic; reconstruction is
        # what triggers the RF-WEB gadget chain.
        remembered_username()
        username = current_username()
        try:
            targets = db.list_targets(username)
        except psycopg2.Error:
            app.logger.exception("target-list backend unavailable")
            return render_template("dashboard.html", targets=[], backend_error=True), 503
        return render_template("dashboard.html", targets=targets, backend_error=False)

    @app.post("/connections")
    @login_required
    def request_connection():
        validate_csrf()
        fields = _safe_request_fields()
        if fields is None:
            abort(400, description="Invalid relay request.")
        try:
            request_id = db.submit_safe_request(current_username(), *fields)
        except psycopg2.Error:
            app.logger.exception("connection request backend unavailable")
            abort(503, description="Relay service unavailable.")
        return redirect(url_for("connection_status", request_id=request_id), code=303)

    @app.get("/connections/<request_id>")
    @login_required
    def connection_status(request_id: str):
        canonical = _uuid4(request_id)
        if canonical is None:
            abort(404)
        try:
            status = db.request_status(current_username(), canonical)
        except psycopg2.Error:
            app.logger.exception("connection status backend unavailable")
            abort(503, description="Relay service unavailable.")
        if status is None:
            abort(404)
        status = _json_value(status)
        browser_url = _browser_worker_url(status)
        request_state = status.get("request_state")
        job_state = status.get("job_state")
        refreshing = request_state in {"pending", "reviewing"} or (
            request_state == "approved"
            and job_state in {None, "ready", "dispatching", "stop-ready", "stopping"}
        )
        response = make_response(
            render_template(
                "connection.html",
                status=status,
                browser_url=browser_url,
                refreshing=refreshing,
            )
        )
        if refreshing:
            response.headers["Refresh"] = f"2; url={url_for('connection_status', request_id=canonical)}"
        return response

    @app.post("/connections/cancel")
    @login_required
    def cancel_connection():
        validate_csrf()
        canonical = _uuid4(_request_value("id", ""))
        if canonical is None:
            abort(400, description="Invalid request identifier.")
        try:
            cancelled = db.cancel_request(current_username(), canonical)
        except psycopg2.Error:
            app.logger.exception("connection cancellation backend unavailable")
            abort(503, description="Relay service unavailable.")
        if not cancelled:
            abort(409, description="Relay is not cancellable.")
        return redirect(url_for("connection_status", request_id=canonical), code=303)

    @app.post("/api/request")
    @login_required
    @_api_database_errors
    def submit_request():
        validate_csrf()
        fields = _safe_request_fields()
        if fields is None:
            return jsonify(error="invalid request"), 400
        request_id = db.submit_safe_request(current_username(), *fields)
        return jsonify(request_id=request_id), 202

    @app.get("/api/status")
    @app.get("/api/status/<request_id>")
    @login_required
    @_api_database_errors
    def request_status(request_id: str | None = None):
        canonical = _uuid4(request_id or request.args.get("id"))
        if canonical is None:
            return jsonify(error="invalid request id"), 400
        status_row = db.request_status(current_username(), canonical)
        if status_row is None:
            return jsonify(error="not found"), 404
        payload = _json_value(status_row)
        browser_url = _browser_worker_url(payload)
        if browser_url is not None:
            payload["browser_url"] = browser_url
        return jsonify(payload)

    @app.post("/api/cancel")
    @login_required
    @_api_database_errors
    def cancel_request():
        validate_csrf()
        canonical = _uuid4(_request_value("id", ""))
        if canonical is None:
            return jsonify(error="invalid request id"), 400
        if not db.cancel_request(current_username(), canonical):
            return jsonify(error="relay is not cancellable"), 409
        return jsonify(stopping=True)

    @app.get("/api/result")
    @app.get("/api/result/<name>")
    @login_required
    def result(name: str | None = None):
        candidate = name or request.args.get("name", "")
        if RESULT_RE.fullmatch(candidate) is None:
            return jsonify(error="invalid result name"), 400
        output = _read_one_shot_result(app, candidate)
        if output is None:
            return jsonify(error="result not found"), 404
        return jsonify(name=candidate, output=output)

    @app.errorhandler(413)
    def too_large(_error):
        if request.path.startswith("/api/"):
            return jsonify(error="request too large"), 413
        return "request too large\n", 413

    return app
