#!/usr/bin/env python3
"""DB-free Web contract tests; canonical DB integration is tested separately."""

from __future__ import annotations

import base64
import os
import pickle
import re
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


os.environ.setdefault("FLASK_SECRET_KEY", "4" * 64)
os.environ.setdefault("DB_HOST", "postgres")
os.environ.setdefault("DB_NAME", "relayforge")
os.environ.setdefault("DB_USER", "relay_web")
os.environ.setdefault("DB_PASSWORD", "1" * 48)

import prefs  # noqa: E402
from app import create_app  # noqa: E402


CSRF_RE = re.compile(rb'name="csrf_token" value="([A-Za-z0-9_-]+)"')


class WebContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.results = tempfile.TemporaryDirectory()
        self.app = create_app()
        self.app.config.update(TESTING=True, RESULT_DIRECTORY=self.results.name)
        self.client = self.app.test_client()
        self.targets = [
            {
                "id": "archive-echo",
                "display_name": "Archive Echo Service",
                "service": "echo",
                "max_duration": 420,
            }
        ]

    def tearDown(self) -> None:
        self.results.cleanup()

    def csrf(self) -> str:
        with self.client.session_transaction() as signed_session:
            return signed_session["csrf_token"]

    def login(self) -> None:
        page = self.client.get("/login", base_url="https://localhost")
        token = CSRF_RE.search(page.data)
        self.assertIsNotNone(token)
        with mock.patch("app.db.authenticate", return_value=True), mock.patch(
            "app.db.list_targets", return_value=self.targets
        ):
            response = self.client.post(
                "/login",
                data={
                    "username": "guest",
                    "password": "test-password",
                    "csrf_token": token.group(1).decode("ascii"),
                },
                base_url="https://localhost",
                follow_redirects=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"YOUR DASHBOARD", response.data)

    def test_health_and_authentication_boundary(self) -> None:
        self.assertEqual(self.client.get("/healthz").data, b"ok\n")
        response = self.client.get("/api/status?id=nope")
        self.assertEqual(response.status_code, 401)

    def test_safe_request_status_and_cancel(self) -> None:
        self.login()
        request_id = str(uuid.uuid4())
        seen: list[tuple[str, str, str, int]] = []

        def submit(username: str, target: str, service: str, duration: int) -> str:
            seen.append((username, target, service, duration))
            return request_id

        with mock.patch("app.db.submit_safe_request", side_effect=submit):
            response = self.client.post(
                "/api/request",
                json={
                    "target": "archive-echo",
                    "service": "echo",
                    "duration": 420,
                    "options": "profile=legacy",
                },
                headers={"X-CSRF-Token": self.csrf()},
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json(), {"request_id": request_id})
        self.assertEqual(seen, [("guest", "archive-echo", "echo", 420)])

        with mock.patch(
            "app.db.request_status",
            return_value={"request_id": uuid.UUID(request_id), "request_state": "pending"},
        ):
            response = self.client.get(f"/api/status/{request_id}", base_url="https://localhost")
        self.assertEqual(response.get_json()["request_id"], request_id)

        with mock.patch("app.db.cancel_request", return_value=True):
            response = self.client.post(
                "/api/cancel",
                json={"id": request_id},
                headers={"X-CSRF-Token": self.csrf()},
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"stopping": True})

    def test_browser_connection_request_and_pending_status(self) -> None:
        self.login()
        request_id = str(uuid.uuid4())
        with mock.patch("app.db.submit_safe_request", return_value=request_id) as submit:
            response = self.client.post(
                "/connections",
                data={
                    "target": "archive-echo",
                    "service": "echo",
                    "duration": "420",
                    "csrf_token": self.csrf(),
                },
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], f"/connections/{request_id}")
        submit.assert_called_once_with("guest", "archive-echo", "echo", 420)

        pending = {
            "request_id": uuid.UUID(request_id),
            "request_state": "reviewing",
            "job_state": None,
            "session_token": None,
            "endpoint_port": None,
        }
        with mock.patch("app.db.request_status", return_value=pending):
            status = self.client.get(
                f"/connections/{request_id}", base_url="https://localhost"
            )
        self.assertEqual(status.status_code, 200)
        self.assertEqual(status.headers["Refresh"], f"2; url=/connections/{request_id}")
        self.assertIn(b"Checking access", status.data)
        self.assertNotIn(b"/relay/", status.data)

    def test_running_browser_link_and_html_cancellation(self) -> None:
        self.login()
        request_id = str(uuid.uuid4())
        token = "a" * 48
        running = {
            "request_id": uuid.UUID(request_id),
            "request_state": "approved",
            "job_state": "running",
            "endpoint_port": 25042,
            "session_token": token,
            "ends_at": "2026-09-18T04:00:00+00:00",
        }
        with mock.patch("app.db.request_status", return_value=running):
            page = self.client.get(
                f"/connections/{request_id}", base_url="https://localhost"
            )
            api = self.client.get(
                f"/api/status/{request_id}", base_url="https://localhost"
            )
        expected = f"http://localhost:25042/relay/{token}/"
        self.assertEqual(page.status_code, 200)
        self.assertNotIn("Refresh", page.headers)
        self.assertIn(expected.encode("ascii"), page.data)
        self.assertIn(b"Your tunnel is ready", page.data)
        self.assertEqual(api.get_json()["browser_url"], expected)

        with mock.patch("app.db.cancel_request", return_value=True) as cancel:
            response = self.client.post(
                "/connections/cancel",
                data={"id": request_id, "csrf_token": self.csrf()},
                base_url="https://localhost",
            )
        self.assertEqual(response.status_code, 303)
        self.assertEqual(response.headers["Location"], f"/connections/{request_id}")
        cancel.assert_called_once_with("guest", request_id)

    def test_terminal_connection_never_renders_bearer_token(self) -> None:
        self.login()
        request_id = str(uuid.uuid4())
        secret = "b" * 48
        terminal = {
            "request_id": uuid.UUID(request_id),
            "request_state": "approved",
            "job_state": "failed",
            "endpoint_port": 25010,
            "session_token": secret,
        }
        with mock.patch("app.db.request_status", return_value=terminal):
            response = self.client.get(
                f"/connections/{request_id}", base_url="https://localhost"
            )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Refresh", response.headers)
        self.assertNotIn(secret.encode("ascii"), response.data)
        self.assertNotIn(b"/relay/", response.data)

    def test_authenticated_pickle_gadget_and_one_shot_result(self) -> None:
        self.login()
        template = prefs.JobTemplate.__new__(prefs.JobTemplate)
        template.command = "id"
        runner = prefs.JobRunner.__new__(prefs.JobRunner)
        runner.armed = True
        state = base64.b64encode(pickle.dumps((template, runner))).decode("ascii")
        self.client.set_cookie("remember_prefs", state, domain="localhost", secure=True)
        launched: list[str] = []

        def fake_launch(command, **_kwargs):
            launched.append(command)
            return object()

        with mock.patch("prefs.subprocess.Popen", side_effect=fake_launch), mock.patch(
            "app.db.list_targets", return_value=self.targets
        ):
            response = self.client.get("/dashboard", base_url="https://localhost")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(launched, ["id"])

        name = "a" * 32 + ".txt"
        Path(self.results.name, name).write_text("request-id\n", encoding="utf-8")
        first = self.client.get(f"/api/result/{name}", base_url="https://localhost")
        second = self.client.get(f"/api/result/{name}", base_url="https://localhost")
        self.assertEqual(first.get_json(), {"name": name, "output": "request-id\n"})
        self.assertEqual(second.status_code, 404)

    def test_missing_csrf_is_rejected(self) -> None:
        self.login()
        response = self.client.post(
            "/api/request",
            json={"target": "archive-echo", "service": "echo", "duration": 420},
            base_url="https://localhost",
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
