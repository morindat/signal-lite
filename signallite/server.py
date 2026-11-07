"""A deliberately dumb relay server.

The relay stores public prekey bundles and opaque ciphertext envelopes.  It
cannot decrypt anything.  It has no accounts, no authentication, and no
durability: it exists to move bytes between two terminals during the demo.

Run it with:

    python -m signallite.cli server --port 8765

The ``/debug/state`` endpoint exists so the demo can show that the server only
holds public keys and ciphertext.
"""

from __future__ import annotations

import copy
import json
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlparse

MAX_BODY = 1_000_000

REQUIRED_BUNDLE_FIELDS = (
    "user",
    "identity_signing_key",
    "identity_dh_key",
    "identity_signature",
    "signed_prekey_id",
    "signed_prekey",
    "signed_prekey_signature",
    "one_time_prekeys",
)


class RelayState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.users: dict[str, dict] = {}
        self.inboxes: dict[str, list[dict]] = {}


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "signal-lite-relay/0.1"
    protocol_version = "HTTP/1.1"

    # -- plumbing --------------------------------------------------------

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        if getattr(self.server, "verbose", False):
            super().log_message(fmt, *args)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("invalid Content-Length") from exc
        if length <= 0:
            raise ValueError("request body is required")
        if length > MAX_BODY:
            raise ValueError("request body is too large")
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("request body is not valid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("request body must be a JSON object")
        return data

    def _route_path(self) -> str:
        return urlparse(self.path).path

    # -- routes ----------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802
        path = self._route_path()
        try:
            if path == "/health":
                self._send_json(200, {"ok": True})
                return

            if path == "/users":
                with self.server.state.lock:
                    users = sorted(self.server.state.users)
                self._send_json(200, {"users": users})
                return

            if path == "/debug/state":
                with self.server.state.lock:
                    snapshot = copy.deepcopy(
                        {
                            "users": self.server.state.users,
                            "inboxes": self.server.state.inboxes,
                        }
                    )
                self._send_json(200, snapshot)
                return

            if path.startswith("/bundle/"):
                self._handle_bundle(unquote(path[len("/bundle/") :]))
                return

            if path.startswith("/identity/"):
                self._handle_identity(unquote(path[len("/identity/") :]))
                return

            if path.startswith("/inbox/"):
                self._handle_inbox(unquote(path[len("/inbox/") :]))
                return

            self._send_json(404, {"error": "not found"})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # keep the demo server alive
            self._send_json(500, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        path = self._route_path()
        try:
            if path == "/register":
                self._handle_register()
                return
            if path == "/send":
                self._handle_send()
                return
            self._send_json(404, {"error": "not found"})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    # -- handlers --------------------------------------------------------

    def _handle_register(self) -> None:
        body = self._read_json()
        missing = [field for field in REQUIRED_BUNDLE_FIELDS if field not in body]
        if missing:
            raise ValueError(f"missing fields: {', '.join(missing)}")

        user = str(body["user"])
        if not user or "/" in user:
            raise ValueError("invalid user name")
        opks_raw = body["one_time_prekeys"]
        if not isinstance(opks_raw, list):
            raise ValueError("one_time_prekeys must be a list")
        try:
            opks = [
                {"id": int(item["id"]), "public": str(item["public"])}
                for item in opks_raw
            ]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("malformed one-time prekey entry") from exc

        record = {
            "user": user,
            "device": str(body.get("device", "default")),
            "identity_signing_key": str(body["identity_signing_key"]),
            "identity_dh_key": str(body["identity_dh_key"]),
            "identity_signature": str(body["identity_signature"]),
            "signed_prekey_id": int(body["signed_prekey_id"]),
            "signed_prekey": str(body["signed_prekey"]),
            "signed_prekey_signature": str(body["signed_prekey_signature"]),
            "one_time_prekeys": opks,
        }

        with self.server.state.lock:
            self.server.state.users[user] = record
            self.server.state.inboxes.setdefault(user, [])

        self._send_json(200, {"ok": True, "user": user, "opk_count": len(opks)})

    def _handle_bundle(self, user: str) -> None:
        with self.server.state.lock:
            record = self.server.state.users.get(user)
            bundle = None
            if record is not None:
                bundle = {
                    key: value
                    for key, value in record.items()
                    if key != "one_time_prekeys"
                }
                opks = record.get("one_time_prekeys", [])
                if opks:
                    opk = opks.pop(0)  # one-time use
                    bundle["one_time_prekey_id"] = opk["id"]
                    bundle["one_time_prekey"] = opk["public"]
                else:
                    bundle["one_time_prekey_id"] = None
                    bundle["one_time_prekey"] = None

        if bundle is None:
            self._send_json(404, {"error": f"unknown user: {user}"})
            return
        self._send_json(200, bundle)

    def _handle_identity(self, user: str) -> None:
        with self.server.state.lock:
            record = self.server.state.users.get(user)
            identity = None
            if record is not None:
                identity = {
                    "user": user,
                    "device": record.get("device", "default"),
                    "identity_signing_key": record["identity_signing_key"],
                    "identity_dh_key": record["identity_dh_key"],
                    "identity_signature": record["identity_signature"],
                }
        if identity is None:
            self._send_json(404, {"error": f"unknown user: {user}"})
            return
        self._send_json(200, identity)

    def _handle_inbox(self, user: str) -> None:
        with self.server.state.lock:
            known = user in self.server.state.users
            messages = self.server.state.inboxes.get(user, [])
            if known:
                self.server.state.inboxes[user] = []
        if not known:
            self._send_json(404, {"error": f"unknown user: {user}"})
            return
        self._send_json(200, {"messages": messages})

    def _handle_send(self) -> None:
        body = self._read_json()
        sender = body.get("sender")
        recipient = body.get("recipient")
        payload = body.get("payload")
        if not isinstance(sender, str) or not sender:
            raise ValueError("sender is required")
        if not isinstance(recipient, str) or not recipient:
            raise ValueError("recipient is required")
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")

        with self.server.state.lock:
            if recipient in self.server.state.users:
                envelope = {
                    "id": uuid.uuid4().hex,
                    "sender": sender,
                    "recipient": recipient,
                    "payload": payload,
                    "ts": time.time(),
                }
                self.server.state.inboxes.setdefault(recipient, []).append(
                    envelope
                )
                envelope_id = envelope["id"]
            else:
                envelope_id = None

        if envelope_id is None:
            self._send_json(404, {"error": f"unknown recipient: {recipient}"})
            return
        self._send_json(200, {"ok": True, "id": envelope_id})


def create_server(
    host: str = "127.0.0.1", port: int = 8765, verbose: bool = False
) -> ThreadingHTTPServer:
    """Create (but do not start) the relay server."""
    server = ThreadingHTTPServer((host, port), RelayHandler)
    server.daemon_threads = True
    server.state = RelayState()
    server.verbose = verbose
    return server
