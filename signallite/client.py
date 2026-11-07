"""High-level client: registration, session setup, sending, receiving.

The relay is untrusted.  All confidentiality, integrity, and authentication
comes from X3DH + the Double Ratchet; the relay only routes opaque envelopes.
"""

from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import requests

from .account import Account, Session
from .crypto import (
    CryptoError,
    INFO_IDENTITY_FINGERPRINT,
    INFO_SAFETY_NUMBER,
    generate_x25519_keypair,
)
from .encoding import b64d, b64e
from .ratchet import decrypt, encrypt, initiator_init, responder_init
from .x3dh import (
    PreKeyBundle,
    initiator_root_key,
    responder_root_key,
    verify_bundle,
    verify_identity_binding,
)


class ClientError(Exception):
    """A client-side protocol or relay failure."""


class Client:
    """One device talking to the relay and to other devices."""

    def __init__(
        self,
        account: Account,
        server_url: str,
        state_path: str | Path | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.account = account
        self.server_url = server_url.rstrip("/")
        self.state_path = Path(state_path) if state_path is not None else None
        self.timeout = timeout
        self.events: list[tuple] = []
        self._lock = threading.RLock()

    # -- relay plumbing --------------------------------------------------

    def _request(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            response = requests.request(
                method,
                self.server_url + path,
                json=body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ClientError(f"relay request failed: {exc}") from exc

        if response.status_code >= 400:
            try:
                detail = response.json().get("error", response.text)
            except ValueError:
                detail = response.text
            raise ClientError(
                f"relay returned {response.status_code}: {detail}"
            )
        try:
            data = response.json()
        except ValueError as exc:
            raise ClientError("relay returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise ClientError("relay returned an unexpected JSON value")
        return data

    def register(self) -> dict:
        """Publish this device's public prekey bundle to the relay."""
        return self._request("POST", "/register", self.account.bundle_dict())

    def list_users(self) -> list[str]:
        return list(self._request("GET", "/users").get("users", []))

    def fetch_identity(self, peer: str) -> bytes:
        """Fetch and verify a peer's long-term identity key."""
        data = self._request("GET", f"/identity/{peer}")
        try:
            signing_key = b64d(data["identity_signing_key"])
            identity_key = b64d(data["identity_dh_key"])
            signature = b64d(data["identity_signature"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ClientError(f"malformed identity for {peer}") from exc
        verify_identity_binding(signing_key, identity_key, signature)
        return identity_key

    def fetch_bundle(self, peer: str) -> PreKeyBundle:
        """Fetch, verify, and trust a peer's prekey bundle."""
        data = self._request("GET", f"/bundle/{peer}")
        try:
            bundle = PreKeyBundle.from_dict(data)
        except CryptoError as exc:
            raise ClientError(str(exc)) from exc
        try:
            verify_bundle(bundle)
        except CryptoError as exc:
            raise ClientError(f"prekey bundle for {peer} failed verification: {exc}") from exc
        self._check_trust(peer, bundle.identity_dh_key)
        return bundle

    # -- trust -----------------------------------------------------------

    def _check_trust(self, peer: str, identity_key: bytes) -> None:
        current = b64e(identity_key)
        known = self.account.trusted.get(peer)
        if known is None:
            self.account.trusted[peer] = current
        elif known != current:
            self.events.append(("identity_changed", peer, known, current))
            self.account.trusted[peer] = current

    def own_fingerprint(self) -> str:
        digest = hashlib.sha256(
            INFO_IDENTITY_FINGERPRINT + self.account.dh_pub
        ).hexdigest()
        return _format_fingerprint(digest)

    def safety_number(self, peer: str) -> str:
        """Deterministic pairwise fingerprint both sides can compare out of band."""
        peer_identity = self.account.trusted.get(peer)
        if peer_identity is None:
            peer_identity = b64e(self.fetch_identity(peer))
        first, second = sorted([self.account.dh_pub, b64d(peer_identity)])
        digest = hashlib.sha256(
            INFO_SAFETY_NUMBER + first + second
        ).hexdigest()
        return _format_fingerprint(digest)

    # -- sessions --------------------------------------------------------

    def ensure_session(self, peer: str) -> Session:
        with self._lock:
            return self._ensure_session_locked(peer)

    def _ensure_session_locked(self, peer: str) -> Session:
        existing = self.account.sessions.get(peer)
        if existing is not None:
            return existing

        bundle = self.fetch_bundle(peer)
        ephemeral_priv, ephemeral_pub = generate_x25519_keypair()
        root_key = initiator_root_key(
            self.account.dh_priv, ephemeral_priv, bundle
        )
        state = initiator_init(root_key, bundle.signed_prekey)

        pending_prekey = {
            "identity_key": b64e(self.account.dh_pub),
            "signing_key": b64e(self.account.signing_pub),
            "identity_signature": b64e(self.account.identity_signature),
            "ephemeral": b64e(ephemeral_pub),
            "signed_prekey_id": bundle.signed_prekey_id,
            "one_time_prekey_id": bundle.one_time_prekey_id,
        }
        session = Session(
            peer=peer, ratchet=state, pending_prekey=pending_prekey
        )
        self.account.sessions[peer] = session
        self.save()
        return session

    # -- send / receive --------------------------------------------------

    def send(self, peer: str, text: str) -> str:
        """Encrypt and send one text message.  Returns the relay envelope id."""
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        with self._lock:
            session = self._ensure_session_locked(peer)
            header: dict = {
                "type": (
                    "prekey" if session.pending_prekey is not None else "message"
                ),
                "sender": self.account.user,
                "sender_device": self.account.device,
            }
            if session.pending_prekey is not None:
                header.update(session.pending_prekey)

            header, iv, ciphertext, mac = encrypt(
                session.ratchet, text.encode("utf-8"), header
            )
            payload = {
                "header": header,
                "iv": b64e(iv),
                "ct": b64e(ciphertext),
                "mac": b64e(mac),
            }
            response = self._request(
                "POST",
                "/send",
                {
                    "sender": self.account.user,
                    "recipient": peer,
                    "payload": payload,
                },
            )
            self.save()
            return str(response.get("id", ""))

    def receive_all(self) -> list[tuple[str, str]]:
        """Drain the relay inbox and decrypt every message we can.

        A malformed or forged envelope is recorded as an event and does not
        abort the batch; a real messenger would surface a retry request instead.
        """
        with self._lock:
            data = self._request("GET", f"/inbox/{self.account.user}")
            messages = data.get("messages", [])
            if not isinstance(messages, list):
                raise ClientError("relay returned a malformed inbox")
            received: list[tuple[str, str]] = []
            for envelope in messages:
                try:
                    received.append(self._receive_envelope_locked(envelope))
                except Exception as exc:  # keep the chat loop alive
                    sender = None
                    if isinstance(envelope, dict):
                        sender = envelope.get("sender")
                    self.events.append(("decrypt_error", sender, str(exc)))
            self.save()
            return received

    def receive_envelope(self, envelope: dict) -> tuple[str, str]:
        """Decrypt one specific envelope.  Used by tests and demos."""
        with self._lock:
            result = self._receive_envelope_locked(envelope)
            self.save()
            return result

    def _receive_envelope_locked(self, envelope: dict) -> tuple[str, str]:
        if not isinstance(envelope, dict):
            raise ClientError("envelope must be an object")
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            raise ClientError("envelope payload is missing")
        header = payload.get("header")
        if not isinstance(header, dict):
            raise ClientError("message header is missing")
        peer = header.get("sender")
        if not isinstance(peer, str) or not peer:
            raise ClientError("message header has no sender")

        try:
            iv = b64d(payload["iv"])
            ciphertext = b64d(payload["ct"])
            mac = b64d(payload["mac"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ClientError("malformed ciphertext payload") from exc
        if len(mac) != 32:
            raise ClientError("malformed MAC")
        if len(iv) != 16:
            raise ClientError("malformed IV")

        message_type = header.get("type")
        if message_type == "prekey":
            identity_key = self._verify_prekey_header(header)
            identity_b64 = b64e(identity_key)
            known = self.account.trusted.get(peer)
            if (
                peer in self.account.sessions
                and known is not None
                and known != identity_b64
            ):
                self.events.append(
                    ("identity_changed", peer, known, identity_b64)
                )
                self.account.trusted[peer] = identity_b64
                del self.account.sessions[peer]
            if peer not in self.account.sessions:
                self._accept_prekey(peer, header, identity_key)
        elif peer not in self.account.sessions:
            raise ClientError(
                f"no session with {peer}; expected a prekey message"
            )

        session = self.account.sessions[peer]
        plaintext = decrypt(session.ratchet, header, iv, ciphertext, mac)
        # A reply proves the peer built the session; stop advertising prekey
        # material from now on.
        session.pending_prekey = None
        try:
            text = plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ClientError("decrypted payload is not valid UTF-8") from exc
        return peer, text

    def _verify_prekey_header(self, header: dict) -> bytes:
        for field in (
            "identity_key",
            "signing_key",
            "identity_signature",
            "ephemeral",
        ):
            if not isinstance(header.get(field), str):
                raise ClientError(f"prekey header is missing {field}")
        spk_id = header.get("signed_prekey_id")
        if isinstance(spk_id, bool) or not isinstance(spk_id, int):
            raise ClientError("prekey header has an invalid signed prekey id")
        opk_id = header.get("one_time_prekey_id")
        if opk_id is not None and (
            isinstance(opk_id, bool) or not isinstance(opk_id, int)
        ):
            raise ClientError("prekey header has an invalid one-time prekey id")

        try:
            identity_key = b64d(header["identity_key"])
            signing_key = b64d(header["signing_key"])
            signature = b64d(header["identity_signature"])
            ephemeral = b64d(header["ephemeral"])
        except (TypeError, ValueError) as exc:
            raise ClientError("prekey header contains invalid base64") from exc
        if len(ephemeral) != 32:
            raise ClientError("prekey header ephemeral key is not 32 bytes")
        verify_identity_binding(signing_key, identity_key, signature)
        return identity_key

    def _accept_prekey(
        self, peer: str, header: dict, identity_key: bytes
    ) -> None:
        spk_id = header["signed_prekey_id"]
        if spk_id != self.account.spk_id:
            raise ClientError(
                f"unknown signed prekey {spk_id}; this device has "
                f"{self.account.spk_id}"
            )
        try:
            opk_private = self.account.take_opk(
                header.get("one_time_prekey_id")
            )
            root_key = responder_root_key(
                self.account.dh_priv,
                self.account.spk_priv,
                opk_private,
                identity_key,
                b64d(header["ephemeral"]),
            )
        except (CryptoError, ValueError) as exc:
            raise ClientError(f"cannot accept prekey message: {exc}") from exc

        self._check_trust(peer, identity_key)
        self.account.sessions[peer] = Session(
            peer=peer,
            ratchet=responder_init(
                root_key, self.account.spk_priv, self.account.spk_pub
            ),
        )

    # -- misc ------------------------------------------------------------

    def drain_events(self) -> list[tuple]:
        with self._lock:
            events = self.events[:]
            self.events.clear()
            return events

    def save(self) -> None:
        if self.state_path is not None:
            self.account.save(self.state_path)


def _format_fingerprint(hex_digest: str) -> str:
    return " ".join(
        hex_digest[index : index + 4] for index in range(0, 32, 4)
    )
