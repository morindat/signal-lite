"""Device identity, prekeys, sessions, and on-disk state.

One ``Account`` is one device.  It holds the long-term Ed25519 signing key, the
X25519 identity key, a signed prekey, a pool of one-time prekeys, and the
per-peer ratchet sessions.  Private material never leaves the device.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .crypto import (
    CryptoError,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    sign,
    x25519_public_from_private,
)
from .encoding import b64d, b64e
from .ratchet import RatchetState
from .x3dh import identity_binding_data, signed_prekey_signing_data


class AccountError(CryptoError):
    """The local account state is inconsistent or a prekey is missing."""


@dataclass
class Session:
    """A live pairwise session with one remote device."""

    peer: str
    ratchet: RatchetState
    # Populated for the initiator until the peer replies.  The whitepaper says
    # the initiator keeps advertising this material on every message until then,
    # so a lost first message does not strand the session.
    pending_prekey: dict | None = None

    def to_dict(self) -> dict:
        return {
            "peer": self.peer,
            "ratchet": self.ratchet.to_dict(),
            "pending_prekey": self.pending_prekey,
        }

    @classmethod
    def from_dict(cls, peer: str, data: dict) -> "Session":
        return cls(
            peer=peer,
            ratchet=RatchetState.from_dict(data["ratchet"]),
            pending_prekey=data.get("pending_prekey"),
        )


@dataclass
class Account:
    user: str
    device: str = "default"
    signing_priv: bytes = b""
    signing_pub: bytes = b""
    dh_priv: bytes = b""
    dh_pub: bytes = b""
    spk_id: int = 1
    spk_priv: bytes = b""
    spk_pub: bytes = b""
    identity_signature: bytes = b""
    spk_signature: bytes = b""
    opks: dict[int, bytes] = field(default_factory=dict)
    next_opk_id: int = 1
    sessions: dict[str, Session] = field(default_factory=dict)
    trusted: dict[str, str] = field(default_factory=dict)

    # -- construction ----------------------------------------------------

    @classmethod
    def create(
        cls, user: str, device: str = "default", num_opks: int = 20
    ) -> "Account":
        if not user or "/" in user:
            raise AccountError("user name must be non-empty and contain no '/'")
        signing_priv, signing_pub = generate_ed25519_keypair()
        dh_priv, dh_pub = generate_x25519_keypair()
        spk_id = 1
        spk_priv, spk_pub = generate_x25519_keypair()
        account = cls(
            user=user,
            device=device,
            signing_priv=signing_priv,
            signing_pub=signing_pub,
            dh_priv=dh_priv,
            dh_pub=dh_pub,
            spk_id=spk_id,
            spk_priv=spk_priv,
            spk_pub=spk_pub,
            identity_signature=sign(
                signing_priv, identity_binding_data(dh_pub)
            ),
            spk_signature=sign(
                signing_priv, signed_prekey_signing_data(spk_id, spk_pub)
            ),
        )
        account.add_opks(num_opks)
        return account

    def add_opks(self, count: int) -> list[int]:
        """Generate ``count`` one-time prekeys and return their ids."""
        ids: list[int] = []
        for _ in range(max(0, int(count))):
            opk_id = self.next_opk_id
            self.next_opk_id += 1
            private, _public = generate_x25519_keypair()
            self.opks[opk_id] = private
            ids.append(opk_id)
        return ids

    def take_opk(self, opk_id: int | None) -> bytes | None:
        """Consume a one-time prekey.  Each OPK may be used at most once."""
        if opk_id is None:
            return None
        try:
            return self.opks.pop(int(opk_id))
        except (KeyError, TypeError, ValueError) as exc:
            raise AccountError(f"unknown or already consumed OPK {opk_id}") from exc

    def opk_public(self, opk_id: int) -> bytes:
        try:
            return x25519_public_from_private(self.opks[int(opk_id)])
        except KeyError as exc:
            raise AccountError(f"unknown OPK {opk_id}") from exc

    # -- server-facing bundle -------------------------------------------

    def bundle_dict(self) -> dict:
        """Public registration bundle.  Never includes private keys."""
        return {
            "user": self.user,
            "device": self.device,
            "identity_signing_key": b64e(self.signing_pub),
            "identity_dh_key": b64e(self.dh_pub),
            "identity_signature": b64e(self.identity_signature),
            "signed_prekey_id": self.spk_id,
            "signed_prekey": b64e(self.spk_pub),
            "signed_prekey_signature": b64e(self.spk_signature),
            "one_time_prekeys": [
                {"id": opk_id, "public": b64e(self.opk_public(opk_id))}
                for opk_id in sorted(self.opks)
            ],
        }

    # -- persistence -----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "user": self.user,
            "device": self.device,
            "signing_priv": b64e(self.signing_priv),
            "signing_pub": b64e(self.signing_pub),
            "dh_priv": b64e(self.dh_priv),
            "dh_pub": b64e(self.dh_pub),
            "spk_id": self.spk_id,
            "spk_priv": b64e(self.spk_priv),
            "spk_pub": b64e(self.spk_pub),
            "identity_signature": b64e(self.identity_signature),
            "spk_signature": b64e(self.spk_signature),
            "opks": {str(i): b64e(priv) for i, priv in self.opks.items()},
            "next_opk_id": self.next_opk_id,
            "sessions": {
                peer: session.to_dict() for peer, session in self.sessions.items()
            },
            "trusted": dict(self.trusted),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Account":
        try:
            sessions = {
                peer: Session.from_dict(peer, session_data)
                for peer, session_data in data.get("sessions", {}).items()
            }
            return cls(
                user=str(data["user"]),
                device=str(data.get("device", "default")),
                signing_priv=b64d(data["signing_priv"]),
                signing_pub=b64d(data["signing_pub"]),
                dh_priv=b64d(data["dh_priv"]),
                dh_pub=b64d(data["dh_pub"]),
                spk_id=int(data.get("spk_id", 1)),
                spk_priv=b64d(data["spk_priv"]),
                spk_pub=b64d(data["spk_pub"]),
                identity_signature=b64d(data["identity_signature"]),
                spk_signature=b64d(data["spk_signature"]),
                opks={
                    int(opk_id): b64d(private)
                    for opk_id, private in data.get("opks", {}).items()
                },
                next_opk_id=int(data.get("next_opk_id", 1)),
                sessions=sessions,
                trusted={
                    str(peer): str(key)
                    for peer, key in data.get("trusted", {}).items()
                },
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AccountError(f"malformed account state: {exc}") from exc

    def save(self, path: str | os.PathLike) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        temporary.replace(path)

    @classmethod
    def load(cls, path: str | os.PathLike) -> "Account":
        path = Path(path)
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
