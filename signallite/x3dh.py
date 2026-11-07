"""X3DH: the asynchronous key-agreement handshake.

This follows the construction in Meta's Messenger E2EE whitepaper, section 7:

    master = DH(IK_A, SPK_B) || DH(EK_A, IK_B) || DH(EK_A, SPK_B)
             || DH(EK_A, OPK_B)          # last term omitted if no OPK

with X25519 for every DH and HKDF-SHA256 to turn the master secret into a
32-byte root key for the Double Ratchet.

Deviation from Signal: Signal signs the signed prekey with the X25519 identity
key using XEdDSA.  XEdDSA is a rabbit hole, so signal-lite uses a separate
Ed25519 signing key, binds it to the X25519 identity key with a signature, and
signs the signed prekey with the Ed25519 key.  The security-relevant property
(the signed prekey cannot be substituted without the identity private key) is
preserved.
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import (
    CryptoError,
    INFO_IDENTITY_BINDING,
    INFO_SIGNED_PREKEY,
    INFO_X3DH,
    SignatureError,
    ZERO32,
    dh,
    hkdf,
    verify,
)
from .encoding import b64d, b64e


class BundleError(CryptoError):
    """A prekey bundle is malformed or has an invalid signature."""


def identity_binding_data(identity_dh_public: bytes) -> bytes:
    """The message the Ed25519 identity key signs to bind the X25519 key."""
    return INFO_IDENTITY_BINDING + identity_dh_public


def signed_prekey_signing_data(spk_id: int, spk_public: bytes) -> bytes:
    """The message the identity key signs to authorise a signed prekey."""
    return INFO_SIGNED_PREKEY + int(spk_id).to_bytes(4, "big") + spk_public


@dataclass(frozen=True)
class PreKeyBundle:
    """The public material a sender needs to start a session with a device."""

    user: str
    device: str
    identity_signing_key: bytes
    identity_dh_key: bytes
    identity_signature: bytes
    signed_prekey_id: int
    signed_prekey: bytes
    signed_prekey_signature: bytes
    one_time_prekey_id: int | None = None
    one_time_prekey: bytes | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "PreKeyBundle":
        try:
            opk_id_raw = data.get("one_time_prekey_id")
            opk_raw = data.get("one_time_prekey")
            return cls(
                user=str(data["user"]),
                device=str(data.get("device", "default")),
                identity_signing_key=b64d(data["identity_signing_key"]),
                identity_dh_key=b64d(data["identity_dh_key"]),
                identity_signature=b64d(data["identity_signature"]),
                signed_prekey_id=int(data["signed_prekey_id"]),
                signed_prekey=b64d(data["signed_prekey"]),
                signed_prekey_signature=b64d(data["signed_prekey_signature"]),
                one_time_prekey_id=(
                    int(opk_id_raw) if opk_id_raw is not None else None
                ),
                one_time_prekey=(
                    b64d(opk_raw) if opk_raw is not None else None
                ),
            )
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise BundleError(f"malformed prekey bundle: {exc}") from exc

    def to_dict(self) -> dict:
        return {
            "user": self.user,
            "device": self.device,
            "identity_signing_key": b64e(self.identity_signing_key),
            "identity_dh_key": b64e(self.identity_dh_key),
            "identity_signature": b64e(self.identity_signature),
            "signed_prekey_id": self.signed_prekey_id,
            "signed_prekey": b64e(self.signed_prekey),
            "signed_prekey_signature": b64e(self.signed_prekey_signature),
            "one_time_prekey_id": self.one_time_prekey_id,
            "one_time_prekey": (
                b64e(self.one_time_prekey)
                if self.one_time_prekey is not None
                else None
            ),
        }


def verify_identity_binding(
    identity_signing_key: bytes,
    identity_dh_key: bytes,
    identity_signature: bytes,
) -> None:
    if len(identity_signing_key) != 32:
        raise BundleError("identity signing key must be 32 bytes")
    if len(identity_dh_key) != 32:
        raise BundleError("identity DH key must be 32 bytes")
    verify(
        identity_signing_key,
        identity_signature,
        identity_binding_data(identity_dh_key),
    )


def verify_bundle(bundle: PreKeyBundle) -> None:
    """Check key lengths and both signatures before using a bundle."""
    if len(bundle.signed_prekey) != 32:
        raise BundleError("signed prekey must be 32 bytes")
    try:
        verify_identity_binding(
            bundle.identity_signing_key,
            bundle.identity_dh_key,
            bundle.identity_signature,
        )
    except SignatureError as exc:
        raise BundleError("identity binding signature is invalid") from exc
    if bundle.one_time_prekey_id is None and bundle.one_time_prekey is not None:
        raise BundleError("one-time prekey present without an id")
    if bundle.one_time_prekey_id is not None and bundle.one_time_prekey is None:
        raise BundleError("one-time prekey id present without a key")
    if bundle.one_time_prekey is not None and len(bundle.one_time_prekey) != 32:
        raise BundleError("one-time prekey must be 32 bytes")
    try:
        verify(
            bundle.identity_signing_key,
            bundle.signed_prekey_signature,
            signed_prekey_signing_data(
                bundle.signed_prekey_id, bundle.signed_prekey
            ),
        )
    except SignatureError as exc:
        raise BundleError("signed prekey signature is invalid") from exc


def initiator_root_key(
    identity_dh_private: bytes,
    ephemeral_private: bytes,
    bundle: PreKeyBundle,
) -> bytes:
    """Derive the initial root key from the sender's point of view."""
    dh1 = dh(identity_dh_private, bundle.signed_prekey)
    dh2 = dh(ephemeral_private, bundle.identity_dh_key)
    dh3 = dh(ephemeral_private, bundle.signed_prekey)
    parts = [dh1, dh2, dh3]
    if bundle.one_time_prekey is not None:
        parts.append(dh(ephemeral_private, bundle.one_time_prekey))
    return hkdf(
        b"".join(parts), salt=ZERO32, info=INFO_X3DH, length=32
    )


def responder_root_key(
    identity_dh_private: bytes,
    signed_prekey_private: bytes,
    one_time_prekey_private: bytes | None,
    initiator_identity_public: bytes,
    initiator_ephemeral_public: bytes,
) -> bytes:
    """Derive the same root key from the recipient's point of view."""
    dh1 = dh(signed_prekey_private, initiator_identity_public)
    dh2 = dh(identity_dh_private, initiator_ephemeral_public)
    dh3 = dh(signed_prekey_private, initiator_ephemeral_public)
    parts = [dh1, dh2, dh3]
    if one_time_prekey_private is not None:
        parts.append(dh(one_time_prekey_private, initiator_ephemeral_public))
    return hkdf(
        b"".join(parts), salt=ZERO32, info=INFO_X3DH, length=32
    )
