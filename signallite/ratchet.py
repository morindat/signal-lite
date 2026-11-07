"""Double Ratchet with out-of-order handling.

This is the standard Signal construction, minus header encryption:

* A DH ratchet step happens whenever a message carries a new ratchet public key.
* A symmetric hash ratchet advances the sending and receiving chain keys.
* Message keys that are skipped because of out-of-order delivery are cached,
  keyed by (ratchet public key, message number), up to ``MAX_SKIP``.

Decryption is copy-on-write: the live session is only committed after the MAC
verifies.  A forged message therefore cannot desynchronise the ratchet.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field

from .crypto import (
    CryptoError,
    MessageKeys,
    decrypt_aead,
    dh,
    encrypt_aead,
    expand_message_key,
    generate_x25519_keypair,
    kdf_ck,
    kdf_rk,
)
from .encoding import b64d, b64e, canonical_json

MAX_SKIP = 1000


class RatchetError(CryptoError):
    """The ratchet cannot process this message."""


class ReplayError(RatchetError):
    """This message key was already used, or belongs to an old chain."""


class InvalidHeaderError(RatchetError):
    """The message header is malformed."""


@dataclass
class RatchetState:
    root_key: bytes
    dh_self_priv: bytes
    dh_self_pub: bytes
    dh_peer_pub: bytes | None = None
    ck_send: bytes | None = None
    ck_recv: bytes | None = None
    n_send: int = 0
    n_recv: int = 0
    pn: int = 0
    skipped: dict[str, bytes] = field(default_factory=dict)

    # -- persistence -----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "root_key": b64e(self.root_key),
            "dh_self_priv": b64e(self.dh_self_priv),
            "dh_self_pub": b64e(self.dh_self_pub),
            "dh_peer_pub": (
                b64e(self.dh_peer_pub) if self.dh_peer_pub is not None else None
            ),
            "ck_send": b64e(self.ck_send) if self.ck_send is not None else None,
            "ck_recv": b64e(self.ck_recv) if self.ck_recv is not None else None,
            "n_send": self.n_send,
            "n_recv": self.n_recv,
            "pn": self.pn,
            "skipped": {key: b64e(value) for key, value in self.skipped.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "RatchetState":
        try:
            return cls(
                root_key=b64d(data["root_key"]),
                dh_self_priv=b64d(data["dh_self_priv"]),
                dh_self_pub=b64d(data["dh_self_pub"]),
                dh_peer_pub=(
                    b64d(data["dh_peer_pub"])
                    if data.get("dh_peer_pub") is not None
                    else None
                ),
                ck_send=(
                    b64d(data["ck_send"])
                    if data.get("ck_send") is not None
                    else None
                ),
                ck_recv=(
                    b64d(data["ck_recv"])
                    if data.get("ck_recv") is not None
                    else None
                ),
                n_send=int(data.get("n_send", 0)),
                n_recv=int(data.get("n_recv", 0)),
                pn=int(data.get("pn", 0)),
                skipped={
                    str(key): b64d(value)
                    for key, value in data.get("skipped", {}).items()
                },
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise RatchetError(f"malformed ratchet state: {exc}") from exc


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------


def header_ad(header: dict) -> bytes:
    """Associated data: the entire header, canonically encoded."""
    return canonical_json(header)


def validate_header(header: dict) -> None:
    if not isinstance(header, dict):
        raise InvalidHeaderError("header must be an object")
    for name in ("dh", "pn", "n"):
        if name not in header:
            raise InvalidHeaderError(f"header is missing {name!r}")
    if not isinstance(header["dh"], str):
        raise InvalidHeaderError("header.dh must be a base64 string")
    try:
        raw_dh = b64d(header["dh"])
    except (TypeError, ValueError) as exc:
        raise InvalidHeaderError("header.dh is not valid base64") from exc
    if len(raw_dh) != 32:
        raise InvalidHeaderError("header.dh must decode to 32 bytes")
    for name in ("pn", "n"):
        value = header[name]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise InvalidHeaderError(f"header.{name} must be a non-negative int")
    if "type" in header and not isinstance(header["type"], str):
        raise InvalidHeaderError("header.type must be a string")
    if "sender" in header and not isinstance(header["sender"], str):
        raise InvalidHeaderError("header.sender must be a string")


# ---------------------------------------------------------------------------
# Ratchet setup
# ---------------------------------------------------------------------------


def initiator_init(root_key: bytes, peer_signed_prekey_public: bytes) -> RatchetState:
    """Initialise the sender's ratchet after X3DH.

    The sender immediately performs the first DH ratchet step with a fresh
    ratchet key pair, producing the first sending chain.  The recipient will
    derive the matching receiving chain when the first message arrives.
    """
    ratchet_priv, ratchet_pub = generate_x25519_keypair()
    new_root, send_chain = kdf_rk(
        root_key, dh(ratchet_priv, peer_signed_prekey_public)
    )
    return RatchetState(
        root_key=new_root,
        dh_self_priv=ratchet_priv,
        dh_self_pub=ratchet_pub,
        dh_peer_pub=peer_signed_prekey_public,
        ck_send=send_chain,
        ck_recv=None,
    )


def responder_init(
    root_key: bytes,
    signed_prekey_private: bytes,
    signed_prekey_public: bytes,
) -> RatchetState:
    """Initialise the recipient's ratchet after X3DH.

    The recipient starts with the signed prekey as its current ratchet key and
    no chains; the first incoming message triggers the first DH ratchet step.
    """
    return RatchetState(
        root_key=root_key,
        dh_self_priv=signed_prekey_private,
        dh_self_pub=signed_prekey_public,
        dh_peer_pub=None,
        ck_send=None,
        ck_recv=None,
    )


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------


def encrypt(
    state: RatchetState,
    plaintext: bytes,
    extra_header: dict | None = None,
) -> tuple[dict, bytes, bytes, bytes]:
    """Encrypt one message.

    Returns ``(header, iv, ciphertext, mac)``.  ``extra_header`` supplies the
    protocol-level fields (type, sender, prekey material) that are also
    authenticated as associated data.
    """
    if state.ck_send is None:
        raise RatchetError("sending chain is not initialized")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")

    next_chain, message_key_seed = kdf_ck(state.ck_send)
    keys = expand_message_key(message_key_seed)

    header = dict(extra_header or {})
    header["dh"] = b64e(state.dh_self_pub)
    header["pn"] = state.pn
    header["n"] = state.n_send
    ad = header_ad(header)

    ciphertext, mac = encrypt_aead(
        keys.aes_key, keys.mac_key, keys.iv, plaintext, ad
    )

    # Commit only after encryption succeeded.
    state.ck_send = next_chain
    state.n_send += 1
    return header, keys.iv, ciphertext, mac


def decrypt(
    state: RatchetState,
    header: dict,
    iv: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> bytes:
    """Authenticate and decrypt one message, committing state only on success."""
    validate_header(header)
    working = copy.deepcopy(state)
    plaintext = _decrypt_inner(working, header, iv, ciphertext, mac)
    state.__dict__.update(working.__dict__)
    return plaintext


def _decrypt_inner(
    state: RatchetState,
    header: dict,
    iv: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> bytes:
    dh_raw = b64d(header["dh"])
    n = header["n"]
    pn = header["pn"]

    # A message from an older chain may still be decryptable with a cached
    # skipped key.  Check that before considering a DH ratchet.
    cached_key = _skipped_key(dh_raw, n)
    if cached_key in state.skipped:
        message_key_seed = state.skipped.pop(cached_key)
        return _open(state, message_key_seed, header, iv, ciphertext, mac)

    if state.dh_peer_pub is None or dh_raw != state.dh_peer_pub:
        _skip_message_keys(state, pn)
        _dhratchet(state, dh_raw)

    message_key_seed = _next_message_key(state, n)
    return _open(state, message_key_seed, header, iv, ciphertext, mac)


def _open(
    state: RatchetState,
    message_key_seed: bytes,
    header: dict,
    iv: bytes,
    ciphertext: bytes,
    mac: bytes,
) -> bytes:
    keys: MessageKeys = expand_message_key(message_key_seed)
    return decrypt_aead(
        keys.aes_key,
        keys.mac_key,
        iv,
        ciphertext,
        mac,
        header_ad(header),
    )


def _skipped_key(dh_public: bytes | None, n: int) -> str:
    if dh_public is None:
        raise RatchetError("no peer ratchet key")
    return f"{b64e(dh_public)}:{n}"


def _skip_message_keys(state: RatchetState, until: int) -> None:
    """Advance the receiving chain to ``until``, caching the skipped keys."""
    if until < state.n_recv:
        return
    gap = until - state.n_recv
    if gap > MAX_SKIP:
        raise RatchetError(f"message gap of {gap} exceeds MAX_SKIP={MAX_SKIP}")
    if len(state.skipped) + gap > MAX_SKIP:
        raise RatchetError("too many skipped message keys")
    if state.ck_recv is None:
        if gap:
            raise RatchetError("no receiving chain to skip")
        return
    while state.n_recv < until:
        state.ck_recv, message_key_seed = kdf_ck(state.ck_recv)
        state.skipped[_skipped_key(state.dh_peer_pub, state.n_recv)] = (
            message_key_seed
        )
        state.n_recv += 1


def _next_message_key(state: RatchetState, n: int) -> bytes:
    if n < state.n_recv:
        raise ReplayError(
            f"message {n} is older than the receiving counter {state.n_recv}"
        )
    _skip_message_keys(state, n)
    if state.ck_recv is None:
        raise RatchetError("receiving chain is not initialized")
    state.ck_recv, message_key_seed = kdf_ck(state.ck_recv)
    state.n_recv += 1
    return message_key_seed


def _dhratchet(state: RatchetState, peer_ratchet_public: bytes) -> None:
    state.pn = state.n_send
    state.n_send = 0
    state.n_recv = 0
    state.dh_peer_pub = peer_ratchet_public

    state.root_key, state.ck_recv = kdf_rk(
        state.root_key, dh(state.dh_self_priv, peer_ratchet_public)
    )
    state.dh_self_priv, state.dh_self_pub = generate_x25519_keypair()
    state.root_key, state.ck_send = kdf_rk(
        state.root_key, dh(state.dh_self_priv, peer_ratchet_public)
    )
