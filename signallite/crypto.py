"""Cryptographic primitives for signal-lite.

The design is deliberately boring:

* X25519 for Diffie-Hellman
* Ed25519 for signatures
* HKDF-SHA256 for key derivation
* AES-256-CBC + HMAC-SHA256, encrypt-then-MAC, for message protection

No primitives are implemented from scratch; this module wires together
well-reviewed implementations from ``cryptography``.
"""

from __future__ import annotations

import hashlib
import hmac as std_hmac
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Domain-separation labels. Changing any of these breaks compatibility with
# previously stored sessions, so they carry a version suffix.
INFO_X3DH = b"signal-lite/x3dh/v1"
INFO_RATCHET = b"signal-lite/ratchet/v1"
INFO_MESSAGE_KEY = b"signal-lite/message-key/v1"
INFO_IDENTITY_BINDING = b"signal-lite/identity-binding/v1"
INFO_SIGNED_PREKEY = b"signal-lite/signed-prekey/v1"
INFO_SAFETY_NUMBER = b"signal-lite/safety-number/v1"
INFO_IDENTITY_FINGERPRINT = b"signal-lite/identity-fingerprint/v1"

ZERO32 = b"\x00" * 32

KEY_LEN = 32
IV_LEN = 16
MAC_LEN = 32


class CryptoError(Exception):
    """Base class for cryptographic failures."""


class SignatureError(CryptoError):
    """A signature or public-key binding failed verification."""


class AuthenticationError(CryptoError):
    """A message MAC failed verification."""


class DecryptionError(CryptoError):
    """An authenticated ciphertext could not be decrypted or unpadded."""


# ---------------------------------------------------------------------------
# Key generation and raw-key helpers
# ---------------------------------------------------------------------------


def generate_x25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_raw, public_raw) for a fresh X25519 key pair."""
    private = X25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def x25519_public_from_private(private_raw: bytes) -> bytes:
    private = X25519PrivateKey.from_private_bytes(private_raw)
    return private.public_key().public_bytes_raw()


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Return (private_raw, public_raw) for a fresh Ed25519 key pair."""
    private = Ed25519PrivateKey.generate()
    return private.private_bytes_raw(), private.public_key().public_bytes_raw()


def ed25519_public_from_private(private_raw: bytes) -> bytes:
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    return private.public_key().public_bytes_raw()


def dh(private_raw: bytes, peer_public_raw: bytes) -> bytes:
    """X25519 Diffie-Hellman shared secret."""
    if len(private_raw) != KEY_LEN:
        raise CryptoError("X25519 private key must be 32 bytes")
    if len(peer_public_raw) != KEY_LEN:
        raise CryptoError("X25519 public key must be 32 bytes")
    try:
        private = X25519PrivateKey.from_private_bytes(private_raw)
        peer = X25519PublicKey.from_public_bytes(peer_public_raw)
        return private.exchange(peer)
    except ValueError as exc:
        # Raised for low-order / all-zero peer keys, among other invalid input.
        raise CryptoError(f"X25519 exchange failed: {exc}") from exc


def sign(private_raw: bytes, data: bytes) -> bytes:
    if len(private_raw) != KEY_LEN:
        raise CryptoError("Ed25519 private key must be 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(private_raw).sign(data)


def verify(public_raw: bytes, signature: bytes, data: bytes) -> None:
    """Verify an Ed25519 signature, raising SignatureError on failure."""
    if len(public_raw) != KEY_LEN:
        raise SignatureError("Ed25519 public key must be 32 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(public_raw).verify(signature, data)
    except (InvalidSignature, ValueError) as exc:
        raise SignatureError("signature verification failed") from exc


# ---------------------------------------------------------------------------
# KDFs
# ---------------------------------------------------------------------------


def hkdf(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    if length <= 0:
        raise ValueError("HKDF length must be positive")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return std_hmac.new(key, data, hashlib.sha256).digest()


def kdf_rk(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """Root-key ratchet step: returns (new_root_key, new_chain_key)."""
    if len(root_key) != KEY_LEN:
        raise CryptoError("root key must be 32 bytes")
    out = hkdf(dh_output, salt=root_key, info=INFO_RATCHET, length=64)
    return out[:32], out[32:]


def kdf_ck(chain_key: bytes) -> tuple[bytes, bytes]:
    """Chain-key ratchet step: returns (next_chain_key, message_key_seed)."""
    if len(chain_key) != KEY_LEN:
        raise CryptoError("chain key must be 32 bytes")
    message_key_seed = hmac_sha256(chain_key, b"\x01")
    next_chain_key = hmac_sha256(chain_key, b"\x02")
    return next_chain_key, message_key_seed


@dataclass(frozen=True)
class MessageKeys:
    aes_key: bytes
    mac_key: bytes
    iv: bytes


def expand_message_key(message_key_seed: bytes) -> MessageKeys:
    """Expand a 32-byte seed into the 80-byte Signal-style message key material.

    The Messenger whitepaper describes an 80-byte message key (32-byte AES key,
    32-byte HMAC key, 16-byte IV) but also gives a 32-byte HMAC formula.  The
    reference implementation expands the seed with HKDF; so do we.
    """
    if len(message_key_seed) != KEY_LEN:
        raise CryptoError("message key seed must be 32 bytes")
    material = hkdf(
        message_key_seed,
        salt=ZERO32,
        info=INFO_MESSAGE_KEY,
        length=KEY_LEN + MAC_LEN + IV_LEN,
    )
    return MessageKeys(
        aes_key=material[:32],
        mac_key=material[32:64],
        iv=material[64:80],
    )


# ---------------------------------------------------------------------------
# AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)
# ---------------------------------------------------------------------------


def encrypt_aead(
    aes_key: bytes,
    mac_key: bytes,
    iv: bytes,
    plaintext: bytes,
    associated_data: bytes,
) -> tuple[bytes, bytes]:
    """Encrypt with AES-256-CBC/PKCS7 and authenticate header || IV || ciphertext."""
    if len(aes_key) != KEY_LEN:
        raise ValueError("AES key must be 32 bytes")
    if len(mac_key) != MAC_LEN:
        raise ValueError("MAC key must be 32 bytes")
    if len(iv) != IV_LEN:
        raise ValueError("IV must be 16 bytes")

    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    tag = hmac_sha256(mac_key, associated_data + iv + ciphertext)
    return ciphertext, tag


def decrypt_aead(
    aes_key: bytes,
    mac_key: bytes,
    iv: bytes,
    ciphertext: bytes,
    tag: bytes,
    associated_data: bytes,
) -> bytes:
    """Verify first, then decrypt.  Never processes unauthenticated ciphertext."""
    if len(aes_key) != KEY_LEN:
        raise ValueError("AES key must be 32 bytes")
    if len(mac_key) != MAC_LEN:
        raise ValueError("MAC key must be 32 bytes")
    if len(iv) != IV_LEN:
        raise ValueError("IV must be 16 bytes")
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise DecryptionError("ciphertext length is not a positive multiple of 16")

    expected = hmac_sha256(mac_key, associated_data + iv + ciphertext)
    if not std_hmac.compare_digest(expected, tag):
        raise AuthenticationError("message authentication failed")

    try:
        decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()
    except ValueError as exc:
        raise DecryptionError("invalid ciphertext padding") from exc
