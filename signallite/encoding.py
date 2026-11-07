"""Base64 and canonical-JSON helpers used on the wire."""

from __future__ import annotations

import base64
import json


def b64e(raw: bytes) -> str:
    """Encode bytes as standard base64 text."""
    return base64.b64encode(raw).decode("ascii")


def b64d(text: str) -> bytes:
    """Decode standard base64 text, rejecting malformed input."""
    if not isinstance(text, str):
        raise TypeError("expected a base64 string")
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:  # binascii.Error, ValueError
        raise ValueError("invalid base64") from exc


def canonical_json(obj: object) -> bytes:
    """Deterministic JSON encoding used for associated data.

    The same header must produce byte-identical output on both ends, so keys
    are sorted, whitespace is removed, and non-ASCII is preserved.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
