import json

import pytest
import requests

from signallite.account import Account
from signallite.client import Client
from signallite.crypto import AuthenticationError
from signallite.encoding import b64d, b64e


def test_chat_round_trip(client_factory):
    alice = client_factory("alice")
    bob = client_factory("bob")

    alice.send("bob", "hello bob")
    assert bob.receive_all() == [("alice", "hello bob")]

    bob.send("alice", "hello alice")
    assert alice.receive_all() == [("bob", "hello alice")]


def test_relay_only_sees_ciphertext(client_factory, relay):
    alice = client_factory("alice")
    client_factory("bob")

    alice.send("bob", "the launch code is 0000")
    state = requests.get(f"{relay}/debug/state", timeout=5).json()
    blob = json.dumps(state)

    assert "the launch code is 0000" not in blob
    inbox = state["inboxes"]["bob"]
    assert len(inbox) == 1
    payload = inbox[0]["payload"]
    assert {"header", "iv", "ct", "mac"} <= set(payload)
    assert b"the launch code is 0000" not in b64d(payload["ct"])


def test_one_time_prekeys_are_consumed(client_factory):
    alice = client_factory("alice")
    client_factory("bob")

    ids = [alice.fetch_bundle("bob").one_time_prekey_id for _ in range(5)]
    assert len(ids) == 5
    assert len(set(ids)) == 5
    assert alice.fetch_bundle("bob").one_time_prekey_id is None


def test_tampered_ciphertext_is_rejected(client_factory, relay):
    alice = client_factory("alice")
    bob = client_factory("bob")

    alice.send("bob", "hello")
    inbox = requests.get(f"{relay}/inbox/bob", timeout=5).json()["messages"]
    envelope = inbox[0]
    payload = envelope["payload"]
    raw = bytearray(b64d(payload["ct"]))
    raw[0] ^= 1
    payload["ct"] = b64e(bytes(raw))

    with pytest.raises(AuthenticationError):
        bob.receive_envelope(envelope)

    # The bogus envelope must not desynchronise the session.
    alice.send("bob", "second message")
    assert bob.receive_all() == [("alice", "second message")]


def test_identity_change_emits_a_warning(client_factory):
    alice = client_factory("alice")
    bob = client_factory("bob")

    alice.send("bob", "hello")
    assert bob.receive_all() == [("alice", "hello")]
    bob.send("alice", "hi")
    assert alice.receive_all() == [("bob", "hi")]

    # Simulate a reinstall: a fresh identity under the same user name.
    bob2 = client_factory("bob")
    bob2.send("alice", "new phone, who dis")
    assert alice.receive_all() == [("bob", "new phone, who dis")]
    events = alice.drain_events()
    assert any(event[0] == "identity_changed" for event in events)

    # Alice's session was reset to the new identity and keeps working.
    alice.send("bob", "welcome back")
    assert bob2.receive_all() == [("alice", "welcome back")]


def test_safety_numbers_match(client_factory):
    alice = client_factory("alice")
    bob = client_factory("bob")
    assert alice.safety_number("bob") == bob.safety_number("alice")


def test_session_state_survives_restart(client_factory, tmp_path):
    alice = client_factory("alice")
    bob = client_factory("bob")

    alice.send("bob", "before restart")
    assert bob.receive_all() == [("alice", "before restart")]
    alice.save()

    restored = Client(
        Account.load(tmp_path / "alice.json"),
        alice.server_url,
        tmp_path / "alice.json",
    )
    restored.send("bob", "after restart")
    assert bob.receive_all() == [("alice", "after restart")]
