import copy

import pytest

from signallite.crypto import AuthenticationError, generate_x25519_keypair
from signallite.ratchet import (
    RatchetState,
    ReplayError,
    decrypt,
    encrypt,
    initiator_init,
    responder_init,
)


def new_pair():
    root_key = b"\x42" * 32
    spk_private, spk_public = generate_x25519_keypair()
    alice = initiator_init(root_key, spk_public)
    bob = responder_init(root_key, spk_private, spk_public)
    return alice, bob


def send(state, text, sender, message_type="message"):
    header, iv, ciphertext, mac = encrypt(
        state, text.encode(), {"type": message_type, "sender": sender}
    )
    return header, iv, ciphertext, mac


def receive(state, envelope):
    header, iv, ciphertext, mac = envelope
    return decrypt(state, header, iv, ciphertext, mac)


def test_first_message_and_reply():
    alice, bob = new_pair()
    first = send(alice, "hello bob", "alice", "prekey")
    assert receive(bob, first) == b"hello bob"

    reply = send(bob, "hello alice", "bob")
    assert receive(alice, reply) == b"hello alice"


def test_multiple_round_trips():
    alice, bob = new_pair()
    for index in range(5):
        message = send(alice, f"alice {index}", "alice", "prekey" if index == 0 else "message")
        assert receive(bob, message) == f"alice {index}".encode()
        message = send(bob, f"bob {index}", "bob")
        assert receive(alice, message) == f"bob {index}".encode()


def test_out_of_order_within_one_chain():
    alice, bob = new_pair()
    messages = [send(alice, f"m{index}", "alice", "prekey" if index == 0 else "message") for index in range(3)]
    assert receive(bob, messages[2]) == b"m2"
    assert receive(bob, messages[0]) == b"m0"
    assert receive(bob, messages[1]) == b"m1"


def test_out_of_order_across_a_ratchet_step():
    alice, bob = new_pair()

    m0 = send(alice, "m0", "alice", "prekey")
    m1 = send(alice, "m1", "alice")
    assert receive(bob, m0) == b"m0"

    r0 = send(bob, "r0", "bob")
    assert receive(alice, r0) == b"r0"

    # Alice's new chain.  Bob receives m2 first, which must cache m1.
    m2 = send(alice, "m2", "alice")
    assert receive(bob, m2) == b"m2"
    assert receive(bob, m1) == b"m1"


def test_tampered_ciphertext_is_rejected_and_state_survives():
    alice, bob = new_pair()
    header, iv, ciphertext, mac = send(alice, "hello", "alice", "prekey")
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]

    with pytest.raises(AuthenticationError):
        decrypt(bob, header, iv, tampered, mac)

    # The failed attempt must not advance Bob's ratchet.
    assert decrypt(bob, header, iv, ciphertext, mac) == b"hello"


def test_tampered_header_is_rejected():
    alice, bob = new_pair()
    header, iv, ciphertext, mac = send(alice, "hello", "alice", "prekey")
    forged = copy.deepcopy(header)
    forged["type"] = "message"

    with pytest.raises(AuthenticationError):
        decrypt(bob, forged, iv, ciphertext, mac)


def test_replay_is_rejected():
    alice, bob = new_pair()
    envelope = send(alice, "hello", "alice", "prekey")
    assert receive(bob, envelope) == b"hello"
    with pytest.raises(ReplayError):
        receive(bob, envelope)


def test_state_serialisation_round_trip():
    alice, bob = new_pair()
    first = send(alice, "hello", "alice", "prekey")
    assert receive(bob, first) == b"hello"

    reloaded = RatchetState.from_dict(bob.to_dict())
    second = send(alice, "again", "alice")
    assert receive(reloaded, second) == b"again"


def test_old_chain_message_without_cached_key_is_rejected():
    alice, bob = new_pair()
    m0 = send(alice, "m0", "alice", "prekey")
    m1 = send(alice, "m1", "alice")
    assert receive(bob, m1) == b"m1"

    # m0 was skipped, so it is still decryptable exactly once.
    assert receive(bob, m0) == b"m0"
    with pytest.raises(ReplayError):
        receive(bob, m0)
