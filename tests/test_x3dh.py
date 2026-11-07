import copy

import pytest

from signallite.account import Account
from signallite.crypto import generate_x25519_keypair
from signallite.encoding import b64d, b64e
from signallite.x3dh import (
    BundleError,
    PreKeyBundle,
    initiator_root_key,
    responder_root_key,
    verify_bundle,
)


def bundle_for(bob: Account, index: int | None = 0) -> PreKeyBundle:
    data = bob.bundle_dict()
    if index is not None:
        opk = data["one_time_prekeys"][index]
        data["one_time_prekey_id"] = opk["id"]
        data["one_time_prekey"] = opk["public"]
    return PreKeyBundle.from_dict(data)


def test_x3dh_root_keys_agree():
    alice = Account.create("alice", num_opks=0)
    bob = Account.create("bob", num_opks=3)
    bundle = bundle_for(bob)
    verify_bundle(bundle)

    ephemeral_priv, ephemeral_pub = generate_x25519_keypair()
    alice_root = initiator_root_key(alice.dh_priv, ephemeral_priv, bundle)

    opk_private = bob.opks[bundle.one_time_prekey_id]
    bob_root = responder_root_key(
        bob.dh_priv,
        bob.spk_priv,
        opk_private,
        alice.dh_pub,
        ephemeral_pub,
    )
    assert alice_root == bob_root
    assert len(alice_root) == 32


def test_x3dh_without_one_time_prekey():
    alice = Account.create("alice", num_opks=0)
    bob = Account.create("bob", num_opks=0)
    bundle = bundle_for(bob, index=None)
    verify_bundle(bundle)

    ephemeral_priv, ephemeral_pub = generate_x25519_keypair()
    alice_root = initiator_root_key(alice.dh_priv, ephemeral_priv, bundle)
    bob_root = responder_root_key(
        bob.dh_priv, bob.spk_priv, None, alice.dh_pub, ephemeral_pub
    )
    assert alice_root == bob_root


def test_tampered_signed_prekey_is_rejected():
    bob = Account.create("bob", num_opks=1)
    data = bob.bundle_dict()
    opk = data["one_time_prekeys"][0]
    data["one_time_prekey_id"] = opk["id"]
    data["one_time_prekey"] = opk["public"]

    tampered = copy.deepcopy(data)
    raw = bytearray(b64d(tampered["signed_prekey"]))
    raw[0] ^= 1
    tampered["signed_prekey"] = b64e(bytes(raw))

    with pytest.raises(BundleError):
        verify_bundle(PreKeyBundle.from_dict(tampered))


def test_tampered_identity_binding_is_rejected():
    bob = Account.create("bob", num_opks=0)
    data = bob.bundle_dict()
    tampered = copy.deepcopy(data)
    raw = bytearray(b64d(tampered["identity_dh_key"]))
    raw[0] ^= 1
    tampered["identity_dh_key"] = b64e(bytes(raw))

    with pytest.raises(BundleError):
        verify_bundle(PreKeyBundle.from_dict(tampered))
