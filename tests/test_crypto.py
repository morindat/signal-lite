import pytest

from signallite.crypto import (
    AuthenticationError,
    SignatureError,
    decrypt_aead,
    dh,
    encrypt_aead,
    expand_message_key,
    generate_ed25519_keypair,
    generate_x25519_keypair,
    kdf_ck,
    sign,
    verify,
)


def test_x25519_agreement_is_symmetric():
    alice_priv, alice_pub = generate_x25519_keypair()
    bob_priv, bob_pub = generate_x25519_keypair()
    assert dh(alice_priv, bob_pub) == dh(bob_priv, alice_pub)


def test_ed25519_sign_and_verify():
    private, public = generate_ed25519_keypair()
    signature = sign(private, b"hello")
    verify(public, signature, b"hello")
    with pytest.raises(SignatureError):
        verify(public, signature, b"hello!")


def test_aead_roundtrip_and_tamper():
    aes_key = b"\x11" * 32
    mac_key = b"\x22" * 32
    iv = b"\x33" * 16
    associated_data = b'{"n":0}'

    ciphertext, tag = encrypt_aead(
        aes_key, mac_key, iv, b"top secret", associated_data
    )
    assert (
        decrypt_aead(
            aes_key, mac_key, iv, ciphertext, tag, associated_data
        )
        == b"top secret"
    )

    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    with pytest.raises(AuthenticationError):
        decrypt_aead(
            aes_key, mac_key, iv, tampered, tag, associated_data
        )

    with pytest.raises(AuthenticationError):
        decrypt_aead(
            aes_key, mac_key, iv, ciphertext, tag, b'{"n":1}'
        )


def test_chain_ratchet_is_one_way():
    chain_key = b"\x44" * 32
    next_chain, message_seed = kdf_ck(chain_key)
    assert next_chain != chain_key
    assert message_seed != chain_key
    assert len(next_chain) == 32
    assert len(message_seed) == 32


def test_message_key_expansion_is_80_bytes():
    keys = expand_message_key(b"\x55" * 32)
    assert len(keys.aes_key) == 32
    assert len(keys.mac_key) == 32
    assert len(keys.iv) == 16
