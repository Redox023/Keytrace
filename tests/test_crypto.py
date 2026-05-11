"""Tests for keytrace.core.crypto."""
import pytest

from keytrace.core.crypto import EncryptedBlob, MAGIC, decrypt, encrypt


def test_roundtrip_preserves_plaintext():
    pt = b"the quick brown fox jumps over the lazy dog"
    blob = encrypt(pt, "correct horse battery staple")
    out = decrypt(blob, "correct horse battery staple")
    assert out == pt


def test_blob_starts_with_magic():
    blob = encrypt(b"x", "passphrase!")
    assert blob[:4] == MAGIC


def test_wrong_passphrase_fails():
    blob = encrypt(b"secret", "passphrase-one")
    with pytest.raises(Exception):
        decrypt(blob, "passphrase-two")


def test_tampered_ciphertext_fails():
    blob = bytearray(encrypt(b"hello", "passphrase!"))
    # Flip a byte in the ciphertext region
    blob[40] ^= 0xFF
    with pytest.raises(Exception):
        decrypt(bytes(blob), "passphrase!")


def test_tampered_salt_fails_via_aad():
    blob = bytearray(encrypt(b"hello", "passphrase!"))
    # Salt sits at offset 5..21. AAD binds it.
    blob[10] ^= 0x01
    with pytest.raises(Exception):
        decrypt(bytes(blob), "passphrase!")


def test_short_passphrase_rejected():
    with pytest.raises(ValueError):
        encrypt(b"x", "short")
