"""Authenticated encryption for log files.

Design:
    file layout:   MAGIC(4) || VERSION(1) || SALT(16) || NONCE(12) || CT || TAG(16)
    cipher:        AES-256-GCM
    KDF:           PBKDF2-HMAC-SHA256, 600k iterations (OWASP 2023)
    nonce:         96-bit random per file (NIST SP 800-38D recommendation)
    AAD:           MAGIC || VERSION || SALT || NONCE  (binds header to ciphertext)

Why GCM and not CBC? CBC is unauthenticated; padding-oracle and bit-flipping
attacks are trivial on tampered ciphertext. GCM gives us confidentiality AND
integrity with a single primitive — which is exactly what a forensic log
needs.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"KTRC"                 # 4-byte magic
VERSION = b"\x01"               # 1-byte format version
HEADER_LEN = 4 + 1 + 16 + 12    # magic + ver + salt + nonce


@dataclass
class EncryptedBlob:
    salt: bytes
    nonce: bytes
    ciphertext: bytes           # includes 16-byte GCM tag at the end

    def serialize(self) -> bytes:
        return MAGIC + VERSION + self.salt + self.nonce + self.ciphertext

    @classmethod
    def parse(cls, raw: bytes) -> "EncryptedBlob":
        if len(raw) < HEADER_LEN:
            raise ValueError("blob too short")
        if raw[:4] != MAGIC:
            raise ValueError("bad magic; not a KeyTrace log")
        if raw[4:5] != VERSION:
            raise ValueError(f"unsupported version {raw[4]}")
        salt = raw[5:21]
        nonce = raw[21:33]
        ciphertext = raw[33:]
        return cls(salt=salt, nonce=nonce, ciphertext=ciphertext)


def derive_key(passphrase: str, salt: bytes, iterations: int = 600_000) -> bytes:
    """Derive a 32-byte AES key from a passphrase + salt via PBKDF2-HMAC-SHA256."""
    if not isinstance(passphrase, str) or len(passphrase) < 8:
        raise ValueError("passphrase must be >= 8 characters")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: bytes, passphrase: str, *, iterations: int = 600_000) -> bytes:
    """Encrypt plaintext, returning a self-describing blob."""
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive_key(passphrase, salt, iterations)
    try:
        aead = AESGCM(key)
        aad = MAGIC + VERSION + salt + nonce
        ct = aead.encrypt(nonce, plaintext, aad)
        return EncryptedBlob(salt=salt, nonce=nonce, ciphertext=ct).serialize()
    finally:
        # Best-effort key zeroization. Python strings/bytes are immutable so
        # this is mostly symbolic — for true zeroization you'd use a mlocked
        # ctypes buffer. We at least drop the reference promptly.
        del key


def decrypt(blob: bytes, passphrase: str, *, iterations: int = 600_000) -> bytes:
    """Inverse of encrypt(). Raises if magic/version/tag are wrong."""
    parsed = EncryptedBlob.parse(blob)
    key = derive_key(passphrase, parsed.salt, iterations)
    try:
        aead = AESGCM(key)
        aad = MAGIC + VERSION + parsed.salt + parsed.nonce
        return aead.decrypt(parsed.nonce, parsed.ciphertext, aad)
    finally:
        del key
