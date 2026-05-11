"""Tests for the HMAC chain."""
import secrets

from keytrace.core.integrity import chain_entry, genesis, verify_chain


def _build_chain(n: int):
    salt = secrets.token_bytes(16)
    key = secrets.token_bytes(32)
    prev = genesis(salt, key)
    entries = []
    for i in range(n):
        e = chain_entry({"i": i, "data": f"event-{i}"}, prev, key)
        prev = e["hmac"]
        entries.append(e)
    return salt, key, entries


def test_intact_chain_verifies():
    salt, key, entries = _build_chain(20)
    ok, idx = verify_chain(entries, salt, key)
    assert ok and idx == -1


def test_modified_entry_breaks_chain():
    salt, key, entries = _build_chain(10)
    # Silently mutate entry 5's data
    entries[5]["data"] = "tampered"
    ok, idx = verify_chain(entries, salt, key)
    assert not ok
    assert idx == 5


def test_deleted_entry_breaks_chain():
    salt, key, entries = _build_chain(10)
    del entries[3]
    ok, idx = verify_chain(entries, salt, key)
    assert not ok
    assert idx == 3


def test_inserted_entry_breaks_chain():
    salt, key, entries = _build_chain(10)
    fake = dict(entries[2])
    fake["data"] = "injected"
    entries.insert(2, fake)
    ok, idx = verify_chain(entries, salt, key)
    assert not ok
