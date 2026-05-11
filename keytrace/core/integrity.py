"""Tamper-evident logging via an HMAC chain.

Each log entry carries `prev_hmac` (the HMAC of the previous entry). The first
entry's prev_hmac is the genesis value, derived from the session salt. Any
silent edit, insertion, or deletion of a past entry breaks every subsequent
HMAC and is detected by `verify_chain`.

This is the same idea that underpins certificate transparency logs, git, and
blockchains — applied here to a humble keystroke log.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from typing import Iterable

GENESIS_LABEL = b"keytrace-genesis-v1"


def genesis(session_salt: bytes, hmac_key: bytes) -> str:
    """Compute the genesis HMAC for a session, returned as hex."""
    return hmac.new(hmac_key, GENESIS_LABEL + session_salt, hashlib.sha256).hexdigest()


def chain_entry(entry: dict, prev_hmac_hex: str, hmac_key: bytes) -> dict:
    """Return a new entry dict with `prev_hmac` and `hmac` fields populated."""
    enriched = dict(entry)
    enriched["prev_hmac"] = prev_hmac_hex
    # Canonical serialization: sort keys, no extra whitespace. Critical for
    # reproducible HMAC computation across platforms.
    payload = json.dumps(enriched, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()
    enriched["hmac"] = digest
    return enriched


def verify_chain(entries: Iterable[dict], session_salt: bytes, hmac_key: bytes) -> tuple[bool, int]:
    """Verify the chain. Returns (ok, broken_index_or_-1)."""
    prev = genesis(session_salt, hmac_key)
    for i, entry in enumerate(entries):
        if entry.get("prev_hmac") != prev:
            return False, i
        # Recompute HMAC after stripping the stored hmac field
        body = {k: v for k, v in entry.items() if k != "hmac"}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(hmac_key, payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, entry.get("hmac", "")):
            return False, i
        prev = entry["hmac"]
    return True, -1
