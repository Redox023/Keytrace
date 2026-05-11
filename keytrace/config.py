"""Runtime configuration for KeyTrace.

Configuration is loaded from environment + sane defaults. Secrets (the
passphrase) are never read from disk; they must come from an env var or
interactive prompt at startup.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class Config:
    # Storage
    log_dir: Path = Path("logs")
    max_log_bytes: int = 5 * 1024 * 1024   # 5 MiB -> rotate
    log_file_prefix: str = "kt"

    # Crypto
    pbkdf2_iterations: int = 600_000        # OWASP 2023 recommendation
    pbkdf2_salt_bytes: int = 16
    aes_key_bytes: int = 32                 # AES-256
    gcm_nonce_bytes: int = 12               # 96-bit nonce per NIST SP 800-38D

    # Runtime
    toggle_key: str = "f9"
    flush_interval_seconds: float = 2.0

    # Analytics
    dynamics_window: int = 50               # rolling N keystrokes for stats
    anomaly_z_threshold: float = 3.0        # |z| > 3 flags an anomaly

    # Ethics
    consent_filename: str = "CONSENT.md"
    consent_required_phrase: str = "I am running KeyTrace exclusively on a system that I personally own"

    # Optional fields (sources, etc.)
    passphrase_env: str = "KEYTRACE_PASS"


def load() -> Config:
    """Build a Config, allowing a small set of env overrides."""
    cfg = Config()
    overrides = {}
    if v := os.environ.get("KEYTRACE_LOG_DIR"):
        overrides["log_dir"] = Path(v)
    if v := os.environ.get("KEYTRACE_MAX_LOG_BYTES"):
        overrides["max_log_bytes"] = int(v)
    if v := os.environ.get("KEYTRACE_TOGGLE_KEY"):
        overrides["toggle_key"] = v
    if not overrides:
        return cfg
    # dataclasses.replace would be cleaner; this keeps the frozen guarantee
    from dataclasses import replace
    return replace(cfg, **overrides)
