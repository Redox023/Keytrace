"""Command-line interface.

Subcommands:
    run      — start the capture pipeline (requires signed CONSENT.md)
    decrypt  — decrypt a session log to plaintext JSONL
    verify   — verify the HMAC chain of a session log
    analyze  — print keystroke-dynamics summary for a session
    detect   — emit YARA rule artifact details for a given log
"""
from __future__ import annotations

import argparse
import getpass
import io
import json
import os
import secrets
import signal
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import __version__, config as cfgmod
from .analytics.anomaly import Baseline, score, train_baseline
from .analytics.dynamics import DynamicsExtractor, DynamicsSnapshot
from .core.capture import CaptureEngine, KeyEvent
from .core.crypto import decrypt, encrypt
from .core.integrity import chain_entry, genesis, verify_chain
from .core.redaction import redact
from .ethics.consent import ConsentError, check as consent_check


# ---------------------------------------------------------------------------
# Session writer — buffers events, runs the chain, encrypts on rotation/stop.
# ---------------------------------------------------------------------------

class SessionWriter:
    def __init__(self, cfg, passphrase: str, log_dir: Path) -> None:
        self._cfg = cfg
        self._passphrase = passphrase
        self._log_dir = log_dir
        self._log_dir.mkdir(parents=True, exist_ok=True)
        # HMAC chain key: derived from passphrase via separate label so it's
        # NOT the same as the AES key. Keep it simple: HKDF would be nicer.
        self._hmac_key = secrets.token_bytes(32)   # ephemeral per session
        self._session_salt = secrets.token_bytes(16)
        self._prev_hmac = genesis(self._session_salt, self._hmac_key)
        self._buffer = io.StringIO()
        self._lock = threading.Lock()
        self._current_path = self._new_path()
        # Header line records the salt and hmac_key (hex). Without this, the
        # chain can't be verified after decryption. In production you'd seal
        # the hmac_key under a separate KMS — out of scope here.
        header = {
            "type": "session_header",
            "ts": datetime.now(timezone.utc).isoformat(),
            "session_salt_hex": self._session_salt.hex(),
            "hmac_key_hex": self._hmac_key.hex(),
            "version": __version__,
        }
        self._buffer.write(json.dumps(header) + "\n")

    def _new_path(self) -> Path:
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S")
        return self._log_dir / f"{self._cfg.log_file_prefix}-{stamp}.kt.enc"

    def write_event(self, ev: KeyEvent) -> None:
        d = ev.to_dict()
        # Redaction is applied to the `key` field so we don't capture, say,
        # a credit card typed one digit at a time? Hard to detect at single
        # char granularity — redaction has its real teeth in the analyze
        # pipeline below where we reassemble strings per window.
        chained = chain_entry(d, self._prev_hmac, self._hmac_key)
        self._prev_hmac = chained["hmac"]
        with self._lock:
            self._buffer.write(json.dumps(chained) + "\n")
            if self._buffer.tell() >= self._cfg.max_log_bytes:
                self._rotate_locked()

    def _rotate_locked(self) -> None:
        # Encrypt current buffer and write atomically.
        plaintext = self._buffer.getvalue().encode("utf-8")
        blob = encrypt(plaintext, self._passphrase, iterations=self._cfg.pbkdf2_iterations)
        tmp = self._current_path.with_suffix(self._current_path.suffix + ".tmp")
        tmp.write_bytes(blob)
        tmp.replace(self._current_path)
        # Reset buffer for next chunk; chain continues across rotation
        self._buffer = io.StringIO()
        self._current_path = self._new_path()

    def close(self) -> Path:
        with self._lock:
            if self._buffer.tell() > 0:
                self._rotate_locked()
        return self._current_path


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _get_passphrase(cfg) -> str:
    pp = os.environ.get(cfg.passphrase_env)
    if not pp:
        pp = getpass.getpass(
            f"Passphrase (or set ${cfg.passphrase_env}): "
        )
    if len(pp) < 8:
        sys.exit("passphrase must be >= 8 characters")
    return pp


def cmd_run(args) -> None:
    cfg = cfgmod.load()
    try:
        consent_check(cfg)
    except ConsentError as e:
        sys.exit(str(e))

    passphrase = _get_passphrase(cfg)
    writer = SessionWriter(cfg, passphrase, cfg.log_dir)
    extractor = DynamicsExtractor(window=cfg.dynamics_window)
    baseline = None
    if args.baseline and Path(args.baseline).is_file():
        baseline = Baseline.load(Path(args.baseline))

    def handle(ev: KeyEvent) -> None:
        writer.write_event(ev)
        extractor.feed(ev.to_dict())

    engine = CaptureEngine(cfg, on_event=handle)

    print(f"KeyTrace {__version__} started. Toggle: {cfg.toggle_key.upper()}.  Ctrl+C to stop.")
    print(f"Logs -> {cfg.log_dir.resolve()}")

    stop_evt = threading.Event()

    def on_sigint(*_):
        stop_evt.set()
        engine.stop()

    signal.signal(signal.SIGINT, on_sigint)

    engine.start()
    last_snap = 0.0
    try:
        while not stop_evt.is_set():
            time.sleep(0.5)
            now = time.time()
            if now - last_snap >= 5.0:
                snap = extractor.snapshot()
                status = "ON " if engine.enabled else "OFF"
                line = (
                    f"[{status}] keys={snap.n_keys:4d}  "
                    f"dwell={snap.mean_dwell_ms:6.1f}ms  "
                    f"flight={snap.mean_flight_ms:6.1f}ms  "
                    f"sd={snap.rhythm_sigma_ms:5.1f}ms"
                )
                if baseline:
                    rep = score(snap.to_dict(), baseline, z_threshold=cfg.anomaly_z_threshold)
                    if rep.is_anomalous:
                        line += "  [!] ANOMALY: " + ", ".join(rep.reasons)
                print(line)
                last_snap = now
    finally:
        engine.stop()
        path = writer.close()
        print(f"\nFlushed encrypted log -> {path}")


def _iter_events(blob: bytes, passphrase: str, cfg) -> Iterable[dict]:
    plaintext = decrypt(blob, passphrase, iterations=cfg.pbkdf2_iterations)
    for line in plaintext.decode("utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def cmd_decrypt(args) -> None:
    cfg = cfgmod.load()
    passphrase = _get_passphrase(cfg)
    blob = Path(args.log).read_bytes()
    plaintext = decrypt(blob, passphrase, iterations=cfg.pbkdf2_iterations)
    sys.stdout.write(plaintext.decode("utf-8"))


def cmd_verify(args) -> None:
    cfg = cfgmod.load()
    passphrase = _get_passphrase(cfg)
    blob = Path(args.log).read_bytes()
    entries = list(_iter_events(blob, passphrase, cfg))
    if not entries or entries[0].get("type") != "session_header":
        sys.exit("malformed log: missing session header")
    header = entries[0]
    body = entries[1:]
    salt = bytes.fromhex(header["session_salt_hex"])
    key = bytes.fromhex(header["hmac_key_hex"])
    ok, idx = verify_chain(body, salt, key)
    if ok:
        print(f"OK -- chain verified across {len(body)} entries")
        sys.exit(0)
    print(f"FAIL -- chain broken at entry index {idx}", file=sys.stderr)
    sys.exit(2)


def cmd_analyze(args) -> None:
    cfg = cfgmod.load()
    passphrase = _get_passphrase(cfg)
    blob = Path(args.log).read_bytes()
    entries = list(_iter_events(blob, passphrase, cfg))
    body = [e for e in entries if e.get("kind") in ("press", "release")]
    snap = DynamicsExtractor.from_events(body)
    # Reassemble typed strings per window for redaction reporting
    typed = "".join(e["key"] for e in body if e["kind"] == "press" and len(e["key"]) == 1)
    rep = redact(typed)
    out = {
        "n_events": len(body),
        "dynamics": snap.to_dict(),
        "redactions": rep.counts,
        "redacted_excerpt": rep.text[:200] + ("..." if len(rep.text) > 200 else ""),
    }
    print(json.dumps(out, indent=2))


def cmd_detect(args) -> None:
    """Print the YARA + Sigma artifacts paths and a one-line summary."""
    root = Path(__file__).resolve().parent.parent
    yara = root / "detection" / "keytrace.yar"
    sigma = root / "detection" / "keytrace.sigma.yml"
    print(json.dumps({
        "yara_rule": str(yara),
        "sigma_rule": str(sigma),
        "summary": "Run `yara detection/keytrace.yar logs/` to scan.",
    }, indent=2))


# ---------------------------------------------------------------------------
# argparse
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="keytrace", description="Keystroke telemetry & analytics (educational).")
    p.add_argument("--version", action="version", version=f"keytrace {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="start capture (requires CONSENT.md)")
    p_run.add_argument("--baseline", help="path to a trained baseline JSON for live anomaly scoring")
    p_run.set_defaults(func=cmd_run)

    p_dec = sub.add_parser("decrypt", help="decrypt a session log to stdout")
    p_dec.add_argument("log")
    p_dec.set_defaults(func=cmd_decrypt)

    p_ver = sub.add_parser("verify", help="verify HMAC chain of a session log")
    p_ver.add_argument("log")
    p_ver.set_defaults(func=cmd_verify)

    p_an = sub.add_parser("analyze", help="summarize dynamics + redactions for a log")
    p_an.add_argument("log")
    p_an.set_defaults(func=cmd_analyze)

    p_det = sub.add_parser("detect", help="print shipped detection rule paths")
    p_det.set_defaults(func=cmd_detect)

    return p


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
