# Architecture

## Layered design

KeyTrace is built as a one-way pipeline. Each layer has a single responsibility and a narrow interface, which makes the security properties of the whole tool reducible to the properties of each layer.

```
  capture  →  analytics  →  redaction  →  integrity  →  storage
```

### 1. Capture layer (`keytrace/core/capture.py`)

A `pynput.keyboard.Listener` runs in its own thread. Every press and release is wrapped in a `KeyEvent` dataclass with:

- `ts_ns` — `time.monotonic_ns()`, which is robust against wall-clock shifts (NTP, suspend/resume). This is the timestamp we use for dynamics math.
- `wall_iso` — a separate ISO-8601 timestamp for human eyeballs.
- `window_title`, `window_process` — enriched via the active-window module.
- `kind` — `"press"` or `"release"` (we capture both, which is what makes dwell-time analysis possible).

A second listener — `GlobalHotKeys` — owns the F9 toggle, so a paused state never silently swallows a hotkey.

### 2. Analytics layer (`keytrace/analytics/`)

- `dynamics.py` maintains a rolling window of dwell and flight times and exposes a `snapshot()` returning the mean dwell, mean flight, and rhythm σ. The window size is 50 events by default — long enough to smooth noise, short enough that a sudden shift (intruder takes over) shows up within a few seconds.
- `anomaly.py` consumes snapshots and a trained `Baseline` and produces an `AnomalyReport` via z-score. We avoid heavyweight ML on purpose: the baseline + z-score paradigm is what the simplest UEBA products actually ship, and it composes well with the rest of the pipeline.

### 3. Redaction layer (`keytrace/core/redaction.py`)

Runs over reassembled key buffers (at analysis time, not per-keystroke — single-character redaction is meaningless for credit-card detection). Patterns covered: CC (Luhn-validated), SSN, Indian PAN, Aadhaar, JWTs, AWS access keys, generic hex tokens, and email addresses (domain preserved for triage).

The output is a `RedactionReport` carrying both the redacted text and the per-category counts, which is what shows up in the `analyze` subcommand output.

### 4. Integrity layer (`keytrace/core/integrity.py`)

Each session opens with a per-session HMAC key (`secrets.token_bytes(32)`) and a 16-byte salt. The genesis HMAC binds the chain to that salt. Every entry includes:

- `prev_hmac` — the HMAC of the previous entry.
- `hmac` — `HMAC(K, canonical_json(entry_without_hmac))`.

Canonical JSON is critical here — Python's default `json.dumps` is not deterministic across platforms because dict ordering is implementation-defined. We force `sort_keys=True` and a minimal separator.

The `verify` subcommand replays the chain and exits non-zero on the first mismatch, reporting the broken index. This is the same model used by Certificate Transparency: any silent edit, insertion, or deletion is detectable, even though we don't prevent it.

### 5. Storage layer (`keytrace/core/crypto.py`)

AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`. Key derivation is PBKDF2-HMAC-SHA256 at 600,000 iterations (OWASP 2023 baseline). The file format is self-describing:

```
| MAGIC ("KTRC") | VERSION (0x01) | SALT (16B) | NONCE (12B) | CIPHERTEXT || TAG (16B) |
   4B               1B               16B          12B           N+16B
```

The header bytes (magic||version||salt||nonce) are passed as AAD. That means an attacker who swaps the salt or nonce to try a confused-deputy attack will get a tag mismatch on decryption.

The HMAC key for the integrity chain is included in the encrypted session header (`hmac_key_hex`). In a production scenario, you'd want this key sealed under a separate KMS — the current arrangement assumes a single-trust-domain operator and prioritizes verifiability of legacy logs.

## Threading model

Three threads run concurrently during capture:

1. **Main thread** — the CLI loop. Sleeps in 500ms increments, prints a status line every 5s, handles SIGINT.
2. **Capture listener** — pynput's own thread, calling `_on_press`/`_on_release` on every event.
3. **Hotkey listener** — pynput's `GlobalHotKeys`, listening for F9 and flipping the engine's `enabled` flag.

The `SessionWriter` is protected by a `threading.Lock` because both capture-thread `write_event` calls and main-thread rotation/close calls touch the buffer.

## Cross-platform notes

Active-window detection has three backends:

- Windows: `user32.GetForegroundWindow` + `psapi.GetModuleBaseNameW` via ctypes — no external deps.
- macOS: `Quartz.CGWindowListCopyWindowInfo` from `pyobjc-framework-Quartz`.
- Linux: shells out to `xdotool` then reads `/proc/<pid>/comm`. Wayland is intentionally not supported; this is a teaching moment about how Wayland's security model breaks legacy keylogger assumptions (no global keyboard hook outside the compositor).

All three backends return `{"title": "unknown", "process": "unknown"}` on failure rather than crashing the capture loop — the philosophy is that telemetry should degrade gracefully, never silently lose events.
