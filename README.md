# KeyTrace

**Keystroke Telemetry & Behavioral Analytics Framework**

> An educational red-team tool built with blue-team instincts. Captures keystrokes, but every design decision — encryption at rest, tamper-evident logging, automatic PII redaction, behavioral biometrics, and shipped detection rules — is meant to teach how attackers think *and* how defenders catch them.

![Status](https://img.shields.io/badge/status-educational-yellow)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT--Educational-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey)

---

## ⚠️ Ethics Gate

KeyTrace will not run until you create a `CONSENT.md` file in the project root acknowledging that you own — or have explicit written authorization to monitor — the system on which it runs. Unauthorized keystroke capture is a felony in most jurisdictions (US: 18 U.S.C. § 2511; EU: GDPR Art. 5 & national wiretap statutes; IN: IT Act § 66E/72). The consent gate is implemented in `keytrace/ethics/consent.py` and cannot be silently bypassed.

---

## Why This Exists

Most "beginner keylogger" projects show that the author can call `pynput.Listener`. KeyTrace is built to demonstrate something different: that the author understands the *full security lifecycle* around a credential-stealing tool — from collection, to storage hygiene, to exfiltration, to detection engineering.

Every feature in this project maps to a real-world security competency:

| Feature | Skill Demonstrated |
|---|---|
| AES-256-GCM encryption at rest | Applied cryptography (authenticated encryption) |
| PBKDF2-HMAC-SHA256 key derivation | KDF selection, salting, iteration tuning |
| HMAC-chained log entries | Tamper-evident logging, forensic integrity |
| Keystroke-dynamics extraction (dwell/flight times) | Behavioral biometrics, continuous authentication |
| Statistical anomaly detection (z-score over baseline) | Lightweight UEBA, baseline modeling |
| Automatic redaction of CC/SSN/JWT/API-key patterns | DLP engineering, regex hardening |
| MITRE ATT&CK mapping | Threat-informed defense literacy |
| Shipped YARA + Sigma detection rules | Detection engineering, purple-team mindset |
| Consent-gated execution | Secure-by-default tooling, ethical disclosure |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CONSENT GATE                            │
│  (refuses to start without signed CONSENT.md in project root)   │
└────────────────────────────────┬────────────────────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │           CAPTURE LAYER             │
              │   pynput listener → raw events      │
              │   active-window enricher            │
              │   F9 runtime pause/resume           │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │         ANALYTICS PIPELINE          │
              │   ├─ Keystroke dynamics             │
              │   │  (dwell, flight, rhythm σ)      │
              │   └─ Anomaly detector               │
              │      (z-score vs trained baseline)  │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │         REDACTION FILTER            │
              │   Regex DLP for CC/SSN/JWT/keys     │
              │   → replaces with [REDACTED:TYPE]   │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │         INTEGRITY LAYER             │
              │   HMAC-SHA256 chain over entries    │
              │   (Hₙ = HMAC(K, Hₙ₋₁ ‖ entryₙ))    │
              └──────────────────┬──────────────────┘
                                 │
              ┌──────────────────┴──────────────────┐
              │          STORAGE LAYER              │
              │   AES-256-GCM (PBKDF2-derived key)  │
              │   Size-based rotation               │
              └─────────────────────────────────────┘
```

Full details in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). MITRE ATT&CK mapping in [`docs/MITRE-ATTACK.md`](docs/MITRE-ATTACK.md). Threat model in [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md).

---

## Quick Start

```bash
git clone https://github.com/Redox023/Keytrace-.git
cd Keytrace-
python -m venv .venv && source .venv/bin/activate
pip install -e .

# Sign the consent file (refuses to run otherwise)
cp CONSENT.template.md CONSENT.md
# edit CONSENT.md, replace <YOUR NAME> and <DATE>

# Run
keytrace run --passphrase-env KEYTRACE_PASS
```

Press **F9** to pause/resume capture. **Ctrl+C** to stop and flush the encrypted log.

### Decrypt a session log

```bash
keytrace decrypt logs/2026-05-11T13-22-04.kt.enc --passphrase-env KEYTRACE_PASS
keytrace verify  logs/2026-05-11T13-22-04.kt.enc  # checks HMAC chain
```

### Analyze keystroke dynamics

```bash
keytrace analyze logs/2026-05-11T13-22-04.kt.enc
# → mean dwell, mean flight, rhythm σ, top-N anomalous windows
```

---

## Detection Engineering

KeyTrace ships with detection content for the tool itself — because building offensive tooling without thinking about how it gets caught is half a project.

- [`detection/keytrace.yar`](detection/keytrace.yar) — YARA rule matching the encrypted-log magic bytes, embedded string artifacts, and the GCM nonce-prefix pattern.
- [`detection/keytrace.sigma.yml`](detection/keytrace.sigma.yml) — Sigma rule for SIEM ingestion (process creation + suspicious python child of explorer with `pynput` in command line).

Load the YARA rule against a sample log:

```bash
yara detection/keytrace.yar logs/
```

---

## Threat Model (Summary)

| Threat | Mitigation in KeyTrace |
|---|---|
| Log theft at rest | AES-256-GCM, key never written to disk |
| Log tampering by attacker | HMAC chain — any silent edit breaks `verify` |
| Sensitive data in logs (passwords, cards) | Regex DLP redaction before encryption |
| Operator misuse | Consent gate; refuses to start without signed file |
| Forensic attribution | Logs are timestamped and chain-anchored |
| Memory dumping the key | Key zeroized on shutdown via `secrets.token_bytes` overwrite |

The threat model is intentionally incomplete in places — see [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the residual-risk discussion (memory dumps during runtime, kernel-level loggers below this one, etc.). That discussion is itself part of what makes this a portfolio piece.

---

## The Elevator Pitch

If you're wondering what makes this project different from a standard keylogger tutorial, here is the elevator pitch:

> "KeyTrace is an educational keystroke-telemetry framework I built to teach myself the full lifecycle of a credential-collection tool — not just the capture mechanic, but encryption at rest with AES-GCM, tamper-evident logging via an HMAC chain, behavioral biometrics through dwell/flight-time extraction, statistical anomaly detection, and DLP-style PII redaction. The interesting part is that I also shipped the YARA and Sigma rules to detect it — so the project demonstrates I can build offensive tooling and then reason about how a SOC would catch it. Every feature is mapped to a MITRE ATT&CK technique in the docs."

---

## License

MIT, with an Educational-Use rider. See [`LICENSE`](LICENSE). Do not use this tool against systems you do not own or have explicit written authorization to monitor.
