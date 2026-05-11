# Threat Model

This document is half of what makes KeyTrace a portfolio piece. Building a tool that *works* is easy. Articulating its threat model — what it defends against, what it does not, and where the residual risk lives — is what hiring managers are actually screening for.

## Assets

| Asset | Sensitivity | Stored where |
|---|---|---|
| Captured keystrokes | High (may include credentials despite DLP) | Encrypted session log on disk |
| Session passphrase | Critical | Memory only (env var or interactive prompt); never written |
| Session HMAC key | High | Embedded in the encrypted session header |
| Active-window context | Medium | Encrypted session log |
| Trained baseline | Low | Plain JSON (no secrets) |

## Adversaries

We define three:

**A1 — Curious local user** with normal-user access to the host after the session ends. Wants to read log contents.

**A2 — Forensic analyst** authorized by the system owner. Wants to verify log integrity and authenticity, ideally without the original operator's cooperation.

**A3 — Sophisticated attacker** who has root/SYSTEM on the host during a live capture session. Wants to silently insert false entries to frame a user, or exfiltrate the passphrase.

## What KeyTrace defends against

| Threat | Mitigation | Verdict |
|---|---|---|
| A1 reads logs from disk | AES-256-GCM with PBKDF2-derived key | **Mitigated** |
| A1 swaps a log file's salt or nonce | AAD binds header to ciphertext; GCM tag fails | **Mitigated** |
| A1 silently edits a past log entry | HMAC chain breaks at the modified index | **Mitigated (detected, not prevented)** |
| A2 needs to verify a log's integrity | `keytrace verify` replays the chain end-to-end | **Mitigated** |
| Operator accidentally exfils PII | Regex DLP redacts CC/SSN/JWT/keys at analysis time | **Partially mitigated** — see residual risk |
| Operator runs without authorization | Consent gate refuses to start without signed file | **Mitigated against accidents, not bypass** |

## What KeyTrace does NOT defend against (residual risk)

This is the section that distinguishes engineers from script-kiddies. Owning the gaps is the work.

| Threat | Why it's unmitigated | What would mitigate it |
|---|---|---|
| **A3 dumps process memory during a live session** | The AES key is in plaintext in `cryptography`'s internal buffers while AESGCM exists. Python strings/bytes are immutable, so even `del` doesn't zeroize. | Use `mlock`-ed ctypes buffers; rotate keys per N entries; use a hardware key store (TPM, Secure Enclave). |
| **A3 hooks keyboard input below KeyTrace** | A kernel-mode keylogger sees keystrokes before pynput does. KeyTrace cannot detect this. | EDR / kernel callback monitoring is the right tool here, not a user-mode keylogger. |
| **DLP regex false negatives** | A credit card typed with non-standard separators, or a one-time-pad typed digit-by-digit across windows, evades the regex. | Move redaction from raw key-stream to reassembled-buffer analysis (`analyze` already does this); add entropy-based heuristics. |
| **Consent gate bypass** | A user with source-edit access can delete the `consent.py` import. | Threat is by-design out of scope: the gate is a deliberation forcing function, not a tamper-resistant DRM lock. |
| **C2 exfiltration after the operator's intent flips** | Logs sit on disk in cleartext after `decrypt`. Anything the operator does with the plaintext is outside the tool's control. | DRM / data-rights enforcement is a different product category. |
| **Replay attacks against the HMAC chain** | A full-file replacement with a valid older chain plus a re-encryption goes undetected unless the verifier tracks expected session IDs. | Out-of-band ledger of session salts (e.g., write `(session_salt, first_hmac)` tuples to a separate append-only store). |

## Things I deliberately left out

For an educational project, these would have crossed from "demonstrates skills" into "publishes a weapon":

- **Persistence** (registry run keys, launchd plists, cron, systemd user units). Implementable in 20 lines; intentionally omitted.
- **Anti-debug / anti-VM / unhooking AmsiScanBuffer**. Easy to copy from public sources; not in scope for a portfolio piece that wants to be hire-able rather than alarming.
- **Network exfiltration** of any kind, including DNS tunneling, webhook callbacks, or steganography. The original beginner project simulated webhook C2; I downgraded.
- **Screenshot or clipboard capture** alongside keystrokes. Trivial to add (`Pillow.ImageGrab` / `pyperclip`); intentionally absent.

If an interviewer asks "could you add X?", the answer is yes; the more interesting answer is *why you didn't*.
