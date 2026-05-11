# MITRE ATT&CK Mapping

Every meaningful capability in KeyTrace maps to a published ATT&CK technique. This document is what an interviewer might ask you to walk through — being fluent in this framework is one of the most universally-requested skills in entry-level cybersecurity job descriptions.

| Technique ID | Name | Where in KeyTrace | Notes |
|---|---|---|---|
| **T1056.001** | Input Capture: Keylogging | `keytrace/core/capture.py` | Core capability. User-mode hook via `pynput`, no kernel driver. |
| **T1056** | Input Capture (parent) | (same) | Listed for completeness when scanning for the parent technique. |
| **T1547** | Boot or Logon Autostart Execution | *Not implemented* | Deliberately omitted. A persistence story would convert this from a research tool to malware. |
| **T1041** | Exfiltration Over C2 Channel | *Not implemented* | The original project simulated a webhook C2; KeyTrace deliberately stops at on-disk encrypted storage. The threat model entry for "C2 exfiltration" is left explicit so a reviewer sees the choice. |
| **T1027** | Obfuscated Files or Information | `keytrace/core/crypto.py` | Logs at rest are AES-256-GCM. This is "defensive obfuscation" — protecting captured data from third-party theft — not anti-analysis evasion of the binary itself. |
| **T1140** | Deobfuscate/Decode Files or Information | `keytrace decrypt` subcommand | The legitimate reverse path. |
| **T1622** | Debugger Evasion | *Not implemented* | Excluded by design. |
| **T1059.006** | Command and Scripting Interpreter: Python | Whole project | Python runtime is the execution vector. The Sigma rule keys on this. |

## Defender mapping (D3FEND)

| D3FEND ID | Name | Implementation |
|---|---|---|
| **D3-FA** | File Analysis | `detection/keytrace.yar` — YARA rule scanning for log magic bytes and source strings |
| **D3-PA** | Process Analysis | `detection/keytrace.sigma.yml` — Sigma rule for Python process creation patterns |
| **D3-UBA** | User Behavior Analysis | `keytrace/analytics/anomaly.py` — z-score deviation against trained baseline |
| **D3-MH** | Message Hashing | `keytrace/core/integrity.py` — HMAC chain over log entries |

## Why this matters on a resume

Knowing the technique IDs is table-stakes. The interview-differentiating move is being able to articulate *why* a given capability was included or excluded:

- *Why no persistence?* Because the moment KeyTrace can survive a reboot without the operator's intervention, it stops being a teaching tool and becomes a credible threat. The educational framing requires keeping execution explicit.
- *Why no C2 exfiltration?* Same reason. The original beginner project simulated this with a webhook; I made a deliberate downgrade to demonstrate that I understand which capabilities cross the line.
- *Why AES-GCM and not ChaCha20-Poly1305?* GCM is in `cryptography`'s standard high-level API and is the dominant choice in industry artifacts (TLS 1.3, AWS KMS); ChaCha would have been an equally defensible choice and would be preferable on devices without AES-NI.
- *Why z-score and not isolation forest?* Honest framing: a one-week project shouldn't pretend to be a research-grade UEBA engine. The z-score baseline is what most actual UEBA products start with, and it composes cleanly with the rest of the pipeline. An iso-forest upgrade is a documented Future Work item.
