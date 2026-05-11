"""Ethics consent gate.

KeyTrace refuses to start unless a `CONSENT.md` file exists in the project
root and contains the canonical acknowledgment phrase. Yes, this can be
bypassed by anyone willing to edit the source — the point is not to be a
DRM-style lock but to force a deliberate, conscious choice. A user who
modifies this module to disable the gate has clearly made an affirmative
decision and bears responsibility for it.

This pattern is borrowed from sqlmap (`--batch` confirmation) and Metasploit
(banner disclaimers).
"""
from __future__ import annotations

from pathlib import Path

from ..config import Config


class ConsentError(RuntimeError):
    """Raised when the consent gate refuses to open."""


def check(cfg: Config, project_root: Path | None = None) -> None:
    root = project_root or Path.cwd()
    path = root / cfg.consent_filename
    if not path.is_file():
        raise ConsentError(
            f"Refusing to start: {cfg.consent_filename} not found at {root}.\n"
            f"Copy CONSENT.template.md -> {cfg.consent_filename} and sign it."
        )
    text = path.read_text(encoding="utf-8", errors="replace")
    if cfg.consent_required_phrase not in text:
        raise ConsentError(
            f"Refusing to start: {cfg.consent_filename} does not contain the "
            f"required acknowledgment phrase. Did you sign the template?"
        )
    # Heuristic: did the operator at least fill in *something* for name/date?
    if "<YOUR NAME>" in text or "<DATE>" in text:
        raise ConsentError(
            f"Refusing to start: {cfg.consent_filename} still has placeholder "
            f"<YOUR NAME> / <DATE>. Fill those in before running."
        )
