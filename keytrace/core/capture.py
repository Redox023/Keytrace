"""Keystroke capture engine.

Built on pynput. Emits structured KeyEvent objects through an asyncio-style
callback. We capture press AND release timestamps separately — that's what
enables the dwell-time / flight-time analytics later.

The hotkey listener (F9 by default) is kept in its own pynput Listener so
that toggling capture doesn't interfere with the main key stream and vice
versa.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, asdict
from typing import Callable, Optional

from pynput import keyboard

from ..config import Config
from .window import get_active_window


@dataclass
class KeyEvent:
    ts_ns: int                  # nanosecond timestamp (monotonic-ish)
    wall_iso: str               # ISO wall-clock for human readability
    kind: str                   # "press" or "release"
    key: str                    # printable char, or special key name
    window_title: str
    window_process: str

    def to_dict(self) -> dict:
        return asdict(self)


def _key_to_str(key) -> str:
    """Best-effort stringification of pynput keys."""
    if hasattr(key, "char") and key.char is not None:
        return key.char
    name = getattr(key, "name", None)
    if name:
        return f"<{name}>"
    return str(key)


class CaptureEngine:
    """Owns the pynput listeners and emits KeyEvents while enabled."""

    def __init__(self, cfg: Config, on_event: Callable[[KeyEvent], None]) -> None:
        self._cfg = cfg
        self._on_event = on_event
        self._enabled = threading.Event()
        self._enabled.set()                    # capture on by default
        self._stop = threading.Event()
        self._listener: Optional[keyboard.Listener] = None
        self._hotkey_listener: Optional[keyboard.GlobalHotKeys] = None

    @property
    def enabled(self) -> bool:
        return self._enabled.is_set()

    def toggle(self) -> None:
        if self._enabled.is_set():
            self._enabled.clear()
        else:
            self._enabled.set()

    def _emit(self, kind: str, key) -> None:
        if not self._enabled.is_set():
            return
        win = get_active_window()
        ev = KeyEvent(
            ts_ns=time.monotonic_ns(),
            wall_iso=time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            kind=kind,
            key=_key_to_str(key),
            window_title=win["title"],
            window_process=win["process"],
        )
        try:
            self._on_event(ev)
        except Exception:
            # The capture loop must never die because a downstream handler
            # raised. In a real SOC tool you'd push the exception to a
            # sentry-style sink here.
            pass

    def _on_press(self, key) -> None:
        self._emit("press", key)

    def _on_release(self, key) -> None:
        self._emit("release", key)

    def start(self) -> None:
        self._listener = keyboard.Listener(
            on_press=self._on_press, on_release=self._on_release
        )
        self._listener.start()
        # Hotkey: <f9> by default
        hk = "<" + self._cfg.toggle_key + ">"
        self._hotkey_listener = keyboard.GlobalHotKeys({hk: self.toggle})
        self._hotkey_listener.start()

    def stop(self) -> None:
        self._stop.set()
        if self._listener:
            self._listener.stop()
        if self._hotkey_listener:
            self._hotkey_listener.stop()

    def wait(self) -> None:
        """Block until stop()."""
        while not self._stop.is_set():
            self._stop.wait(0.5)
