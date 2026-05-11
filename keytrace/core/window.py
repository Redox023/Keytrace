"""Active-window enricher (cross-platform).

Returns a small dict { "title": str, "process": str } for the foreground
window. Used to label keystroke events with context so analytics can ask
"how long does this user spend typing in 1Password vs. Slack?" without ever
storing the keystrokes themselves in cleartext.

Each backend is best-effort: on failure we return ("unknown", "unknown")
rather than crashing the capture loop.
"""
from __future__ import annotations

import sys
from typing import TypedDict


class WindowInfo(TypedDict):
    title: str
    process: str


def _windows() -> WindowInfo:
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi

        hwnd = user32.GetForegroundWindow()
        length = user32.GetWindowTextLengthW(hwnd) + 1
        buf = ctypes.create_unicode_buffer(length)
        user32.GetWindowTextW(hwnd, buf, length)
        title = buf.value or "unknown"

        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        h_proc = kernel32.OpenProcess(0x0410, False, pid.value)  # query+vm_read
        name_buf = ctypes.create_unicode_buffer(260)
        psapi.GetModuleBaseNameW(h_proc, None, name_buf, 260)
        kernel32.CloseHandle(h_proc)
        process = name_buf.value or "unknown"
        return {"title": title, "process": process}
    except Exception:
        return {"title": "unknown", "process": "unknown"}


def _macos() -> WindowInfo:
    try:
        # Quartz is part of pyobjc-framework-Quartz
        from Quartz import (
            CGWindowListCopyWindowInfo,
            kCGNullWindowID,
            kCGWindowListOptionOnScreenOnly,
        )
        windows = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly, kCGNullWindowID
        )
        for w in windows:
            if w.get("kCGWindowLayer") == 0:
                return {
                    "title": w.get("kCGWindowName", "") or "unknown",
                    "process": w.get("kCGWindowOwnerName", "") or "unknown",
                }
        return {"title": "unknown", "process": "unknown"}
    except Exception:
        return {"title": "unknown", "process": "unknown"}


def _linux() -> WindowInfo:
    # Try xdotool, then xprop, then fail gracefully. Wayland is intentionally
    # not supported -- this is a teaching moment about how Wayland's security
    # model breaks keylogger-friendly assumptions.
    import shutil
    import subprocess
    if shutil.which("xdotool"):
        try:
            wid = subprocess.check_output(
                ["xdotool", "getactivewindow"], stderr=subprocess.DEVNULL, timeout=1
            ).decode().strip()
            title = subprocess.check_output(
                ["xdotool", "getwindowname", wid], stderr=subprocess.DEVNULL, timeout=1
            ).decode().strip() or "unknown"
            pid = subprocess.check_output(
                ["xdotool", "getwindowpid", wid], stderr=subprocess.DEVNULL, timeout=1
            ).decode().strip()
            try:
                with open(f"/proc/{pid}/comm") as f:
                    process = f.read().strip()
            except OSError:
                process = "unknown"
            return {"title": title, "process": process}
        except Exception:
            pass
    return {"title": "unknown", "process": "unknown"}


def get_active_window() -> WindowInfo:
    if sys.platform.startswith("win"):
        return _windows()
    if sys.platform == "darwin":
        return _macos()
    if sys.platform.startswith("linux"):
        return _linux()
    return {"title": "unknown", "process": "unknown"}
