"""Smoke test for the Tkinter GUI.

Constructs the whole window (style + all tabs + status bar) without entering
the mainloop, catching crashes in _build_ui / _apply_style that the pure-logic
tests in test_core.py can't reach. Skips when there is no usable display
(e.g. CI without Xvfb); run under `xvfb-run` to exercise it headlessly.
"""

import pytest

tk = pytest.importorskip("tkinter")

import app  # noqa: E402  (imported after the tkinter availability check)


def test_app_constructs_and_destroys():
    try:
        win = app.App()
    except tk.TclError as exc:
        pytest.skip(f"no usable display: {exc}")
    try:
        # Title carries the resolved version; the status bar exists.
        assert win.title().startswith("b64")
        assert win._status_var.get() == "Ready"
    finally:
        win.destroy()
