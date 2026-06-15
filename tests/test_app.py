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


def _make_win():
    try:
        return app.App()
    except tk.TclError as exc:
        pytest.skip(f"no usable display: {exc}")


def test_validate_waits_for_in_flight_controller_lookup(monkeypatch):
    """Switching contexts fast leaves the controller fields blank while the
    lookup runs; Validate must not fire kubeseal against an empty controller."""
    win = _make_win()
    try:
        calls = []
        monkeypatch.setattr(app, "run_bg", lambda *a, **k: calls.append((a, k)))
        win._set_text(win._sealed_out, "kind: SealedSecret\n")
        win._seal_ctx.set("ctxA")
        win._ctl_pending = "ctxA"  # detection for the current context still running

        win._do_validate()

        assert calls == []  # kubeseal was not launched
        assert "Detecting controller" in win._status_var.get()
    finally:
        win.destroy()


def test_validate_runs_once_controller_lookup_lands(monkeypatch):
    """Once detection for the current context resolves, Validate proceeds."""
    win = _make_win()
    try:
        calls = []
        monkeypatch.setattr(app, "run_bg", lambda *a, **k: calls.append((a, k)))
        win._set_text(win._sealed_out, "kind: SealedSecret\n")
        win._seal_ctx.set("ctxA")
        win._ctl_pending = None  # lookup landed

        win._do_validate()

        assert len(calls) == 1  # kubeseal launched
    finally:
        win.destroy()


def test_seal_waits_for_in_flight_controller_lookup(monkeypatch):
    """Without a cert, sealing while detection runs would use kubeseal's defaults
    (wrong cert → undecryptable); it must wait for the lookup instead."""
    win = _make_win()
    try:
        calls = []
        monkeypatch.setattr(app, "run_bg", lambda *a, **k: calls.append((a, k)))
        win._set_text(win._yaml_out, "kind: Secret\n")
        win._seal_ctx.set("ctxA")
        win._cert = ""               # no cert → controller is required
        win._ctl_pending = "ctxA"    # detection still running

        win._do_seal()

        assert calls == []
        assert "Detecting controller" in win._status_var.get()
    finally:
        win.destroy()


def test_seal_with_cert_ignores_in_flight_lookup(monkeypatch):
    """A selected cert seals offline, so the controller race doesn't apply."""
    win = _make_win()
    try:
        calls = []
        monkeypatch.setattr(app, "run_bg", lambda *a, **k: calls.append((a, k)))
        win._set_text(win._yaml_out, "kind: Secret\n")
        win._seal_ctx.set("ctxA")
        win._cert = "/tmp/pub.pem"   # cert present → controller irrelevant
        win._ctl_pending = "ctxA"    # detection still running

        win._do_seal()

        assert len(calls) == 1       # sealed anyway
    finally:
        win.destroy()
