#!/usr/bin/env python3
"""b64 - Kubernetes Secrets Tool: dark-themed Tkinter GUI for Kubernetes secrets.

Encode / decode base64, build Secret YAML from .env, fetch from a cluster
(read-only), and seal with kubeseal. Never runs `kubectl apply`.

Requires a modern Tcl/Tk (8.6+). On macOS, Apple's system Tk 8.5 renders
custom colours incorrectly — launch via `make start` (see README.md).
"""

import os
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, ttk

try:
    import yaml
    PYYAML_OK = True
except ImportError:
    PYYAML_OK = False


def _resolve_version() -> str:
    """Best-effort app version.

    Release tarballs carry a stamped ``_version.py`` (written by the release
    workflow); a plain git checkout falls back to ``git describe``; failing
    both, the version is unknown.
    """
    try:
        from _version import __version__ as stamped
        return stamped
    except Exception:
        pass
    try:
        here = os.path.dirname(os.path.abspath(__file__))
        out = subprocess.run(
            ["git", "describe", "--tags", "--match", "v[0-9]*", "--dirty"],
            cwd=here, capture_output=True, text=True, timeout=2)
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip().lstrip("v")
    except Exception:
        pass
    return "unknown"


__version__ = _resolve_version()

# ---------------------------------------------------------------------------
# Dark palette
# ---------------------------------------------------------------------------
BG     = "#1e1e1e"
BG2    = "#252526"
BG3    = "#2d2d30"
FG     = "#d4d4d4"
FGDIM  = "#858585"
ACCENT = "#4ec9b0"
BLUE   = "#569cd6"
OK_C   = "#4caf50"
ERR_C  = "#f44747"
BORDER = "#3c3c3c"
ROW_A  = "#232323"
ROW_B  = "#2a2a2a"

if sys.platform == "darwin":
    MONO = "Menlo"
    SANS = "Helvetica Neue"
elif sys.platform == "win32":
    MONO = "Consolas"
    SANS = "Segoe UI"
else:
    MONO = "DejaVu Sans Mono"
    SANS = "DejaVu Sans"
SZ = 11

# ---------------------------------------------------------------------------
# Core logic lives in core.py (pure, no UI) — re-exported here so the rest of
# the app and the test suite can keep referring to these names.
# ---------------------------------------------------------------------------

from core import (  # noqa: E402
    SECRET_TYPES,
    b64_decode,
    b64_encode,
    build_secret_yaml,
    kubeseal_seal_cmd,
    kubeseal_validate_cmd,
    parse_dotenv,
    secret_entries,
    write_secret_file,
)

# ---------------------------------------------------------------------------
# Background command runner — never blocks the UI
# ---------------------------------------------------------------------------

def run_bg(cmd: list, callback, stdin_data: str = None, timeout: int = 15):
    def _worker():
        try:
            p = subprocess.run(
                cmd, input=stdin_data, capture_output=True,
                text=True, timeout=timeout,
            )
            callback(p.stdout, p.stderr, p.returncode)
        except FileNotFoundError:
            callback("", f"Command not found: {cmd[0]}", -1)
        except subprocess.TimeoutExpired:
            callback("", "Command timed out", -2)
        except Exception as exc:
            callback("", str(exc), -99)
    threading.Thread(target=_worker, daemon=True).start()


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

class App(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title(f"b64 - Kubernetes Secrets Tool — v{__version__}")
        self.geometry("880x720")
        self.minsize(740, 580)
        self.configure(bg=BG)
        self._status_job = None
        # Sub-pixel remainder carried between wheel events (see _on_wheel) so slow
        # macOS trackpad deltas accumulate instead of rounding away to nothing.
        self._wheel_accum = 0.0
        # Context whose controller lookup is still in flight. Switching contexts
        # fast leaves the Controller fields blank until detection lands; Validate
        # checks this so it doesn't run against an empty/stale controller.
        self._ctl_pending = None
        # Whether a seal / validate kubeseal run is currently in flight. These
        # gate the action buttons (see _refresh_action_buttons) so a controller
        # lookup landing mid-operation can't re-enable a button under it.
        self._sealing = False
        self._validating = False

        self._enc_ctx = tk.StringVar()
        self._enc_ns  = tk.StringVar()
        self._enc_sec = tk.StringVar()

        # Binary (non-UTF-8) values from a loaded template, kept as their
        # original base64 so Generate YAML can re-emit them verbatim instead of
        # silently dropping them (they can't be edited as plaintext .env).
        self._tpl_binary = {}

        self._apply_style()
        self._fix_x11_paste()
        self._build_ui()
        # Defer until mainloop is running: the fetch worker thread reports
        # back via self.after(), which raises RuntimeError before mainloop
        # starts (e.g. kubectl missing fails the thread instantly).
        self.after(0, self._fetch_contexts)

    def _fix_x11_paste(self):
        """On X11, tk.Text's default <<Paste>> inserts at the cursor without
        first removing the current selection, so pasting over selected text
        appends instead of replacing it (Windows/macOS delete the selection
        first). Reimplement Ctrl+V to delete any selection before inserting.

        Only tk.Text is affected: ttk entries/combobox already replace the
        selection on all platforms (ttk::entry::Paste runs PendingDelete first),
        so they are left untouched. Middle-click paste uses <<PasteSelection>>
        and is also left untouched."""
        if self.tk.call("tk", "windowingsystem") != "x11":
            return

        def paste(event):
            w = event.widget
            # Fetch the clipboard before touching the selection: on an empty /
            # unavailable CLIPBOARD (common on X11 once the source app exits)
            # ::tk::GetSelection raises, and deleting first would destroy the
            # selection with nothing pasted. ::tk::GetSelection tries
            # UTF8_STRING then STRING, matching the default handler.
            try:
                text = w.tk.call("::tk::GetSelection", w, "CLIPBOARD")
            except tk.TclError:
                return "break"  # nothing to paste — leave the selection intact
            try:
                w.delete("sel.first", "sel.last")
            except tk.TclError:
                pass  # nothing selected
            w.insert("insert", text)
            return "break"

        self.bind_class("Text", "<<Paste>>", paste)

    # ------------------------------------------------------------------ style

    def _apply_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")

        s.configure(".",
            background=BG2, foreground=FG, fieldbackground=BG3,
            troughcolor=BG2, bordercolor=BORDER,
            darkcolor=BG3, lightcolor=BG3,
            insertcolor=FG, selectbackground=ACCENT, selectforeground=BG,
            focuscolor=ACCENT, font=(SANS, SZ),
        )
        s.configure("TFrame", background=BG2)
        s.configure("TLabel", background=BG2, foreground=FG)
        s.configure("Dim.TLabel",  background=BG2, foreground=FGDIM)
        s.configure("Head.TLabel", background=BG2, foreground=ACCENT,
                    font=(SANS, SZ + 1, "bold"))
        s.configure("Warn.TLabel", background=BG2, foreground=ERR_C)

        # Notebook
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=[6, 6, 6, 0])
        s.configure("TNotebook.Tab",
            background=BG3, foreground=FGDIM,
            padding=[18, 8], borderwidth=0, font=(SANS, SZ))
        s.map("TNotebook.Tab",
            background=[("selected", BG2)],
            foreground=[("selected", ACCENT)],
            expand=[("selected", [1, 1, 1, 0])])

        # Buttons
        s.configure("TButton",
            background=BG3, foreground=FG, relief="flat",
            borderwidth=1, padding=[10, 5], font=(SANS, SZ))
        s.map("TButton",
            background=[("active", BORDER), ("pressed", BORDER), ("disabled", BG2)],
            foreground=[("disabled", FGDIM)],
            bordercolor=[("active", ACCENT)])

        s.configure("Accent.TButton",
            background=ACCENT, foreground=BG, font=(SANS, SZ, "bold"))
        s.map("Accent.TButton",
            background=[("active", "#3cb899"), ("pressed", "#3cb899"),
                       ("disabled", BG3)],
            foreground=[("disabled", FGDIM)])

        s.configure("Icon.TButton", padding=[6, 5])

        # Combobox
        s.configure("TCombobox",
            fieldbackground=BG3, background=BG3, foreground=FG,
            arrowcolor=FG, bordercolor=BORDER,
            selectbackground=BG3, selectforeground=FG, padding=[6, 4])
        s.map("TCombobox",
            fieldbackground=[("readonly", BG3)],
            foreground=[("readonly", FG)],
            bordercolor=[("focus", ACCENT)],
            arrowcolor=[("active", ACCENT)])
        # Dropdown list colours (Tk option DB)
        self.option_add("*TCombobox*Listbox.background", BG3)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT)
        self.option_add("*TCombobox*Listbox.selectForeground", BG)
        self.option_add("*TCombobox*Listbox.font", (SANS, SZ))

        # Entry
        s.configure("TEntry",
            fieldbackground=BG3, foreground=FG, insertcolor=FG,
            bordercolor=BORDER, padding=[6, 4])
        # Default entries (incl. readonly OUTPUT fields) keep full-contrast text.
        s.map("TEntry",
            bordercolor=[("focus", ACCENT)],
            fieldbackground=[("readonly", BG3)],
            foreground=[("readonly", FG)])
        # Dimmed read-only style — used only for the auto-detected controller
        # fields, to signal they aren't user-editable.
        s.configure("RO.TEntry",
            fieldbackground=BG2, foreground=FGDIM, bordercolor=BORDER, padding=[6, 4])
        s.map("RO.TEntry",
            fieldbackground=[("readonly", BG2)],
            foreground=[("readonly", FGDIM)])

        # Scrollbars
        s.configure("Vertical.TScrollbar",
            background=BG3, troughcolor=BG, bordercolor=BG,
            arrowcolor=FGDIM, relief="flat")
        s.configure("Horizontal.TScrollbar",
            background=BG3, troughcolor=BG, bordercolor=BG,
            arrowcolor=FGDIM, relief="flat")
        s.map("Vertical.TScrollbar",   background=[("active", BORDER)])
        s.map("Horizontal.TScrollbar", background=[("active", BORDER)])

        s.configure("TSeparator", background=BORDER)

    # --------------------------------------------------------------- status bar

    def _build_status_bar(self):
        bar = tk.Frame(self, bg=BG, height=26)
        bar.pack(side="bottom", fill="x")
        tk.Frame(self, bg=BORDER, height=1).pack(side="bottom", fill="x")
        tk.Label(bar, text=f"v{__version__}", bg=BG, fg=FGDIM,
                 anchor="e", padx=10, font=(SANS, SZ - 1)).pack(side="right")
        self._status_var = tk.StringVar(value="Ready")
        self._status_lbl = tk.Label(
            bar, textvariable=self._status_var,
            bg=BG, fg=FGDIM, anchor="w", padx=10, font=(SANS, SZ - 1))
        self._status_lbl.pack(side="left", fill="both", expand=True)

    def _status(self, msg: str, kind: str = "dim"):
        color = {"ok": OK_C, "err": ERR_C, "dim": FGDIM}.get(kind, FGDIM)
        self._status_var.set(msg)
        self._status_lbl.configure(fg=color)
        if self._status_job:
            self.after_cancel(self._status_job)
        def _reset():
            self._status_var.set("Ready")
            self._status_lbl.configure(fg=FGDIM)
            self._status_job = None
        self._status_job = self.after(4000, _reset)

    # ---------------------------------------------------------------- top-level

    def _build_ui(self):
        self._build_status_bar()
        nb = ttk.Notebook(self)
        self._nb = nb
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        ef = ttk.Frame(nb); nb.add(ef, text="Encode")
        df = ttk.Frame(nb, padding=10); nb.add(df, text="Decode")
        sf = ttk.Frame(nb); nb.add(sf, text="Seal")

        # Encode and Seal can outgrow the window, so wrap each in a vertical
        # canvas that scrolls as a whole; Decode has its own table canvas.
        self._enc_cv, enc_inner = self._scrollable(ef)
        enc_inner.configure(padding=10)
        self._build_encode_tab(enc_inner)
        self._build_decode_tab(df)   # sets self._tbl_cv
        self._seal_cv, seal_inner = self._scrollable(sf)
        seal_inner.configure(padding=10)
        self._build_seal_tab(seal_inner)

        # Route the mouse wheel to whichever tab's canvas is showing, so the
        # wheel scrolls the page no matter what it's hovering over.
        self._tab_canvas = {str(ef): self._enc_cv, str(df): self._tbl_cv,
                            str(sf): self._seal_cv}
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(seq, self._on_wheel)
        # Comboboxes cycle their value on the wheel by default (ttk's
        # combobox::Scroll). Now that the page scrolls, that would silently change
        # the selected context / namespace / secret / type as you scroll past one
        # — so neutralise it (no "break" → the bind_all page-scroller still runs).
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_class("TCombobox", seq, lambda e: None)

    def _scrollable(self, parent):
        """Wrap `parent`'s content in a vertical Canvas + Scrollbar so the page
        can scroll when it outgrows the window. Returns (canvas, inner_frame);
        build the tab's widgets into inner_frame."""
        # yscrollincrement=1 makes "scroll N units" mean N pixels, so _on_wheel
        # can scroll by the exact pixel amount Tk's own wheel bindings use.
        cv = tk.Canvas(parent, bg=BG2, bd=0, highlightthickness=0,
                       yscrollincrement=1)
        sb = ttk.Scrollbar(parent, orient="vertical", command=cv.yview)
        cv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        cv.pack(side="left", fill="both", expand=True)
        inner = ttk.Frame(cv)
        win = cv.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>",
                   lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
        return cv, inner

    def _on_wheel(self, e):
        """Global mouse-wheel / trackpad handler: scroll the active tab's page
        canvas so the wheel works anywhere in the window. Over a Text widget that
        has its own overflow, leave the scroll to the Text; otherwise move the
        whole page."""
        cv = self._tab_canvas.get(self._nb.select())
        if cv is None:
            return
        w = e.widget
        if isinstance(w, tk.Text) and w.yview() != (0.0, 1.0):
            return  # the Text scrolls itself — don't also move the page
        if e.num in (4, 5):                  # X11 wheel buttons (Linux)
            cv.yview_scroll(-60 if e.num == 4 else 60, "units")  # ~3 lines/click
            return
        if not e.delta:
            return
        # Scroll by pixels (canvas units are pinned to 1px). 0.5px per delta unit
        # matches Tk's own Listbox/page wheel feel (it scrolls delta/40 lines, a
        # line ≈ 20px); plain "-delta units" jumped the whole page because raw
        # macOS deltas are large. Carry the sub-pixel remainder so slow trackpad
        # deltas accumulate instead of rounding away to nothing.
        self._wheel_accum += -e.delta * 0.5
        step = int(self._wheel_accum)
        self._wheel_accum -= step
        if step:
            cv.yview_scroll(step, "units")

    # ---------------------------------------------------------------- encode tab

    def _build_encode_tab(self, p):
        ttk.Label(p, text="Single Value Encoder", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        # Buttons packed right-first so they stay visible; the entry fills the gap.
        r = ttk.Frame(p); r.pack(fill="x", pady=2)
        ttk.Button(r, text="Encode →", command=self._sv_encode) \
            .pack(side="right", padx=(6, 0))
        self._sv_in = ttk.Entry(r, font=(MONO, SZ))
        self._sv_in.pack(side="left", fill="x", expand=True)
        self._sv_in.bind("<Return>", lambda _: self._sv_encode())

        r2 = ttk.Frame(p); r2.pack(fill="x", pady=2)
        ttk.Button(r2, text="Copy", command=lambda: self._clip(self._sv_out.get())) \
            .pack(side="right", padx=(6, 0))
        self._sv_out = ttk.Entry(r2, font=(MONO, SZ), state="readonly")
        self._sv_out.pack(side="left", fill="x", expand=True)

        ttk.Separator(p).pack(fill="x", pady=10)

        ttk.Label(p, text=".env → Kubernetes Secret YAML", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        # file picker
        fp = ttk.Frame(p); fp.pack(fill="x", pady=2)
        ttk.Label(fp, text="File:").pack(side="left")
        self._env_lbl = ttk.Label(fp, text="(no file)", style="Dim.TLabel")
        self._env_lbl.pack(side="left", padx=6)
        ttk.Button(fp, text="Browse…", command=self._browse_env).pack(side="left")
        ttk.Button(fp, text="Clear", command=self._clear_env).pack(side="left", padx=(4, 0))

        # cluster fetch row
        cf = ttk.Frame(p); cf.pack(fill="x", pady=(6, 2))
        ttk.Label(cf, text="Context:").pack(side="left")
        self._ctx_cb = ttk.Combobox(cf, textvariable=self._enc_ctx, width=16,
                                    state="readonly")
        self._ctx_cb.pack(side="left", padx=(4, 0))
        self._ctx_cb.bind("<<ComboboxSelected>>", self._on_ctx_change)
        ttk.Button(cf, text="⟳", style="Icon.TButton", width=2,
                   command=self._fetch_contexts).pack(side="left", padx=3)
        ttk.Label(cf, text="NS:").pack(side="left", padx=(6, 0))
        self._ns_cb = ttk.Combobox(cf, textvariable=self._enc_ns, width=12,
                                   state="readonly")
        self._ns_cb.pack(side="left", padx=(4, 0))
        self._ns_cb.bind("<<ComboboxSelected>>", self._on_ns_change)
        ttk.Label(cf, text="Secret:").pack(side="left", padx=(6, 0))
        self._sec_cb = ttk.Combobox(cf, textvariable=self._enc_sec, width=16,
                                    state="readonly")
        self._sec_cb.pack(side="left", padx=(4, 0))
        self._load_btn = ttk.Button(cf, text="Load Template",
                                    command=self._load_template)
        if not PYYAML_OK:
            self._load_btn.configure(state="disabled")
        self._load_btn.pack(side="left", padx=(8, 0))

        # Row-based KV editor — one row per key/value, with a multiline popup
        # (Edit…) for long values like PEM certs or JSON.
        ttk.Label(p, text="Key / value pairs:").pack(anchor="w", pady=(8, 2))
        self._kv_frame = ttk.Frame(p); self._kv_frame.pack(fill="x")
        ttk.Button(p, text="+ Add", command=lambda: self._kv_add_row(focus=True)) \
            .pack(anchor="w", pady=(4, 0))
        self._kv_rows = []
        self._kv_add_row()  # always keep at least one row

        # name + namespace
        mr = ttk.Frame(p); mr.pack(fill="x", pady=(6, 2))
        ttk.Label(mr, text="Secret name:").pack(side="left")
        self._sec_name = ttk.Entry(mr, width=22, font=(MONO, SZ))
        self._sec_name.insert(0, "my-secret")
        self._sec_name.pack(side="left", padx=(4, 12))
        ttk.Label(mr, text="Namespace:").pack(side="left")
        self._sec_ns_e = ttk.Entry(mr, width=14, font=(MONO, SZ))
        self._sec_ns_e.insert(0, "default")
        self._sec_ns_e.pack(side="left", padx=(4, 12))

        # type + generate — editable combobox: pick a built-in type or type
        # any custom one; Load Template fills it from the fetched secret.
        tr = ttk.Frame(p); tr.pack(fill="x", pady=(0, 2))
        ttk.Label(tr, text="Type:").pack(side="left")
        self._sec_type = ttk.Combobox(tr, width=30, font=(MONO, SZ),
                                      values=SECRET_TYPES)
        self._sec_type.set("Opaque")
        self._sec_type.pack(side="left", padx=(4, 12))
        ttk.Button(tr, text="Generate YAML", command=self._gen_yaml).pack(side="left")

        # YAML output — fixed height so the scrollable page has a definite size
        # (an expanding pane would fight the canvas for vertical space).
        yf = ttk.Frame(p); yf.pack(fill="x", pady=(6, 2))
        xsb = ttk.Scrollbar(yf, orient="horizontal"); xsb.pack(side="bottom", fill="x")
        ysb = ttk.Scrollbar(yf, orient="vertical");   ysb.pack(side="right",  fill="y")
        self._yaml_out = tk.Text(
            yf, height=14, bg=BG3, fg=BLUE, insertbackground=FG,
            font=(MONO, SZ), relief="flat", bd=0, padx=6, pady=4, wrap="none",
            highlightthickness=1, highlightbackground=BORDER,
            xscrollcommand=xsb.set, yscrollcommand=ysb.set, state="disabled")
        self._yaml_out.pack(fill="both", expand=True)
        xsb.config(command=self._yaml_out.xview)
        ysb.config(command=self._yaml_out.yview)

        # Output actions sit below the pane now that the page scrolls.
        br = ttk.Frame(p); br.pack(fill="x", pady=(6, 0))
        ttk.Button(br, text="Copy YAML",
                   command=lambda: self._clip(self._yaml_out.get("1.0", "end"))) \
            .pack(side="left", padx=(0, 6))
        ttk.Button(br, text="Save YAML…", command=self._save_yaml).pack(side="left")

    def _sv_encode(self):
        t = self._sv_in.get()
        if not t:
            return
        self._sv_out.configure(state="normal")
        self._sv_out.delete(0, "end")
        self._sv_out.insert(0, b64_encode(t))
        self._sv_out.configure(state="readonly")
        self._status("Encoded", "ok")

    # ---------------------------------------------------------- KV row editor

    def _kv_add_row(self, key="", value="", binary=False, focus=False):
        """Append one key/value row. A `binary` row is a read-only marker for a
        template value that can't be edited as text (re-emitted verbatim on
        Generate); a normal row is an editable key Entry + value Entry, with an
        Edit… popup for long values."""
        row = ttk.Frame(self._kv_frame); row.pack(fill="x", pady=1)
        var = tk.StringVar(value=value)
        rd = {"frame": row, "binary": binary, "key": key, "var": var}

        key_e = ttk.Entry(row, font=(MONO, SZ), width=22)
        key_e.insert(0, key)
        key_e.pack(side="left")
        rd["key_e"] = key_e
        ttk.Label(row, text="=").pack(side="left", padx=4)

        if binary:
            key_e.configure(state="readonly")  # binary keys aren't text-editable
            ttk.Button(row, text="✕", style="Icon.TButton", width=2,
                       command=lambda: self._kv_del_row(rd)).pack(side="right")
            ttk.Label(row, text="⟨binary — kept as-is on Generate⟩",
                      style="Dim.TLabel").pack(side="left", fill="x",
                                               expand=True, padx=(0, 4))
        else:
            # Create the value field before the buttons so Tab moves
            # key → value → Edit… → ✕ (Tk traversal follows creation order),
            # but pack the buttons first (side="right") so the value fills the
            # gap between "=" and the buttons.
            val_e = ttk.Entry(row, textvariable=var, font=(MONO, SZ))
            rd["val_e"] = val_e
            edit_b = ttk.Button(row, text="Edit…", style="Icon.TButton",
                                command=lambda: self._kv_edit_value(rd))
            del_b = ttk.Button(row, text="✕", style="Icon.TButton", width=2,
                               command=lambda: self._kv_del_row(rd))
            del_b.pack(side="right")
            edit_b.pack(side="right", padx=(0, 4))
            val_e.pack(side="left", fill="x", expand=True, padx=(0, 4))

        self._kv_rows.append(rd)
        if focus:
            key_e.focus_set()
        return rd

    def _kv_del_row(self, rd):
        if rd in self._kv_rows:
            self._kv_rows.remove(rd)
        if rd["binary"]:
            self._tpl_binary.pop(rd["key"], None)  # drop its passthrough value
        rd["frame"].destroy()
        if not self._kv_rows:  # always keep at least one editable row
            self._kv_add_row()

    def _kv_clear(self):
        for rd in list(self._kv_rows):
            rd["frame"].destroy()
        self._kv_rows.clear()
        self._kv_add_row()

    def _kv_set_pairs(self, pairs, binary_keys=None):
        """Replace all rows with `pairs` (key, value) plus a read-only marker row
        for each key in `binary_keys`. Keeps one blank row if everything's empty."""
        for rd in list(self._kv_rows):
            rd["frame"].destroy()
        self._kv_rows.clear()
        for k, v in pairs:
            self._kv_add_row(k, v)
        for k in (binary_keys or []):
            self._kv_add_row(k, binary=True)
        if not self._kv_rows:
            self._kv_add_row()

    def _kv_get_pairs(self):
        """Editable rows as {key: value}, reading values from the StringVars.
        Blank keys (and binary marker rows) are skipped; last duplicate wins."""
        pairs = {}
        for rd in self._kv_rows:
            if rd["binary"]:
                continue
            key = rd["key_e"].get().strip()
            if key:
                pairs[key] = rd["var"].get()
        return pairs

    def _kv_edit_value(self, rd):
        """Modal multiline editor for one row's value (PEM certs/keys, JSON)."""
        top = tk.Toplevel(self)
        top.title("Edit value")
        top.configure(bg=BG2)
        top.transient(self)
        top.geometry("760x520")
        top.minsize(480, 320)
        key = rd["key_e"].get().strip() or "value"

        # Buttons go in first, packed to the bottom, so a tall value can't push
        # them off-screen / clip them.
        btns = ttk.Frame(top, padding=(10, 8)); btns.pack(side="bottom", fill="x")

        def save(_=None):
            rd["var"].set(txt.get("1.0", "end-1c"))
            top.destroy()

        ttk.Button(btns, text="Save", style="Accent.TButton", command=save) \
            .pack(side="right")
        ttk.Button(btns, text="Cancel", command=top.destroy) \
            .pack(side="right", padx=(0, 6))
        ttk.Label(btns, text="⌘/Ctrl+Enter to save · Esc to cancel",
                  style="Dim.TLabel").pack(side="left")

        ttk.Label(top, text=f"Value for {key}", style="Head.TLabel") \
            .pack(anchor="w", padx=10, pady=(10, 4))
        ef = ttk.Frame(top, padding=(10, 0)); ef.pack(fill="both", expand=True)
        sb = ttk.Scrollbar(ef, orient="vertical"); sb.pack(side="right", fill="y")
        txt = tk.Text(ef, bg=BG3, fg=FG, insertbackground=FG, font=(MONO, SZ),
                      relief="flat", bd=0, padx=6, pady=4, wrap="word",
                      highlightthickness=1, highlightbackground=BORDER,
                      highlightcolor=ACCENT, yscrollcommand=sb.set)
        txt.pack(side="left", fill="both", expand=True)
        sb.config(command=txt.yview)
        txt.insert("1.0", rd["var"].get())
        txt.focus_set()

        top.bind("<Escape>", lambda _: top.destroy())
        txt.bind("<Command-Return>", save)
        txt.bind("<Control-Return>", save)
        top.grab_set()  # modal

    def _browse_env(self):
        path = filedialog.askopenfilename(
            filetypes=[(".env files", "*.env"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path) as f:
                text = f.read()
        except (OSError, UnicodeDecodeError) as e:
            self._status(f"Could not read file: {e}", "err"); return
        self._env_lbl.configure(text=path)
        self._tpl_binary = {}  # a plain .env carries no binary passthrough
        self._kv_set_pairs(parse_dotenv(text).items())
        self._sec_type.set("Opaque")
        self._status(f"Loaded {os.path.basename(path)}", "ok")

    def _clear_env(self):
        self._env_lbl.configure(text="(no file)")
        self._tpl_binary = {}
        self._kv_clear()
        self._set_text(self._yaml_out, "")
        self._sec_type.set("Opaque")
        self._status("Cleared", "ok")

    def _gen_yaml(self):
        data = self._kv_get_pairs()
        # Binary keys from a loaded template are re-emitted verbatim; an edited
        # plaintext key of the same name wins over the original.
        raw = {k: v for k, v in self._tpl_binary.items() if k not in data}
        if not data and not raw:
            self._status("No KEY=VALUE pairs found", "err"); return
        name  = self._sec_name.get().strip() or "my-secret"
        ns    = self._sec_ns_e.get().strip()  or "default"
        type_ = self._sec_type.get().strip()
        if not type_:
            type_ = "Opaque"
            self._sec_type.set(type_)
        self._set_text(self._yaml_out,
                       build_secret_yaml(name, ns, data, type_, raw_data=raw))
        msg = f"Generated YAML with {len(data) + len(raw)} key(s)"
        if raw:
            msg += f" ({len(raw)} binary kept as-is)"
        self._status(msg, "ok")

    def _save_yaml(self):
        name = self._sec_name.get().strip() or "my-secret"
        path = filedialog.asksaveasfilename(
            defaultextension=".yaml", initialfile=f"{name}.yaml",
            filetypes=[("YAML", "*.yaml"), ("All", "*.*")])
        if not path:
            return
        self._write_file(path, self._yaml_out.get("1.0", "end-1c"))

    # ---------------------------------------------------------------- decode tab

    def _build_decode_tab(self, p):
        ttk.Label(p, text="Single Value Decoder", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        # Buttons packed right-first so they stay visible; the entry fills the gap.
        r = ttk.Frame(p); r.pack(fill="x", pady=2)
        ttk.Button(r, text="Decode →", command=self._sv_decode) \
            .pack(side="right", padx=(6, 0))
        self._dv_in = ttk.Entry(r, font=(MONO, SZ))
        self._dv_in.pack(side="left", fill="x", expand=True)
        self._dv_in.bind("<Return>", lambda _: self._sv_decode())

        r2 = ttk.Frame(p); r2.pack(fill="x", pady=2)
        self._dv_var = tk.StringVar()
        ttk.Button(r2, text="Copy", command=lambda: self._clip(self._dv_var.get())) \
            .pack(side="right", padx=(6, 0))
        self._dv_shown = False
        self._dv_tog = ttk.Button(r2, text="Show", command=self._toggle_dv)
        self._dv_tog.pack(side="right", padx=(6, 0))
        self._dv_out = ttk.Entry(r2, textvariable=self._dv_var, font=(MONO, SZ),
                                 state="readonly", show="•")
        self._dv_out.pack(side="left", fill="x", expand=True)

        if not PYYAML_OK:
            ttk.Label(p, text="⚠  PyYAML not installed — YAML decode table disabled",
                      style="Warn.TLabel").pack(anchor="w", pady=4)

        ttk.Separator(p).pack(fill="x", pady=10)

        ttk.Label(p, text="Kubernetes Secret YAML → Decoded Table",
                  style="Head.TLabel").pack(anchor="w", pady=(0, 4))

        fp = ttk.Frame(p); fp.pack(fill="x", pady=2)
        ttk.Label(fp, text="File:").pack(side="left")
        self._dec_lbl = ttk.Label(fp, text="(no file)", style="Dim.TLabel")
        self._dec_lbl.pack(side="left", padx=6)
        ttk.Button(fp, text="Browse…", command=self._browse_yaml).pack(side="left")
        ttk.Button(fp, text="Show All", command=lambda: self._tbl_show_all(True)) \
            .pack(side="left", padx=(10, 0))
        ttk.Button(fp, text="Hide All", command=lambda: self._tbl_show_all(False)) \
            .pack(side="left", padx=(6, 0))

        # fixed header
        cols = [("Key", 22), ("Decoded value", 40), ("Actions", 16)]
        hdr = tk.Frame(p, bg=BG3)
        hdr.pack(fill="x", pady=(8, 0))
        for txt, w in cols:
            tk.Label(hdr, text=txt, bg=BG3, fg=ACCENT, width=w, anchor="w",
                     padx=6, pady=4, font=(SANS, SZ, "bold")).pack(side="left")

        # scrollable canvas body
        body = ttk.Frame(p); body.pack(fill="both", expand=True)
        vsb = ttk.Scrollbar(body, orient="vertical"); vsb.pack(side="right", fill="y")
        self._tbl_cv = tk.Canvas(body, bg=BG2, bd=0, highlightthickness=0,
                                 yscrollincrement=1, yscrollcommand=vsb.set)
        self._tbl_cv.pack(side="left", fill="both", expand=True)
        vsb.config(command=self._tbl_cv.yview)

        self._tbl_body = tk.Frame(self._tbl_cv, bg=BG2)
        self._tbl_win = self._tbl_cv.create_window((0, 0), window=self._tbl_body,
                                                   anchor="nw")
        self._tbl_body.bind("<Configure>",
            lambda e: self._tbl_cv.configure(scrollregion=self._tbl_cv.bbox("all")))
        self._tbl_cv.bind("<Configure>",
            lambda e: self._tbl_cv.itemconfig(self._tbl_win, width=e.width))
        # Wheel scrolling is handled globally by _on_wheel, which routes to this
        # canvas while the Decode tab is showing (see self._tab_canvas).

        self._tbl_rows = []

    def _sv_decode(self):
        t = self._dv_in.get().strip()
        if not t:
            return
        try:
            result = b64_decode(t)
        except Exception as e:
            self._status(f"Decode error: {e}", "err"); return
        self._dv_var.set(result)
        self._status("Decoded", "ok")

    def _toggle_dv(self):
        self._dv_shown = not self._dv_shown
        self._dv_out.configure(show="" if self._dv_shown else "•")
        self._dv_tog.configure(text="Hide" if self._dv_shown else "Show")

    def _browse_yaml(self):
        if not PYYAML_OK:
            self._status("PyYAML not installed", "err"); return
        path = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml *.yml"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path) as f:
                content = f.read()
        except (OSError, UnicodeDecodeError) as e:
            self._status(f"Could not read file: {e}", "err"); return
        self._dec_lbl.configure(text=path)
        self._populate_table(content)

    def _populate_table(self, content: str):
        try:
            doc = yaml.safe_load(content)
        except yaml.YAMLError as e:
            self._status(f"YAML parse error: {e}", "err"); return

        entries = secret_entries(doc)  # data + stringData, decoded

        for w in self._tbl_body.winfo_children():
            w.destroy()
        self._tbl_rows.clear()

        for i, (key, value, kind) in enumerate(entries):
            binary = kind == "binary"
            # Binary values can't be shown as text; display a marker and let
            # Copy hand back the raw base64 instead of rendering mojibake.
            shown = "⟨binary — Copy gives base64⟩" if binary else value
            masked = shown if binary else "•" * min(len(shown), 32)
            bg = ROW_A if i % 2 == 0 else ROW_B
            row = tk.Frame(self._tbl_body, bg=bg)
            row.pack(fill="x")

            tk.Label(row, text=key, bg=bg, fg=FG, width=22, anchor="w",
                     padx=6, pady=3, font=(MONO, SZ)).pack(side="left")
            sv = tk.BooleanVar(value=False)
            vl = tk.Label(row, text=masked, bg=bg, fg=BLUE, width=40, anchor="w",
                          padx=6, pady=3, font=(MONO, SZ))
            vl.pack(side="left")

            af = tk.Frame(row, bg=bg)
            af.pack(side="left", fill="x")

            tb = tk.Button(af, text="Show", bg=BG3, fg=FG,
                           activebackground=BORDER, activeforeground=FG,
                           relief="flat", bd=0, padx=8, pady=1, font=(SANS, SZ - 1),
                           highlightthickness=0, cursor="hand2")
            if binary:
                tb.configure(state="disabled")  # nothing to reveal
            else:
                tb.configure(command=lambda shown=shown, masked=masked, sv=sv,
                             vl=vl, tb=tb: self._set_row_visible(
                                 shown, masked, sv, vl, tb, not sv.get()))
            tb.pack(side="left", padx=(6, 2), pady=2)
            tk.Button(af, text="Copy", bg=BG3, fg=FG,
                      activebackground=BORDER, activeforeground=FG,
                      relief="flat", bd=0, padx=8, pady=1, font=(SANS, SZ - 1),
                      highlightthickness=0, cursor="hand2",
                      command=lambda d=value: self._clip(d)).pack(side="left", pady=2)

            self._tbl_rows.append((shown, masked, sv, vl, tb, binary))

        self._tbl_body.update_idletasks()
        self._tbl_cv.configure(scrollregion=self._tbl_cv.bbox("all"))
        self._status(f"Loaded {len(entries)} key(s)", "ok")

    @staticmethod
    def _set_row_visible(shown, masked, sv, vl, tb, show):
        """Reveal/hide one decoded-table row."""
        vl.configure(text=shown if show else masked)
        sv.set(show)
        tb.configure(text="Hide" if show else "Show")

    def _tbl_show_all(self, show: bool):
        for shown, masked, sv, vl, tb, binary in self._tbl_rows:
            if not binary:  # binary rows have nothing to reveal
                self._set_row_visible(shown, masked, sv, vl, tb, show)

    # ----------------------------------------------------------------- seal tab

    def _build_seal_tab(self, p):
        ttk.Label(p, text="Seal Kubernetes Secret", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        cs = ttk.Frame(p); cs.pack(fill="x", pady=2)
        ttk.Label(cs, text="Context:").pack(side="left")
        self._seal_ctx = tk.StringVar()
        self._seal_ctx_cb = ttk.Combobox(cs, textvariable=self._seal_ctx, width=20,
                                         state="readonly")
        self._seal_ctx_cb.bind("<<ComboboxSelected>>", self._on_seal_ctx_change)
        self._seal_ctx_cb.pack(side="left", padx=(4, 4))
        # Re-read kubeconfig: picks up a context for a cluster created after the
        # app started, without a restart.
        ttk.Button(cs, text="⟳", style="Icon.TButton", width=2,
                   command=self._fetch_contexts).pack(side="left", padx=(0, 14))
        ttk.Label(cs, text="Scope:").pack(side="left")
        self._seal_scope = tk.StringVar(value="strict")
        ttk.Combobox(cs, textvariable=self._seal_scope, width=16, state="readonly",
                     values=["strict", "namespace-wide", "cluster-wide"]) \
            .pack(side="left", padx=(4, 0))

        # Controller name / namespace — auto-detected from the cluster and shown
        # read-only (no manual entry; they refresh when the context changes).
        ctl = ttk.Frame(p); ctl.pack(fill="x", pady=(6, 2))
        ttk.Label(ctl, text="Controller name:").pack(side="left")
        self._ctl_name = ttk.Entry(ctl, width=28, font=(MONO, SZ),
                                   state="readonly", style="RO.TEntry")
        self._ctl_name.pack(side="left", padx=(4, 12))
        ttk.Label(ctl, text="NS:").pack(side="left")
        self._ctl_ns = ttk.Entry(ctl, width=16, font=(MONO, SZ),
                                  state="readonly", style="RO.TEntry")
        self._ctl_ns.pack(side="left", padx=(4, 0))

        cr = ttk.Frame(p); cr.pack(fill="x", pady=(6, 2))
        ttk.Label(cr, text="Cert (optional):").pack(side="left")
        self._cert_lbl = ttk.Label(cr, text="(none)", style="Dim.TLabel")
        self._cert_lbl.pack(side="left", padx=6)
        ttk.Button(cr, text="Browse…", command=self._browse_cert).pack(side="left")
        ttk.Button(cr, text="✕", style="Icon.TButton", width=2,
                   command=self._clear_cert).pack(side="left", padx=3)
        self._cert = ""

        sr = ttk.Frame(p); sr.pack(fill="x", pady=10)
        self._seal_btn = ttk.Button(sr, text="⊙  Seal →", style="Accent.TButton",
                                    command=self._do_seal)
        self._seal_btn.pack(side="left")
        # Enabled only once there is sealed output to check; asks the controller
        # to test-decrypt it (creates nothing — stays within the read-only promise).
        self._validate_btn = ttk.Button(sr, text="Validate", command=self._do_validate,
                                         state="disabled")
        self._validate_btn.pack(side="left", padx=(6, 0))
        ttk.Label(sr, text="Seals the YAML generated on the Encode tab",
                  style="Dim.TLabel").pack(side="left", padx=10)

        # Sealed output — fixed height so the scrollable page has a definite size.
        of_ = ttk.Frame(p); of_.pack(fill="x", pady=2)
        xsb = ttk.Scrollbar(of_, orient="horizontal"); xsb.pack(side="bottom", fill="x")
        ysb = ttk.Scrollbar(of_, orient="vertical");   ysb.pack(side="right",  fill="y")
        self._sealed_out = tk.Text(
            of_, height=14, bg=BG3, fg=BLUE, insertbackground=FG,
            font=(MONO, SZ), relief="flat", bd=0, padx=6, pady=4, wrap="none",
            highlightthickness=1, highlightbackground=BORDER,
            xscrollcommand=xsb.set, yscrollcommand=ysb.set, state="disabled")
        self._sealed_out.pack(fill="both", expand=True)
        xsb.config(command=self._sealed_out.xview)
        ysb.config(command=self._sealed_out.yview)

        # Output actions sit below the pane now that the page scrolls.
        br = ttk.Frame(p); br.pack(fill="x", pady=(6, 0))
        ttk.Button(br, text="Copy Sealed",
                   command=lambda: self._clip(self._sealed_out.get("1.0", "end"))) \
            .pack(side="left", padx=(0, 6))
        ttk.Button(br, text="Save Sealed…", command=self._save_sealed).pack(side="left")

    def _browse_cert(self):
        path = filedialog.askopenfilename(
            filetypes=[("Certs", "*.pem *.crt *.cer"), ("All", "*.*")])
        if path:
            self._cert = path
            self._cert_lbl.configure(text=path)

    def _clear_cert(self):
        self._cert = ""
        self._cert_lbl.configure(text="(none)")

    def _do_seal(self):
        yaml_text = self._yaml_out.get("1.0", "end").strip()
        if not yaml_text:
            self._status("Generate YAML on the Encode tab first", "err"); return
        # Without a cert, kubeseal fetches the cert from the controller; if its
        # lookup hasn't landed yet we'd silently seal against kubeseal's defaults
        # (wrong cert → undecryptable). With a cert the controller is irrelevant.
        if not self._cert and self._ctl_pending == self._seal_ctx.get():
            self._status("Detecting controller… try again in a moment", "dim"); return
        cmd = kubeseal_seal_cmd(
            self._seal_scope.get(),
            context=self._seal_ctx.get() or None,
            cert=self._cert or None,
            ctl_name=self._ctl_name.get().strip() or None,
            ctl_ns=self._ctl_ns.get().strip() or None)
        # Sealing disables both buttons (the current sealed output, and thus any
        # validation of it, is about to be replaced) until _on_sealed lands.
        self._sealing = True
        self._refresh_action_buttons()
        self._status("Sealing…", "dim")
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._on_sealed(o, e, r)),
               stdin_data=yaml_text)

    @staticmethod
    def _kubeseal_rc_error(rc):
        """Map run_bg's sentinel return codes to a status message, or None."""
        if rc == -1:
            return "kubeseal not in PATH"
        if rc == -2:
            return "kubeseal timed out"
        return None

    def _on_sealed(self, stdout, stderr, rc):
        self._sealing = False
        sentinel = self._kubeseal_rc_error(rc)
        if sentinel:
            self._refresh_action_buttons()
            self._status(sentinel, "err"); return
        if rc != 0:
            err = stderr.strip() or "kubeseal failed"
            # Show the full error in the output pane (it scrolls); the status bar
            # only fits one truncated line.
            self._set_text(self._sealed_out, "# kubeseal error\n" + err)
            self._refresh_action_buttons()
            self._status(f"kubeseal error: {err.splitlines()[-1][:90]}", "err")
            return
        self._set_text(self._sealed_out, stdout)
        self._refresh_action_buttons()
        self._status("Sealed successfully", "ok")

    def _sealed_output(self) -> str:
        """The sealed YAML in the output pane, or '' when empty / an error."""
        sealed = self._sealed_out.get("1.0", "end").strip()
        return "" if not sealed or sealed.startswith("# kubeseal error") else sealed

    def _refresh_action_buttons(self):
        """Single source of truth for the Seal / Validate button states. Seal is
        live unless a controller lookup or a seal is in flight; Validate also
        needs sealed output and no validate already running."""
        detecting = self._ctl_pending == self._seal_ctx.get()
        self._seal_btn.configure(
            state="disabled" if (detecting or self._sealing) else "normal")
        can_validate = (bool(self._sealed_output())
                        and not detecting and not self._sealing
                        and not self._validating)
        self._validate_btn.configure(state="normal" if can_validate else "disabled")

    def _do_validate(self):
        # Round-trips the sealed output through the controller's verify endpoint:
        # catches a wrong key/controller, wrong scope, or wrong name/namespace —
        # the mis-seals that otherwise only surface at apply time. Creates nothing.
        sealed = self._sealed_output()
        if not sealed:
            self._status("Seal a secret first", "err"); return
        # Controller lookup for the current context hasn't landed yet — validating
        # now would hit an empty/stale controller and fail confusingly.
        if self._ctl_pending == self._seal_ctx.get():
            self._status("Detecting controller… try again in a moment", "dim"); return
        cmd = kubeseal_validate_cmd(
            context=self._seal_ctx.get() or None,
            ctl_name=self._ctl_name.get().strip() or None,
            ctl_ns=self._ctl_ns.get().strip() or None)
        self._validating = True
        self._refresh_action_buttons()
        self._status("Validating…", "dim")
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._on_validated(o, e, r)),
               stdin_data=sealed)

    def _on_validated(self, stdout, stderr, rc):
        self._validating = False
        self._refresh_action_buttons()
        sentinel = self._kubeseal_rc_error(rc)
        if sentinel:
            self._status(sentinel, "err"); return
        if rc != 0:
            # kubeseal prints the reason (e.g. "unable to decrypt") to stderr.
            err = (stderr.strip() or "validation failed").splitlines()[-1][:90]
            self._status(f"Invalid seal: {err}", "err"); return
        self._status("Valid — the controller can decrypt this", "ok")

    def _save_sealed(self):
        name = self._sec_name.get().strip() or "my-secret"
        path = filedialog.asksaveasfilename(
            defaultextension=".yaml", initialfile=f"sealed-{name}.yaml",
            filetypes=[("YAML", "*.yaml"), ("All", "*.*")])
        if not path:
            return
        self._write_file(path, self._sealed_out.get("1.0", "end-1c"))

    # -------------------------------------------------------- kubectl integration

    def _fetch_contexts(self):
        run_bg(["kubectl", "config", "get-contexts", "-o", "name"],
               lambda o, e, r: self.after(0, lambda: self._got_contexts(o, e, r)))

    def _got_contexts(self, stdout, stderr, rc):
        if rc == -1:
            self._status("kubectl not in PATH", "err"); return
        if rc != 0:
            self._status(f"kubectl error: {stderr.strip()[:60]}", "err"); return
        ctxs = [c.strip() for c in stdout.splitlines() if c.strip()]
        self._ctx_cb["values"] = ctxs
        self._seal_ctx_cb["values"] = ctxs
        if ctxs and not self._enc_ctx.get():
            self._enc_ctx.set(ctxs[0])
            self._seal_ctx.set(ctxs[0])
            self._fetch_namespaces(ctxs[0])
            self._detect_controller(ctxs[0])
        else:
            # A manual refresh (button); confirm so the user knows it landed and
            # whether a freshly-created context showed up.
            self._status(f"Loaded {len(ctxs)} context(s)", "ok")

    def _on_ctx_change(self, _=None):
        ctx = self._enc_ctx.get()
        self._seal_ctx.set(ctx)
        self._enc_ns.set(""); self._enc_sec.set("")
        self._ns_cb["values"] = []; self._sec_cb["values"] = []
        # Controller is cluster-specific — clear so detection refills for the new ctx.
        self._set_ro_entry(self._ctl_name, ""); self._set_ro_entry(self._ctl_ns, "")
        if ctx:
            self._fetch_namespaces(ctx)
            self._detect_controller(ctx)

    def _on_seal_ctx_change(self, _=None):
        # Seal context picked independently of the Encode tab — re-detect the
        # controller for the chosen cluster so the fields match what we seal against.
        ctx = self._seal_ctx.get()
        self._set_ro_entry(self._ctl_name, ""); self._set_ro_entry(self._ctl_ns, "")
        if ctx:
            self._detect_controller(ctx)

    def _detect_controller(self, ctx: str):
        """Find the sealed-secrets controller service in the cluster and
        auto-fill the Controller name / NS fields (read-only lookup)."""
        self._ctl_pending = ctx
        # Block Seal/Validate while the controller for the new context resolves —
        # acting now would seal/validate against an empty or stale controller.
        self._refresh_action_buttons()
        cmd = ["kubectl", "get", "svc", "-A", f"--context={ctx}", "-o",
               "jsonpath={range .items[*]}{.metadata.namespace}{'\\t'}"
               "{.metadata.name}{'\\n'}{end}"]
        run_bg(cmd, lambda o, e, r: self.after(0,
               lambda: self._got_controller(ctx, o, e, r)))

    def _got_controller(self, ctx, stdout, stderr, rc):
        # Lookups run on background threads and resolve out of order; ignore a
        # stale result if the user has since switched to a different context.
        if ctx != self._seal_ctx.get():
            return
        # This is the result for the current context — detection is no longer in
        # flight, whatever the outcome (error / no controller / found). Re-enable
        # the buttons, unless a seal/validate is still running under us.
        self._ctl_pending = None
        self._refresh_action_buttons()
        if rc != 0:
            return
        svcs = []
        for line in stdout.splitlines():
            if "\t" not in line:
                continue
            ns, name = line.split("\t", 1)
            if "sealed-secrets" in name and "metrics" not in name:
                svcs.append((ns.strip(), name.strip()))
        if not svcs:
            return
        # Prefer the canonical "sealed-secrets-controller" service if present.
        ns, name = next((s for s in svcs if s[1] == "sealed-secrets-controller"),
                        svcs[0])
        self._set_ro_entry(self._ctl_name, name)
        self._set_ro_entry(self._ctl_ns, ns)
        self._status(f"Sealed-secrets controller: {ns}/{name}", "ok")

    def _fetch_namespaces(self, ctx: str):
        cmd = ["kubectl", "get", "namespaces", f"--context={ctx}",
               "-o", "jsonpath={.items[*].metadata.name}"]
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._got_ns(ctx, o, e, r)))

    def _got_ns(self, ctx, stdout, stderr, rc):
        # Lookups run on background threads and resolve out of order; ignore a
        # stale result if the user has since switched to a different context.
        if ctx != self._enc_ctx.get():
            return
        if rc != 0:
            self._status(f"Namespace fetch failed: {stderr.strip()[:60]}", "err"); return
        nss = stdout.strip().split()
        self._ns_cb["values"] = nss
        if nss:
            self._enc_ns.set(nss[0])
            self._fetch_secrets(ctx, nss[0])

    def _on_ns_change(self, _=None):
        self._enc_sec.set(""); self._sec_cb["values"] = []
        ctx, ns = self._enc_ctx.get(), self._enc_ns.get()
        if ctx and ns:
            self._fetch_secrets(ctx, ns)

    def _fetch_secrets(self, ctx: str, ns: str):
        cmd = ["kubectl", "get", "secrets", f"--context={ctx}", f"--namespace={ns}",
               "-o", "jsonpath={.items[*].metadata.name}"]
        run_bg(cmd, lambda o, e, r: self.after(0,
               lambda: self._got_secrets(ctx, ns, o, e, r)))

    def _got_secrets(self, ctx, ns, stdout, stderr, rc):
        if ctx != self._enc_ctx.get() or ns != self._enc_ns.get():
            return
        if rc != 0:
            return
        secs = stdout.strip().split()
        self._sec_cb["values"] = secs
        if secs:
            self._enc_sec.set(secs[0])

    def _load_template(self):
        ctx, ns, sec = self._enc_ctx.get(), self._enc_ns.get(), self._enc_sec.get()
        if not all([ctx, ns, sec]):
            self._status("Select context, namespace, and secret first", "err"); return
        cmd = ["kubectl", "get", "secret", sec,
               f"--context={ctx}", f"--namespace={ns}", "-o", "yaml"]
        self._load_btn.configure(state="disabled")
        run_bg(cmd, lambda o, e, r: self.after(0,
               lambda: self._got_template(ctx, ns, sec, o, e, r)))

    def _got_template(self, ctx, ns, sec, stdout, stderr, rc):
        # Re-enable the button regardless — the load attempt is done — *before*
        # the stale check, or a discarded result would leave it stuck disabled.
        self._load_btn.configure(state="normal" if PYYAML_OK else "disabled")
        # Guard against a stale load: the user may have changed the context /
        # namespace / secret while this kubectl fetch was in flight.
        if (ctx, ns, sec) != (self._enc_ctx.get(), self._enc_ns.get(),
                              self._enc_sec.get()):
            return
        if rc != 0:
            self._status(f"kubectl error: {stderr.strip()[:80]}", "err"); return
        try:
            doc = yaml.safe_load(stdout)
        except yaml.YAMLError as e:
            self._status(f"YAML parse error: {e}", "err"); return

        self._tpl_binary = {}
        text_pairs = []
        entries = secret_entries(doc)  # data + stringData, decoded
        for k, value, kind in entries:
            if kind == "binary":
                # Can't edit binary as text without corrupting it on re-encode:
                # keep the original base64 and re-emit it verbatim at Generate
                # (tracked in _tpl_binary). A marker row shows it in the editor.
                self._tpl_binary[k] = value
            else:
                text_pairs.append((k, value))
        self._kv_set_pairs(text_pairs, binary_keys=list(self._tpl_binary.keys()))

        # Also populate the editable Secret name / Namespace fields from the
        # fetched secret's metadata (falling back to the selected combo values),
        # so they can be tweaked before Generate YAML.
        meta = doc.get("metadata", {}) if isinstance(doc, dict) else {}
        name = meta.get("name") or sec
        nsv  = meta.get("namespace") or ns
        self._sec_name.delete(0, "end"); self._sec_name.insert(0, name)
        self._sec_ns_e.delete(0, "end"); self._sec_ns_e.insert(0, nsv)
        self._sec_type.set(
            (doc.get("type") if isinstance(doc, dict) else None) or "Opaque")

        binary = len(self._tpl_binary)
        msg = f"Loaded {len(entries)} key(s) from {sec}"
        if binary:
            msg += f" — {binary} binary value(s) kept as-is"
        self._status(msg, "ok")

    # --------------------------------------------------------------- helpers

    def _set_ro_entry(self, entry: "tk.Entry", value: str):
        """Set the text of a read-only ttk.Entry (toggles state to write)."""
        entry.configure(state="normal")
        entry.delete(0, "end")
        entry.insert(0, value)
        entry.configure(state="readonly")

    def _set_text(self, widget: tk.Text, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _run_async(self, work, done):
        """Run work() on a daemon thread, then done(result) on the UI thread.
        Drops the result if the app is destroyed mid-call (window closed)."""
        def worker():
            result = work()
            try:
                self.after(0, done, result)
            except (tk.TclError, RuntimeError):
                pass
        threading.Thread(target=worker, daemon=True).start()

    def _clip(self, text: str):
        payload = text.rstrip("\n")
        # On X11 the Tk clipboard is lost when the app exits, so prefer a real
        # clipboard manager (xclip/xsel) that keeps the value after we quit. It
        # can block, so run it off the UI thread and fall back to the Tk
        # clipboard (handled on the main thread by _clip_done).
        if sys.platform.startswith("linux"):
            self._run_async(lambda: self._clip_external(payload),
                            lambda ok: self._clip_done(ok, payload))
        else:
            self._clip_done(False, payload)

    def _clip_done(self, external_ok: bool, payload: str):
        if not external_ok:  # no external tool — Tk clipboard (lost on exit)
            self.clipboard_clear()
            self.clipboard_append(payload)
        self._status("Copied to clipboard", "ok")

    @staticmethod
    def _clip_external(text: str) -> bool:
        # Encode stdin as UTF-8 explicitly: with text=True a non-UTF-8 locale
        # (e.g. LC_ALL=C) raises UnicodeEncodeError on non-ASCII secrets.
        # Keep the timeout short — a well-behaved xclip/xsel forks and returns
        # at once; this only bounds a misbehaving build.
        for cmd in (["xclip", "-selection", "clipboard"],
                    ["xsel", "--clipboard", "--input"]):
            try:
                subprocess.run(cmd, input=text, encoding="utf-8",
                               timeout=1, check=True)
                return True
            except (OSError, ValueError, subprocess.SubprocessError):
                continue
        return False

    def _write_file(self, path: str, content: str):
        try:
            write_secret_file(path, content)  # owner-only (0o600) — holds secrets
            self._status(f"Saved {os.path.basename(path)}", "ok")
        except OSError as e:
            self._status(f"Save failed: {e}", "err")


if __name__ == "__main__":
    App().mainloop()
