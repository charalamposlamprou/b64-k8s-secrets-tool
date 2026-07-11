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
    first_invalid_key,
    has_sealed_secret,
    kubeseal_seal_cmd,
    kubeseal_validate_cmd,
    parse_dotenv,
    secret_carryover,
    secret_entries,
    select_secret_doc,
    write_secret_file,
)

# Fallback Secret identity when the fields are blank / nothing was loaded.
# Single source of truth — the same pair feeds the widget defaults, Generate,
# and the save-dialog filenames.
DEF_NAME = "my-secret"
DEF_NS = "default"

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
        # Editor generation, bumped by _invalidate_outputs. A seal/validate
        # captures it at dispatch; a result landing after the editor was
        # repopulated is stale (it describes the previous secret) and is
        # discarded instead of resurrecting the just-cleared output pane.
        self._out_gen = 0

        self._enc_ctx = tk.StringVar()
        self._enc_ns  = tk.StringVar()
        self._enc_sec = tk.StringVar()

        # Binary (non-UTF-8) values from a loaded template, kept as their
        # original base64 so Generate YAML can re-emit them verbatim instead of
        # silently dropping them (they can't be edited as plaintext .env).
        self._tpl_binary = {}
        # Carry-over metadata (labels / annotations / immutable) from a loaded
        # or imported Secret doc, re-emitted by Generate so a fix-and-reapply
        # round-trip doesn't strip GitOps ownership or the immutability flag.
        # _tpl_skipped counts fields dropped as malformed, so Generate's status
        # can flag a lossy round-trip instead of claiming full fidelity.
        self._tpl_carry = {}
        self._tpl_skipped = 0

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

    def _status(self, msg: str, kind: str = "dim", duration_ms: int = 4000):
        color = {"ok": OK_C, "err": ERR_C, "dim": FGDIM}.get(kind, FGDIM)
        self._status_var.set(msg)
        self._status_lbl.configure(fg=color)
        if self._status_job:
            self.after_cancel(self._status_job)
        def _reset():
            self._status_var.set("Ready")
            self._status_lbl.configure(fg=FGDIM)
            self._status_job = None
        self._status_job = self.after(duration_ms, _reset)

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
        # The input is the plaintext secret, so mask it by default (like the
        # Decode tab masks its decoded output) with a Show/Hide toggle.
        r = ttk.Frame(p); r.pack(fill="x", pady=2)
        ttk.Button(r, text="Encode →", command=self._sv_encode) \
            .pack(side="right", padx=(6, 0))
        self._sv_in = ttk.Entry(r, font=(MONO, SZ), show="•")
        self._sv_shown = False
        self._sv_tog = ttk.Button(r, text="Show", command=self._toggle_sv)
        self._sv_tog.pack(side="right", padx=(6, 0))
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

        # file picker — buttons live in a right-pinned sub-frame so a long file
        # path can't push them off-screen; the path label takes the middle and
        # clips if too long. The sub-frame keeps Tab order matching the layout.
        fp = ttk.Frame(p); fp.pack(fill="x", pady=2)
        ttk.Label(fp, text="File:").pack(side="left")
        env_btns = ttk.Frame(fp); env_btns.pack(side="right")
        ttk.Button(env_btns, text="Browse…", command=self._browse_env).pack(side="left")
        # Import an existing Secret YAML from disk (e.g. one that never made it
        # into the cluster, so Load Template can't fetch it) to edit and re-emit.
        imp_btn = ttk.Button(env_btns, text="Import Secret…",
                             command=self._import_secret)
        if not PYYAML_OK:
            imp_btn.configure(state="disabled")
        imp_btn.pack(side="left", padx=(6, 0))
        ttk.Button(env_btns, text="Clear", command=self._clear_env) \
            .pack(side="left", padx=(6, 0))
        self._env_lbl = ttk.Label(fp, text="(no file)", style="Dim.TLabel", anchor="w")
        self._env_lbl.pack(side="left", padx=6, fill="x", expand=True)

        # cluster fetch row
        cf = ttk.Frame(p); cf.pack(fill="x", pady=(6, 2))
        # Pin Load Template to the right (packed first so it reserves the right
        # edge) so the Context/NS/Secret combos can't push it off-screen; the
        # Secret combo expands to take the slack between them.
        self._load_btn = ttk.Button(cf, text="Load Template",
                                    command=self._load_template)
        if not PYYAML_OK:
            self._load_btn.configure(state="disabled")
        self._load_btn.pack(side="right", padx=(8, 0))

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
        self._sec_cb.pack(side="left", padx=(4, 0), fill="x", expand=True)
        # Load Template was created first (to reserve the right edge); raise it
        # to the top of the stacking order so Tab reaches it last — matching its
        # rightmost visual position rather than its creation order.
        self._load_btn.lift()

        # Persistent malformed-metadata warning. A transient status line is
        # the wrong home for "your generated YAML will be lossy": it auto-
        # clears, and any later Save/Seal success message overwrites it. This
        # label stays on screen for as long as the loaded secret carries
        # skipped fields (shown/hidden by _refresh_skip_warning, driven from
        # the _invalidate_outputs choke point so it can never go stale).
        self._skip_lbl = ttk.Label(p, style="Warn.TLabel", anchor="w")

        # Row-based KV editor — one row per key/value, with a multiline popup
        # (Edit…) for long values like PEM certs or JSON.
        # Column header bar, mirroring the Decode tab's decoded-table header so
        # the editor reads as a table (Key | Value | Actions) instead of rows
        # joined by "=".
        kv_hdr = tk.Frame(p, bg=BG3); kv_hdr.pack(fill="x", pady=(8, 0))
        self._skip_anchor = kv_hdr  # the warning re-packs just above the editor
        tk.Label(kv_hdr, text="Key", bg=BG3, fg=ACCENT, width=22, anchor="w",
                 padx=6, pady=4, font=(SANS, SZ, "bold")).pack(side="left")
        tk.Label(kv_hdr, text="Actions", bg=BG3, fg=ACCENT, anchor="e",
                 padx=6, pady=4, font=(SANS, SZ, "bold")).pack(side="right")
        tk.Label(kv_hdr, text="Value", bg=BG3, fg=ACCENT, anchor="w",
                 padx=6, pady=4, font=(SANS, SZ, "bold")) \
            .pack(side="left", fill="x", expand=True)
        self._kv_frame = ttk.Frame(p); self._kv_frame.pack(fill="x")
        # + Add plus bulk reveal/mask controls, grouped on one row.
        kv_ctrls = ttk.Frame(p); kv_ctrls.pack(fill="x", pady=(4, 0))
        ttk.Button(kv_ctrls, text="+ Add",
                   command=lambda: self._kv_add_row(focus=True)).pack(side="left")
        ttk.Button(kv_ctrls, text="Show All",
                   command=lambda: self._kv_show_all(True)) \
            .pack(side="left", padx=(6, 0))
        ttk.Button(kv_ctrls, text="Hide All",
                   command=lambda: self._kv_show_all(False)) \
            .pack(side="left", padx=(6, 0))
        self._kv_rows = []
        self._kv_add_row()  # always keep at least one row

        # Secret name / namespace / type / generate — all on one row. Generate
        # YAML is pinned right (packed first to reserve the edge) so the fields
        # can't push it off-screen; the Type combo expands to take the slack.
        # The editable type combo lets you pick a built-in type or enter a
        # custom one; Load Template fills it from the fetched secret.
        form = ttk.Frame(p); form.pack(fill="x", pady=(6, 2))
        gen_btn = ttk.Button(form, text="Generate YAML", command=self._gen_yaml)
        gen_btn.pack(side="right", padx=(12, 0))
        ttk.Label(form, text="Secret name:").pack(side="left")
        self._sec_name = ttk.Entry(form, width=16, font=(MONO, SZ))
        self._sec_name.insert(0, DEF_NAME)
        self._sec_name.pack(side="left", padx=(6, 12))
        ttk.Label(form, text="Namespace:").pack(side="left")
        self._sec_ns_e = ttk.Entry(form, width=10, font=(MONO, SZ))
        self._sec_ns_e.insert(0, DEF_NS)
        self._sec_ns_e.pack(side="left", padx=(6, 12))
        ttk.Label(form, text="Type:").pack(side="left")
        self._sec_type = ttk.Combobox(form, width=18, font=(MONO, SZ),
                                      values=SECRET_TYPES)
        self._sec_type.set("Opaque")
        self._sec_type.pack(side="left", padx=(6, 12), fill="x", expand=True)
        # Generate was created first to pin it right; raise it so Tab reaches it
        # last (matching its rightmost position) rather than its creation order.
        gen_btn.lift()

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

    def _toggle_sv(self):
        """Reveal/mask the plaintext input, mirroring the Decode tab's _toggle_dv."""
        self._sv_shown = not self._sv_shown
        self._sv_in.configure(show="" if self._sv_shown else "•")
        self._sv_tog.configure(text="Hide" if self._sv_shown else "Show")

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
        key_e.pack(side="left", padx=(0, 6))
        rd["key_e"] = key_e

        if binary:
            key_e.configure(state="readonly")  # binary keys aren't text-editable
            ttk.Button(row, text="✕", style="Icon.TButton", width=2,
                       command=lambda: self._kv_del_row(rd)).pack(side="right")
            ttk.Label(row, text="⟨binary — kept as-is on Generate⟩",
                      style="Dim.TLabel").pack(side="left", fill="x",
                                               expand=True, padx=(0, 4))
        else:
            # Create the value field before the buttons so Tab moves
            # key → value → Show → Edit… → ✕ (Tk traversal follows creation
            # order), but pack the buttons first (side="right") so the value
            # fills the gap between the key and the buttons. Values are masked
            # by default (like the Decode table) so they don't leak on screen.
            val_e = ttk.Entry(row, textvariable=var, font=(MONO, SZ), show="•")
            rd["val_e"] = val_e
            rd["shown"] = False
            show_b = ttk.Button(row, text="Show", style="Icon.TButton",
                                command=lambda: self._kv_toggle_show(rd))
            rd["show_b"] = show_b
            edit_b = ttk.Button(row, text="Edit…", style="Icon.TButton",
                                command=lambda: self._kv_edit_value(rd))
            del_b = ttk.Button(row, text="✕", style="Icon.TButton", width=2,
                               command=lambda: self._kv_del_row(rd))
            del_b.pack(side="right")
            edit_b.pack(side="right", padx=(0, 4))
            show_b.pack(side="right", padx=(0, 4))
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

    @staticmethod
    def _kv_set_row_visible(rd, show):
        """Reveal/mask one editable row's value (mirrors _set_row_visible)."""
        rd["shown"] = show
        rd["val_e"].configure(show="" if show else "•")
        rd["show_b"].configure(text="Hide" if show else "Show")

    def _kv_toggle_show(self, rd):
        """Reveal/mask one row's value, mirroring the Decode table's Show/Hide."""
        self._kv_set_row_visible(rd, not rd.get("shown", False))

    def _kv_show_all(self, show):
        """Reveal/mask every editable row at once (binary rows have no value)."""
        for rd in self._kv_rows:
            if not rd["binary"]:
                self._kv_set_row_visible(rd, show)

    def _kv_clear(self):
        for rd in list(self._kv_rows):
            rd["frame"].destroy()
        self._kv_rows.clear()
        self._kv_add_row()
        self._invalidate_outputs()

    def _kv_drop_binary(self):
        """Delete every binary marker row along with its _tpl_binary
        passthrough. The explicit reset keeps the drop correct even if a
        passthrough key ever lacked a matching marker row. Returns how many
        rows were dropped."""
        dropped = [rd for rd in self._kv_rows if rd["binary"]]
        for rd in dropped:
            self._kv_del_row(rd)
        self._tpl_binary = {}
        return len(dropped)

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
        self._invalidate_outputs()

    def _invalidate_outputs(self):
        """The secret in the editor changed — any generated YAML and any
        sealed output describe the *previous* one, so clear both, advance the
        generation (in-flight seal/validate results become stale), and re-gate
        the Seal-tab buttons. Called structurally from two tails: the
        row-replacement choke points (_kv_set_pairs / _kv_clear — Browse .env
        / Import / full Load Template / Clear) and _set_secret_identity (every
        doc-driven identity change, including the identity-only load, which
        replaces no rows). A future repopulation path that neither replaces
        rows nor sets a doc identity must call it itself."""
        self._out_gen += 1  # in-flight seal/validate results are now stale
        self._set_text(self._yaml_out, "")
        self._set_text(self._sealed_out, "")
        self._refresh_action_buttons()
        # Every path that changes _tpl_skipped (Browse .env / Clear reset it,
        # _set_secret_identity assigns it) flows through here afterwards, so
        # refreshing at this choke point keeps the on-screen warning in
        # lockstep with the state instead of relying on each caller.
        self._refresh_skip_warning()

    def _refresh_skip_warning(self):
        """Show/hide the persistent Encode-tab warning to match _tpl_skipped.
        Persistent because the loss stays relevant for as long as the loaded
        secret is being edited — unlike the status bar, it survives the
        Save/Seal success messages and needs no lucky glance within 10s."""
        if self._tpl_skipped:
            self._skip_lbl.configure(text=(
                f"⚠  {self._tpl_skipped} invalid metadata field(s) in the "
                "loaded secret — they will be missing from generated YAML"))
            self._skip_lbl.pack(fill="x", pady=(8, 0),
                                before=self._skip_anchor)
        else:
            self._skip_lbl.pack_forget()

    def _status_output(self, msg):
        """Status for an operation whose result derives from the generated
        YAML (Generate / Save / Seal). While the carryover skipped fields,
        an unqualified green success would contradict the pending loss — so
        the message carries the skip count and warning severity instead."""
        if self._tpl_skipped:
            self._status(f"{msg} — {self._tpl_skipped} invalid metadata "
                         "field(s) skipped", "err", duration_ms=10000)
        else:
            self._status(msg, "ok")

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
        text = self._read_file(path)
        if text is None:
            return
        self._env_lbl.configure(text=path)
        self._tpl_binary = {}  # a plain .env carries no binary passthrough...
        self._tpl_carry = {}   # ...and no metadata to carry over
        self._tpl_skipped = 0
        self._kv_set_pairs(parse_dotenv(text).items())  # invalidates outputs
        self._sec_type.set("Opaque")
        self._status(f"Loaded {os.path.basename(path)}", "ok")

    def _import_secret(self):
        """Import a Kubernetes Secret YAML from disk into the KV editor — for
        editing a secret that never reached the cluster (a mis-sealed deploy,
        say), where Load Template has nothing to fetch. Decodes data /
        stringData into editable rows and fills name / namespace / type."""
        if not PYYAML_OK:
            self._status("PyYAML not installed", "err"); return
        path = filedialog.askopenfilename(
            filetypes=[("YAML files", "*.yaml *.yml"), ("All files", "*.*")])
        if not path:
            return
        content = self._read_file(path)
        if content is None:
            return
        doc = self._yaml_secret_doc(content, verb="import")
        if doc is None:
            return
        entries = secret_entries(doc)
        err = self._check_entries(entries)
        if err:
            self._status(err, "err")
            return
        self._env_lbl.configure(text=path)
        total, binary = self._apply_secret_doc(doc, entries)
        self._status(self._applied_msg("Imported", total, binary,
                                       os.path.basename(path)), "ok")

    @staticmethod
    def _check_entries(entries):
        """Guards shared by Import and Load Template, run BEFORE the editor is
        touched so a rejected secret can't destroy in-progress rows. Returns
        an error message, or None if the entries are safe to apply. (The empty
        case is Import-only — Load Template turns an empty secret into an
        identity-only load before calling this.)"""
        if not entries:
            return "Secret has no data/stringData — nothing to import"
        # "invalid" means Kubernetes itself would reject the value at apply
        # time. Applying it would silently round-trip the raw string as if it
        # were base64 (garbage on deploy). Two causes, two remedies: plaintext
        # mistakenly under `data`, or binary base64 with broken padding.
        bad = first_invalid_key(entries)
        if bad is not None:
            return (f"data.{bad} is not valid base64 for Kubernetes — "
                    "plaintext belongs under stringData; binary needs exact "
                    "'=' padding")
        return None

    def _clear_env(self):
        self._env_lbl.configure(text="(no file)")
        self._tpl_binary = {}
        self._tpl_carry = {}
        self._tpl_skipped = 0
        self._kv_clear()  # invalidates outputs
        self._sec_type.set("Opaque")
        self._status("Cleared", "ok")

    def _gen_yaml(self):
        data = self._kv_get_pairs()
        # Binary keys from a loaded template are re-emitted verbatim; an edited
        # plaintext key of the same name wins over the original.
        raw = {k: v for k, v in self._tpl_binary.items() if k not in data}
        if not data and not raw:
            self._status("No KEY=VALUE pairs found", "err"); return
        name  = self._sec_name.get().strip() or DEF_NAME
        ns    = self._sec_ns_e.get().strip()  or DEF_NS
        type_ = self._sec_type.get().strip()
        if not type_:
            type_ = "Opaque"
            self._sec_type.set(type_)
        self._set_text(self._yaml_out,
                       build_secret_yaml(name, ns, data, type_, raw_data=raw,
                                         carryover=self._tpl_carry))
        msg = f"Generated YAML with {len(data) + len(raw)} key(s)"
        if raw:
            msg += f" ({len(raw)} binary kept as-is)"
        if self._tpl_carry:
            msg += " — labels/annotations/immutable carried over"
        # _status_output appends the skip count and warning severity when the
        # carryover was lossy, so 'carried over' can't imply full fidelity.
        self._status_output(msg)

    def _save_yaml(self):
        name = self._sec_name.get().strip() or DEF_NAME
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
        # Buttons live in a right-pinned sub-frame so a long file path can't
        # push them off-screen; the path label takes the middle and clips. The
        # sub-frame keeps Tab order (Browse… → Show All → Hide All) = layout.
        dec_btns = ttk.Frame(fp); dec_btns.pack(side="right")
        ttk.Button(dec_btns, text="Browse…", command=self._browse_yaml).pack(side="left")
        ttk.Button(dec_btns, text="Show All", command=lambda: self._tbl_show_all(True)) \
            .pack(side="left", padx=(10, 0))
        ttk.Button(dec_btns, text="Hide All", command=lambda: self._tbl_show_all(False)) \
            .pack(side="left", padx=(6, 0))
        self._dec_lbl = ttk.Label(fp, text="(no file)", style="Dim.TLabel", anchor="w")
        self._dec_lbl.pack(side="left", padx=6, fill="x", expand=True)

        # fixed header — Key fixed, Decoded value fills the middle, Actions
        # pinned right so it lines up with the row buttons (which are themselves
        # right-pinned so they're never clipped by the scrollbar).
        hdr = tk.Frame(p, bg=BG3); hdr.pack(fill="x", pady=(8, 0))
        tk.Label(hdr, text="Key", bg=BG3, fg=ACCENT, width=22, anchor="w",
                 padx=6, pady=4, font=(SANS, SZ, "bold")).pack(side="left")
        tk.Label(hdr, text="Actions", bg=BG3, fg=ACCENT, anchor="e",
                 padx=6, pady=4, font=(SANS, SZ, "bold")).pack(side="right")
        tk.Label(hdr, text="Decoded value", bg=BG3, fg=ACCENT, anchor="w",
                 padx=6, pady=4, font=(SANS, SZ, "bold")) \
            .pack(side="left", fill="x", expand=True)

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
        content = self._read_file(path)
        if content is None:
            return
        # Label only on success: on a bail (SealedSecret / no Secret / parse
        # error) the previous file's rows stay on screen, and the label must
        # keep naming *them*, not the file that failed to decode.
        if self._populate_table(content):
            self._dec_lbl.configure(text=path)

    def _populate_table(self, content: str) -> bool:
        """Decode a Secret YAML into the table. Returns True when the table
        was (re)populated, False when it bailed leaving the table untouched."""
        doc = self._yaml_secret_doc(content, verb="decode")
        if doc is None:
            return False

        entries = secret_entries(doc)  # data + stringData, decoded

        for w in self._tbl_body.winfo_children():
            w.destroy()
        self._tbl_rows.clear()

        for i, (key, value, kind) in enumerate(entries):
            binary = kind != "text"
            # Non-text values can't be shown as plaintext; display a marker and
            # let Copy hand back the original value instead of mojibake.
            if kind == "binary":
                shown = "⟨binary — Copy gives base64⟩"
            elif kind == "invalid":
                shown = "⟨not valid base64 — Copy gives raw value⟩"
            else:
                shown = value
            masked = shown if binary else "•" * min(len(shown), 32)
            bg = ROW_A if i % 2 == 0 else ROW_B
            row = tk.Frame(self._tbl_body, bg=bg)
            row.pack(fill="x")

            tk.Label(row, text=key, bg=bg, fg=FG, width=22, anchor="w",
                     padx=6, pady=3, font=(MONO, SZ)).pack(side="left")
            sv = tk.BooleanVar(value=False)
            vl = tk.Label(row, text=masked, bg=bg, fg=BLUE, anchor="w",
                          padx=6, pady=3, font=(MONO, SZ))

            # Action buttons pinned right so they're never clipped by the
            # scrollbar; the value label (packed last) fills the middle. Use the
            # Encode tab's Icon.TButton style so they match the KV editor.
            af = tk.Frame(row, bg=bg)
            af.pack(side="right")

            tb = ttk.Button(af, text="Show", style="Icon.TButton")
            if binary:
                tb.configure(state="disabled")  # nothing to reveal
            else:
                tb.configure(command=lambda shown=shown, masked=masked, sv=sv,
                             vl=vl, tb=tb: self._set_row_visible(
                                 shown, masked, sv, vl, tb, not sv.get()))
            tb.pack(side="left", padx=(6, 2), pady=2)
            ttk.Button(af, text="Copy", style="Icon.TButton",
                       command=lambda d=value: self._clip(d)) \
                .pack(side="left", padx=(0, 6), pady=2)
            vl.pack(side="left", fill="x", expand=True)

            self._tbl_rows.append((shown, masked, sv, vl, tb, binary))

        self._tbl_body.update_idletasks()
        self._tbl_cv.configure(scrollregion=self._tbl_cv.bbox("all"))
        self._status(f"Loaded {len(entries)} key(s)", "ok")
        return True

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
            # Seal's gating depends on the cert (a cert lifts the
            # detection-in-flight block) — re-evaluate it.
            self._refresh_action_buttons()

    def _clear_cert(self):
        self._cert = ""
        self._cert_lbl.configure(text="(none)")
        self._refresh_action_buttons()

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
        self._dispatch_gen(cmd, self._on_sealed, yaml_text)

    def _dispatch_gen(self, cmd, handler, stdin_data):
        """Dispatch a background op whose result feeds the output panes:
        captures the current editor generation and hands it to `handler`
        (o, e, rc, gen) so the landing callback can discard a result made
        stale by a repopulation while it ran. Every output-producing run_bg
        must go through here — a copy that forgets the capture reopens the
        stale-resurrection race."""
        gen = self._out_gen
        run_bg(cmd,
               lambda o, e, r: self.after(0, lambda: handler(o, e, r, gen)),
               stdin_data=stdin_data)

    def _discard_stale(self, gen, verb, hint=""):
        """True (with an explanatory status) when a background result was made
        stale by an editor repopulation while it ran — the shared guard for
        every _dispatch_gen handler. `hint` appends a recovery cue."""
        if gen == self._out_gen:
            return False
        self._status(f"Editor changed during {verb} — stale result discarded"
                     f"{hint}", "err")
        return True

    @staticmethod
    def _kubeseal_rc_error(rc):
        """Map run_bg's sentinel return codes to a status message, or None."""
        if rc == -1:
            return "kubeseal not in PATH"
        if rc == -2:
            return "kubeseal timed out"
        return None

    def _on_sealed(self, stdout, stderr, rc, gen):
        self._sealing = False
        # A stale result describes the previous secret: drop it rather than
        # resurrect the cleared pane (writing it would let Save/Validate act
        # on a secret the editor no longer shows).
        if self._discard_stale(gen, "sealing", hint="; seal again"):
            self._refresh_action_buttons()
            return
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
        # Via _status_output: a seal of lossy-carryover YAML must not read as
        # an unqualified success right as the manifest becomes applyable.
        self._status_output("Sealed successfully")

    def _sealed_output(self) -> str:
        """The sealed YAML in the output pane, or '' when empty / an error."""
        sealed = self._sealed_out.get("1.0", "end").strip()
        return "" if not sealed or sealed.startswith("# kubeseal error") else sealed

    def _refresh_action_buttons(self):
        """Single source of truth for the Seal / Validate button states.

        Seal is blocked by: a seal in flight; a VALIDATE in flight (re-sealing
        would swap the pane out from under the pending verdict, which would
        then read 'Valid' about the previous sealed output); or a controller
        lookup in flight WITHOUT a cert (with a cert the controller is
        irrelevant to sealing — mirrors _do_seal's own guard). Validate also
        needs sealed output, and always needs the controller resolved."""
        detecting = self._ctl_pending == self._seal_ctx.get()
        seal_blocked = (self._sealing or self._validating
                        or (detecting and not self._cert))
        self._seal_btn.configure(
            state="disabled" if seal_blocked else "normal")
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
        self._dispatch_gen(cmd, self._on_validated, sealed)

    def _on_validated(self, stdout, stderr, rc, gen):
        self._validating = False
        self._refresh_action_buttons()
        # A stale verdict is about the previous secret's sealed output (since
        # cleared) — reporting "Valid" now would mislead. Drop it.
        if self._discard_stale(gen, "validation"):
            return
        sentinel = self._kubeseal_rc_error(rc)
        if sentinel:
            self._status(sentinel, "err"); return
        if rc != 0:
            # kubeseal prints the reason (e.g. "unable to decrypt") to stderr.
            err = (stderr.strip() or "validation failed").splitlines()[-1][:90]
            self._status(f"Invalid seal: {err}", "err"); return
        self._status("Valid — the controller can decrypt this", "ok")

    def _save_sealed(self):
        name = self._sec_name.get().strip() or DEF_NAME
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
        # Via _dispatch_gen: the template write must also be discarded if the
        # editor is repopulated (Import / Browse / Clear) while kubectl runs —
        # the (ctx, ns, sec) check below only catches *selection* changes.
        self._dispatch_gen(cmd,
                           lambda o, e, r, gen: self._got_template(
                               ctx, ns, sec, o, e, r, gen),
                           None)

    def _got_template(self, ctx, ns, sec, stdout, stderr, rc, gen):
        # Re-enable the button regardless — the load attempt is done — *before*
        # the stale checks, or a discarded result would leave it stuck disabled.
        self._load_btn.configure(state="normal" if PYYAML_OK else "disabled")
        # Guard against a stale load: the user may have changed the context /
        # namespace / secret while this kubectl fetch was in flight...
        if (ctx, ns, sec) != (self._enc_ctx.get(), self._enc_ns.get(),
                              self._enc_sec.get()):
            return
        # ...or repopulated the editor (Import / Browse / Clear) without
        # touching the selectors — applying this template would silently
        # clobber those fresh rows.
        if self._discard_stale(gen, "the template load"):
            return
        if rc != 0:
            self._status(f"kubectl error: {stderr.strip()[:80]}", "err"); return
        try:
            doc = yaml.safe_load(stdout)
        except yaml.YAMLError as e:
            self._status(f"YAML parse error: {e}", "err"); return

        entries = secret_entries(doc)
        if not entries:
            dropped = self._apply_identity_only(doc, fb_name=sec, fb_ns=ns)
            # The File label is the editor's provenance — Import points it at
            # a path, so a cluster load must repoint it or it keeps naming a
            # file whose contents the editor no longer shows.
            self._env_lbl.configure(text=f"(cluster: {ns}/{sec})")
            msg = f"{sec} has no data/stringData — loaded name/namespace/type only"
            if dropped:
                # Real data left the editor — same lossy-result severity and
                # staying power as _status_output's skipped-metadata warning,
                # not a green flash a glance-away would miss.
                msg += (f"; dropped {dropped} binary value(s) from the "
                        "previous secret")
                self._status(msg, "err", duration_ms=10000)
            else:
                self._status(msg, "ok")
            return
        err = self._check_entries(entries)
        if err:
            self._status(err, "err")
            return
        total, binary = self._apply_secret_doc(doc, entries, fb_name=sec,
                                               fb_ns=ns)
        self._env_lbl.configure(text=f"(cluster: {ns}/{sec})")  # provenance
        self._status(self._applied_msg("Loaded", total, binary, sec), "ok")

    @staticmethod
    def _applied_msg(verb, total, binary, src):
        """Status line for a secret applied to the editor (Loaded/Imported)."""
        msg = f"{verb} {total} key(s) from {src}"
        if binary:
            msg += f" — {binary} binary value(s) kept as-is"
        return msg

    def _apply_secret_doc(self, doc, entries, fb_name=DEF_NAME,
                          fb_ns=DEF_NS):
        """Populate the KV editor and Secret name / Namespace / Type fields
        from a parsed Secret doc (shared by Load Template and Import Secret…).
        `entries` is the caller's secret_entries(doc) — already computed for
        the _check_entries guard, so the base64 decode pass runs only once.
        (doc normalization lives in _set_secret_identity, the only place doc
        is read.) Returns (total_keys, binary_keys) for the status line."""
        self._tpl_binary = {}
        text_pairs = []
        for k, value, kind in entries:
            if kind == "text":
                text_pairs.append((k, value))
            else:
                # binary can't be edited as text without corrupting it on
                # re-encode: keep the original base64 and re-emit it verbatim
                # at Generate (tracked in _tpl_binary). A marker row shows it
                # in the editor. ("invalid" never reaches here — both callers
                # run _check_entries first.)
                self._tpl_binary[k] = value
        self._kv_set_pairs(text_pairs, binary_keys=list(self._tpl_binary.keys()))
        self._set_secret_identity(doc, fb_name, fb_ns)
        return len(entries), len(self._tpl_binary)

    def _apply_identity_only(self, doc, fb_name, fb_ns):
        """Apply an entry-less Secret to the editor — _apply_secret_doc's
        counterpart for empty docs. Inherits name/namespace/type as
        scaffolding and keeps editable text rows, but drops binary passthrough
        rows: those are invisible values bound to the *previous* secret, and
        re-emitting them verbatim under the new identity would silently leak
        them. (_set_secret_identity invalidates the outputs — this path never
        reaches the _kv_set_pairs/_kv_clear choke points.) Returns the
        dropped-binary count for the status line."""
        dropped = self._kv_drop_binary()
        self._set_secret_identity(doc, fb_name, fb_ns)
        return dropped

    def _set_secret_identity(self, doc, fb_name, fb_ns):
        """Fill the editable Secret name / Namespace / Type fields from a
        parsed Secret doc's metadata (falling back to the caller's values), so
        they can be tweaked before Generate YAML. Also captures the doc's
        carry-over metadata (labels / annotations / immutable) for Generate,
        and invalidates the output panes: a doc-driven identity change stales
        any generated/sealed output whether or not rows were replaced, so the
        invalidation is coupled here structurally instead of being a step
        each caller must remember (the round-4 bug was exactly a caller
        forgetting it)."""
        if not isinstance(doc, dict):
            doc = {}
        meta = doc.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
        name = meta.get("name") or fb_name
        nsv  = meta.get("namespace") or fb_ns
        self._sec_name.delete(0, "end"); self._sec_name.insert(0, name)
        self._sec_ns_e.delete(0, "end"); self._sec_ns_e.insert(0, nsv)
        self._sec_type.set(doc.get("type") or "Opaque")
        self._tpl_carry, self._tpl_skipped = secret_carryover(doc)
        self._invalidate_outputs()

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

    def _read_file(self, path: str):
        """Read a user-picked text file, reporting failure in the status bar.
        Returns the content, or None on error. Explicit UTF-8: the locale
        default (e.g. cp1252 on Windows) would reject or mojibake non-ASCII
        secret values saved as UTF-8."""
        try:
            with open(path, encoding="utf-8") as f:
                return f.read()
        except (OSError, UnicodeDecodeError) as e:
            self._status(f"Could not read file: {e}", "err")
            return None

    def _yaml_secret_doc(self, content: str, verb: str):
        """Parse YAML text (multi-doc tolerant — manifests often bundle several
        resources) and pick the Secret doc, reporting failures in the status
        bar. `verb` names the caller's action for the SealedSecret hint.
        Returns the doc, or None."""
        try:
            docs = [d for d in yaml.safe_load_all(content) if d is not None]
        except yaml.YAMLError as e:
            self._status(f"YAML parse error: {e}", "err")
            return None
        doc = select_secret_doc(docs)
        if doc is None:
            if has_sealed_secret(docs):
                self._status(f"SealedSecret is encrypted — {verb} the plain "
                             "Secret YAML it was sealed from", "err")
            else:
                self._status("No Secret data/stringData found in file", "err")
        return doc

    def _write_file(self, path: str, content: str):
        try:
            write_secret_file(path, content)  # owner-only (0o600) — holds secrets
            # Via _status_output: a plain green "Saved" would erase the lossy-
            # carryover warning at the exact moment the incomplete file lands
            # on disk (both save paths hold YAML derived from the generation).
            self._status_output(f"Saved {os.path.basename(path)}")
        except OSError as e:
            self._status(f"Save failed: {e}", "err")


if __name__ == "__main__":
    App().mainloop()
