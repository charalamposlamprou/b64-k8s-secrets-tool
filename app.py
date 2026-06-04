#!/usr/bin/env python3
"""b64 - Kubernetes Secrets Tool: dark-themed Tkinter GUI for Kubernetes secrets.

Encode / decode base64, build Secret YAML from .env, fetch from a cluster
(read-only), and seal with kubeseal. Never runs `kubectl apply`.

Requires a modern Tcl/Tk (8.6+). On macOS, Apple's system Tk 8.5 renders
custom colours incorrectly — launch via `make start` (see README.md).
"""

import os
os.environ.setdefault("TK_SILENCE_DEPRECATION", "1")

import base64
import re
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
# Core logic (pure functions, no UI)
# ---------------------------------------------------------------------------

def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64_decode(s: str) -> str:
    s = s.strip()
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.b64decode(s).decode("utf-8", errors="replace")


def parse_dotenv(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        val = val.replace("\\n", "\n")
        result[key] = val
    return result


# Plain (unquoted) YAML scalars: valid DNS-style k8s names/keys match this.
_SAFE_YAML = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def yaml_scalar(v: str) -> str:
    """Return v as a YAML scalar, double-quoting (with escaping) if it isn't a
    plain DNS-safe token, so hand-edited names/keys can't break the document."""
    if _SAFE_YAML.match(v):
        return v
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_secret_yaml(name: str, namespace: str, data: dict) -> str:
    # base64 values are always plain-safe scalars; name/namespace/keys may be
    # hand-edited, so quote them when necessary.
    lines = [
        "apiVersion: v1",
        "kind: Secret",
        "metadata:",
        f"  name: {yaml_scalar(name)}",
        f"  namespace: {yaml_scalar(namespace)}",
        "type: Opaque",
        "data:",
    ]
    for k, v in data.items():
        lines.append(f"  {yaml_scalar(k)}: {b64_encode(v)}")
    return "\n".join(lines) + "\n"


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
        self.title("b64 - Kubernetes Secrets Tool")
        self.geometry("880x720")
        self.minsize(740, 580)
        self.configure(bg=BG)
        self._status_job = None

        self._enc_ctx = tk.StringVar()
        self._enc_ns  = tk.StringVar()
        self._enc_sec = tk.StringVar()

        self._apply_style()
        self._build_ui()
        self._fetch_contexts()

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
        s.map("TEntry", bordercolor=[("focus", ACCENT)])

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
        self._status_var = tk.StringVar(value="Ready")
        self._status_lbl = tk.Label(
            bar, textvariable=self._status_var,
            bg=BG, fg=FGDIM, anchor="w", padx=10, font=(SANS, SZ - 1))
        self._status_lbl.pack(fill="both", expand=True)

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
        nb.pack(fill="both", expand=True, padx=0, pady=0)

        ef = ttk.Frame(nb, padding=10); nb.add(ef, text="Encode")
        df = ttk.Frame(nb, padding=10); nb.add(df, text="Decode")
        sf = ttk.Frame(nb, padding=10); nb.add(sf, text="Seal")

        self._build_encode_tab(ef)
        self._build_decode_tab(df)
        self._build_seal_tab(sf)

    # ---------------------------------------------------------------- encode tab

    def _build_encode_tab(self, p):
        ttk.Label(p, text="Single Value Encoder", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        r = ttk.Frame(p); r.pack(fill="x", pady=2)
        self._sv_in = ttk.Entry(r, font=(MONO, SZ))
        self._sv_in.pack(side="left", fill="x", expand=True)
        self._sv_in.bind("<Return>", lambda _: self._sv_encode())
        ttk.Button(r, text="Encode →", command=self._sv_encode) \
            .pack(side="left", padx=(6, 0))

        r2 = ttk.Frame(p); r2.pack(fill="x", pady=2)
        self._sv_out = ttk.Entry(r2, font=(MONO, SZ), state="readonly")
        self._sv_out.pack(side="left", fill="x", expand=True)
        ttk.Button(r2, text="Copy", command=lambda: self._clip(self._sv_out.get())) \
            .pack(side="left", padx=(6, 0))

        ttk.Separator(p).pack(fill="x", pady=10)

        ttk.Label(p, text=".env → Kubernetes Secret YAML", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        # file picker
        fp = ttk.Frame(p); fp.pack(fill="x", pady=2)
        ttk.Label(fp, text="File:").pack(side="left")
        self._env_lbl = ttk.Label(fp, text="(no file)", style="Dim.TLabel")
        self._env_lbl.pack(side="left", padx=6)
        ttk.Button(fp, text="Browse…", command=self._browse_env).pack(side="left")

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

        # KV editable text area (6 rows)
        kf = ttk.Frame(p); kf.pack(fill="x", pady=(6, 2))
        ksb = ttk.Scrollbar(kf, orient="vertical")
        ksb.pack(side="right", fill="y")
        self._kv = tk.Text(
            kf, height=6, bg=BG3, fg=FG, insertbackground=FG,
            font=(MONO, SZ), relief="flat", bd=0, padx=6, pady=4,
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=ACCENT,
            yscrollcommand=ksb.set)
        self._kv.pack(fill="x")
        ksb.config(command=self._kv.yview)

        # name + namespace + generate
        mr = ttk.Frame(p); mr.pack(fill="x", pady=(6, 2))
        ttk.Label(mr, text="Secret name:").pack(side="left")
        self._sec_name = ttk.Entry(mr, width=22, font=(MONO, SZ))
        self._sec_name.insert(0, "my-secret")
        self._sec_name.pack(side="left", padx=(4, 12))
        ttk.Label(mr, text="Namespace:").pack(side="left")
        self._sec_ns_e = ttk.Entry(mr, width=14, font=(MONO, SZ))
        self._sec_ns_e.insert(0, "default")
        self._sec_ns_e.pack(side="left", padx=(4, 12))
        ttk.Button(mr, text="Generate YAML", command=self._gen_yaml).pack(side="left")

        # YAML output — expands to fill remaining space
        yf = ttk.Frame(p); yf.pack(fill="both", expand=True, pady=(6, 2))
        xsb = ttk.Scrollbar(yf, orient="horizontal"); xsb.pack(side="bottom", fill="x")
        ysb = ttk.Scrollbar(yf, orient="vertical");   ysb.pack(side="right",  fill="y")
        self._yaml_out = tk.Text(
            yf, bg=BG3, fg=BLUE, insertbackground=FG,
            font=(MONO, SZ), relief="flat", bd=0, padx=6, pady=4, wrap="none",
            highlightthickness=1, highlightbackground=BORDER,
            xscrollcommand=xsb.set, yscrollcommand=ysb.set, state="disabled")
        self._yaml_out.pack(fill="both", expand=True)
        xsb.config(command=self._yaml_out.xview)
        ysb.config(command=self._yaml_out.yview)

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

    def _browse_env(self):
        path = filedialog.askopenfilename(
            filetypes=[(".env files", "*.env"), ("All files", "*.*")])
        if not path:
            return
        try:
            with open(path) as f:
                text = f.read()
        except OSError as e:
            self._status(f"File not found: {e}", "err"); return
        self._env_lbl.configure(text=path)
        self._kv.delete("1.0", "end")
        self._kv.insert("1.0", text)
        self._status(f"Loaded {os.path.basename(path)}", "ok")

    def _gen_yaml(self):
        data = parse_dotenv(self._kv.get("1.0", "end"))
        if not data:
            self._status("No KEY=VALUE pairs found", "err"); return
        name = self._sec_name.get().strip() or "my-secret"
        ns   = self._sec_ns_e.get().strip()  or "default"
        self._set_text(self._yaml_out, build_secret_yaml(name, ns, data))
        self._status(f"Generated YAML with {len(data)} key(s)", "ok")

    def _save_yaml(self):
        name = self._sec_name.get().strip() or "my-secret"
        path = filedialog.asksaveasfilename(
            defaultextension=".yaml", initialfile=f"{name}.yaml",
            filetypes=[("YAML", "*.yaml"), ("All", "*.*")])
        if not path:
            return
        self._write_file(path, self._yaml_out.get("1.0", "end"))

    # ---------------------------------------------------------------- decode tab

    def _build_decode_tab(self, p):
        ttk.Label(p, text="Single Value Decoder", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        r = ttk.Frame(p); r.pack(fill="x", pady=2)
        self._dv_in = ttk.Entry(r, font=(MONO, SZ))
        self._dv_in.pack(side="left", fill="x", expand=True)
        self._dv_in.bind("<Return>", lambda _: self._sv_decode())
        ttk.Button(r, text="Decode →", command=self._sv_decode) \
            .pack(side="left", padx=(6, 0))

        r2 = ttk.Frame(p); r2.pack(fill="x", pady=2)
        self._dv_var = tk.StringVar()
        self._dv_out = ttk.Entry(r2, textvariable=self._dv_var, font=(MONO, SZ),
                                 state="readonly", show="•")
        self._dv_out.pack(side="left", fill="x", expand=True)
        self._dv_shown = False
        self._dv_tog = ttk.Button(r2, text="Show", command=self._toggle_dv)
        self._dv_tog.pack(side="left", padx=(6, 0))
        ttk.Button(r2, text="Copy", command=lambda: self._clip(self._dv_var.get())) \
            .pack(side="left", padx=(6, 0))

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
                                 yscrollcommand=vsb.set)
        self._tbl_cv.pack(side="left", fill="both", expand=True)
        vsb.config(command=self._tbl_cv.yview)

        self._tbl_body = tk.Frame(self._tbl_cv, bg=BG2)
        self._tbl_win = self._tbl_cv.create_window((0, 0), window=self._tbl_body,
                                                   anchor="nw")
        self._tbl_body.bind("<Configure>",
            lambda e: self._tbl_cv.configure(scrollregion=self._tbl_cv.bbox("all")))
        self._tbl_cv.bind("<Configure>",
            lambda e: self._tbl_cv.itemconfig(self._tbl_win, width=e.width))
        self._tbl_cv.bind("<Enter>",
            lambda e: self._tbl_cv.bind_all("<MouseWheel>", self._tbl_scroll))
        self._tbl_cv.bind("<Leave>",
            lambda e: self._tbl_cv.unbind_all("<MouseWheel>"))

        self._tbl_rows = []

    def _tbl_scroll(self, e):
        self._tbl_cv.yview_scroll(int(-1 * (e.delta / 120)), "units")

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
        except OSError as e:
            self._status(f"File not found: {e}", "err"); return
        self._dec_lbl.configure(text=path)
        self._populate_table(content)

    def _populate_table(self, content: str):
        try:
            doc = yaml.safe_load(content)
        except yaml.YAMLError as e:
            self._status(f"YAML parse error: {e}", "err"); return

        raw = doc["data"] if isinstance(doc, dict) and isinstance(doc.get("data"), dict) else {}

        for w in self._tbl_body.winfo_children():
            w.destroy()
        self._tbl_rows.clear()

        for i, (key, val) in enumerate(raw.items()):
            try:
                decoded = b64_decode(str(val)) if val else ""
            except Exception:
                decoded = "(decode error)"
            bg = ROW_A if i % 2 == 0 else ROW_B
            row = tk.Frame(self._tbl_body, bg=bg)
            row.pack(fill="x")

            tk.Label(row, text=key, bg=bg, fg=FG, width=22, anchor="w",
                     padx=6, pady=3, font=(MONO, SZ)).pack(side="left")
            sv = tk.BooleanVar(value=False)
            masked = "•" * min(len(decoded), 32)
            vl = tk.Label(row, text=masked, bg=bg, fg=BLUE, width=40, anchor="w",
                          padx=6, pady=3, font=(MONO, SZ))
            vl.pack(side="left")

            af = tk.Frame(row, bg=bg)
            af.pack(side="left", fill="x")
            tb_ref = [None]

            def _toggle(sv=sv, vl=vl, decoded=decoded, tb_ref=tb_ref):
                if sv.get():
                    vl.configure(text="•" * min(len(decoded), 32)); sv.set(False)
                    tb_ref[0].configure(text="Show")
                else:
                    vl.configure(text=decoded); sv.set(True)
                    tb_ref[0].configure(text="Hide")

            tb = tk.Button(af, text="Show", bg=BG3, fg=FG,
                           activebackground=BORDER, activeforeground=FG,
                           relief="flat", bd=0, padx=8, pady=1, font=(SANS, SZ - 1),
                           highlightthickness=0, cursor="hand2", command=_toggle)
            tb.pack(side="left", padx=(6, 2), pady=2)
            tb_ref[0] = tb
            tk.Button(af, text="Copy", bg=BG3, fg=FG,
                      activebackground=BORDER, activeforeground=FG,
                      relief="flat", bd=0, padx=8, pady=1, font=(SANS, SZ - 1),
                      highlightthickness=0, cursor="hand2",
                      command=lambda d=decoded: self._clip(d)).pack(side="left", pady=2)

            self._tbl_rows.append((decoded, sv, vl, tb))

        self._tbl_body.update_idletasks()
        self._tbl_cv.configure(scrollregion=self._tbl_cv.bbox("all"))
        self._status(f"Loaded {len(raw)} key(s)", "ok")

    def _tbl_show_all(self, show: bool):
        for decoded, sv, vl, tb in self._tbl_rows:
            vl.configure(text=decoded if show else "•" * min(len(decoded), 32))
            sv.set(show)
            tb.configure(text="Hide" if show else "Show")

    # ----------------------------------------------------------------- seal tab

    def _build_seal_tab(self, p):
        ttk.Label(p, text="Seal Kubernetes Secret", style="Head.TLabel") \
            .pack(anchor="w", pady=(0, 4))

        cs = ttk.Frame(p); cs.pack(fill="x", pady=2)
        ttk.Label(cs, text="Context:").pack(side="left")
        self._seal_ctx = tk.StringVar()
        self._seal_ctx_cb = ttk.Combobox(cs, textvariable=self._seal_ctx, width=20,
                                         state="readonly")
        self._seal_ctx_cb.pack(side="left", padx=(4, 14))
        ttk.Label(cs, text="Scope:").pack(side="left")
        self._seal_scope = tk.StringVar(value="strict")
        ttk.Combobox(cs, textvariable=self._seal_scope, width=16, state="readonly",
                     values=["strict", "namespace-wide", "cluster-wide"]) \
            .pack(side="left", padx=(4, 0))

        # Controller name / namespace (only needed when the sealed-secrets
        # controller isn't at its default kube-system/sealed-secrets-controller)
        ctl = ttk.Frame(p); ctl.pack(fill="x", pady=(6, 2))
        ttk.Label(ctl, text="Controller name:").pack(side="left")
        self._ctl_name = ttk.Entry(ctl, width=24, font=(MONO, SZ))
        self._ctl_name.pack(side="left", padx=(4, 12))
        ttk.Label(ctl, text="NS:").pack(side="left")
        self._ctl_ns = ttk.Entry(ctl, width=16, font=(MONO, SZ))
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
        ttk.Label(sr, text="Seals the YAML generated on the Encode tab",
                  style="Dim.TLabel").pack(side="left", padx=10)

        of_ = ttk.Frame(p); of_.pack(fill="both", expand=True, pady=2)
        xsb = ttk.Scrollbar(of_, orient="horizontal"); xsb.pack(side="bottom", fill="x")
        ysb = ttk.Scrollbar(of_, orient="vertical");   ysb.pack(side="right",  fill="y")
        self._sealed_out = tk.Text(
            of_, bg=BG3, fg=BLUE, insertbackground=FG,
            font=(MONO, SZ), relief="flat", bd=0, padx=6, pady=4, wrap="none",
            highlightthickness=1, highlightbackground=BORDER,
            xscrollcommand=xsb.set, yscrollcommand=ysb.set, state="disabled")
        self._sealed_out.pack(fill="both", expand=True)
        xsb.config(command=self._sealed_out.xview)
        ysb.config(command=self._sealed_out.yview)

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
        cmd = ["kubeseal", "--format=yaml", f"--scope={self._seal_scope.get()}"]
        if self._seal_ctx.get():
            cmd.append(f"--context={self._seal_ctx.get()}")
        if self._cert:
            cmd.append(f"--cert={self._cert}")
        ctl_name = self._ctl_name.get().strip()
        if ctl_name:
            cmd.append(f"--controller-name={ctl_name}")
        ctl_ns = self._ctl_ns.get().strip()
        if ctl_ns:
            cmd.append(f"--controller-namespace={ctl_ns}")
        self._seal_btn.configure(state="disabled")
        self._status("Sealing…", "dim")
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._on_sealed(o, e, r)),
               stdin_data=yaml_text)

    def _on_sealed(self, stdout, stderr, rc):
        self._seal_btn.configure(state="normal")
        if rc == -1:
            self._status("kubeseal not in PATH", "err"); return
        if rc == -2:
            self._status("kubeseal timed out", "err"); return
        if rc != 0:
            err = stderr.strip() or "kubeseal failed"
            # Show the full error in the output pane (it scrolls); the status bar
            # only fits one truncated line.
            self._set_text(self._sealed_out, "# kubeseal error\n" + err)
            self._status(f"kubeseal error: {err.splitlines()[-1][:90]}", "err")
            return
        self._set_text(self._sealed_out, stdout)
        self._status("Sealed successfully", "ok")

    def _save_sealed(self):
        name = self._sec_name.get().strip() or "my-secret"
        path = filedialog.asksaveasfilename(
            defaultextension=".yaml", initialfile=f"sealed-{name}.yaml",
            filetypes=[("YAML", "*.yaml"), ("All", "*.*")])
        if not path:
            return
        self._write_file(path, self._sealed_out.get("1.0", "end"))

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

    def _on_ctx_change(self, _=None):
        ctx = self._enc_ctx.get()
        self._seal_ctx.set(ctx)
        self._enc_ns.set(""); self._enc_sec.set("")
        self._ns_cb["values"] = []; self._sec_cb["values"] = []
        # Controller is cluster-specific — clear so detection refills for the new ctx.
        self._ctl_name.delete(0, "end"); self._ctl_ns.delete(0, "end")
        if ctx:
            self._fetch_namespaces(ctx)
            self._detect_controller(ctx)

    def _detect_controller(self, ctx: str):
        """Find the sealed-secrets controller service in the cluster and
        auto-fill the Controller name / NS fields (read-only lookup)."""
        cmd = ["kubectl", "get", "svc", "-A", f"--context={ctx}", "-o",
               "jsonpath={range .items[*]}{.metadata.namespace}{'\\t'}"
               "{.metadata.name}{'\\n'}{end}"]
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._got_controller(o, e, r)))

    def _got_controller(self, stdout, stderr, rc):
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
        # Only fill fields the user hasn't already typed into.
        if not self._ctl_name.get().strip():
            self._ctl_name.delete(0, "end"); self._ctl_name.insert(0, name)
        if not self._ctl_ns.get().strip():
            self._ctl_ns.delete(0, "end"); self._ctl_ns.insert(0, ns)
        self._status(f"Sealed-secrets controller: {ns}/{name}", "ok")

    def _fetch_namespaces(self, ctx: str):
        cmd = ["kubectl", "get", "namespaces", f"--context={ctx}",
               "-o", "jsonpath={.items[*].metadata.name}"]
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._got_ns(o, e, r)))

    def _got_ns(self, stdout, stderr, rc):
        if rc != 0:
            self._status(f"Namespace fetch failed: {stderr.strip()[:60]}", "err"); return
        nss = stdout.strip().split()
        self._ns_cb["values"] = nss
        if nss:
            self._enc_ns.set(nss[0])
            self._fetch_secrets(self._enc_ctx.get(), nss[0])

    def _on_ns_change(self, _=None):
        self._enc_sec.set(""); self._sec_cb["values"] = []
        ctx, ns = self._enc_ctx.get(), self._enc_ns.get()
        if ctx and ns:
            self._fetch_secrets(ctx, ns)

    def _fetch_secrets(self, ctx: str, ns: str):
        cmd = ["kubectl", "get", "secrets", f"--context={ctx}", f"--namespace={ns}",
               "-o", "jsonpath={.items[*].metadata.name}"]
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._got_secrets(o, e, r)))

    def _got_secrets(self, stdout, stderr, rc):
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
        run_bg(cmd, lambda o, e, r: self.after(0, lambda: self._got_template(o, e, r)))

    def _got_template(self, stdout, stderr, rc):
        self._load_btn.configure(state="normal" if PYYAML_OK else "disabled")
        if rc != 0:
            self._status(f"kubectl error: {stderr.strip()[:80]}", "err"); return
        try:
            doc = yaml.safe_load(stdout)
        except yaml.YAMLError as e:
            self._status(f"YAML parse error: {e}", "err"); return
        data = doc["data"] if isinstance(doc, dict) and isinstance(doc.get("data"), dict) else {}
        lines = []
        for k, v in data.items():
            try:
                dec = b64_decode(str(v)) if v else ""
            except Exception:
                dec = str(v)
            # Escape newlines so multi-line values (certs, keys) stay on one
            # KV line; parse_dotenv turns the literal \n back into a newline.
            # (Mirrors parse_dotenv, which only un-escapes \n.)
            dec = dec.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\\n")
            lines.append(f"{k}={dec}")
        self._kv.delete("1.0", "end")
        self._kv.insert("1.0", "\n".join(lines))

        # Also populate the editable Secret name / Namespace fields from the
        # fetched secret's metadata (falling back to the selected combo values),
        # so they can be tweaked before Generate YAML.
        meta = doc.get("metadata", {}) if isinstance(doc, dict) else {}
        name = meta.get("name") or self._enc_sec.get()
        ns   = meta.get("namespace") or self._enc_ns.get()
        self._sec_name.delete(0, "end"); self._sec_name.insert(0, name)
        self._sec_ns_e.delete(0, "end"); self._sec_ns_e.insert(0, ns)

        self._status(f"Loaded {len(data)} key(s) from {self._enc_sec.get()}", "ok")

    # --------------------------------------------------------------- helpers

    def _set_text(self, widget: tk.Text, text: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _clip(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text.rstrip("\n"))
        self._status("Copied to clipboard", "ok")

    def _write_file(self, path: str, content: str):
        try:
            with open(path, "w") as f:
                f.write(content)
            self._status(f"Saved {os.path.basename(path)}", "ok")
        except OSError as e:
            self._status(f"Save failed: {e}", "err")


if __name__ == "__main__":
    App().mainloop()
