# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A dark-themed Tkinter GUI for Kubernetes secrets: encode/decode base64, build
Secret YAML from a `.env` file or a live cluster, and seal with `kubeseal`.
**Read-only against the cluster** — it never runs `kubectl apply`/`create`/
`patch`/`delete`, only reads (contexts, namespaces, secrets) and produces YAML
locally. Preserve that invariant in any change that touches cluster calls.

## Commands

```bash
make setup                              # create .venv + install deps (idempotent)
make start / stop / restart / status    # run the app in the background
.venv/bin/python -m pytest tests/ -v    # run the full test suite
.venv/bin/python -m pytest tests/test_core.py::test_name -v   # single test
.venv/bin/python -m ruff check .        # lint (matches CI)
```

CI (`.github/workflows/ci.yml`) runs `ruff check .` then
`xvfb-run -a python -m pytest tests/ -v` on Python 3.11 and 3.13 — match that
locally before pushing. `tests/test_core.py` needs no display; `tests/test_app.py`
needs one (or `xvfb-run` on Linux) since it builds real Tk widgets.

**macOS: always run through `.venv/bin/python` / `make`, never the system
Python.** macOS ships a deprecated system Tk 8.5 that renders custom widget
colours incorrectly (invisible labels, blank panels); `make setup` builds the
venv from a Homebrew Python linked against Tcl/Tk 9.

Every PR merged to `main` cuts a release automatically (patch bump by
default; label `release:minor`/`release:major` to bump higher, `release:skip`
to skip). No manual tagging.

## Architecture

Two flat modules, no package — `core.py` (pure logic) and `app.py` (the GUI),
mirrored by `tests/test_core.py` and `tests/test_app.py`.

- **`core.py` is tkinter-free by design** — base64 encode/decode, `.env`
  parse/render, Secret YAML assembly (`build_secret_yaml`), Secret-doc
  introspection (`secret_entries`, `select_secret_doc`, `secret_carryover`),
  and `kubeseal` command construction. It's unit-tested without a display and
  has no side effects (no file I/O, no subprocesses) except `write_secret_file`
  (owner-only 0o600 write) and the pure YAML/base64 functions. When adding
  logic, ask whether it belongs here rather than in `app.py` — anything that
  doesn't need a widget almost always does, since it becomes independently
  testable and reusable across the Encode/Decode/Seal tabs.
- **`app.py`** is the single `App(tk.Tk)` class: three notebook tabs (Encode,
  Decode, Seal) built by `_build_encode_tab`/`_build_decode_tab`/`_build_seal_tab`,
  plus a persistent status bar and lossy-metadata warning that live in the
  window chrome (outside the notebook) so they're visible on every tab.

### Background work never blocks the UI

Every `kubectl`/`kubeseal` invocation goes through `run_bg()` (module-level
helper): it runs the subprocess on a daemon thread and marshals the result
back to the main thread via `self.after(0, callback)` with a `(stdout, stderr,
returncode)` callback contract (plus sentinel codes for not-found/timeout).
Never call `subprocess.run` directly from a UI callback. `_run_async(work,
done)` is the more general form — it runs any callable on a daemon thread and
delivers its return value to `done(result)` — for background work whose result
doesn't fit `run_bg`'s stdout/stderr/rc shape (e.g. the Linux clipboard write,
which is itself a subprocess but returns a plain success bool).

### The staleness guard: `_out_gen` / `_dispatch_gen` / `_discard_stale`

Because background results land asynchronously, a fetch or seal dispatched for
one secret can complete *after* the user has already loaded a different one.
`_out_gen` is an integer bumped every time the editor's secret changes
(`_invalidate_outputs`, called from the row-replacement choke points
`_kv_set_pairs`/`_kv_clear` and from `_set_secret_identity`). Any background
op whose result writes into `_yaml_out`/`_sealed_out` must dispatch through
`_dispatch_gen()` (captures the current generation) and check it on landing
via `_discard_stale()` — if the generation changed while the op was in
flight, the result is stale and gets discarded rather than applied. `_do_seal`/
`_on_sealed` and `_load_template`/`_got_template` follow this pattern; adopt
it for any new background op that writes into those panes rather than
inventing a one-off guard.

### Per-secret state that must stay consistent

Loading/importing a secret populates three parallel pieces of state:
`_tpl_binary` (base64 values that can't round-trip as plaintext — re-emitted
verbatim), `_tpl_carry` (labels/annotations/`immutable` carried through from
the source doc, via `core.secret_carryover`), and `_tpl_skipped` (count of
malformed metadata fields dropped rather than silently corrupted). They are
reset on **different** paths, not one shared choke point — this split is the
usual source of "a load path forgot to reset X" bugs, so trace it fully before
adding a fourth:

- `_tpl_binary` is reset wherever the KV rows are (re)populated: `_apply_secret_doc`
  (full doc load), `_kv_drop_binary` (the identity-only load path,
  `_apply_identity_only`), and directly in `_browse_env` / `_clear_env`.
- `_tpl_carry` / `_tpl_skipped` are recomputed in `_set_secret_identity` (reached
  by *both* doc-driven load paths) and reset directly in `_browse_env` / `_clear_env`.

Note `_set_secret_identity` does **not** touch `_tpl_binary` (the row-population
step already did). The invariant to preserve: every path that replaces the
editor's secret must leave all three consistent with the newly-loaded (or
empty) secret. When adding a fourth piece of per-secret state, decide which of
those paths it belongs on and cover all of them.

### Status messaging

`_status(msg, kind, duration_ms)` drives the transient status-bar line
(`"ok"`/`"err"`/`"dim"`, 4s default). `_status_output(msg, skipped=None)` is
the wrapper for any action whose result derives from the generated/sealed
YAML (Generate, Save, Seal, Copy) — it qualifies the message with the pending
skipped-metadata count in warning severity instead of an unqualified green
success, so a lossy round-trip can't read as fully successful. The persistent
`_warn_lbl` in the window chrome (not the transient status line) is the
durable indicator that a loaded secret has skipped metadata; it's kept in
sync via `_refresh_skip_warning`, called from the same `_invalidate_outputs`
choke point.
