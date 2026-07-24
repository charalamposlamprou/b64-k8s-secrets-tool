# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A dark-themed Tkinter GUI for Kubernetes secrets: encode/decode base64, build
Secret YAML from a `.env` file or a live cluster, and seal with `kubeseal`.
**Read-only against the cluster** — it never runs `kubectl apply`/`create`/
`patch`/`delete`, only reads (contexts, namespaces, secrets) and produces YAML
locally. Preserve that invariant in any change that touches cluster calls.

## Working in this repo

Apply the `karpathy-guidelines` skill to all coding work in this repo, not
just `/code-review`: surface assumptions and tradeoffs before implementing,
keep every change minimal and surgical (touch only what the task requires,
don't drive-by refactor adjacent code), and verify against an explicit,
stated success criterion rather than "looks right" — e.g. actually run the
install/test/lint, not just read the diff.

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
doesn't fit `run_bg`'s stdout/stderr/rc shape: the Linux clipboard write, and
all file I/O on user-picked paths (`_read_file_async`/`_read_editor_file` for
Browse/Import reads, `_write_file` for saves — a network mount or cloud-sync
placeholder can stall `open()`/`read()`/`write()` and would freeze the
window). Tests make these synchronous by stubbing `_run_async` to run inline
(`_sync_io` in `tests/test_app.py`) instead of pumping the event loop.

### The staleness guard: `_out_gen` / `_dispatch_gen` / `_discard_stale`

Because background results land asynchronously, a fetch or seal dispatched for
one secret can complete *after* the user has already loaded a different one.
`_out_gen` is an integer bumped every time what the output panes describe
changes (`_invalidate_outputs`, called from the row-replacement choke points
`_kv_set_pairs`/`_kv_clear`, from `_set_secret_identity`, and from `_gen_yaml`
— regenerating over an in-place row-value edit changes the panes without
replacing rows). Any background op whose result writes into
`_yaml_out`/`_sealed_out` must dispatch through `_dispatch_gen()` (captures
the current generation) and check it on landing via `_discard_stale()` — if
the generation changed while the op was in flight, the result is stale and
gets discarded rather than applied. `_do_seal`/`_on_sealed` and
`_load_template`/`_got_template` follow this pattern; adopt it for any new
background op that writes into those panes rather than inventing a one-off
guard.

The selector-driven kubectl fetches (contexts / controller / namespaces /
secret list) use the companion `_dispatch_latest(key, cmd, handler, *args)`:
a newest-wins token per key (`_claim_latest`/`_is_latest`). Their landing
callbacks also compare the captured ctx/ns against the current combobox
selection, but that value-equality check cannot tell two in-flight lookups
for the *same* selection apart (switch prod → staging → prod fast and the
older prod result could land last, overwriting the newer one or clearing the
`_ctl_pending` guard while the newer lookup still runs) — the token handles
that ordering. `_read_file_async` reuses the same tokens so a newer file pick
supersedes a hung read, and `_load_template` claims a token keyed by
`("template", ctx, ns, sec)` on top of its `_dispatch_gen` checks, so a
double-click can't apply the older of two same-selection fetches — keyed by
selection, not a single global slot, so switching to a different secret and
back without re-clicking Load doesn't make the still-in-flight original
fetch land as "superseded" when nothing actually superseded it. New fetch
call sites should come through
`_dispatch_latest` rather than hand-rolling the wrapper — it's not the *only*
place a `self.after` marshal is written (`_dispatch_gen` and `_run_async`
each write their own), but it's the one built for this per-key-supersession
shape.

`_ctl_cache` (context → `(ns, name)` or `None`) sits alongside the
`"controller"` `_dispatch_latest` key: `_detect_controller` checks
`ctx in self._ctl_cache` (not `.get()`) before dispatching, because a
context with no sealed-secrets controller caches as the value `None` — a
context genuinely never looked up is *absent* from the dict, not present
with a `None` value, and `.get()` can't tell the two apart. A cache hit
dispatches nothing and needs no token bookkeeping of its own, because
every landing is guarded where it lands: `_dispatch_latest`'s token drops
any superseded lookup (each new dispatch claims afresh, so whichever
landing populated the cache was dispatched after — and thereby superseded
— every earlier same-context lookup, including ones still in flight), and
`_got_controller`'s `ctx != self._seal_ctx.get()` check drops
cross-context stragglers. The cache is invalidated by the ⟳ refresh
(`_invalidate_ctl_cache`, called from `_fetch_contexts`), which clears the
dict and bumps `_ctl_refresh_gen` together (never one without the other —
that's the whole point of having them share one method) — a lookup
dispatched before the refresh captures the pre-bump generation as
`ctl_gen`, and `_got_controller` checks it on landing, but only for a
successful (`rc == 0`) result: a mismatch there means a ⟳ happened
meanwhile, so the found/not-found ANSWER is discarded entirely (not
shown, not cached — showing a stale answer in the fields would be just as
wrong as caching it, since Seal/Validate read those fields directly) and
`_detect_controller` is called again for a fresh one, with a `_status`
line so the wait isn't silent. An `rc != 0` result is reported
unconditionally regardless of `ctl_gen`, staleness or not — an error
carries no controller DATA for the gate to protect, and discarding it the
same way would leave a persistently unreachable cluster retrying forever
with no explanation ever shown. Discarding a stale answer only pays the
extra round-trip in the (rare) case a landing actually goes stale — ⟳
itself stays a cheap dict-clear-and-bump, not a forced `get svc -A` for
the current context on every click. There's no per-context or TTL
invalidation, so a controller reinstalled under a different name/namespace
in an already-cached context reads stale until ⟳ (and even then, only
once that context is reselected — the ⟳ won't proactively pick it up
until it does, and only self-corrects sooner if a lookup happens to
already be in flight when ⟳ is clicked).

A background op that's about to *replace all KV rows* (`_read_editor_file`,
`_got_template`) needs a THIRD check beyond `_out_gen`: `_kv_edit_gen`, bumped
by `_kv_row_edited` on every row add/remove, and — via `_kv_key_edited`/
`_kv_value_edited` — on a key-or-value edit that actually changes the text
(both fields' Entries are `textvariable`-bound, with a write trace on each
StringVar; `_kv_key_edited`/`_kv_value_edited` filter out a same-value
`.set()`, which fires the trace but isn't a real edit). `_out_gen` only moves
when the output panes' generation changes (a full repopulation, or
`_gen_yaml`) — a plain in-place row edit (type a new value, click "+", click
"✕") doesn't touch it, so a slow file read or template fetch landing after
such an edit would sail past `_discard_stale` and silently clobber the edit.
`_discard_if_kv_edited(kv_gen, verb)` is the row-level counterpart of
`_discard_stale`; any op that replaces rows on landing should capture
`self._kv_edit_gen` at dispatch and check both. Both fields use a
`textvariable` write trace rather than a raw `<KeyRelease>` bind
specifically because a bind only sees keyboard-driven edits — a non-keyboard
mutation (e.g. X11 middle-click paste, which inserts the primary selection
with no keyboard event at all) would leave the key/value text changed but
`_kv_edit_gen` un-bumped.

### Per-secret state that must stay consistent

Loading/importing a secret populates three parallel pieces of state:
`_tpl_binary` (base64 values that can't round-trip as plaintext — re-emitted
verbatim), `_tpl_carry` (labels/annotations/`immutable` carried through from
the source doc, via `core.secret_carryover`), and `_tpl_skipped` (count of
malformed metadata fields dropped rather than silently corrupted). The
reset has a single owner, `_reset_secret_state(binary=…)`, reached from both
paths a new secret can enter the editor by: the row-replacement choke point
`_kv_set_pairs(pairs, binary=…)` (`_kv_clear` is just `_kv_set_pairs([])`,
not a separate reset), and the identity-only load (`_apply_identity_only`,
which replaces no rows and instead resets via `_kv_drop_binary`). In both,
`_set_secret_identity` assigns the newly loaded doc's carry/skipped right
after (rows/reset first, then identity — `_apply_secret_doc` relies on that
ordering). Don't reset the trio caller-side; pass `binary=` to the choke
point instead. When adding a fourth piece of per-secret state, add it to
`_reset_secret_state` and both paths get it structurally.

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
