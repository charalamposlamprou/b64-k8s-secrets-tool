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
        win._sealed_ok = True  # simulate a successful earlier seal
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
        win._sealed_ok = True  # simulate a successful earlier seal
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


def test_context_switch_disables_seal_and_validate(monkeypatch):
    """Starting a controller lookup (e.g. on context switch) greys out both
    action buttons so they can't be clicked against an unresolved controller."""
    win = _make_win()
    try:
        monkeypatch.setattr(app, "run_bg", lambda *a, **k: None)  # lookup stays pending
        win._seal_ctx.set("ctxA")

        win._detect_controller("ctxA")

        assert str(win._seal_btn.cget("state")) == "disabled"
        assert str(win._validate_btn.cget("state")) == "disabled"
    finally:
        win.destroy()


def test_controller_landing_reenables_seal_only(monkeypatch):
    """When the lookup lands, Seal comes back; Validate stays disabled until
    there is sealed output to check."""
    win = _make_win()
    try:
        win._seal_ctx.set("ctxA")
        win._seal_btn.configure(state="disabled")
        win._validate_btn.configure(state="disabled")

        win._got_controller("ctxA", "kube-system\tsealed-secrets-controller\n", "", 0)

        assert str(win._seal_btn.cget("state")) == "normal"
        assert str(win._validate_btn.cget("state")) == "disabled"
    finally:
        win.destroy()


def test_controller_landing_reenables_validate_with_output():
    """With existing sealed output, the lookup landing re-enables Validate too."""
    win = _make_win()
    try:
        win._seal_ctx.set("ctxA")
        win._set_text(win._sealed_out, "kind: SealedSecret\n")
        win._sealed_ok = True  # simulate a successful earlier seal
        win._validate_btn.configure(state="disabled")

        win._got_controller("ctxA", "kube-system\tsealed-secrets-controller\n", "", 0)

        assert str(win._validate_btn.cget("state")) == "normal"
    finally:
        win.destroy()


def test_controller_landing_mid_seal_keeps_buttons_disabled():
    """A lookup resolving while a seal is still in flight must not re-enable the
    buttons under the running operation (would allow a duplicate concurrent seal)."""
    win = _make_win()
    try:
        win._seal_ctx.set("ctxA")
        win._set_text(win._sealed_out, "kind: SealedSecret\n")
        win._sealed_ok = True  # simulate a successful earlier seal
        win._sealing = True  # a seal started by _do_seal is still running
        win._seal_btn.configure(state="disabled")
        win._validate_btn.configure(state="disabled")

        win._got_controller("ctxA", "kube-system\tsealed-secrets-controller\n", "", 0)

        assert str(win._seal_btn.cget("state")) == "disabled"
        assert str(win._validate_btn.cget("state")) == "disabled"
    finally:
        win.destroy()


def _sync_io(win, monkeypatch):
    """Run _run_async work inline: file reads/writes (and their landing
    callbacks) complete synchronously so tests can assert right after the
    call, without pumping the Tk event loop."""
    monkeypatch.setattr(win, "_run_async", lambda work, done: done(work()))


def _import_file(win, monkeypatch, tmp_path, content):
    """Drive Import Secret… against a temp YAML file, bypassing the dialog."""
    path = tmp_path / "secret.yaml"
    path.write_text(content)
    monkeypatch.setattr(app.filedialog, "askopenfilename",
                        lambda **k: str(path))
    _sync_io(win, monkeypatch)
    win._import_secret()
    return path


def test_import_secret_populates_editor(monkeypatch, tmp_path):
    """Importing a Secret YAML from disk decodes data/stringData into the KV
    editor and pre-fills the name / namespace / type fields."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: app-creds
  namespace: prod
type: kubernetes.io/basic-auth
data:
  username: YWRtaW4=
stringData:
  password: hunter2
""")
        assert win._kv_get_pairs() == {"username": "admin", "password": "hunter2"}
        assert win._sec_name.get() == "app-creds"
        assert win._sec_ns_e.get() == "prod"
        assert win._sec_type.get() == "kubernetes.io/basic-auth"
        assert "Imported 2 key(s)" in win._status_var.get()
    finally:
        win.destroy()


def test_import_secret_skips_non_secret_docs(monkeypatch, tmp_path):
    """A multi-doc manifest imports the Secret, not the resources around it."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cfg
data:
  KEY: not-a-secret
---
apiVersion: v1
kind: Secret
metadata:
  name: from-bundle
data:
  token: c2VjcmV0
""")
        assert win._kv_get_pairs() == {"token": "secret"}
        assert win._sec_name.get() == "from-bundle"
    finally:
        win.destroy()


def test_import_sealed_secret_is_rejected_with_hint(monkeypatch, tmp_path):
    """A SealedSecret can't be decoded locally — the status must say to import
    the plain Secret instead, and the editor must stay untouched."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._kv_set_pairs([("KEEP", "me")])
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: bitnami.com/v1alpha1
kind: SealedSecret
metadata:
  name: app-creds
spec:
  encryptedData:
    password: AgB0zXyEncrypted==
""")
        assert "SealedSecret is encrypted" in win._status_var.get()
        assert win._kv_get_pairs() == {"KEEP": "me"}  # nothing imported
    finally:
        win.destroy()


def test_import_prefers_real_secret_over_kindless_fragment(monkeypatch, tmp_path):
    """A kind-less data-bearing fragment must not shadow the real kind: Secret
    that follows it in the same file."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
data:
  DECOY: bm90LXRoaXM=
---
apiVersion: v1
kind: Secret
metadata:
  name: the-real-one
data:
  token: c2VjcmV0
""")
        assert win._kv_get_pairs() == {"token": "secret"}
        assert win._sec_name.get() == "the-real-one"
    finally:
        win.destroy()


def test_import_rejects_plaintext_under_data(monkeypatch, tmp_path):
    """Plaintext mistakenly under `data:` (k8s would reject it at apply time)
    must fail the import loudly instead of silently round-tripping the
    plaintext as if it were base64 — and must not touch the editor."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._kv_set_pairs([("KEEP", "me")])
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: oops
data:
  password: hunter2
""")
        assert "not valid base64" in win._status_var.get()
        assert "stringData" in win._status_var.get()
        assert win._kv_get_pairs() == {"KEEP": "me"}  # nothing imported
    finally:
        win.destroy()


def test_import_rejects_secret_without_data(monkeypatch, tmp_path):
    """An empty Secret has nothing to import — the editor must survive."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._kv_set_pairs([("KEEP", "me")])
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: hollow
""")
        assert "nothing to import" in win._status_var.get()
        assert win._kv_get_pairs() == {"KEEP": "me"}
    finally:
        win.destroy()


def test_import_clears_stale_generated_yaml(monkeypatch, tmp_path):
    """Importing a new secret must clear the YAML pane, or the Seal tab would
    quietly seal the previously generated secret."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._set_text(win._yaml_out, "kind: Secret  # stale, from secret A\n")
        _import_file(win, monkeypatch, tmp_path, """\
kind: Secret
data:
  token: c2VjcmV0
""")
        assert win._kv_get_pairs() == {"token": "secret"}
        assert win._yaml_out.get("1.0", "end").strip() == ""
    finally:
        win.destroy()


def test_yaml_secret_doc_selects_from_multidoc_and_hints_sealed():
    """The Decode tab and Import share _yaml_secret_doc: multi-doc bundles
    yield the Secret (not the ConfigMap around it), and a SealedSecret gets
    the explanatory hint. (Driven directly rather than via _populate_table —
    building the decoded table calls update_idletasks, which macOS Tk can't
    survive outside a running mainloop.)"""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        doc = win._yaml_secret_doc(
            "kind: ConfigMap\ndata:\n  K: not-a-secret\n---\n"
            "kind: Secret\ndata:\n  token: c2VjcmV0\n", verb="decode")
        assert doc == {"kind": "Secret", "data": {"token": "c2VjcmV0"}}

        rows_before = list(win._tbl_rows)
        win._populate_table(
            "kind: SealedSecret\nspec:\n  encryptedData:\n    p: AgA=\n")
        assert "SealedSecret is encrypted" in win._status_var.get()
        assert win._tbl_rows == rows_before  # error path leaves the table alone
    finally:
        win.destroy()


def test_load_template_empty_secret_loads_identity_only():
    """An empty cluster Secret is scaffolding: Load Template inherits its
    name/namespace/type but must not wipe in-progress editor rows."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._kv_set_pairs([("KEEP", "me")])
        win._enc_ctx.set("c"); win._enc_ns.set("n"); win._enc_sec.set("s")

        win._got_template("c", "n", "s", win._kv_edit_gen,
                          "apiVersion: v1\nkind: Secret\nmetadata:\n"
                          "  name: hollow\n  namespace: prod\n"
                          "type: kubernetes.io/tls\n",
                          "", 0, win._out_gen)

        assert "name/namespace/type only" in win._status_var.get()
        assert win._kv_get_pairs() == {"KEEP": "me"}  # rows untouched
        assert win._sec_name.get() == "hollow"        # identity inherited
        assert win._sec_ns_e.get() == "prod"
        assert win._sec_type.get() == "kubernetes.io/tls"
    finally:
        win.destroy()


def test_identity_only_load_invalidates_and_drops_binary():
    """The identity-only path changes what the outputs describe, so it must
    invalidate them like any repopulation — and it must not carry the previous
    secret's binary passthrough (invisible values that Generate would re-emit
    verbatim) into the new identity."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        # State from a previously loaded secret A: a text row, a binary
        # passthrough, generated + sealed output, and an in-flight seal.
        win._kv_set_pairs([("KEEP", "me")], binary={"tls.key": "QUJD"})
        win._set_text(win._yaml_out,   "kind: Secret  # A\n")
        win._set_text(win._sealed_out, "kind: SealedSecret  # A\n")
        gen = win._out_gen  # a seal dispatched under the old identity
        win._enc_ctx.set("c"); win._enc_ns.set("n"); win._enc_sec.set("s")

        win._got_template("c", "n", "s", win._kv_edit_gen,
                          "kind: Secret\nmetadata:\n  name: hollow\n", "", 0,
                          win._out_gen)

        assert win._kv_get_pairs() == {"KEEP": "me"}   # text rows kept
        assert win._tpl_binary == {}                   # binary NOT migrated
        assert "dropped 1 binary value(s)" in win._status_var.get()
        assert win._yaml_out.get("1.0", "end").strip() == ""    # invalidated
        assert win._sealed_out.get("1.0", "end").strip() == ""
        assert win._out_gen != gen  # in-flight results are now stale
    finally:
        win.destroy()


def test_stale_seal_result_is_discarded_after_repopulation():
    """A background seal that lands after the editor was repopulated must not
    resurrect the cleared sealed pane with the previous secret's manifest."""
    win = _make_win()
    try:
        gen = win._out_gen          # generation the seal was dispatched under
        win._sealing = True
        win._kv_set_pairs([("NEW", "b")])  # repopulation bumps the generation

        win._on_sealed("kind: SealedSecret  # secret A\n", "", 0, gen)

        assert win._sealed_out.get("1.0", "end").strip() == ""  # not resurrected
        assert "stale result discarded" in win._status_var.get()
        assert win._sealing is False
        # A seal dispatched under the CURRENT generation still lands normally.
        win._sealing = True
        win._on_sealed("kind: SealedSecret  # secret B\n", "", 0, win._out_gen)
        assert "secret B" in win._sealed_out.get("1.0", "end")
        assert "Sealed successfully" in win._status_var.get()
    finally:
        win.destroy()


def test_stale_validate_result_is_discarded_after_repopulation():
    """A background validate landing after repopulation must not report
    'Valid' for the previous secret's sealed output."""
    win = _make_win()
    try:
        gen = win._out_gen
        win._validating = True
        win._kv_set_pairs([("NEW", "b")])  # bumps the generation

        win._on_validated("", "", 0, gen)

        assert "Valid" not in win._status_var.get()
        assert "stale result discarded" in win._status_var.get()
        assert win._validating is False
    finally:
        win.destroy()


def test_import_invalidates_stale_sealed_output(monkeypatch, tmp_path):
    """Repopulating the editor must clear BOTH output panes: leaving the old
    sealed manifest around lets the user validate/save secret A while the
    editor shows secret B."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._set_text(win._yaml_out,   "kind: Secret  # stale A\n")
        win._set_text(win._sealed_out, "kind: SealedSecret  # stale sealed A\n")
        win._validate_btn.configure(state="normal")

        _import_file(win, monkeypatch, tmp_path,
                     "kind: Secret\ndata:\n  token: c2VjcmV0\n")

        assert win._yaml_out.get("1.0", "end").strip() == ""
        assert win._sealed_out.get("1.0", "end").strip() == ""
        assert str(win._validate_btn.cget("state")) == "disabled"
    finally:
        win.destroy()


def test_import_unwraps_kind_list(monkeypatch, tmp_path):
    """A saved `kubectl get secrets -o yaml` (kind: List) imports the Secret
    inside .items instead of failing with 'no Secret found'."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Secret
  metadata:
    name: from-list
  data:
    token: c2VjcmV0
""")
        assert win._kv_get_pairs() == {"token": "secret"}
        assert win._sec_name.get() == "from-list"
    finally:
        win.destroy()


def test_browse_yaml_keeps_label_on_failed_decode(monkeypatch, tmp_path):
    """When decode bails (e.g. a SealedSecret), the previous file's rows stay
    on screen — so the File label must keep naming them, not the failed file."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._dec_lbl.configure(text="previous.yaml")
        path = tmp_path / "sealed.yaml"
        path.write_text("kind: SealedSecret\nspec:\n  encryptedData:\n    p: AgA=\n")
        monkeypatch.setattr(app.filedialog, "askopenfilename",
                            lambda **k: str(path))
        _sync_io(win, monkeypatch)

        win._browse_yaml()

        assert "SealedSecret is encrypted" in win._status_var.get()
        assert win._dec_lbl.cget("text") == "previous.yaml"
    finally:
        win.destroy()


def test_stale_template_result_is_discarded_after_repopulation():
    """A Load Template fetch landing after the editor was repopulated (e.g. by
    Import, which bumps the generation without touching the selectors) must
    not clobber the fresh rows."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._enc_ctx.set("c"); win._enc_ns.set("n"); win._enc_sec.set("s")
        gen = win._out_gen          # generation the fetch was dispatched under
        kv_gen = win._kv_edit_gen   # ditto, row-edit generation
        win._kv_set_pairs([("FRESH", "import")])  # repopulation bumps both

        win._got_template("c", "n", "s", kv_gen,
                          "kind: Secret\ndata:\n  old: c3RhbGU=\n", "", 0, gen)

        assert win._kv_get_pairs() == {"FRESH": "import"}  # not clobbered
        assert "stale result discarded" in win._status_var.get()
    finally:
        win.destroy()


def test_import_carries_labels_annotations_immutable(monkeypatch, tmp_path):
    """Import → Generate must preserve GitOps ownership metadata and the
    immutable flag (previously the round-trip silently stripped them)."""
    pytest.importorskip("yaml")
    import yaml as _yaml
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: app-creds
  namespace: prod
  labels:
    app.kubernetes.io/managed-by: Helm
  annotations:
    argocd.argoproj.io/tracking-id: "web:Secret:prod/app-creds"
    kubectl.kubernetes.io/last-applied-configuration: '{"data":{"old":"x"}}'
immutable: true
data:
  token: c2VjcmV0
""")
        win._gen_yaml()
        doc = _yaml.safe_load(win._yaml_out.get("1.0", "end"))
        assert doc["metadata"]["labels"] == {
            "app.kubernetes.io/managed-by": "Helm"}
        assert doc["metadata"]["annotations"] == {
            "argocd.argoproj.io/tracking-id": "web:Secret:prod/app-creds"}
        assert doc["immutable"] is True
        assert "carried over" in win._status_var.get()

        # A subsequent .env load is a fresh secret — nothing carries over.
        env = tmp_path / "fresh.env"
        env.write_text("K=v\n")
        monkeypatch.setattr(app.filedialog, "askopenfilename",
                            lambda **k: str(env))
        win._browse_env()
        win._gen_yaml()
        doc = _yaml.safe_load(win._yaml_out.get("1.0", "end"))
        assert "labels" not in doc["metadata"]
        assert "immutable" not in doc
    finally:
        win.destroy()


def test_import_immutable_false_does_not_claim_carryover(monkeypatch, tmp_path):
    """An `immutable: false` secret with no labels/annotations carries nothing,
    so Generate must not append the misleading 'carried over' note."""
    pytest.importorskip("yaml")
    import yaml as _yaml
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: plain
immutable: false
data:
  token: c2VjcmV0
""")
        win._gen_yaml()
        doc = _yaml.safe_load(win._yaml_out.get("1.0", "end"))
        assert "immutable" not in doc          # false == default, omitted
        status = win._status_var.get()
        assert "carried over" not in status    # nothing carried...
        assert "skipped" not in status         # ...and nothing malformed
    finally:
        win.destroy()


def test_import_flags_skipped_malformed_metadata(monkeypatch, tmp_path):
    """When some metadata carries but a malformed field is dropped, Generate's
    status must flag the drop instead of an unqualified 'carried over' that
    hides the loss — e.g. a string `immutable: "true"` alongside a valid label."""
    pytest.importorskip("yaml")
    import yaml as _yaml
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: mixed
  labels:
    app.kubernetes.io/name: web
immutable: "true"
data:
  token: c2VjcmV0
""")
        win._gen_yaml()
        doc = _yaml.safe_load(win._yaml_out.get("1.0", "end"))
        assert doc["metadata"]["labels"] == {"app.kubernetes.io/name": "web"}
        assert "immutable" not in doc          # the string spelling was dropped
        status = win._status_var.get()
        assert "carried over" in status        # the label did survive...
        assert "1 invalid metadata field(s) skipped" in status  # ...immutable didn't
        # A lossy result outranks the otherwise-successful generation: it must
        # use the warning color (not a reassuring green "ok") and stay on
        # screen well past the default 4s so a glance-away doesn't miss it.
        assert win._status_lbl.cget("fg") == app.ERR_C
        assert win._status_job is not None
    finally:
        win.destroy()


def test_import_flags_skipped_malformed_section(monkeypatch, tmp_path):
    """A section that's present but the wrong shape (e.g. `labels: null`) must
    be flagged too, not just individual bad values within an otherwise-valid
    mapping — previously this silently dropped the whole section uncounted."""
    pytest.importorskip("yaml")
    import yaml as _yaml
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: partial
  labels:
  annotations:
    a.io/id: kept
data:
  token: c2VjcmV0
""")
        win._gen_yaml()
        doc = _yaml.safe_load(win._yaml_out.get("1.0", "end"))
        assert doc["metadata"]["annotations"] == {"a.io/id": "kept"}
        assert "labels" not in doc["metadata"]
        status = win._status_var.get()
        assert "carried over" in status                        # annotations survived
        assert "1 invalid metadata field(s) skipped" in status  # labels: null didn't
    finally:
        win.destroy()


def test_seal_gating_cert_and_validate():
    """A loaded cert lifts the detection-in-flight block on Seal (matching
    _do_seal's guard), and a validate in flight blocks Seal (re-sealing would
    swap the pane out from under the pending verdict)."""
    win = _make_win()
    try:
        win._seal_ctx.set("ctxA")
        win._ctl_pending = "ctxA"     # controller detection in flight

        win._cert = ""
        win._refresh_action_buttons()
        assert str(win._seal_btn.cget("state")) == "disabled"  # no cert: wait

        win._cert = "/tmp/pub.pem"
        win._refresh_action_buttons()
        assert str(win._seal_btn.cget("state")) == "normal"    # cert: sealable

        win._clear_cert()  # refreshes buttons itself
        assert str(win._seal_btn.cget("state")) == "disabled"

        win._ctl_pending = None
        win._validating = True        # validate in flight blocks re-sealing
        win._refresh_action_buttons()
        assert str(win._seal_btn.cget("state")) == "disabled"
    finally:
        win.destroy()


def test_load_template_repoints_file_label_to_cluster():
    """The File label is the editor's provenance: after a cluster load it must
    stop naming a previously imported/browsed file."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._env_lbl.configure(text="/tmp/imported.yaml")
        win._enc_ctx.set("c"); win._enc_ns.set("prod"); win._enc_sec.set("s")

        win._got_template("c", "prod", "s", win._kv_edit_gen,
                          "kind: Secret\ndata:\n  token: c2VjcmV0\n", "", 0,
                          win._out_gen)
        assert win._env_lbl.cget("text") == "(cluster: prod/s)"

        win._env_lbl.configure(text="/tmp/imported.yaml")
        win._got_template("c", "prod", "s", win._kv_edit_gen,
                          "kind: Secret\nmetadata:\n  name: hollow\n", "", 0,
                          win._out_gen)  # identity-only branch
        assert win._env_lbl.cget("text") == "(cluster: prod/s)"
    finally:
        win.destroy()


def test_skip_warning_survives_save_and_seal_statuses(monkeypatch, tmp_path):
    """The lossy-carryover warning must be durable: visible from the moment of
    import (before Generate is ever clicked), qualified in the Save/Seal/Copy
    success messages instead of being erased by them, and persistent in the
    tab-independent window chrome throughout."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path, """\
apiVersion: v1
kind: Secret
metadata:
  name: lossy
  labels:
immutable: "true"
data:
  token: c2VjcmV0
""")
        # Visible at import time — no Generate needed to learn of the loss.
        assert win._warn_lbl.winfo_manager() == "pack"
        assert "2 invalid metadata field(s)" in win._warn_lbl.cget("text")

        win._gen_yaml()
        assert "2 invalid metadata field(s) skipped" in win._status_var.get()

        # Save must not flash an unqualified green over the warning...
        win._write_file(str(tmp_path / "out.yaml"), win._yaml_out.get("1.0", "end"))
        status = win._status_var.get()
        assert "Saved out.yaml" in status and "skipped" in status
        assert win._status_lbl.cget("fg") == app.ERR_C

        # ...neither must a successful seal...
        win._on_sealed("kind: SealedSecret\n", "", 0, win._out_gen)
        status = win._status_var.get()
        assert "Sealed successfully" in status and "skipped" in status
        assert win._status_lbl.cget("fg") == app.ERR_C

        # ...nor a Copy of the (lossy) generated/sealed content.
        win._clip_done(False, "payload", qualify=True)
        status = win._status_var.get()
        assert "Copied to clipboard" in status and "skipped" in status
        assert win._status_lbl.cget("fg") == app.ERR_C
        assert win._warn_lbl.winfo_manager() == "pack"  # banner still up

        # Clearing the editor resolves the lossy state — warning goes away
        # and output statuses return to plain green.
        win._clear_env()
        assert win._warn_lbl.winfo_manager() == ""
    finally:
        win.destroy()


def test_skip_warning_hidden_after_clean_reload(monkeypatch, tmp_path):
    """Loading a clean secret (or a .env) over a lossy one retires the
    warning — it reflects the CURRENT editor contents, not history."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path,
                     "kind: Secret\nmetadata:\n  labels:\ndata:\n  t: c2VjcmV0\n")
        assert win._warn_lbl.winfo_manager() == "pack"

        _import_file(win, monkeypatch, tmp_path,
                     "kind: Secret\ndata:\n  t: c2VjcmV0\n")  # clean import
        assert win._warn_lbl.winfo_manager() == ""

        win._gen_yaml()
        win._write_file(str(tmp_path / "clean.yaml"), "x")
        status = win._status_var.get()
        assert "Saved" in status and "skipped" not in status
        assert win._status_lbl.cget("fg") == app.OK_C
        # A plain (non-YAML) copy stays unqualified even mid-session.
        win._clip_done(False, "x", qualify=False)
        assert win._status_var.get() == "Copied to clipboard"
    finally:
        win.destroy()


def test_copy_confirmation_uses_skip_count_frozen_at_copy_time(monkeypatch):
    """The clipboard write is async on Linux; the confirmation must describe
    the payload copied, not whatever _tpl_skipped drifted to before the write
    landed. _clip freezes the count at click time; _clip_done honours it."""
    win = _make_win()
    try:
        # _clip_done honours a frozen count over the live attribute: the
        # payload was captured while 2 were skipped, even though state now
        # reads clean.
        win._tpl_skipped = 0
        win._clip_done(False, "lossy yaml", qualify=True, skipped=2)
        status = win._status_var.get()
        assert "Copied to clipboard" in status
        assert "2 invalid metadata field(s) skipped" in status  # frozen, not 0
        assert win._status_lbl.cget("fg") == app.ERR_C

        # ...and the reverse: a clean copy stays unqualified even if the editor
        # has since become lossy.
        win._tpl_skipped = 3
        win._clip_done(False, "clean yaml", qualify=True, skipped=0)
        assert win._status_var.get() == "Copied to clipboard"
        assert win._status_lbl.cget("fg") == app.OK_C

        # _clip itself captures the live count at call time. Force the
        # synchronous (non-Linux) clip path so the callback runs inline.
        monkeypatch.setattr(app.sys, "platform", "darwin")
        seen = {}
        real_done = win._clip_done

        def spy(ok, payload, qualify=False, skipped=None):
            seen["skipped"] = skipped
            return real_done(ok, payload, qualify, skipped)

        win._clip_done = spy
        win._tpl_skipped = 5
        win._clip("some yaml", qualify=True)   # must freeze 5 here...
        win._tpl_skipped = 0                   # ...before this later change
        assert seen["skipped"] == 5
    finally:
        win.destroy()


def test_warning_bar_sits_above_status_bar(monkeypatch, tmp_path):
    """The warning is anchored just above the status separator, not merely
    'somewhere bottom' — a later side=bottom widget must not be able to slip
    between them. Assert the actual pack order, which presence-only checks
    (winfo_manager) never covered."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        _import_file(win, monkeypatch, tmp_path,
                     "kind: Secret\nmetadata:\n  labels:\ndata:\n  t: c2VjcmV0\n")
        # Among the root window's bottom-packed children, the warning label
        # must be immediately above the status separator (adjacent in the
        # pack list, warning after separator). pack_slaves() reflects the
        # manager's list without needing an idle-tasks flush (which macOS Tk
        # can't survive outside a running mainloop).
        slaves = win.pack_slaves()
        assert win._warn_lbl in slaves and win._status_sep in slaves
        assert slaves.index(win._warn_lbl) == slaves.index(win._status_sep) + 1
    finally:
        win.destroy()


def test_identity_only_binary_drop_uses_warning_severity():
    """Dropping binary passthrough on an identity-only load is a real data
    loss — it must use the warning color, not a green 'ok' flash."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._kv_set_pairs([("KEEP", "me")], binary={"tls.key": "QUJD"})
        win._enc_ctx.set("c"); win._enc_ns.set("n"); win._enc_sec.set("s")

        win._got_template("c", "n", "s", win._kv_edit_gen,
                          "kind: Secret\nmetadata:\n  name: hollow\n", "", 0,
                          win._out_gen)

        assert "dropped 1 binary value(s)" in win._status_var.get()
        assert win._status_lbl.cget("fg") == app.ERR_C
    finally:
        win.destroy()


def test_regenerate_after_inplace_edit_stales_inflight_seal():
    """Editing a row's value IN PLACE passes no repopulation choke point, so
    Generate itself must advance the generation: a seal of the previous YAML
    still in flight has to land stale instead of overwriting the pane with a
    manifest that no longer matches the shown YAML — and sealed output of the
    previous YAML must be retired immediately."""
    win = _make_win()
    try:
        win._kv_set_pairs([("A", "1")])
        win._gen_yaml()
        gen = win._out_gen                       # a seal dispatched now
        win._set_text(win._sealed_out, "kind: SealedSecret  # of A=1\n")

        win._kv_rows[0]["var"].set("2")          # in-place value edit
        win._gen_yaml()                          # regenerate

        assert win._out_gen != gen               # in-flight seal is now stale
        assert win._sealed_out.get("1.0", "end").strip() == ""  # retired
        win._sealing = True
        win._on_sealed("kind: SealedSecret  # of A=1\n", "", 0, gen)
        assert "stale result discarded" in win._status_var.get()
        assert win._sealed_out.get("1.0", "end").strip() == ""  # not resurrected
    finally:
        win.destroy()


def test_kv_clear_resets_per_secret_state():
    """_kv_clear/_kv_set_pairs own the per-secret state reset (the choke
    point): a caller that skips the manual resets must still get a clean
    slate, or stale _tpl_binary would silently re-emit deleted values into
    the next Generate."""
    win = _make_win()
    try:
        win._kv_set_pairs([("A", "1")], binary={"blob": "QUJD"})
        win._tpl_carry = {"labels": {"x": "y"}}
        win._tpl_skipped = 2

        win._kv_clear()

        assert win._tpl_binary == {}
        assert win._tpl_carry == {}
        assert win._tpl_skipped == 0
        win._gen_yaml()  # nothing left — must not resurrect the binary blob
        assert "No KEY=VALUE pairs found" in win._status_var.get()
    finally:
        win.destroy()


def test_dispatch_latest_drops_superseded_result(monkeypatch):
    """Two in-flight lookups for the SAME selection: the older result landing
    last must be dropped — the value-equality guards in the landing callbacks
    can't tell the two apart (the controller-detection race)."""
    win = _make_win()
    try:
        landings = []
        monkeypatch.setattr(app, "run_bg",
                            lambda cmd, cb, **k: landings.append(cb))
        monkeypatch.setattr(win, "after", lambda _ms, fn, *a: fn(*a))
        got = []
        win._dispatch_latest("k", ["cmd1"],
                             lambda o, e, r: got.append(("old", o)))
        win._dispatch_latest("k", ["cmd2"],
                             lambda o, e, r: got.append(("new", o)))

        landings[1]("out2", "", 0)   # newer lands first
        landings[0]("out1", "", 0)   # older lands last — must be dropped

        assert got == [("new", "out2")]
    finally:
        win.destroy()


def test_browse_read_discards_result_after_concurrent_row_edit(monkeypatch, tmp_path):
    """A Browse .env read is async (so the UI stays live while it runs); if
    the user directly edits a KV row (add/type, no Generate, no selector
    change) before the read lands, applying the read must not silently
    overwrite that edit — the race the async-I/O fix itself opened."""
    win = _make_win()
    try:
        path = tmp_path / "x.env"
        path.write_text("NEW=1\n")
        monkeypatch.setattr(app.filedialog, "askopenfilename",
                            lambda **k: str(path))
        captured = {}
        monkeypatch.setattr(win, "_read_file_async",
                            lambda path, key, done: captured.setdefault("done", done))
        win._kv_set_pairs([("EXISTING", "value")])

        win._browse_env()               # dispatches; read hasn't "landed" yet
        win._kv_add_row("NEWKEY", "newval")  # user edits mid-read
        captured["done"](str(path), "NEW=1\n")  # the read finally lands

        assert win._kv_get_pairs() == {"EXISTING": "value", "NEWKEY": "newval"}
        assert "KV rows changed" in win._status_var.get()
    finally:
        win.destroy()


def test_load_template_discards_result_after_concurrent_row_edit():
    """Same race as above for the kubectl fetch path: a Load Template result
    landing after a direct row edit (no selector change, so the (ctx,ns,sec)
    guard alone wouldn't catch it) must be discarded, not silently applied."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        win._kv_set_pairs([("EXISTING", "value")])
        win._enc_ctx.set("c"); win._enc_ns.set("n"); win._enc_sec.set("s")
        kv_gen = win._kv_edit_gen   # captured at dispatch time
        gen = win._out_gen

        win._kv_add_row("NEWKEY", "newval")  # user edits mid-fetch

        win._got_template("c", "n", "s", kv_gen,
                          "kind: Secret\ndata:\n  token: c2VjcmV0\n", "", 0, gen)

        assert win._kv_get_pairs() == {"EXISTING": "value", "NEWKEY": "newval"}
        assert "KV rows changed" in win._status_var.get()
    finally:
        win.destroy()


def test_kubectl_rc_error_consistent_across_call_sites():
    """_got_contexts/_got_controller (and the other kubectl landing
    callbacks) map run_bg's not-found sentinel through the same shared
    _rc_error helper, so a missing kubectl reads identically everywhere
    instead of five near-but-not-quite-identical strings."""
    win = _make_win()
    try:
        assert win._rc_error(-1, "kubectl") == "kubectl not in PATH"
        assert win._rc_error(-2, "kubectl") == "kubectl timed out"
        assert win._rc_error(0, "kubectl") is None
        assert win._rc_error(-1, "kubeseal") == "kubeseal not in PATH"

        win._got_contexts("", "Command not found: kubectl", -1)
        ctx_msg = win._status_var.get()

        win._seal_ctx.set("ctxA")
        win._got_controller("ctxA", "", "Command not found: kubectl", -1)
        controller_msg = win._status_var.get()

        assert ctx_msg == controller_msg == "kubectl not in PATH"
    finally:
        win.destroy()


def test_kv_key_edited_ignores_noop_set():
    """The key StringVar's write trace also fires on a same-value .set()
    (calling _kv_key_edited with no actual change) — it must only bump
    _kv_edit_gen when the text actually changed, or an unrelated in-flight
    read/fetch gets falsely discarded."""
    win = _make_win()
    try:
        rd = win._kv_add_row("KEY", "value")
        gen = win._kv_edit_gen

        rd["key_var"].set("KEY")        # same value — a no-op re-set
        assert win._kv_edit_gen == gen  # not bumped

        rd["key_var"].set("KEY2")       # an actual edit
        assert win._kv_edit_gen == gen + 1
    finally:
        win.destroy()


def test_kv_key_edited_catches_non_keyboard_text_change():
    """The key field is textvariable-bound (not a raw <KeyRelease> bind)
    specifically so a non-keyboard edit — e.g. X11 middle-click paste, or
    any other path that changes the Entry's displayed text without a key
    event — still bumps _kv_edit_gen. Simulated here via .insert(), which is
    exactly how such a paste lands: no keyboard event, just an Entry-content
    mutation that Tk syncs to the bound StringVar (and hence the trace)."""
    win = _make_win()
    try:
        rd = win._kv_add_row("KEY", "value")
        gen = win._kv_edit_gen

        rd["key_e"].insert("end", "2")  # content changes with no KeyRelease

        assert win._kv_edit_gen == gen + 1  # still caught
        assert rd["key_var"].get() == "KEY2"
    finally:
        win.destroy()


def test_kv_value_edited_ignores_noop_set():
    """The value StringVar's write trace also fires on a same-value .set()
    (e.g. the Edit… popup's Save with no change). _kv_value_edited must only
    bump _kv_edit_gen when the value actually changed."""
    win = _make_win()
    try:
        rd = win._kv_add_row("KEY", "value")
        gen = win._kv_edit_gen

        rd["var"].set("value")          # same value — the popup's no-op save
        assert win._kv_edit_gen == gen  # not bumped

        rd["var"].set("changed")        # an actual edit
        assert win._kv_edit_gen == gen + 1
    finally:
        win.destroy()


def test_sealed_error_dump_never_copies_saves_or_validates(monkeypatch, tmp_path):
    """After a failed seal the pane shows the error dump for reading, but it
    must never leave the app as if it were a manifest: Copy Sealed / Save
    Sealed… / Validate all gate on the explicit _sealed_ok flag, not on a
    magic-prefix match of the pane text (which a rewording would invert)."""
    win = _make_win()
    try:
        win._sealing = True
        win._on_sealed("", "cannot fetch certificate", 1, win._out_gen)
        assert "# kubeseal error" in win._sealed_out.get("1.0", "end")

        copied = []
        monkeypatch.setattr(win, "_clip",
                            lambda text, qualify=False: copied.append(text))
        win._copy_sealed()
        assert copied == []                       # dump not copied
        assert "Seal a secret first" in win._status_var.get()

        out = tmp_path / "sealed.yaml"
        monkeypatch.setattr(app.filedialog, "asksaveasfilename",
                            lambda **k: str(out))
        _sync_io(win, monkeypatch)
        win._save_sealed()
        assert not out.exists()                   # dump not written

        win._do_validate()
        assert "Seal a secret first" in win._status_var.get()

        # A successful seal flips the gate back on.
        win._sealing = True
        win._on_sealed("kind: SealedSecret\n", "", 0, win._out_gen)
        win._copy_sealed()
        assert copied and "kind: SealedSecret" in copied[0]
    finally:
        win.destroy()


def test_clip_copies_value_verbatim(monkeypatch):
    """Copied values must be byte-exact: a trailing newline is part of the
    secret (PEM certs/keys end with one) — stripping it would paste an
    altered value into the next system."""
    win = _make_win()
    try:
        monkeypatch.setattr(app.sys, "platform", "darwin")  # sync clip path
        seen = {}
        win._clip_done = lambda ok, payload, qualify=False, skipped=None: \
            seen.setdefault("payload", payload)
        win._clip("-----END CERTIFICATE-----\n")
        assert seen["payload"] == "-----END CERTIFICATE-----\n"
    finally:
        win.destroy()


def test_load_template_newest_wins_on_same_selection(monkeypatch):
    """Two Load clicks for the SAME secret while the first fetch hangs: the
    older result landing first must be dropped as superseded — previously it
    applied first-wins and the fresher snapshot was discarded with a
    misleading 'editor changed' message."""
    pytest.importorskip("yaml")
    win = _make_win()
    try:
        launched = []
        monkeypatch.setattr(app, "run_bg",
                            lambda cmd, cb, **k: launched.append(cb))
        monkeypatch.setattr(win, "after", lambda _ms, fn, *a: fn(*a))
        statuses = []
        monkeypatch.setattr(win, "_status",
                            lambda msg, *a, **k: statuses.append(msg))
        win._enc_ctx.set("c"); win._enc_ns.set("n"); win._enc_sec.set("s")

        win._load_template()   # click 1 — fetch hangs
        win._load_template()   # click 2 — supersedes click 1
        launched[0]("kind: Secret\ndata:\n  old: c3RhbGU=\n", "", 0)
        launched[1]("kind: Secret\ndata:\n  fresh: c2VjcmV0\n", "", 0)

        assert win._kv_get_pairs() == {"fresh": "secret"}  # newest won
        assert not any("discarded" in m for m in statuses)
        assert any(m.startswith("Loaded 1 key(s)") for m in statuses)
    finally:
        win.destroy()


def test_controller_detection_cached_per_context(monkeypatch):
    """Detection is a cluster-wide `kubectl get svc -A` with Seal/Validate
    blocked while it runs: re-selecting an already-detected context must be
    served from the cache (no re-list, no blocked buttons); the ⟳ refresh is
    the invalidation point."""
    win = _make_win()
    try:
        calls = []
        monkeypatch.setattr(app, "run_bg", lambda *a, **k: calls.append(a))
        win._seal_ctx.set("A")

        win._detect_controller("A")
        assert len(calls) == 1                    # real lookup dispatched
        win._got_controller("A", "kube-system\tsealed-secrets-controller\n",
                            "", 0)                # lands and caches

        win._set_ro_entry(win._ctl_name, ""); win._set_ro_entry(win._ctl_ns, "")
        win._detect_controller("A")               # re-select the same context
        assert len(calls) == 1                    # served from cache
        assert win._ctl_name.get() == "sealed-secrets-controller"
        assert win._ctl_ns.get() == "kube-system"
        assert str(win._seal_btn.cget("state")) == "normal"  # never blocked

        win._fetch_contexts()                     # ⟳ — clears the cache
        win._detect_controller("A")
        assert len(calls) == 3                    # contexts fetch + fresh lookup
    finally:
        win.destroy()
