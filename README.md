# b64 — Kubernetes Secrets Tool

A dark-themed Tkinter GUI for working with Kubernetes secrets: encode/decode
base64, build Secret YAML from a `.env` file, fetch existing secrets from a
cluster (read-only), and seal them with `kubeseal`.

> **Read-only against the cluster.** The tool never runs `kubectl apply`,
> `create`, `patch`, or `delete`. It only *reads* (contexts, namespaces,
> secrets) and produces YAML locally.

## Screenshots

| Encode | Decode | Seal |
|:---:|:---:|:---:|
| ![Encode tab](docs/encode.png) | ![Decode tab](docs/decode.png) | ![Seal tab](docs/seal.png) |
| Encode a single value or load a `.env` file, fetch a secret from the cluster, and generate Kubernetes Secret YAML. | Decode a single base64 value or load a Secret YAML file to view all keys in a masked, per-row table with Show/Hide and Copy. | Seal the generated YAML with `kubeseal` — auto-detects the controller name and namespace; supports strict, namespace-wide, and cluster-wide scopes. |

## Features

- **Encode tab**
  - Single-value base64 encoder
  - `.env` → Kubernetes Secret YAML: load a `.env` file or fetch an existing
    secret from a cluster, edit the `KEY=value` pairs, then generate, copy, or
    save the Secret YAML
  - Secret **type** selector (`Opaque`, `bootstrap.kubernetes.io/token`,
    `kubernetes.io/tls`, …) — pick a built-in type or enter a custom one;
    while it is left at `Opaque`, the type is auto-detected from the keys
    (e.g. `tls.crt` + `tls.key` → `kubernetes.io/tls`)
  - **Load Template** pulls a secret from the cluster and decodes it into the
    editor — also pre-filling the editable Secret name / Namespace / Type fields
  - **Import Secret…** loads a Secret YAML file from disk into the same editor —
    for fixing a secret that never deployed (e.g. a mis-sealed one), where
    there is no cluster copy to fetch. Multi-doc manifests are handled (an
    explicit `kind: Secret` wins), and plaintext mistakenly under `data:`
    is rejected with a pointer to `stringData` instead of being silently
    re-encoded as garbage
  - Imported/loaded secrets round-trip faithfully: `metadata.labels`,
    `metadata.annotations` (minus kubectl's last-applied snapshot) and
    `immutable` are carried through to the generated YAML, so re-applying
    doesn't strip GitOps ownership metadata. Malformed metadata (a non-string
    label/annotation value, or a non-bool `immutable`) is dropped rather than
    silently rewritten, and Generate's status reports how many fields were
    skipped so a lossy round-trip is visible
- **Decode tab**
  - Single-value base64 decoder with masked output + Show/Hide
  - Secret YAML → decoded table: per-row Show/Hide and Copy, plus Show All / Hide All;
    multi-doc manifests are handled, and a SealedSecret file gets an
    explanatory hint (its values only decrypt in the cluster)
- **Seal tab**
  - Seals the YAML from the Encode tab with `kubeseal`
  - Context + scope (`strict` / `namespace-wide` / `cluster-wide`) and an
    optional cert file
  - **Validate** round-trips the sealed output through the controller
    (`kubeseal --validate`) to confirm it will actually decrypt — catching a
    wrong key, scope, or name/namespace before you apply it (creates nothing)
- All `kubectl` / `kubeseal` calls run on background threads, so the UI never blocks.

## Requirements

- macOS, or Debian/Ubuntu Linux (incl. WSL)
- `kubectl` and `kubeseal` on your `PATH` (for the cluster-fetch and seal features)
- A modern Tcl/Tk — see the note below

`bash install.sh` sets all of these up for you (Homebrew + Command Line Tools on
macOS, or `apt` on Linux/WSL), so you don't need them in place beforehand.

> **Why a Homebrew Python?** macOS ships a deprecated **system Tk 8.5** that
> renders custom widget colours incorrectly (invisible labels, blank panels).
> The `Makefile` builds a virtualenv from a Homebrew Python linked against
> **Tcl/Tk 9**, so the dark theme renders correctly. Running the app with the
> plain `/usr/bin/python3` will look broken — always launch via `make`.

## Quick start

Fresh machine — one command does everything (Command Line Tools / Homebrew on
macOS, or `apt` on Ubuntu/Debian/WSL), then the Tk + venv + deps, plus a
best-effort `kubectl`/`kubeseal`:

```bash
bash install.sh
```

It also installs a global `b64secrets` launcher on your `PATH`, so you can start
the app from anywhere:

```bash
b64secrets
```

> The `b64secrets` launcher just delegates to `make` in this repo, so it hardcodes
> the repo path at install time — if you move the repo, re-run `bash install.sh`.

Prefer to do it by hand? Install the modern Tk + venv + deps and run it directly:

```bash
make bootstrap
make start
```

## Usage

| Command | Action |
|---|---|
| `bash install.sh` | One-command install: prerequisites + `make bootstrap` + `kubectl`/`kubeseal` + the `b64secrets` launcher (`--start` to launch when done) |
| `b64secrets`     | Launch the app from anywhere (also `b64secrets stop` / `restart` / `status`) |
| `make bootstrap` | Full fresh-install setup (Homebrew Tk + venv + deps) |
| `make setup`     | Create the venv and install Python deps (idempotent) |
| `make start`     | Launch the app in the background |
| `make stop`      | Stop the running app |
| `make restart`   | Stop, then start |
| `make status`    | Show whether the app is running |
| `make clean`     | Stop and remove the venv, cache, and pidfile |

The app runs detached in the background; closing the terminal won't stop it —
use `make stop`. The running process ID is tracked in `.app.pid`.

## Project layout

```
app.py        the application (single file)
install.sh    one-command cross-platform installer (+ b64secrets launcher)
Makefile      setup / start / stop / status
README.md     this file
.venv/        virtualenv with Tcl/Tk 9 + PyYAML (created by make)
```

## Releases

**Every pull request merged into `main` cuts a release.** The version bump
defaults to **patch**; add a label to bump higher, or skip the release:

| Label | Bump | Example |
|---|---|---|
| `release:patch` _or no label_ | patch | `v1.2.3` → `v1.2.4` |
| `release:minor` | minor | `v1.2.3` → `v1.3.0` |
| `release:major` | major | `v1.2.3` → `v2.0.0` |
| `release:skip` | _no release_ | — |

The workflow computes the next version from the latest tag, then creates the
tag and a GitHub release with auto-generated notes.
