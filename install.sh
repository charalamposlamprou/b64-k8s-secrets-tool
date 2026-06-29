#!/usr/bin/env bash
#
# One-command installer for b64-k8s-secrets-tool.
#
#   bash install.sh            # install everything, then print how to start
#   bash install.sh --start    # ...and launch the app when done
#
# Idempotent and cross-platform:
#   • macOS         — ensures Xcode Command Line Tools + Homebrew, then runs
#                     `make bootstrap` (Homebrew Tcl/Tk 9 + venv + deps).
#   • Ubuntu/Debian — including WSL: apt-installs make/python/tk/venv, then
#                     `make bootstrap`.
#
# It also installs a global `b64secrets` launcher on your PATH so you can start
# the app from anywhere (b64secrets / b64secrets stop / b64secrets status).
#
# kubectl / kubeseal are installed best-effort — the encode/decode tabs work
# without them; only the cluster-fetch and Seal features need them.
set -euo pipefail

cd "$(dirname "$0")"
APP_DIR="$(pwd -P)"

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
info() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

START_APP=false
[ "${1:-}" = "--start" ] && START_APP=true

OS="$(uname -s)"

# Use sudo only when not already root — root WSL distros and minimal containers
# often have no sudo binary, so calling it unconditionally would break there.
SUDO=""
[ "$(id -u)" = 0 ] || SUDO="sudo"

# Normalise CPU arch for kubectl/kubeseal download URLs.
case "$(uname -m)" in
  x86_64|amd64)   ARCH=amd64 ;;
  aarch64|arm64)  ARCH=arm64 ;;
  *)              ARCH=amd64; warn "unknown CPU arch '$(uname -m)', assuming amd64" ;;
esac

# Detect WSL purely for a friendlier GUI note at the end.
IS_WSL=false
grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null && IS_WSL=true

# ---------------------------------------------------------------------------
# macOS prerequisites: Command Line Tools (for `make`) + Homebrew (for Tk 9).
# ---------------------------------------------------------------------------
ensure_macos_prereqs() {
  if ! xcode-select -p >/dev/null 2>&1; then
    info "Installing Xcode Command Line Tools (a dialog will appear — click Install)…"
    xcode-select --install || true
    # Wait for the install to finish, but bail out instead of looping forever if
    # the dialog is cancelled or stalls (~30 min at 5s/poll).
    tries=0
    until xcode-select -p >/dev/null 2>&1; do
      tries=$((tries + 1))
      if [ "$tries" -gt 360 ]; then
        die "Command Line Tools not detected after ~30 min — finish or retry the install, then re-run: bash install.sh"
      fi
      printf '\r    waiting for Command Line Tools to finish installing…'
      sleep 5
    done
    printf '\n'
  fi

  if ! command -v brew >/dev/null 2>&1; then
    info "Installing Homebrew…"
    local brew_installer
    brew_installer="$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)" \
      || die "could not download the Homebrew installer (network?) — install Homebrew from https://brew.sh, then re-run: bash install.sh"
    NONINTERACTIVE=1 /bin/bash -c "$brew_installer"
  fi
  # Put brew on PATH for the rest of this script (Apple Silicon vs Intel).
  if   [ -x /opt/homebrew/bin/brew ]; then eval "$(/opt/homebrew/bin/brew shellenv)"
  elif [ -x /usr/local/bin/brew  ];  then eval "$(/usr/local/bin/brew shellenv)"
  fi
}

# ---------------------------------------------------------------------------
# Linux prerequisites (Ubuntu/Debian, incl. WSL): need `make` and the build
# tooling present before the Makefile can run. `make bootstrap` will re-run the
# tk/venv/pip apt step itself — that's idempotent, so this just front-loads the
# pieces the Makefile assumes already exist.
# ---------------------------------------------------------------------------
ensure_linux_prereqs() {
  command -v apt-get >/dev/null 2>&1 || \
    die "this installer supports apt-based distros (Ubuntu/Debian/WSL). Install make, python3, python3-tk, python3-venv manually, then run 'make bootstrap'."
  info "Updating apt and installing base tooling (sudo may prompt)…"
  $SUDO apt-get update -y
  $SUDO apt-get install -y make curl ca-certificates tar \
       python3 python3-tk python3-venv python3-pip
}

# ---------------------------------------------------------------------------
# Optional cluster tools — best-effort, never abort the install.
# ---------------------------------------------------------------------------
ensure_cluster_tools() {
  if [ "$OS" = "Darwin" ]; then
    command -v kubectl  >/dev/null 2>&1 || { info "Installing kubectl…";  brew install kubernetes-cli || warn "kubectl install failed — install it later for cluster features"; }
    command -v kubeseal >/dev/null 2>&1 || { info "Installing kubeseal…"; brew install kubeseal      || warn "kubeseal install failed — install it later for the Seal tab"; }
    return
  fi

  # Linux: pull official static binaries into /usr/local/bin (best-effort).
  if ! command -v kubectl >/dev/null 2>&1; then
    info "Installing kubectl…"
    _kc_tmp=""
    if ver="$(curl -fsSL https://dl.k8s.io/release/stable.txt)" \
       && _kc_tmp="$(mktemp)" \
       && curl -fsSL "https://dl.k8s.io/release/${ver}/bin/linux/${ARCH}/kubectl" -o "$_kc_tmp"; then
      $SUDO install -m 0755 "$_kc_tmp" /usr/local/bin/kubectl \
        || warn "kubectl install failed — install it later for cluster features"
      rm -f "$_kc_tmp"
    else
      if [ -n "$_kc_tmp" ]; then rm -f "$_kc_tmp"; fi
      warn "kubectl download failed — install it later for cluster features"
    fi
  fi
  if ! command -v kubeseal >/dev/null 2>&1; then
    info "Installing kubeseal…"
    _ks_tmpdir=""
    if _ks_tag="$(curl -fsSL https://api.github.com/repos/bitnami-labs/sealed-secrets/releases/latest \
                   | grep -m1 '"tag_name"' | cut -d '"' -f4)" \
       && [ -n "$_ks_tag" ] \
       && _ks_ver="${_ks_tag#v}" \
       && _ks_tmpdir="$(mktemp -d)" \
       && curl -fsSL "https://github.com/bitnami-labs/sealed-secrets/releases/download/${_ks_tag}/kubeseal-${_ks_ver}-linux-${ARCH}.tar.gz" \
            | tar -xzf - -C "$_ks_tmpdir" kubeseal; then
      $SUDO install -m 0755 "$_ks_tmpdir/kubeseal" /usr/local/bin/kubeseal \
        || warn "kubeseal install failed — install it later for the Seal tab"
    else
      warn "kubeseal download failed — install it later for the Seal tab"
    fi
    if [ -n "$_ks_tmpdir" ]; then rm -rf "$_ks_tmpdir"; fi
  fi
}

# ---------------------------------------------------------------------------
# Install a global `b64secrets` launcher on PATH. It just delegates to `make`
# in this repo, so `b64secrets` == `make start`, and stop/restart/status work
# too. macOS → $(brew --prefix)/bin (e.g. /opt/homebrew/bin); Linux → /usr/local/bin.
# ---------------------------------------------------------------------------
install_launcher() {
  local bindir target tmp
  if [ "$OS" = "Darwin" ]; then
    bindir="$(brew --prefix)/bin"
  else
    bindir="/usr/local/bin"
  fi
  target="$bindir/b64secrets"

  tmp="$(mktemp)"
  cat >"$tmp" <<EOF
#!/usr/bin/env bash
# b64secrets — launcher for b64-k8s-secrets-tool (generated by install.sh).
# Usage: b64secrets [start|stop|restart|status]   (default: start)
APP_DIR="$APP_DIR"
if [ ! -f "\$APP_DIR/Makefile" ]; then
  echo "b64secrets: tool not found at \$APP_DIR (repo moved or removed?)." >&2
  echo "Re-run the installer from the repo to fix the path: bash install.sh" >&2
  exit 1
fi
exec make -C "\$APP_DIR" "\${1:-start}"
EOF
  chmod 0755 "$tmp"

  mkdir -p "$bindir" 2>/dev/null || true
  if install -m 0755 "$tmp" "$target" 2>/dev/null; then
    :
  else
    info "Writing launcher to $target (may prompt for sudo)…"
    $SUDO install -m 0755 "$tmp" "$target"
  fi
  rm -f "$tmp"
  info "Launcher installed: $target"
  command -v b64secrets >/dev/null 2>&1 || \
    warn "$bindir is not on your PATH yet — open a new shell, or add it to PATH."
}

# ---------------------------------------------------------------------------
case "$OS" in
  Darwin) ensure_macos_prereqs ;;
  Linux)  ensure_linux_prereqs ;;
  *)      die "unsupported OS: $OS (this tool targets macOS and Ubuntu/Debian)" ;;
esac

info "Running make bootstrap (system deps + venv + Python deps)…"
make bootstrap

ensure_cluster_tools
install_launcher

bold "✅ Install complete."
if [ "$OS" = "Linux" ] && $IS_WSL; then
  echo "   (WSL detected — the GUI needs WSLg, which ships with Windows 11.)"
fi
if $START_APP; then
  info "Starting the app…"
  make start
else
  echo "Start it with:  b64secrets      (or: make start)"
fi
