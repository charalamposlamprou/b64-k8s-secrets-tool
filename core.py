"""Pure, UI-independent logic for b64 - Kubernetes Secrets Tool.

Base64 encode/decode, .env parsing/rendering, and Kubernetes Secret YAML
generation. Kept free of any tkinter import so it can be unit-tested without
a display.
"""

import base64
import os
import re

# ---------------------------------------------------------------------------
# base64
# ---------------------------------------------------------------------------


def b64_encode(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def b64_decode(s: str, errors: str = "replace") -> str:
    s = "".join(s.split())   # drop ALL whitespace, incl. line wraps
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.b64decode(s, validate=True).decode("utf-8", errors=errors)


def b64_valid_for_k8s(s: str) -> bool:
    """Whether Kubernetes itself would accept `s` as a base64 `data` value.

    Stricter than b64_decode, which pads and strips all whitespace to be
    forgiving about copy-paste: Go's base64 decoder (behind the API server)
    ignores only \\r and \\n and requires correct padding, so plaintext that
    merely *resembles* base64 (e.g. "hunter2") is rejected at apply time."""
    s = s.replace("\r", "").replace("\n", "")
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# .env parsing / rendering
# ---------------------------------------------------------------------------

_DOTENV_ESCAPES = {"\\": "\\", "n": "\n", "r": "\r", "t": "\t", '"': '"'}
_DOTENV_UNESCAPE = re.compile(r'\\([\\nrt"])')


def parse_dotenv(text: str) -> dict:
    """Parse KEY=value lines. Single-quoted and bare values are literal;
    double-quoted values un-escape \\\\, \\n, \\r, \\t and \\" (the inverse
    of dotenv_line, so Load Template round-trips exactly)."""
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
        if not key:
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            quote, val = val[0], val[1:-1]
            if quote == '"':
                val = _DOTENV_UNESCAPE.sub(
                    lambda m: _DOTENV_ESCAPES[m.group(1)], val)
        result[key] = val
    return result


# Values that survive a bare (unquoted) .env line verbatim.
_BARE_ENV = re.compile(r"[A-Za-z0-9_./:@+,=-]+\Z")


def dotenv_line(key: str, val: str) -> str:
    """Render KEY=value so parse_dotenv reads the exact value back:
    bare when safe, otherwise double-quoted with escaping."""
    if _BARE_ENV.match(val):
        return f"{key}={val}"
    esc = (val.replace("\\", "\\\\").replace('"', '\\"')
              .replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t"))
    return f'{key}="{esc}"'


# ---------------------------------------------------------------------------
# Kubernetes Secret YAML
# ---------------------------------------------------------------------------

# Built-in Kubernetes Secret types (the field accepts any string).
SECRET_TYPES = [
    "Opaque",
    "bootstrap.kubernetes.io/token",
    "kubernetes.io/basic-auth",
    "kubernetes.io/dockercfg",
    "kubernetes.io/dockerconfigjson",
    "kubernetes.io/service-account-token",
    "kubernetes.io/ssh-auth",
    "kubernetes.io/tls",
]


# Plain (unquoted) YAML scalars. Letter-first so nothing digit-led can hit a
# YAML 1.1 numeric form (1234, 0x1A, 1_000, 1.5, ...); digit-led names/keys
# are rare and quoting them is always valid.
_SAFE_YAML = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")

# Words a YAML 1.1 parser (kubectl) reads as booleans/null even when they are
# meant as strings — e.g. a key "NO" or a base64 value "True".
_YAML_AMBIG = {
    "y", "Y", "yes", "Yes", "YES", "n", "N", "no", "No", "NO",
    "true", "True", "TRUE", "false", "False", "FALSE",
    "on", "On", "ON", "off", "Off", "OFF", "null", "Null", "NULL",
}


def yaml_scalar(v: str) -> str:
    """Return v as a YAML scalar, double-quoting (with escaping) if it isn't a
    plain DNS-safe token, so hand-edited names/keys can't break the document.
    The empty string is quoted too — a bare empty scalar reads as null."""
    if _SAFE_YAML.match(v) and v not in _YAML_AMBIG:
        return v
    return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_secret_yaml(name: str, namespace: str, data: dict,
                      type_: str = "Opaque", raw_data: dict = None) -> str:
    """Build Secret YAML. `data` holds plaintext values (base64-encoded here);
    `raw_data` holds values that are ALREADY base64 and are emitted verbatim —
    used for binary keys that can't survive a plaintext round-trip."""
    lines = [
        "apiVersion: v1",
        "kind: Secret",
        "metadata:",
        f"  name: {yaml_scalar(name)}",
        f"  namespace: {yaml_scalar(namespace)}",
        f"type: {yaml_scalar(type_)}",
        "data:",
    ]
    for k, v in data.items():
        lines.append(f"  {yaml_scalar(k)}: {yaml_scalar(b64_encode(v))}")
    for k, v in (raw_data or {}).items():
        lines.append(f"  {yaml_scalar(k)}: {yaml_scalar(v)}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Secret introspection
# ---------------------------------------------------------------------------

def secret_entries(doc) -> list:
    """Flatten a Secret's `data` and `stringData` into an ordered list of
    (key, value, kind) tuples:

      - kind "text":    value is the decoded/plaintext string
      - kind "binary":  valid base64 that isn't UTF-8 text; value is the
                        ORIGINAL base64 (so callers can still copy/round-trip it)
      - kind "invalid": not base64 Kubernetes would accept (plaintext mistakenly
                        under `data` instead of `stringData`, typically); value
                        is the original string

    `data` is base64 (decoded here, strictly); `stringData` is already plaintext
    and overrides `data` on a key conflict, matching how Kubernetes merges them.
    Returns [] for anything that isn't a Secret-shaped mapping.
    """
    if not isinstance(doc, dict):
        return []
    out, index = [], {}

    def put(key, entry):
        if key in index:
            out[index[key]] = entry
        else:
            index[key] = len(out)
            out.append(entry)

    data = doc.get("data")
    if isinstance(data, dict):
        for k, v in data.items():
            if v is None:  # genuinely missing value (`KEY:`); 0/False are real
                put(k, (k, "", "text"))
                continue
            try:
                put(k, (k, b64_decode(str(v), errors="strict"), "text"))
            except Exception:
                kind = "binary" if b64_valid_for_k8s(str(v)) else "invalid"
                put(k, (k, str(v), kind))

    sdata = doc.get("stringData")
    if isinstance(sdata, dict):
        for k, v in sdata.items():
            put(k, (k, "" if v is None else str(v), "text"))

    return out


def select_secret_doc(docs):
    """Pick the Secret to work on from parsed YAML docs (a multi-doc manifest
    may bundle several resources). An explicit `kind: Secret` always wins over
    a kind-less mapping carrying data/stringData (a bare snippet) — a kind-less
    fragment must never shadow a real Secret later in the file. Docs with any
    other kind (ConfigMap, ...) are never picked even though their `data` is
    Secret-shaped. Returns None if nothing qualifies."""
    docs = [d for d in docs if isinstance(d, dict)]
    for d in docs:
        if d.get("kind") == "Secret":
            return d
    for d in docs:
        if d.get("kind") is None and (isinstance(d.get("data"), dict)
                                      or isinstance(d.get("stringData"), dict)):
            return d
    return None


def has_sealed_secret(docs) -> bool:
    """Whether any parsed doc is a SealedSecret — its values are encrypted for
    the cluster controller, so there is nothing to decode/import locally."""
    return any(isinstance(d, dict) and d.get("kind") == "SealedSecret"
               for d in docs)


# ---------------------------------------------------------------------------
# kubeseal command construction
# ---------------------------------------------------------------------------

def _controller_flags(context: str = None, ctl_name: str = None,
                      ctl_ns: str = None) -> list:
    """The --context / --controller-* flags shared by seal and validate.
    Falsy values are omitted so kubeseal falls back to its own defaults."""
    flags = []
    if context:
        flags.append(f"--context={context}")
    if ctl_name:
        flags.append(f"--controller-name={ctl_name}")
    if ctl_ns:
        flags.append(f"--controller-namespace={ctl_ns}")
    return flags


def kubeseal_seal_cmd(scope: str, context: str = None, cert: str = None,
                      ctl_name: str = None, ctl_ns: str = None) -> list:
    """argv to seal a Secret read from stdin into a SealedSecret on stdout."""
    cmd = ["kubeseal", "--format=yaml", f"--scope={scope}"]
    if cert:
        cmd.append(f"--cert={cert}")
    cmd += _controller_flags(context, ctl_name, ctl_ns)
    return cmd


def kubeseal_validate_cmd(context: str = None, ctl_name: str = None,
                          ctl_ns: str = None) -> list:
    """argv to validate a SealedSecret read from stdin against the controller."""
    return ["kubeseal", "--validate"] + _controller_flags(context, ctl_name, ctl_ns)


# ---------------------------------------------------------------------------
# Secret-bearing file output
# ---------------------------------------------------------------------------

def write_secret_file(path: str, content: str) -> None:
    """Write secret-bearing content with owner-only (0o600) permissions.

    O_CREAT only applies the mode when the file is *created*, so overwriting an
    existing (possibly world-readable) file would otherwise keep its old mode;
    fchmod forces 0o600 regardless. (fchmod is absent on Windows, where POSIX
    permissions don't apply — there the open mode is the best available.)
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        if hasattr(os, "fchmod"):
            os.fchmod(f.fileno(), 0o600)
        f.write(content)
