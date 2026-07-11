"""Pure, UI-independent logic for b64 - Kubernetes Secrets Tool.

Base64 encode/decode, .env parsing/rendering, and Kubernetes Secret YAML
generation. Kept free of any tkinter import so it can be unit-tested without
a display.
"""

import base64
import os
import re
from collections import deque

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
# are rare and quoting them is always valid. \Z, not $: $ also matches just
# before a trailing newline, which would let "abc\n" through as a bare scalar
# and break the document.
_SAFE_YAML = re.compile(r"[A-Za-z][A-Za-z0-9._-]*\Z")

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
    The empty string is quoted too — a bare empty scalar reads as null.
    Newlines/CRs are escaped, not emitted raw: a double-quoted scalar spanning
    physical lines gets its line breaks FOLDED TO SPACES on reparse, which
    corrupts values (e.g. multi-line base64 passthrough gains spaces that
    Kubernetes' decoder rejects)."""
    if _SAFE_YAML.match(v) and v not in _YAML_AMBIG:
        return v
    return '"' + (v.replace("\\", "\\\\").replace('"', '\\"')
                   .replace("\n", "\\n").replace("\r", "\\r")) + '"'


# Annotation kubectl regenerates on apply; it embeds a JSON snapshot of the
# PREVIOUS secret (including its data), so carrying it through a round-trip
# would both leak the old values into the new manifest and mislead kubectl.
_LAST_APPLIED = "kubectl.kubernetes.io/last-applied-configuration"

# Metadata sections carried through an import → Generate round-trip. Shared by
# secret_carryover (capture) and build_secret_yaml (emit) so the two can't
# drift — a section captured but never emitted would silently lie about
# round-trip fidelity, the exact bug class secret_carryover exists to avoid.
_CARRY_SECTIONS = ("labels", "annotations")


def secret_carryover(doc):
    """The user-owned fields of a Secret doc that must survive an import →
    Generate round-trip but aren't editable in the UI: metadata.labels,
    metadata.annotations (minus kubectl's last-applied snapshot) and
    `immutable`. Server-managed metadata (uid, resourceVersion,
    creationTimestamp, managedFields, ...) is deliberately NOT carried — the
    emitted manifest is for (re-)applying, where those are rejected or
    regenerated.

    Returns ``(carry, skipped)``: ``carry`` is the mapping to re-emit, and
    ``skipped`` counts candidate metadata fields DROPPED for being malformed
    so the caller can warn the user their round-trip was lossy instead of
    claiming full fidelity. Only str→str label/annotation pairs are carried,
    and only a canonical ``immutable: true``. Kubernetes requires
    labels/annotations to be strings and immutable to be a bool, so real
    cluster secrets always qualify and skip 0; a hand-authored file with a
    non-string value (e.g. a null annotation, which would otherwise be str()'d
    into the literal "None") or a non-bool ``immutable`` (e.g. the string
    "true") is malformed — dropped and counted, never silently rewritten into
    a wrong value. A present-but-wrong-shaped `metadata`, `labels`, or
    `annotations` (e.g. `labels: null`, a list instead of a mapping) is
    likewise malformed and counted — an absent key is normal (most secrets
    carry no labels), but a key that *is* there and unusable is a real,
    countable loss, not a silent no-op. Returns ``({}, 0)`` for anything that
    isn't Secret-shaped."""
    if not isinstance(doc, dict):
        return {}, 0
    carry = {}
    skipped = 0
    meta = doc.get("metadata")
    if not isinstance(meta, dict):
        # Present but unusable counts as a loss (whatever it held is
        # unrecoverable); merely absent does not — one check both counts
        # and normalizes so the two can't drift apart.
        if "metadata" in doc:
            skipped += 1
        meta = {}
    for section in _CARRY_SECTIONS:
        if section not in meta:
            continue  # absent — nothing to carry, nothing lost
        src = meta[section]
        if not isinstance(src, dict):
            skipped += 1  # present but not a mapping — can't inspect its entries
            continue
        kept = {}
        for k, v in src.items():
            if section == "annotations" and k == _LAST_APPLIED:
                continue  # deliberately stripped — not a loss, not counted
            if isinstance(k, str) and isinstance(v, str):
                kept[k] = v
            else:
                skipped += 1
        if kept:
            carry[section] = kept
    imm = doc.get("immutable")
    if imm is True:
        carry["immutable"] = True
    elif imm is not None and not isinstance(imm, bool):
        # A non-bool immutable (e.g. "true") is malformed and dropped. A real
        # `immutable: false` is the k8s default (no loss), so it isn't counted.
        skipped += 1
    return carry, skipped


def build_secret_yaml(name: str, namespace: str, data: dict,
                      type_: str = "Opaque", raw_data: dict = None,
                      carryover: dict = None) -> str:
    """Build Secret YAML. `data` holds plaintext values (base64-encoded here);
    `raw_data` holds values that are ALREADY base64 and are emitted verbatim —
    used for binary keys that can't survive a plaintext round-trip.
    `carryover` (see secret_carryover) re-emits an imported Secret's labels /
    annotations / immutable so a fix-and-reapply round-trip doesn't silently
    strip GitOps ownership metadata or the immutability flag."""
    carry = carryover or {}
    lines = [
        "apiVersion: v1",
        "kind: Secret",
        "metadata:",
        f"  name: {yaml_scalar(name)}",
        f"  namespace: {yaml_scalar(namespace)}",
    ]
    for section in _CARRY_SECTIONS:
        if carry.get(section):
            lines.append(f"  {section}:")
            for k, v in carry[section].items():
                lines.append(f"    {yaml_scalar(k)}: {yaml_scalar(v)}")
    if carry.get("immutable"):
        lines.append("immutable: true")
    lines += [
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


def first_invalid_key(entries):
    """The first key whose value Kubernetes would reject (kind "invalid"), or
    None. Lives beside the kind taxonomy secret_entries defines, so the safety
    gate that stops such values from round-tripping as garbage can't silently
    drift from it."""
    return next((k for k, _v, kind in entries if kind == "invalid"), None)


def _flatten_list_docs(docs) -> list:
    """Expand `kind: List` wrappers (what `kubectl get -o yaml` and helm/argo
    renders emit) into their .items, however deeply nested, so a nested List
    can't hide a Secret. Non-dict docs are dropped.

    Iterative over a deque, with each wrapper expanded at most once: YAML
    anchors/aliases let a hand-crafted List nest arbitrarily deep, contain
    itself (recursion would die with RecursionError), or fan out to a huge
    flat width (a plain list's pop(0)/prepend would go quadratic and hang)."""
    flat, queue, expanded = [], deque(docs), set()
    while queue:
        d = queue.popleft()
        if not isinstance(d, dict):
            continue
        if d.get("kind") == "List" and isinstance(d.get("items"), list):
            if id(d) not in expanded:  # skip an anchor/alias cycle
                expanded.add(id(d))
                # Expand in place, keeping document order.
                queue.extendleft(reversed(d["items"]))
        else:
            flat.append(d)
    return flat


def select_secret_doc(docs):
    """Pick the Secret to work on from parsed YAML docs (a multi-doc manifest
    may bundle several resources; a `kind: List` wrapper is unwrapped). An
    explicit `kind: Secret` always wins over a kind-less mapping carrying
    data/stringData (a bare snippet) — a kind-less fragment must never shadow
    a real Secret later in the file. Docs with any other kind (ConfigMap, ...)
    are never picked even though their `data` is Secret-shaped. Returns None
    if nothing qualifies."""
    docs = _flatten_list_docs(docs)
    for d in docs:
        if d.get("kind") == "Secret":
            return d
    for d in docs:
        if d.get("kind") is None and (isinstance(d.get("data"), dict)
                                      or isinstance(d.get("stringData"), dict)):
            return d
    return None


def has_sealed_secret(docs) -> bool:
    """Whether any parsed doc (List wrappers unwrapped) is a SealedSecret —
    its values are encrypted for the cluster controller, so there is nothing
    to decode/import locally."""
    return any(d.get("kind") == "SealedSecret"
               for d in _flatten_list_docs(docs))


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
