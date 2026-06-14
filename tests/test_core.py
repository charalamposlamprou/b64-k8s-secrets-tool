"""Unit tests for the pure helper functions in core.py.

core.py has no tkinter import, so these run anywhere — no display needed.
"""

import base64
import os
import stat

import pytest
import yaml

import core


# --------------------------------------------------------------------------
# base64
# --------------------------------------------------------------------------

def test_b64_encode_matches_stdlib():
    assert core.b64_encode("hello") == base64.b64encode(b"hello").decode()


@pytest.mark.parametrize("text", ["", "hello", "a", "ab", "abc", "üñîçødé", "k=v\nx=y"])
def test_b64_round_trip(text):
    assert core.b64_decode(core.b64_encode(text)) == text


def test_b64_decode_tolerates_missing_padding():
    # "hello" -> "aGVsbG8=" ; decoding the unpadded form must still work.
    assert core.b64_decode("aGVsbG8") == "hello"


def test_b64_decode_strips_whitespace():
    assert core.b64_decode("  aGVsbG8=\n") == "hello"


# --------------------------------------------------------------------------
# .env parsing / rendering
# --------------------------------------------------------------------------

def test_parse_dotenv_basic():
    assert core.parse_dotenv("FOO=bar\nBAZ=qux") == {"FOO": "bar", "BAZ": "qux"}


def test_parse_dotenv_skips_comments_and_blanks():
    assert core.parse_dotenv("# comment\n\nFOO=bar\n   \n") == {"FOO": "bar"}


def test_parse_dotenv_strips_export_prefix():
    assert core.parse_dotenv("export FOO=bar") == {"FOO": "bar"}


def test_parse_dotenv_single_quotes_are_literal():
    assert core.parse_dotenv(r"FOO='a\nb'") == {"FOO": r"a\nb"}


def test_parse_dotenv_double_quotes_unescape():
    assert core.parse_dotenv(r'FOO="a\nb\t\"c\""') == {"FOO": 'a\nb\t"c"'}


def test_parse_dotenv_ignores_lines_without_equals():
    assert core.parse_dotenv("NOEQUALS\nFOO=bar") == {"FOO": "bar"}


@pytest.mark.parametrize("value", [
    "simple",
    "with space",
    'has"quote',
    "multi\nline",
    "tab\tchar",
    "trailing\\backslash",
    "",
    "a=b=c",
])
def test_dotenv_line_round_trips(value):
    line = core.dotenv_line("KEY", value)
    assert core.parse_dotenv(line) == {"KEY": value}


# --------------------------------------------------------------------------
# YAML scalar quoting
# --------------------------------------------------------------------------

def test_yaml_scalar_plain_token_unquoted():
    assert core.yaml_scalar("my-secret_1.0") == "my-secret_1.0"


@pytest.mark.parametrize("word", ["true", "False", "NO", "yes", "null", "on"])
def test_yaml_scalar_quotes_ambiguous_words(word):
    assert core.yaml_scalar(word) == f'"{word}"'


def test_yaml_scalar_quotes_empty_string():
    assert core.yaml_scalar("") == '""'


def test_yaml_scalar_quotes_digit_led():
    # Letter-first rule: anything digit-led gets quoted.
    assert core.yaml_scalar("123") == '"123"'


def test_yaml_scalar_escapes_quotes_and_backslashes():
    assert core.yaml_scalar(r'a"b\c') == r'"a\"b\\c"'


# --------------------------------------------------------------------------
# Secret YAML assembly
# --------------------------------------------------------------------------

def test_build_secret_yaml_is_valid_and_round_trips():
    out = core.build_secret_yaml("my-secret", "default", {"FOO": "bar"})
    doc = yaml.safe_load(out)

    assert doc["apiVersion"] == "v1"
    assert doc["kind"] == "Secret"
    assert doc["metadata"] == {"name": "my-secret", "namespace": "default"}
    assert doc["type"] == "Opaque"
    # Values are base64-encoded; decoding gets the original back.
    assert core.b64_decode(doc["data"]["FOO"]) == "bar"


def test_build_secret_yaml_honours_explicit_type():
    out = core.build_secret_yaml("s", "ns", {}, type_="kubernetes.io/tls")
    assert yaml.safe_load(out)["type"] == "kubernetes.io/tls"


def test_build_secret_yaml_quotes_tricky_keys_and_stays_valid():
    out = core.build_secret_yaml("name", "ns", {"123key": "value", "NO": "x"})
    doc = yaml.safe_load(out)
    assert core.b64_decode(doc["data"]["123key"]) == "value"
    assert core.b64_decode(doc["data"]["NO"]) == "x"


# --------------------------------------------------------------------------
# kubeseal command construction
# --------------------------------------------------------------------------

def test_kubeseal_seal_cmd_minimal():
    # Only the scope is required; nothing optional leaks in.
    assert core.kubeseal_seal_cmd("strict") == [
        "kubeseal", "--format=yaml", "--scope=strict"]


def test_kubeseal_seal_cmd_full():
    assert core.kubeseal_seal_cmd(
        "cluster-wide", context="prod", cert="/tmp/c.pem",
        ctl_name="sealed-secrets", ctl_ns="kube-system") == [
        "kubeseal", "--format=yaml", "--scope=cluster-wide",
        "--cert=/tmp/c.pem",
        "--context=prod",
        "--controller-name=sealed-secrets",
        "--controller-namespace=kube-system",
    ]


@pytest.mark.parametrize("kwargs", [
    {"context": ""}, {"cert": None}, {"ctl_name": ""}, {"ctl_ns": None},
])
def test_kubeseal_seal_cmd_omits_falsy_options(kwargs):
    # Empty/None optionals must not produce a bare/blank flag.
    assert core.kubeseal_seal_cmd("strict", **kwargs) == [
        "kubeseal", "--format=yaml", "--scope=strict"]


def test_kubeseal_validate_cmd_minimal():
    assert core.kubeseal_validate_cmd() == ["kubeseal", "--validate"]


def test_kubeseal_validate_cmd_full():
    assert core.kubeseal_validate_cmd(
        context="prod", ctl_name="sealed-secrets", ctl_ns="kube-system") == [
        "kubeseal", "--validate",
        "--context=prod",
        "--controller-name=sealed-secrets",
        "--controller-namespace=kube-system",
    ]


def test_kubeseal_validate_cmd_has_no_cert_or_scope():
    # Validate never takes --cert/--scope/--format; guard against copy-paste drift.
    cmd = core.kubeseal_validate_cmd(context="prod", ctl_name="ss")
    assert not any(a.startswith(("--cert", "--scope", "--format")) for a in cmd)


# --------------------------------------------------------------------------
# raw_data passthrough (binary values that can't survive a plaintext round-trip)
# --------------------------------------------------------------------------

def test_build_secret_yaml_raw_data_emitted_verbatim():
    # raw_data values are ALREADY base64 — they must not be re-encoded.
    already_b64 = core.b64_encode("\x00\x01binary")
    out = core.build_secret_yaml("s", "ns", {"FOO": "bar"},
                                 raw_data={"CERT": already_b64})
    doc = yaml.safe_load(out)
    assert doc["data"]["CERT"] == already_b64               # verbatim, not double-encoded
    assert core.b64_decode(doc["data"]["FOO"]) == "bar"     # plaintext still encoded once


def test_build_secret_yaml_raw_data_none_is_noop():
    assert core.build_secret_yaml("s", "ns", {"A": "b"}) == \
        core.build_secret_yaml("s", "ns", {"A": "b"}, raw_data=None)


# --------------------------------------------------------------------------
# write_secret_file — owner-only permissions, even on overwrite
# --------------------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes not applicable on Windows")
def test_write_secret_file_is_owner_only_on_create(tmp_path):
    p = tmp_path / "secret.yaml"
    core.write_secret_file(str(p), "data: x\n")
    assert p.read_text() == "data: x\n"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes not applicable on Windows")
def test_write_secret_file_tightens_existing_world_readable_file(tmp_path):
    p = tmp_path / "secret.yaml"
    p.write_text("old")
    os.chmod(p, 0o644)               # pre-existing, world-readable
    core.write_secret_file(str(p), "new")
    assert p.read_text() == "new"
    assert stat.S_IMODE(p.stat().st_mode) == 0o600   # must be tightened, not left 0o644
