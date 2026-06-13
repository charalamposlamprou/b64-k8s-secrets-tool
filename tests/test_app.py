"""Unit tests for the pure helper functions in app.py.

Importing app.py is safe: the Tk GUI only starts under `if __name__ ==
"__main__"`, so importing the module just loads these helpers.
"""

import base64

import pytest
import yaml

import app


# --------------------------------------------------------------------------
# base64
# --------------------------------------------------------------------------

def test_b64_encode_matches_stdlib():
    assert app.b64_encode("hello") == base64.b64encode(b"hello").decode()


@pytest.mark.parametrize("text", ["", "hello", "a", "ab", "abc", "üñîçødé", "k=v\nx=y"])
def test_b64_round_trip(text):
    assert app.b64_decode(app.b64_encode(text)) == text


def test_b64_decode_tolerates_missing_padding():
    # "hello" -> "aGVsbG8=" ; decoding the unpadded form must still work.
    assert app.b64_decode("aGVsbG8") == "hello"


def test_b64_decode_strips_whitespace():
    assert app.b64_decode("  aGVsbG8=\n") == "hello"


# --------------------------------------------------------------------------
# .env parsing / rendering
# --------------------------------------------------------------------------

def test_parse_dotenv_basic():
    assert app.parse_dotenv("FOO=bar\nBAZ=qux") == {"FOO": "bar", "BAZ": "qux"}


def test_parse_dotenv_skips_comments_and_blanks():
    assert app.parse_dotenv("# comment\n\nFOO=bar\n   \n") == {"FOO": "bar"}


def test_parse_dotenv_strips_export_prefix():
    assert app.parse_dotenv("export FOO=bar") == {"FOO": "bar"}


def test_parse_dotenv_single_quotes_are_literal():
    assert app.parse_dotenv(r"FOO='a\nb'") == {"FOO": r"a\nb"}


def test_parse_dotenv_double_quotes_unescape():
    assert app.parse_dotenv(r'FOO="a\nb\t\"c\""') == {"FOO": 'a\nb\t"c"'}


def test_parse_dotenv_ignores_lines_without_equals():
    assert app.parse_dotenv("NOEQUALS\nFOO=bar") == {"FOO": "bar"}


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
    line = app.dotenv_line("KEY", value)
    assert app.parse_dotenv(line) == {"KEY": value}


# --------------------------------------------------------------------------
# secret type detection
# --------------------------------------------------------------------------

def test_detect_tls():
    assert app.detect_secret_type(["tls.crt", "tls.key"]) == "kubernetes.io/tls"


def test_detect_dockerconfigjson():
    assert app.detect_secret_type([".dockerconfigjson"]) == "kubernetes.io/dockerconfigjson"


def test_detect_ssh_auth():
    assert app.detect_secret_type(["ssh-privatekey"]) == "kubernetes.io/ssh-auth"


def test_detect_bootstrap_token():
    got = app.detect_secret_type(["token-id", "token-secret"])
    assert got == "bootstrap.kubernetes.io/token"


def test_detect_basic_auth_requires_both_keys():
    assert app.detect_secret_type(["username", "password"]) == "kubernetes.io/basic-auth"


def test_lone_password_stays_opaque():
    # A lone "password" key is common in plain Opaque secrets.
    assert app.detect_secret_type(["password"]) == "Opaque"


def test_detect_unknown_is_opaque():
    assert app.detect_secret_type(["foo", "bar"]) == "Opaque"


# --------------------------------------------------------------------------
# YAML scalar quoting
# --------------------------------------------------------------------------

def test_yaml_scalar_plain_token_unquoted():
    assert app.yaml_scalar("my-secret_1.0") == "my-secret_1.0"


@pytest.mark.parametrize("word", ["true", "False", "NO", "yes", "null", "on"])
def test_yaml_scalar_quotes_ambiguous_words(word):
    assert app.yaml_scalar(word) == f'"{word}"'


def test_yaml_scalar_quotes_empty_string():
    assert app.yaml_scalar("") == '""'


def test_yaml_scalar_quotes_digit_led():
    # Letter-first rule: anything digit-led gets quoted.
    assert app.yaml_scalar("123") == '"123"'


def test_yaml_scalar_escapes_quotes_and_backslashes():
    assert app.yaml_scalar(r'a"b\c') == r'"a\"b\\c"'


# --------------------------------------------------------------------------
# Secret YAML assembly
# --------------------------------------------------------------------------

def test_build_secret_yaml_is_valid_and_round_trips():
    out = app.build_secret_yaml("my-secret", "default", {"FOO": "bar"})
    doc = yaml.safe_load(out)

    assert doc["apiVersion"] == "v1"
    assert doc["kind"] == "Secret"
    assert doc["metadata"] == {"name": "my-secret", "namespace": "default"}
    assert doc["type"] == "Opaque"
    # Values are base64-encoded; decoding gets the original back.
    assert app.b64_decode(doc["data"]["FOO"]) == "bar"


def test_build_secret_yaml_honours_explicit_type():
    out = app.build_secret_yaml("s", "ns", {}, type_="kubernetes.io/tls")
    assert yaml.safe_load(out)["type"] == "kubernetes.io/tls"


def test_build_secret_yaml_quotes_tricky_keys_and_stays_valid():
    out = app.build_secret_yaml("name", "ns", {"123key": "value", "NO": "x"})
    doc = yaml.safe_load(out)
    assert app.b64_decode(doc["data"]["123key"]) == "value"
    assert app.b64_decode(doc["data"]["NO"]) == "x"
