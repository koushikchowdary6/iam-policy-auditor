"""Bound untrusted policy reads and reject deeply nested JSON predictably."""

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from iam_auditor import MAX_POLICY_CHARS, parse_policy_json

CLI = ROOT / "src" / "iam_auditor.py"


def test_parse_policy_json_rejects_oversized_input_before_decoding():
    with pytest.raises(ValueError, match="exceeds"):
        parse_policy_json(" " * (MAX_POLICY_CHARS + 1))


def test_parse_policy_json_rejects_excessive_nesting_as_value_error():
    raw = '{"Statement":' + "[" * 1100 + "0" + "]" * 1100 + "}"
    with pytest.raises(ValueError, match="nesting"):
        parse_policy_json(raw)


def test_cli_rejects_oversized_file_without_success_output(tmp_path):
    path = tmp_path / "oversized.json"
    path.write_text(" " * (MAX_POLICY_CHARS + 1), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(CLI), str(path), "--json"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert "exceeds" in result.stderr
    assert not result.stdout


def test_cli_rejects_oversized_stdin_without_success_output():
    result = subprocess.run(
        [sys.executable, str(CLI), "-", "--json"],
        input=" " * (MAX_POLICY_CHARS + 1),
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 2
    assert "exceeds" in result.stderr
    assert not result.stdout


def test_small_valid_policy_remains_supported():
    assert parse_policy_json('{"Statement":{"Effect":"Deny","Action":"s3:*","Resource":"*"}}')[
        "Statement"
    ]["Effect"] == "Deny"
