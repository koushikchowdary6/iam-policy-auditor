"""The CLI must distinguish policy findings from invalid or failed audits."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CLI = ROOT / "src" / "iam_auditor.py"
EXAMPLES = ROOT / "examples"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, str(CLI), *(str(arg) for arg in args)],
        capture_output=True, text=True, check=False,
    )


@pytest.mark.parametrize("args, expected_code", [
    (("admin_wildcard.json", "--fail-on", "HIGH"), 1),
    (("least_privilege.json", "--fail-on", "LOW"), 0),
])
def test_policy_findings_have_expected_exit_codes(args, expected_code):
    name, *flags = args
    result = run_cli(EXAMPLES / name, *flags)
    assert result.returncode == expected_code, result.stderr
    assert not result.stderr


def test_high_risk_json_report_is_machine_readable():
    result = run_cli(EXAMPLES / "admin_wildcard.json", "--json", "--fail-on", "HIGH")
    assert result.returncode == 1
    payload = json.loads(result.stdout)
    assert payload["highest_severity"] == "HIGH"
    assert payload["counts"]["HIGH"] >= 1


def test_malformed_json_is_an_audit_error_not_a_risk_finding(tmp_path):
    bad_policy = tmp_path / "bad-policy.json"
    bad_policy.write_text('{"Statement": [', encoding="utf-8")
    result = run_cli(bad_policy, "--fail-on", "HIGH")
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert not result.stdout


def test_missing_policy_file_is_an_audit_error(tmp_path):
    result = run_cli(tmp_path / "does-not-exist.json", "--fail-on", "HIGH")
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert not result.stdout
