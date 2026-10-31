"""SARIF export must preserve IAM finding severity, identity and CLI exit codes."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "src" / "iam_auditor.py"


def run_cli(*args, input_text=None):
    return subprocess.run(
        [sys.executable, str(CLI), *(str(arg) for arg in args)],
        input=input_text, capture_output=True, text=True, check=False, cwd=ROOT,
    )


def test_sarif_findings_have_stable_rule_ids_and_file_locations():
    result = run_cli("examples/admin_wildcard.json", "--sarif", "--fail-on", "HIGH")
    assert result.returncode == 1, result.stderr
    assert not result.stderr
    payload = json.loads(result.stdout)
    assert payload["version"] == "2.1.0"
    run, = payload["runs"]
    assert run["tool"]["driver"]["name"] == "IAM Policy Auditor"
    findings = run["results"]
    assert findings
    rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    assert rule_ids == {finding["ruleId"] for finding in findings}
    assert all(finding["level"] == "error" for finding in findings)
    assert all(finding["properties"]["severity"] == "HIGH" for finding in findings)
    for finding in findings:
        location, = finding["locations"]
        assert location["physicalLocation"]["artifactLocation"] == {
            "uri": "examples/admin_wildcard.json", "uriBaseId": "%SRCROOT%"
        }
        assert location["logicalLocations"][0]["fullyQualifiedName"].startswith("Statement[")
        assert finding["properties"]["statement_index"] >= 0


def test_clean_policy_has_empty_sarif_results():
    result = run_cli("examples/least_privilege.json", "--sarif", "--fail-on", "LOW")
    assert result.returncode == 0, result.stderr
    run, = json.loads(result.stdout)["runs"]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"] == []


def test_stdin_sarif_does_not_invent_file_location():
    source = (ROOT / "examples" / "admin_wildcard.json").read_text(encoding="utf-8")
    result = run_cli("-", "--sarif", input_text=source)
    assert result.returncode == 0, result.stderr
    findings = json.loads(result.stdout)["runs"][0]["results"]
    assert findings
    assert all("physicalLocation" not in finding["locations"][0] for finding in findings)


def test_outside_checkout_sarif_does_not_claim_repo_path(tmp_path):
    source = (ROOT / "examples" / "admin_wildcard.json").read_text(encoding="utf-8")
    external = tmp_path / "outside-policy.json"
    external.write_text(source, encoding="utf-8")
    result = run_cli(external, "--sarif")
    assert result.returncode == 0, result.stderr
    findings = json.loads(result.stdout)["runs"][0]["results"]
    assert findings
    assert all("physicalLocation" not in finding["locations"][0] for finding in findings)


def test_invalid_policy_produces_no_misleading_sarif(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"Statement": [', encoding="utf-8")
    result = run_cli(bad, "--sarif", "--fail-on", "HIGH")
    assert result.returncode == 2
    assert not result.stdout
    assert "error:" in result.stderr


def test_json_and_sarif_are_mutually_exclusive():
    result = run_cli("examples/admin_wildcard.json", "--json", "--sarif")
    assert result.returncode == 2
    assert not result.stdout
    assert "not allowed with argument" in result.stderr
