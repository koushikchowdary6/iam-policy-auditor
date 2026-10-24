"""NotResource allows are resource-wide grants even for a narrow action."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def _policy(action="s3:GetObject", effect="Allow", excluded=None):
    return {"Statement": [{
        "Effect": effect,
        "Action": action,
        "NotResource": excluded or "arn:aws:s3:::private/*",
    }]}


def test_narrow_action_notresource_is_not_silently_clean():
    report = audit_policy(_policy())
    matches = [f for f in report.findings if f.title == "NotResource expands resource scope"]
    assert len(matches) == 1
    assert matches[0].severity == "MEDIUM"
    assert matches[0].statement_index == 0
    assert "Broad NotResource allow" not in {f.title for f in report.findings}


def test_multiple_exclusions_still_leave_every_other_resource_allowed():
    report = audit_policy(_policy(excluded=[
        "arn:aws:s3:::private/*", "arn:aws:s3:::sensitive/*",
    ]))
    assert any(f.title == "NotResource expands resource scope" for f in report.findings)


@pytest.mark.parametrize("action", ["*", "s3:*", "iam:*"])
def test_broad_action_notresource_remains_high_without_duplicate_medium(action):
    report = audit_policy(_policy(action=action))
    assert any(f.title == "Broad NotResource allow" and f.severity == "HIGH"
               for f in report.findings)
    assert not any(f.title == "NotResource expands resource scope"
                   for f in report.findings)


def test_deny_notresource_does_not_report_allow_risk():
    assert audit_policy(_policy(effect="Deny")).findings == []


def test_cli_fail_on_medium_detects_narrow_action_notresource(tmp_path, capsys):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy()), encoding="utf-8")
    assert main([str(path), "--fail-on", "MEDIUM"]) == 1
    assert main([str(path), "--fail-on", "HIGH"]) == 0
    capsys.readouterr()  # clear text-mode output before checking JSON
    assert main([str(path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["counts"]["MEDIUM"] == 1
    assert report["highest_severity"] == "MEDIUM"
