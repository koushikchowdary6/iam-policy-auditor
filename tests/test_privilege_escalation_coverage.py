"""Regression coverage for trust-policy, group and boundary escalation paths."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(action, effect="Allow"):
    return {"Statement": [{
        "Effect": effect,
        "Action": action,
        "Resource": "arn:aws:iam::123456789012:role/Example",
    }]}


def _escalation_findings(action, effect="Allow"):
    return [
        finding for finding in audit_policy(_policy(action, effect)).findings
        if finding.title == "Privilege-escalation action"
    ]


@pytest.mark.parametrize("action", [
    "iam:UpdateAssumeRolePolicy",
    "iam:AddUserToGroup",
    "iam:PutGroupPolicy",
    "iam:DeleteUserPermissionsBoundary",
    "iam:DeleteRolePermissionsBoundary",
])
def test_new_high_risk_actions_are_reported(action):
    findings = _escalation_findings(action)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert action.lower() in findings[0].detail


@pytest.mark.parametrize(("pattern", "expected"), [
    ("IAM:UPDATEASSUMEROLEPOLIC?", ["iam:updateassumerolepolicy"]),
    ("iam:Delete*PermissionsBoundary", [
        "iam:deleterolepermissionsboundary",
        "iam:deleteuserpermissionsboundary",
    ]),
    ("iam:PutGroupPolic?", ["iam:putgrouppolicy"]),
])
def test_case_insensitive_action_globs_cover_new_paths(pattern, expected):
    findings = _escalation_findings(pattern)
    assert len(findings) == 1
    for action in expected:
        assert action in findings[0].detail


@pytest.mark.parametrize("action", [
    "iam:GetRole", "iam:ListGroups", "iam:GetGroupPolicy",
    "iam:GetUser", "s3:GetObject",
])
def test_read_only_actions_are_not_mislabeled_as_escalation(action):
    assert _escalation_findings(action) == []


def test_explicit_deny_does_not_grant_escalation():
    assert _escalation_findings("iam:UpdateAssumeRolePolicy", "Deny") == []


def test_broad_notaction_is_flagged_separately_not_as_granted_action():
    policy = {"Statement": [{
        "Effect": "Allow",
        "NotAction": "iam:UpdateAssumeRolePolicy",
        "Resource": "*",
    }]}
    titles = {finding.title for finding in audit_policy(policy).findings}
    assert "Broad NotAction allow" in titles
    assert "Privilege-escalation action" not in titles
