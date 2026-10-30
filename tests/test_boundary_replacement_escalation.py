"""Boundary replacement can be a privilege-escalation building block.

An attacker who can attach a more permissive boundary policy may relax an
existing maximum-permissions restriction. This is a static signal, not proof
of effective privileges or the existence of an attacker-controlled policy.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _escalation_details(action, effect="Allow"):
    policy = {"Statement": [{
        "Effect": effect,
        "Action": action,
        "Resource": "arn:aws:iam::123456789012:user/Analyst",
    }]}
    return [
        finding for finding in audit_policy(policy).findings
        if finding.title == "Privilege-escalation action"
    ]


@pytest.mark.parametrize("action", [
    "iam:PutUserPermissionsBoundary",
    "iam:PutRolePermissionsBoundary",
])
def test_permissions_boundary_replacement_is_high_risk(action):
    findings = _escalation_details(action)
    assert len(findings) == 1
    assert findings[0].severity == "HIGH"
    assert action.lower() in findings[0].detail


def test_boundary_replacement_wildcard_reports_both_actions():
    findings = _escalation_details("IAM:PUT*PERMISSIONSBOUNDARY")
    assert len(findings) == 1
    assert "iam:putuserpermissionsboundary" in findings[0].detail
    assert "iam:putrolepermissionsboundary" in findings[0].detail


@pytest.mark.parametrize("action", [
    "iam:GetUser",
    "iam:GetRole",
    "iam:GetPolicy",
])
def test_read_only_actions_are_not_boundary_escalation(action):
    assert _escalation_details(action) == []


def test_deny_boundary_replacement_is_not_a_grant():
    assert _escalation_details("iam:PutRolePermissionsBoundary", "Deny") == []
