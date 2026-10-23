"""Regression tests for IAM statement validation and NotResource risk semantics."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _statement(**overrides):
    stmt = {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*"}
    stmt.update(overrides)
    return stmt


@pytest.mark.parametrize("effect", [None, "Alow", "allow", "", 1])
def test_invalid_effect_is_rejected(effect):
    with pytest.raises(ValueError, match="Effect must be Allow or Deny"):
        audit_policy({"Statement": [_statement(Effect=effect)]})


@pytest.mark.parametrize(
    "overrides, missing",
    [
        ({"Action": None}, "Action"),
        ({"Action": ""}, "Action"),
        ({"Action": []}, "Action"),
        ({"Action": ["s3:GetObject", ""]}, "Action"),
        ({"Action": 42}, "Action"),
        ({"Resource": None}, "Resource"),
        ({"Resource": ""}, "Resource"),
        ({"Resource": []}, "Resource"),
        ({"Resource": ["arn:aws:s3:::x/*", " "]}, "Resource"),
    ],
)
def test_empty_or_malformed_selectors_are_rejected(overrides, missing):
    with pytest.raises(ValueError, match=missing):
        audit_policy({"Statement": [_statement(**overrides)]})


def test_action_and_notaction_are_mutually_exclusive():
    with pytest.raises(ValueError, match="exactly one of Action/NotAction"):
        audit_policy({"Statement": [_statement(NotAction="iam:*")]})


def test_resource_and_notresource_are_mutually_exclusive():
    with pytest.raises(ValueError, match="exactly one of Resource/NotResource"):
        audit_policy({"Statement": [_statement(NotResource="arn:aws:s3:::private/*")]})


def test_missing_action_and_resource_selectors_are_rejected():
    with pytest.raises(ValueError, match="Action/NotAction"):
        audit_policy({"Statement": [{"Effect": "Allow", "Resource": "*"}]})
    with pytest.raises(ValueError, match="Resource/NotResource"):
        audit_policy({"Statement": [{"Effect": "Allow", "Action": "s3:GetObject"}]})


@pytest.mark.parametrize(
    "action_fields",
    [{"Action": "*"}, {"Action": "s3:*"}, {"Action": "IAM:*"},
     {"NotAction": "iam:DeleteRole"}],
)
def test_broad_notresource_allow_is_high(action_fields):
    stmt = {"Effect": "Allow", "NotResource": "arn:aws:s3:::private/*", **action_fields}
    report = audit_policy({"Statement": [stmt]})
    matches = [f for f in report.findings if f.title == "Broad NotResource allow"]
    assert len(matches) == 1
    assert matches[0].severity == "HIGH"
    assert report.highest_severity == "HIGH"


def test_scoped_notresource_allow_not_mislabeled_as_broad_global_action():
    report = audit_policy({"Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject",
        "NotResource": "arn:aws:s3:::private/*",
    }]})
    assert "Broad NotResource allow" not in {f.title for f in report.findings}


def test_valid_deny_with_notresource_has_no_findings():
    report = audit_policy({"Statement": [{
        "Effect": "Deny", "Action": "*", "NotResource": "arn:aws:s3:::public/*",
    }]})
    assert report.findings == []


@pytest.mark.parametrize("policy", [
    {},
    {"Version": "2012-10-17"},
    {"Statement": []},
    {"Statement": None},
])
def test_missing_or_empty_policy_statements_are_rejected(policy):
    """Malformed inputs must not be presented as least-privilege policies."""
    with pytest.raises(ValueError, match="Statement"):
        audit_policy(policy)


def test_cli_rejects_empty_policy_instead_of_reporting_clean(tmp_path, capsys):
    from iam_auditor import main

    path = tmp_path / "empty-policy.json"
    path.write_text('{"Statement": []}', encoding="utf-8")
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "Statement" in captured.err
    assert "No risky statements found" not in captured.out



def test_scoped_action_notresource_does_not_trigger_service_wildcard():
    policy = {"Statement": [{
        "Effect": "Allow", "Action": "s3:GetObject",
        "NotResource": "arn:aws:s3:::private/*",
    }]}
    report = audit_policy(policy)
    assert not any(f.title == "Broad NotResource allow" for f in report.findings)


def test_deny_service_wildcard_notresource_does_not_trigger_allow_finding():
    policy = {"Statement": [{
        "Effect": "Deny", "Action": "s3:*",
        "NotResource": "arn:aws:s3:::public/*",
    }]}
    report = audit_policy(policy)
    assert report.findings == []
