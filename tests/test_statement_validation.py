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
    [{"Action": "*"}, {"NotAction": "iam:DeleteRole"}],
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
