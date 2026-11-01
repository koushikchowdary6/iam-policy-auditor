"""Unsupported NotPrincipal forms must not silently pass an IAM audit."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _statement(effect="Deny"):
    return {
        "Effect": effect,
        "NotPrincipal": {"AWS": "arn:aws:iam::123456789012:root"},
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
    }


def test_allow_notprincipal_is_rejected_not_reported_as_clean():
    with pytest.raises(ValueError, match="NotPrincipal requires Effect Deny"):
        audit_policy({"Statement": [_statement(effect="Allow")]})


@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_principal_and_notprincipal_cannot_coexist(effect):
    statement = _statement(effect=effect)
    statement["Principal"] = "*"
    with pytest.raises(ValueError, match="mutually exclusive"):
        audit_policy({"Statement": [statement]})


def test_supported_deny_notprincipal_warns_about_permissions_boundaries():
    report = audit_policy({"Statement": [_statement()]})
    assert report.highest_severity == "MEDIUM"
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.title == "Deny with NotPrincipal and permissions boundaries"
    assert finding.statement_index == 0
    assert "ArnNotEquals" in finding.detail


def test_ordinary_deny_does_not_trigger_notprincipal_warning():
    stmt = _statement()
    stmt["Principal"] = stmt.pop("NotPrincipal")
    report = audit_policy({"Statement": [stmt]})
    assert report.findings == []


def test_notprincipal_warning_keeps_original_statement_index():
    allow = {"Effect": "Allow", "Action": "s3:GetObject",
             "Resource": "arn:aws:s3:::reports/*"}
    report = audit_policy({"Statement": [allow, _statement()]})
    assert len(report.findings) == 1
    assert report.findings[0].statement_index == 1


def test_rejects_unsupported_statement_in_multi_statement_policy():
    safe = {
        "Effect": "Allow", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
    }
    with pytest.raises(ValueError, match="NotPrincipal requires Effect Deny"):
        audit_policy({"Statement": [safe, _statement(effect="Allow")]})
