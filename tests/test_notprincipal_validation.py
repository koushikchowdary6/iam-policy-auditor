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


def test_supported_deny_notprincipal_remains_auditable():
    assert audit_policy({"Statement": [_statement()]}).findings == []


def test_rejects_unsupported_statement_in_multi_statement_policy():
    safe = {
        "Effect": "Allow", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
    }
    with pytest.raises(ValueError, match="NotPrincipal requires Effect Deny"):
        audit_policy({"Statement": [safe, _statement(effect="Allow")]})
