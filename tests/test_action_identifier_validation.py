"""Reject malformed IAM Action/NotAction selectors instead of false clean audits."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def policy_with(**changes):
    statement = {
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
    }
    statement.update(changes)
    return {"Statement": [statement]}


@pytest.mark.parametrize("invalid", [
    "s3 GetObject", "GetObject", "s3:", ":GetObject", "s3:Get:Object",
    "s3:GetObject ", " s3:GetObject", "s3:Get\nObject",
    "s3:Get/Object", "s3:GetObject\x00",
])
@pytest.mark.parametrize("field", ["Action", "NotAction"])
def test_malformed_action_selectors_rejected(invalid, field):
    statement = policy_with()["Statement"][0]
    statement.pop("Action")
    statement[field] = invalid
    with pytest.raises(ValueError, match=f"{field} has invalid action identifier"):
        audit_policy({"Statement": [statement]})


@pytest.mark.parametrize("valid", [
    "*", "s3:*", "iam:PassR?le", "secretsmanager:GetSecretVal*",
    "aws-marketplace:ViewSubscriptions", "S3:GetObject",
])
def test_valid_iam_action_patterns_remain_supported(valid):
    assert audit_policy(policy_with(Action=valid))


def test_invalid_action_on_deny_is_not_silently_ignored():
    with pytest.raises(ValueError, match="Action has invalid"):
        audit_policy(policy_with(Effect="Deny", Action="iam PassRole"))
