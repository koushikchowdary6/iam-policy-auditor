"""Only concrete, recognizable IAM principal ARNs scope public access."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def public_severity(principal_arn, operator="ArnLike"):
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/*",
        "Condition": {operator: {"aws:PrincipalArn": principal_arn}},
    }]}
    report = audit_policy(policy)
    return next(f.severity for f in report.findings if f.title == "Public principal")


@pytest.mark.parametrize("arn", [
    "arn:aws:iam::123456789012:role/team-*",
    "arn:aws:iam::123456789012:user/engineering/alice",
    "arn:aws:iam::123456789012:root",
    "arn:aws-us-gov:iam::123456789012:role/engineering/*",
    "arn:aws-cn:iam::123456789012:role/engineering",
])
def test_fixed_account_iam_principal_arns_reduce_severity(arn):
    assert public_severity(arn) == "MEDIUM"


@pytest.mark.parametrize("arn", [
    "arn:aws:s3::123456789012:role/team",
    "arn:aws:sts::123456789012:assumed-role/team/session",
    "arn:custom:iam::123456789012:role/team",
    "arn:aws:iam:us-east-1:123456789012:role/team",
    "arn:aws:iam::123456789012:",
    "arn:aws:iam::123456789012:role/",
    "arn:aws:iam::123456789012:policy/admin",
    "arn:aws:iam::*:role/team",
    "arn:aws:iam::123456789012:role/${aws:PrincipalArn}",
    "arn:aws:iam::123456789012:role/team\nInjected",
])
def test_malformed_or_nonprincipal_arns_do_not_downgrade(arn):
    assert public_severity(arn) == "HIGH"


def test_one_invalid_alternative_prevents_false_downgrade():
    assert public_severity([
        "arn:aws:iam::123456789012:role/team",
        "arn:aws:s3::123456789012:role/team",
    ]) == "HIGH"


def test_independent_valid_account_condition_still_scopes():
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/*",
        "Condition": {"StringEquals": {"aws:PrincipalAccount": "123456789012"},
                      "ArnLike": {"aws:PrincipalArn": "arn:aws:s3::123456789012:role/team"}},
    }]}
    report = audit_policy(policy)
    assert next(f.severity for f in report.findings if f.title == "Public principal") == "MEDIUM"
