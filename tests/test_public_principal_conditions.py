"""Regression coverage: public-principal conditions must not give false assurance."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _public_policy(condition):
    return {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::public-bucket/*",
        "Condition": condition,
    }]}


def _public_severity(condition):
    report = audit_policy(_public_policy(condition))
    return next(f.severity for f in report.findings if f.title == "Public principal")


@pytest.mark.parametrize("condition", [
    {"Bool": {"aws:SecureTransport": "true"}},
    {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
    {"StringNotEquals": {"aws:PrincipalOrgID": "o-example"}},
    {"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-example"}},
    {"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
])
def test_unrelated_or_negative_conditions_do_not_downgrade_public_access(condition):
    assert _public_severity(condition) == "HIGH"


@pytest.mark.parametrize("condition", [
    {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    {"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
    {"StringEquals": {"aws:PrincipalAccount": "123456789012"}},
    {"StringEquals": {"aws:SourceVpce": "vpce-123"}},
    {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/team-*"}},
])
def test_recognized_positive_scoping_condition_is_medium(condition):
    assert _public_severity(condition) == "MEDIUM"


@pytest.mark.parametrize("condition", [
    None,
    {},
    "aws:SourceIp",
    {"IpAddress": {}},
    {"IpAddress": {"aws:SourceIp": []}},
    {"IpAddress": {"aws:SourceIp": ""}},
    {"IpAddress": {"aws:SourceIp": {"unexpected": "value"}}},
])
def test_malformed_conditions_are_rejected_instead_of_marked_safe(condition):
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(_public_policy(condition))


def test_invalid_condition_on_deny_is_still_rejected():
    policy = _public_policy({"Bool": {}})
    policy["Statement"][0]["Effect"] = "Deny"
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(policy)


def test_public_grant_without_any_condition_remains_high():
    policy = _public_policy({"Bool": {"aws:SecureTransport": "true"}})
    del policy["Statement"][0]["Condition"]
    report = audit_policy(policy)
    assert next(f.severity for f in report.findings if f.title == "Public principal") == "HIGH"
