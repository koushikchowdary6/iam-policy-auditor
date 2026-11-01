"""Public-principal risk must not be downgraded by malformed fixed boundaries."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def severity(condition):
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/*",
        "Condition": condition,
    }]}
    report = audit_policy(policy)
    return next(f.severity for f in report.findings if f.title == "Public principal")


@pytest.mark.parametrize(("key", "value"), [
    ("aws:PrincipalAccount", "not-an-account"),
    ("aws:PrincipalAccount", "12345678901"),
    ("aws:PrincipalAccount", "1234567890123"),
    ("aws:PrincipalOrgID", "example"),
    ("aws:PrincipalOrgID", "o-"),
    ("aws:PrincipalOrgID", "o-abc123xyz"),  # nine-character ID
    ("aws:PrincipalOrgID", "o-ABCDEFGHIJ"),  # uppercase is invalid
    ("aws:PrincipalOrgID", "o-" + "a" * 33),
    ("aws:SourceVpc", "example-vpc"),
    ("aws:SourceVpc", "vpc-xyz"),
    ("aws:SourceVpc", "vpc-a1b2c3"),  # too short
    ("aws:SourceVpc", "vpc-" + "a" * 16),
    ("aws:SourceVpc", "vpc-" + "a" * 18),
    ("aws:SourceVpce", "vpce-xyz"),
    ("aws:SourceVpce", "vpce-a1b2c3"),
    ("aws:SourceVpce", "vpce-" + "a" * 18),
    ("aws:SourceVpce", "vpce-"),
])
def test_arbitrary_nonwildcard_strings_do_not_narrow_public_access(key, value):
    assert severity({"StringEquals": {key: value}}) == "HIGH"


@pytest.mark.parametrize(("key", "value"), [
    ("aws:PrincipalAccount", "123456789012"),
    ("aws:PrincipalOrgID", "o-abc123xyz0"),
    ("aws:PrincipalOrgID", "o-" + "a" * 32),
    ("aws:SourceVpc", "vpc-a1b2c3d4"),
    ("aws:SourceVpc", "vpc-" + "a" * 17),
    ("aws:SourceVpce", "vpce-a1b2c3d4"),
    ("aws:SourceVpce", "vpce-" + "a" * 17),
])
def test_recognizable_fixed_boundaries_still_reduce_severity(key, value):
    assert severity({"StringEquals": {key: value}}) == "MEDIUM"


def test_one_invalid_or_alternative_prevents_false_downgrade():
    assert severity({"StringEquals": {
        "aws:PrincipalAccount": ["123456789012", "not-an-account"],
    }}) == "HIGH"


def test_independent_concrete_boundary_still_scopes_public_access():
    assert severity({"StringEquals": {
        "aws:PrincipalAccount": "not-an-account",
        "aws:PrincipalOrgID": "o-abc123xyz0",
    }}) == "MEDIUM"
