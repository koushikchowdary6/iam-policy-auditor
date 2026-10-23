"""A broad Condition must not hide an effectively public resource grant."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def public_severity(condition):
    report = audit_policy({
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::example/*",
            "Condition": condition,
        }]
    })
    return next(f.severity for f in report.findings if f.title == "Public principal")


@pytest.mark.parametrize("condition", [
    {"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}},
    {"IpAddress": {"aws:SourceIp": "::/0"}},
    {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "0.0.0.0/0"]}},
    {"IpAddress": {"aws:SourceIp": "not-an-ip-range"}},
    {"StringLike": {"aws:PrincipalOrgID": "*"}},
    {"StringLike": {"aws:PrincipalOrgID": "o-*"}},
    {"StringEquals": {"aws:SourceVpc": "*"}},
    {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}},
])
def test_unrestricted_conditions_remain_high_risk(condition):
    assert public_severity(condition) == "HIGH"


@pytest.mark.parametrize("condition", [
    {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
    {"IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]}},
    {"StringEquals": {"aws:PrincipalOrgID": "o-abc123xyz"}},
    {"ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::123456789012:role/trusted"}},
])
def test_concrete_positive_scopes_remain_medium_risk(condition):
    assert public_severity(condition) == "MEDIUM"


def test_other_positive_condition_can_still_scope_unrestricted_ip_range():
    condition = {
        "IpAddress": {"aws:SourceIp": "0.0.0.0/0"},
        "StringEquals": {"aws:PrincipalOrgID": "o-abc123xyz"},
    }
    assert public_severity(condition) == "MEDIUM"
