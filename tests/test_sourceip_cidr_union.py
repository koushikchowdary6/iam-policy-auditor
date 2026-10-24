"""Regression tests for SourceIp conditions that collectively permit the internet."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _public_severity(ranges):
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/*",
        "Condition": {"IpAddress": {"aws:SourceIp": ranges}},
    }]}
    report = audit_policy(policy)
    return next(f.severity for f in report.findings if f.title == "Public principal")


@pytest.mark.parametrize("ranges", [
    ["0.0.0.0/1", "128.0.0.0/1"],
    ["::/1", "8000::/1"],
    ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"],
    ["10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/1"],
    ["10.0.0.0/8", "::/0"],
])
def test_collectively_unrestricted_cidrs_are_high_risk(ranges):
    assert _public_severity(ranges) == "HIGH"


@pytest.mark.parametrize("ranges", [
    ["10.0.0.0/8", "192.168.0.0/16"],
    ["0.0.0.0/1", "128.0.0.0/2"],
    ["::/1", "8000::/2"],
    ["10.0.0.0/8", "2001:db8::/32"],
])
def test_partially_restricted_cidrs_remain_medium(ranges):
    assert _public_severity(ranges) == "MEDIUM"


def test_independent_org_boundary_still_restricts_full_cidr_union():
    policy = {"Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/*",
        "Condition": {
            "IpAddress": {"aws:SourceIp": ["0.0.0.0/1", "128.0.0.0/1"]},
            "StringEquals": {"aws:PrincipalOrgID": "o-example"},
        },
    }]}
    report = audit_policy(policy)
    assert next(f.severity for f in report.findings if f.title == "Public principal") == "MEDIUM"
