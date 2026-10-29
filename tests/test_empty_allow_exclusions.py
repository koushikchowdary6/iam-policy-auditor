"""A global exclusion makes an Allow statement match no permissions."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


@pytest.mark.parametrize("selector, resource_selector", [
    ({"NotAction": "*"}, {"Resource": "*"}),
    ({"NotAction": ["iam:*", "*"]}, {"Resource": "*"}),
    ({"NotAction": "*"}, {"NotResource": "arn:aws:s3:::private/*"}),
    ({"Action": "*"}, {"NotResource": "*"}),
    ({"Action": "s3:GetObject"}, {"NotResource": ["arn:aws:s3:::private/*", "*"]}),
])
def test_global_exclusion_cannot_grant_permissions(selector, resource_selector):
    statement = {"Effect": "Allow", **selector, **resource_selector}
    report = audit_policy({"Statement": [statement]})
    assert report.findings == []
    assert report.highest_severity == "NONE"


def test_public_principal_cannot_turn_empty_allow_into_public_grant():
    report = audit_policy({"Statement": [{
        "Effect": "Allow", "Principal": "*",
        "NotAction": "*", "Resource": "*",
    }]})
    assert report.findings == []


@pytest.mark.parametrize("statement", [
    {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
    {"Effect": "Allow", "Action": "s3:GetObject",
     "NotResource": "arn:aws:s3:::private/*"},
])
def test_non_global_exclusions_still_report_risk(statement):
    report = audit_policy({"Statement": [statement]})
    assert report.findings
    assert report.highest_severity in ("HIGH", "MEDIUM")


def test_empty_allow_still_validates_conditions():
    with pytest.raises(ValueError, match="invalid CIDR"):
        audit_policy({"Statement": [{
            "Effect": "Allow", "NotAction": "*", "Resource": "*",
            "Condition": {"IpAddress": {"aws:SourceIp": "not-a-cidr"}},
        }]})
