"""Reject malformed aws:SourceIp CIDRs rather than misclassifying public access."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def policy(value, effect="Allow"):
    return {"Statement": [{
        "Effect": effect,
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
        "Condition": {"IpAddress": {"aws:SourceIp": value}},
    }]}


@pytest.mark.parametrize("value", [
    123, 0, True, 10.0,
    "not-a-cidr", "10.0.0.0/99", "2001:db8::/129",
    ["10.0.0.0/8", "not-a-cidr"],
    ["10.0.0.0/8", 123],
])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_invalid_source_ip_conditions_fail_closed(value, effect):
    with pytest.raises(ValueError, match="Condition IpAddress/aws:SourceIp"):
        audit_policy(policy(value, effect))


@pytest.mark.parametrize("value, severity", [
    ("10.0.0.0/8", "MEDIUM"),
    (["10.0.0.0/8", "192.168.0.0/16"], "MEDIUM"),
    ("0.0.0.0/0", "HIGH"),
    (["0.0.0.0/1", "128.0.0.0/1"], "HIGH"),
])
def test_valid_source_ip_conditions_keep_public_risk_scoring(value, severity):
    report = audit_policy(policy(value))
    public = [finding for finding in report.findings if finding.title == "Public principal"]
    assert len(public) == 1
    assert public[0].severity == severity
