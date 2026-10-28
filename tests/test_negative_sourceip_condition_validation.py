"""SourceIp negative/optional conditions must be parsed but never imply a boundary."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(operator, cidrs, effect="Allow", extra_condition=None):
    condition = {operator: {"aws:SourceIp": cidrs}}
    if extra_condition:
        condition.update(extra_condition)
    return {"Statement": [{
        "Effect": effect,
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
        "Condition": condition,
    }]}


@pytest.mark.parametrize("operator", [
    "NotIpAddress", "IpAddressIfExists", "NotIpAddressIfExists",
])
@pytest.mark.parametrize("value", [
    "not-a-cidr", "10.0.0.0/99", ["10.0.0.0/8", "invalid"], 123, True,
])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_malformed_negative_or_optional_sourceip_is_rejected(operator, value, effect):
    with pytest.raises(ValueError, match="requires CIDR strings|invalid CIDR"):
        audit_policy(_policy(operator, value, effect))


@pytest.mark.parametrize("operator", [
    "NotIpAddress", "IpAddressIfExists", "NotIpAddressIfExists",
])
def test_negative_or_optional_sourceip_does_not_downgrade_public_access(operator):
    report = audit_policy(_policy(operator, "10.0.0.0/8"))
    public = [f for f in report.findings if f.title == "Public principal"]
    assert len(public) == 1
    assert public[0].severity == "HIGH"


def test_positive_sourceip_remains_a_scoping_signal():
    report = audit_policy(_policy("IpAddress", "10.0.0.0/8"))
    public = [f for f in report.findings if f.title == "Public principal"]
    assert len(public) == 1
    assert public[0].severity == "MEDIUM"


def test_independent_concrete_org_condition_still_scopes_negative_sourceip():
    report = audit_policy(_policy(
        "NotIpAddress", "10.0.0.0/8",
        extra_condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
    ))
    public = [f for f in report.findings if f.title == "Public principal"]
    assert len(public) == 1
    assert public[0].severity == "MEDIUM"
