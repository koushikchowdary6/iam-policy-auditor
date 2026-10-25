"""Reject malformed principal structures before classifying policy risk."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(field_name, principal, effect="Allow"):
    return {"Statement": [{
        "Effect": effect,
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
        field_name: principal,
    }]}


@pytest.mark.parametrize("principal", [
    None, 0, True, "", " ", [], ["arn:aws:iam::123456789012:root", ""],
    {}, {"AWS": []}, {"AWS": None}, {"AWS": [123]},
    {"AWS": {"nested": "arn:aws:iam::123456789012:root"}}, {"": "*"},
])
def test_invalid_principal_fails_closed(principal):
    with pytest.raises(ValueError, match="Principal has invalid principal values"):
        audit_policy(_policy("Principal", principal))


@pytest.mark.parametrize("principal", [
    None, [], {"AWS": []}, {"Service": [False]}, {"AWS": {"nested": "*"}},
])
def test_invalid_notprincipal_on_deny_is_rejected(principal):
    with pytest.raises(ValueError, match="NotPrincipal has invalid principal values"):
        audit_policy(_policy("NotPrincipal", principal, effect="Deny"))


def test_valid_service_and_account_principals_remain_supported():
    assert audit_policy(_policy("Principal", {"Service": "lambda.amazonaws.com"})).findings == []
    assert audit_policy(_policy("Principal", {"AWS": [
        "arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:role/reader"
    ]})).findings == []


def test_public_principal_nested_in_valid_list_stays_high_severity():
    report = audit_policy(_policy("Principal", {"AWS": [
        "arn:aws:iam::123456789012:root", "*"
    ]}))
    assert any(f.title == "Public principal" and f.severity == "HIGH"
               for f in report.findings)


def test_valid_deny_notprincipal_remains_supported():
    report = audit_policy(_policy(
        "NotPrincipal", {"AWS": "arn:aws:iam::123456789012:root"}, effect="Deny"
    ))
    assert report.findings == []
