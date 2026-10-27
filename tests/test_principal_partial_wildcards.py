"""Principal globs are not AWS IAM principal identities or valid scope."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from iam_auditor import audit_policy, audit_statement


def _policy(principal, *, field="Principal", effect="Allow"):
    return {"Statement": [{
        "Effect": effect,
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
        field: principal,
    }]}


@pytest.mark.parametrize("principal", [
    "arn:aws:iam::123456789012:role/Admin*",
    "arn:aws:iam::123456789012:user/ops?",
    {"AWS": "arn:aws:iam::123456789012:role/*"},
    {"AWS": ["arn:aws:iam::123456789012:root",
             "arn:aws:iam::123456789012:role/Team*"]},
    {"Service": "*.amazonaws.com"},
    {"Federated": "arn:aws:iam::123456789012:oidc-provider/*"},
])
def test_partial_wildcards_in_principals_fail_closed(principal):
    with pytest.raises(ValueError, match="Principal has invalid principal values"):
        audit_policy(_policy(principal))


def test_partial_wildcards_in_deny_notprincipal_are_rejected():
    with pytest.raises(ValueError, match="NotPrincipal has invalid principal values"):
        audit_policy(_policy({"AWS": "arn:aws:iam::123456789012:role/Team?"},
                             field="NotPrincipal", effect="Deny"))


def test_direct_statement_call_rejects_partial_principal_pattern():
    statement = _policy("arn:aws:iam::123456789012:role/*")["Statement"][0]
    with pytest.raises(ValueError, match="Statement #4: Principal"):
        audit_statement(statement, 4)


def test_whole_principal_wildcard_still_reports_public_risk():
    report = audit_policy(_policy({"AWS": [
        "arn:aws:iam::123456789012:root", "*",
    ]}))
    assert any(f.title == "Public principal" and f.severity == "HIGH"
               for f in report.findings)


def test_fixed_role_and_service_principals_remain_valid():
    assert audit_policy(_policy({"AWS": "arn:aws:iam::123456789012:role/Reader"})).findings == []
    assert audit_policy(_policy({"Service": "lambda.amazonaws.com"})).findings == []
