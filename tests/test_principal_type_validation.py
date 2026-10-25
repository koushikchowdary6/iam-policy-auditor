"""Unknown AWS principal type keys must not produce a clean IAM audit."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(field, value, effect="Allow"):
    return {"Statement": [{
        "Effect": effect,
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
        field: value,
    }]}


@pytest.mark.parametrize("field,effect", [
    ("Principal", "Allow"), ("NotPrincipal", "Deny"),
])
@pytest.mark.parametrize("principal", [
    {"aws": "arn:aws:iam::123456789012:root"},
    {"Unknown": "*"},
    {"AWS": "arn:aws:iam::123456789012:root", "Unexpected": "user"},
    {"Service ": "lambda.amazonaws.com"},
    {"Canonicaluser": "canonical-id"},
])
def test_unsupported_principal_type_fails_closed(field, effect, principal):
    with pytest.raises(ValueError, match=f"{field} has invalid principal values"):
        audit_policy(_policy(field, principal, effect))


@pytest.mark.parametrize("field,effect", [
    ("Principal", "Allow"), ("NotPrincipal", "Deny"),
])
@pytest.mark.parametrize("principal", [
    {"AWS": "arn:aws:iam::123456789012:root"},
    {"Service": "lambda.amazonaws.com"},
    {"Federated": "accounts.google.com"},
    {"CanonicalUser": "canonical-user-id"},
    {"AWS": ["arn:aws:iam::123456789012:root", "arn:aws:iam::123456789012:role/reader"]},
])
def test_supported_principal_types_remain_valid(field, effect, principal):
    assert audit_policy(_policy(field, principal, effect)).findings == []
