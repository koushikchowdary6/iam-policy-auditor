"""Invisible and padded IAM identifiers must not produce a false clean audit."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(**changes):
    statement = {
        "Effect": "Allow", "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
    }
    statement.update(changes)
    return {"Version": "2012-10-17", "Statement": [statement]}


@pytest.mark.parametrize("invisible", [
    "\\u200b",  # zero-width space
    "\\u202e",  # right-to-left override
    "\\u2066",  # bidi isolate
    "\\u00ad",  # soft hyphen
    "\\u034f",  # combining grapheme joiner
    "\\ufe0f",  # variation selector
    "\\u0085",  # C1 control
    "\\u2028",  # Unicode line separator
    "\\ud800",  # unpaired UTF-16 surrogate
])
def test_invisible_identifiers_fail_closed(invisible):
    for field in ("Id", "Sid", "Resource", "NotResource"):
        policy = _policy()
        if field == "Id":
            policy["Id"] = "review" + invisible + "safe"
        else:
            if field == "NotResource":
                policy["Statement"][0].pop("Resource")
            policy["Statement"][0][field] = "review" + invisible + "safe"
        with pytest.raises(ValueError, match=field):
            audit_policy(policy)


@pytest.mark.parametrize("principal", [
    "* ", " *", "arn:aws:iam::123456789012:role/reader ",
    "*\\u200b", "*\\u202e", "*\\u2066",
    "arn:aws:iam::123456789012:role/read\\u034fer",
    "arn:aws:iam::123456789012:role/read\\ud800er",
])
@pytest.mark.parametrize("field,effect", [("Principal", "Allow"), ("NotPrincipal", "Deny")])
def test_ambiguous_principal_values_are_rejected(principal, field, effect):
    for value in (principal, {"AWS": principal}, {"AWS": ["arn:aws:iam::123456789012:root", principal]}):
        with pytest.raises(ValueError, match=f"{field} has invalid principal values"):
            audit_policy(_policy(Effect=effect, **{field: value}))


def test_valid_principal_and_readable_unicode_metadata_remain_supported():
    policy = _policy(Principal={"AWS": ["arn:aws:iam::123456789012:root", "*"]}, Sid="Résumé")
    policy["Id"] = "audit résumé"
    report = audit_policy(policy)
    assert any(f.title == "Public principal" and f.severity == "HIGH" for f in report.findings)


def test_clean_named_principal_stays_clean():
    report = audit_policy(_policy(Principal={"Service": "lambda.amazonaws.com"}))
    assert report.highest_severity == "NONE"
