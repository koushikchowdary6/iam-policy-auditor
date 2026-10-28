"""Prevent invisible-only IAM labels from being mistaken for valid identifiers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


BASE = {
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::example/reports/*",
    }]
}
INVISIBLE = "\u0301\u0308"  # combining acute and diaeresis, no base character


@pytest.mark.parametrize("field", ["Id", "Sid", "Resource", "Principal", "NotResource"])
def test_combining_marks_only_are_rejected_in_policy_identifiers(field):
    policy = {"Statement": [dict(BASE["Statement"][0])]}
    if field == "Id":
        policy["Id"] = INVISIBLE
    else:
        statement = policy["Statement"][0]
        if field == "NotResource":
            del statement["Resource"]
        statement[field] = INVISIBLE
    with pytest.raises(ValueError):
        audit_policy(policy)


@pytest.mark.parametrize("location", ["operator", "context_key"])
def test_combining_marks_only_are_rejected_in_conditions(location):
    statement = dict(BASE["Statement"][0])
    if location == "operator":
        statement["Condition"] = {INVISIBLE: {"aws:PrincipalAccount": "123456789012"}}
    else:
        statement["Condition"] = {"StringEquals": {INVISIBLE: "value"}}
    with pytest.raises(ValueError, match="Condition"):
        audit_policy({"Statement": [statement]})


def test_combining_accents_on_visible_letters_remain_accepted():
    statement = dict(BASE["Statement"][0])
    statement["Sid"] = "Re\u0301view"
    statement["Resource"] = "arn:aws:s3:::cafe\u0301/reports/*"
    statement["Condition"] = {
        "StringEquals": {"aws:RequestTag/cafe\u0301": "ok"},
    }
    report = audit_policy({"Id": "Re\u0301view", "Statement": [statement]})
    assert report.highest_severity == "NONE"
