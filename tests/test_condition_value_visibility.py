"""IAM Condition values must not conceal controls or invisible-only strings.

The auditor cannot prove that a policy is safe if a string value is visually
different from what the JSON parser or AWS would evaluate.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(value, effect="Allow", operator="StringEquals", key="aws:PrincipalOrgID"):
    return {
        "Statement": [{
            "Effect": effect,
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::reports/*",
            "Condition": {operator: {key: value}},
        }]
    }


@pytest.mark.parametrize("value", [
    "\u200b",  # invisible-only
    "\u0301",  # standalone combining accent
    "o-test\u202e",  # bidi override
    "o-test\u2066",  # bidi isolate
    "o-test\u034f",  # combining grapheme joiner
    "o-test\ufe0f",  # variation selector
    "team\u00a0blue",  # nonbreaking space looks like a normal space
    "team\u2009blue",  # thin space
    "o-test\ud800",  # invalid UTF-8 surrogate
])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_hidden_condition_values_fail_closed(value, effect):
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(_policy(value, effect=effect))


def test_hidden_values_in_condition_lists_fail_closed():
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(_policy(["o-trusted", "o-test\u202e"]))


def test_hidden_ipaddress_values_fail_closed():
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(_policy(
            ["10.0.0.0/8", "10.0.0.0/8\u200b"],
            operator="IpAddress",
            key="aws:SourceIp",
        ))


def test_visible_unicode_tag_values_and_ascii_spaces_remain_valid():
    # AWS tag values can contain ordinary spaces, including edge spaces;
    # they are not identifiers and should not be silently normalized.
    report = audit_policy(_policy(
        ["José", " Project Alpha "],
        key="s3:ExistingObjectTag/project name",
    ))
    assert any(
        finding.title == "Public principal" and finding.severity == "HIGH"
        for finding in report.findings
    )


def test_numeric_and_boolean_condition_values_remain_supported():
    audit_policy(_policy(3600, operator="NumericLessThan", key="aws:MultiFactorAuthAge"))
    audit_policy(_policy(True, operator="Bool", key="aws:SecureTransport"))
