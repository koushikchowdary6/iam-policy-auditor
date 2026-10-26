"""IAM Condition identifiers must remain unambiguous to human reviewers."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy


def _policy(condition, effect="Allow"):
    return {"Statement": [{
        "Effect": effect,
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
        "Condition": condition,
    }]}


@pytest.mark.parametrize("spoof", [
    "\u200b",  # zero-width space
    "\u202e",  # right-to-left override
    "\u2066",  # bidi isolate
    "\u034f",  # combining grapheme joiner
    "\ufe0f",  # variation selector
    "\u00a0",  # no-break space
    "\u2009",  # thin space
    "\ud800",  # unpaired surrogate
])
@pytest.mark.parametrize("location", ["operator", "context_key"])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_invisible_condition_identifiers_fail_closed(spoof, location, effect):
    if location == "operator":
        condition = {"IpAddress" + spoof: {"aws:SourceIp": "10.0.0.0/8"}}
    else:
        condition = {"IpAddress": {"aws:SourceIp" + spoof: "10.0.0.0/8"}}
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(_policy(condition, effect=effect))


@pytest.mark.parametrize("location", ["operator", "context_key"])
@pytest.mark.parametrize("padding", [" ", "\t", "\n"])
def test_padded_condition_identifiers_are_rejected(location, padding):
    if location == "operator":
        condition = {padding + "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
    else:
        condition = {"IpAddress": {"aws:SourceIp" + padding: "10.0.0.0/8"}}
    with pytest.raises(ValueError, match="Condition"):
        audit_policy(_policy(condition))


def test_valid_scoping_and_readable_tag_values_are_preserved():
    scoped = audit_policy(_policy({"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}))
    assert any(
        f.title == "Public principal" and f.severity == "MEDIUM"
        for f in scoped.findings
    )

    # Tag names and values may contain ordinary visible text and accents.
    tagged = audit_policy(_policy({
        "StringEquals": {"s3:ExistingObjectTag/project name": "José"}
    }))
    assert any(
        f.title == "Public principal" and f.severity == "HIGH"
        for f in tagged.findings
    )
