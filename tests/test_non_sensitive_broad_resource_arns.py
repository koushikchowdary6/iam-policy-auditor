"""Broad resource identities matter even for narrowly named, non-sensitive actions."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def _findings(action, resource, effect="Allow"):
    report = audit_policy({
        "Statement": [{
            "Effect": effect,
            "Action": action,
            "Resource": resource,
        }]
    })
    return {finding.title: finding.severity for finding in report.findings}


@pytest.mark.parametrize("action, resource", [
    ("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123456789012:function:*"),
    ("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123456789012:function:billing-*"),
    ("sns:Publish", "arn:aws:sns:us-east-1:123456789012:*"),
    ("sqs:SendMessage", "arn:aws:sqs:us-east-1:*:billing-queue"),
])
def test_narrow_actions_do_not_hide_broad_arn_resource_scope(action, resource):
    assert _findings(action, resource)["Broad resource ARN pattern"] == "MEDIUM"


@pytest.mark.parametrize("action, resource", [
    ("lambda:InvokeFunction", "arn:aws:lambda:us-east-1:123456789012:function:billing"),
    ("sns:Publish", "arn:aws:sns:us-east-1:123456789012:billing-events"),
    ("sqs:SendMessage", "arn:aws:sqs:us-east-1:123456789012:billing-queue"),
    ("s3:GetObject", "arn:aws:s3:::named-bucket/reports/*"),
])
def test_fixed_resource_identities_and_named_bucket_prefixes_remain_clean(action, resource):
    assert "Broad resource ARN pattern" not in _findings(action, resource)


def test_broad_arn_in_list_is_flagged_for_narrow_lambda_action():
    resources = [
        "arn:aws:lambda:us-east-1:123456789012:function:billing",
        "arn:aws:lambda:us-east-1:123456789012:function:*",
    ]
    assert _findings("lambda:InvokeFunction", resources)["Broad resource ARN pattern"] == "MEDIUM"


def test_deny_with_broad_arn_does_not_create_allow_risk():
    assert _findings(
        "lambda:InvokeFunction",
        "arn:aws:lambda:us-east-1:123456789012:function:*",
        effect="Deny",
    ) == {}
