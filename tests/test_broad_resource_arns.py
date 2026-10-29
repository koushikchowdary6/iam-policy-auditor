"""Wildcard ARN identities should not masquerade as least-privilege resources."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def _titles(action, resource):
    report = audit_policy({
        "Statement": [{
            "Effect": "Allow",
            "Action": action,
            "Resource": resource,
        }]
    })
    return {finding.title: finding.severity for finding in report.findings}


@pytest.mark.parametrize("resource", [
    "arn:aws:s3:::*",
    "arn:aws:s3:::*/*",
    "arn:aws:s3:::reports-*",
    "arn:aws:s3:::*/reports/*",
])
def test_wildcard_bucket_identity_is_flagged(resource):
    assert _titles("s3:GetObject", resource)["Broad resource ARN pattern"] == "MEDIUM"


@pytest.mark.parametrize("action, resource", [
    ("iam:ListRoles", "arn:aws:iam::*:role/auditor"),
    ("kms:Decrypt", "arn:aws:kms:*:123456789012:key/abc"),
    ("iam:ListRoles", "arn:aws:iam::123456789012:*"),
])
def test_wildcard_account_region_or_resource_selector_is_flagged(action, resource):
    assert _titles(action, resource)["Broad resource ARN pattern"] == "MEDIUM"



@pytest.mark.parametrize("action, resource", [
    ("iam:GetRole", "arn:aws:iam::123456789012:role/analytics-*"),
    ("iam:GetRole", "arn:aws:iam::123456789012:role/team/Admin*"),
    ("iam:GetRole", "arn:aws:iam::123456789012:role/*"),
    ("iam:GetPolicy", "arn:aws:iam::123456789012:policy/team-?"),
    ("kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:key/abc*"),
    ("ec2:DescribeInstances", "arn:aws:ec2:us-east-1:123456789012:instance/i-*"),
])
def test_wildcard_resource_identity_after_arn_type_is_flagged(action, resource):
    assert _titles(action, resource)["Broad resource ARN pattern"] == "MEDIUM"


@pytest.mark.parametrize("action, resource", [
    ("iam:GetRole", "arn:aws:iam::123456789012:role/team/Analytics"),
    ("kms:Decrypt", "arn:aws:kms:us-east-1:123456789012:key/abc123"),
    ("ec2:DescribeInstances", "arn:aws:ec2:us-east-1:123456789012:instance/i-123"),
])
def test_named_non_s3_resource_identities_remain_clean(action, resource):
    assert _titles(action, resource) == {}


@pytest.mark.parametrize("action, resource", [
    ("s3:GetObject", "arn:aws:s3:::reports-bucket/2026/*"),
    ("s3:GetObject", "arn:aws:s3:::reports-bucket/*"),
    ("s3:GetObject", "arn:aws:s3:::reports-bucket"),
])
def test_named_resource_with_scoped_path_wildcard_remains_clean(action, resource):
    assert _titles(action, resource) == {}


def test_broad_arn_in_resource_list_is_not_hidden_by_scoped_arn():
    resources = [
        "arn:aws:s3:::reports-bucket/2026/*",
        "arn:aws:s3:::*",
    ]
    assert _titles("s3:GetObject", resources)["Broad resource ARN pattern"] == "MEDIUM"


def test_global_resource_wildcard_keeps_existing_finding_without_duplicate():
    findings = _titles("s3:GetObject", "*")
    assert "Wildcard resource on sensitive service" in findings
    assert "Broad resource ARN pattern" not in findings


def test_deny_wildcard_arn_does_not_generate_allow_risk():
    report = audit_policy({
        "Statement": [{
            "Effect": "Deny",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::*",
        }]
    })
    assert report.findings == []


@pytest.mark.parametrize("action, resource", [
    ("s3:GetObject", "arn:aws:s3:us-east-1:123456789012:accesspoint/*"),
    ("s3:GetObject", "arn:aws:s3:us-east-1:123456789012:accesspoint/team-*"),
    ("s3:GetObject", "arn:aws:s3:us-east-1:123456789012:accesspoint/ap-?"),
    ("s3:DescribeJob", "arn:aws:s3:us-east-1:123456789012:job/*"),
])
def test_wildcard_s3_access_point_or_batch_job_identity_is_flagged(action, resource):
    assert _titles(action, resource)["Broad resource ARN pattern"] == "MEDIUM"


@pytest.mark.parametrize("action, resource", [
    ("s3:GetObject", "arn:aws:s3:us-east-1:123456789012:accesspoint/team-data"),
    ("s3:GetObject", "arn:aws:s3:us-east-1:123456789012:accesspoint/team-data/object/2026/*"),
    ("s3:GetObject", "arn:aws:s3:::reports-bucket/2026/*"),
    ("s3:DescribeJob", "arn:aws:s3:us-east-1:123456789012:job/abc123"),
])
def test_named_s3_resource_with_scoped_object_prefix_remains_clean(action, resource):
    assert _titles(action, resource) == {}
