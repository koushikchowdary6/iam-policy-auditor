"""S3 bucket and regional-resource ARN boundaries must be distinguishable."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def _policy(resource, field="Resource", effect="Allow"):
    return {
        "Statement": [{
            "Effect": effect,
            "Action": "s3:GetObject",
            field: resource,
        }]
    }


@pytest.mark.parametrize("resource", [
    "arn:aws:s3:us-east-1:123456789012:reports-bucket",
    "arn:aws:s3:us-east-1::reports-bucket",
    "arn:aws:s3::123456789012:reports-bucket",
    "arn:aws:s3:us-east-1:invalid:accesspoint/team",
    "arn:aws:s3:us-east-1:123456789012:accesspoint",
    "arn:aws:s3:us-east-1:123456789012:job/",
    "arn:aws:s3::123456789012:accesspoint/",
])
@pytest.mark.parametrize("field", ["Resource", "NotResource"])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_malformed_s3_region_account_or_identity_rejected(resource, field, effect):
    with pytest.raises(ValueError, match="invalid resource identifier"):
        audit_policy(_policy(resource, field, effect))


@pytest.mark.parametrize("resource", [
    "arn:aws:s3:::reports-bucket",
    "arn:aws:s3:::reports-bucket/2026/*",
    "arn:aws:s3:::reports-bucket/${aws:username}/*",
    "arn:aws:s3:us-east-1:123456789012:accesspoint/team-data",
    "arn:aws:s3:us-east-1:123456789012:accesspoint/team-data/object/2026/",
    "arn:aws:s3:us-east-1:123456789012:job/batch-001",
    "arn:aws:s3:us-west-2:123456789012:storage-lens/config-1",
    "arn:aws:s3::123456789012:accesspoint/example.mrap",
    "arn:aws:s3:*:123456789012:accesspoint/team-*",
])
def test_valid_s3_bucket_and_typed_resource_patterns_remain_supported(resource):
    audit_policy(_policy(resource))
    audit_policy(_policy(resource, field="NotResource"))


def test_invalid_s3_resource_fails_cli_without_clean_audit(tmp_path, capsys):
    path = tmp_path / "broken-s3-arn.json"
    path.write_text(
        json.dumps(_policy("arn:aws:s3:us-east-1:123456789012:reports-bucket")),
        encoding="utf-8",
    )
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "invalid resource identifier" in captured.err
    assert "No risky statements found" not in captured.out
