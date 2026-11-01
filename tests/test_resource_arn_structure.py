"""Reject resource identifiers that IAM cannot interpret as ARN boundaries."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def _policy(field: str, resource: str, effect: str = "Allow") -> dict:
    return {
        "Statement": [{
            "Effect": effect,
            "Action": "s3:GetObject",
            field: resource,
        }]
    }


@pytest.mark.parametrize("field", ["Resource", "NotResource"])
@pytest.mark.parametrize("resource", [
    "reports-bucket",
    "s3://reports-bucket",
    "arn:aws:s3",
    "arn:aws:s3:::",
    "arn::s3:::reports-bucket",
    "arn:aws::us-east-1:123456789012:bucket",
    "arn:*:s3:::reports-bucket",
])
def test_malformed_resource_identifier_is_rejected_for_allow_and_deny(field, resource):
    for effect in ("Allow", "Deny"):
        with pytest.raises(ValueError, match="invalid resource identifier"):
            audit_policy(_policy(field, resource, effect))


@pytest.mark.parametrize("resource", [
    "*",
    "arn:aws:s3:::reports-bucket",
    "arn:aws:s3:::reports-bucket/2026/*",
    "arn:aws:iam::123456789012:role/team/Analyst",
    "arn:aws:lambda:us-east-1:123456789012:function:billing",
    "arn:aws:s3:::reports-bucket/\u0024{aws:username}/*",
])
def test_supported_wildcard_and_arn_shapes_are_accepted(resource):
    audit_policy(_policy("Resource", resource))
    audit_policy(_policy("NotResource", resource))


def test_cli_rejects_bare_resource_instead_of_reporting_clean(tmp_path, capsys):
    path = tmp_path / "invalid-resource.json"
    path.write_text(json.dumps(_policy("Resource", "reports-bucket")), encoding="utf-8")
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "invalid resource identifier" in captured.err
    assert "No risky statements found" not in captured.out
