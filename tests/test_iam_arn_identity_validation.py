"""IAM resource ARN shape checks must not mistake broken identities for scope."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def policy(resource, field="Resource", effect="Allow"):
    return {"Statement": [{"Effect": effect, "Action": "iam:GetRole", field: resource}]}


@pytest.mark.parametrize("resource", [
    "arn:aws:iam::123456789012:role/",
    "arn:aws:iam::123456789012:role/team/",
    "arn:aws:iam::123456789012:role",
    "arn:aws:iam:us-east-1:123456789012:role/Admin",
    "arn:aws:iam:::role/Admin",
    "arn:aws:iam::account:role/Admin",
])
@pytest.mark.parametrize("field", ["Resource", "NotResource"])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_invalid_iam_resource_boundaries_fail_closed(resource, field, effect):
    with pytest.raises(ValueError, match="invalid resource identifier"):
        audit_policy(policy(resource, field, effect))


@pytest.mark.parametrize("resource", [
    "arn:aws:iam::123456789012:root",
    "arn:aws:iam::123456789012:role/team/Admin",
    "arn:aws:iam::123456789012:policy/ReadOnly",
    "arn:aws:iam::123456789012:role/*",
    "arn:aws:iam::*:role/Admin",
    "arn:aws:s3:::reports/2026/",
])
def test_valid_iam_resources_and_other_services_still_parse(resource):
    audit_policy(policy(resource))


def test_wildcard_account_is_reported_not_silently_discarded():
    findings = audit_policy(policy("arn:aws:iam::*:role/Admin")).findings
    assert any(f.title == "Broad resource ARN pattern" for f in findings)


def test_cli_rejects_incomplete_iam_role_arn(tmp_path, capsys):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(policy("arn:aws:iam::123456789012:role/")), encoding="utf-8")
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "invalid resource identifier" in captured.err
    assert "No risky statements found" not in captured.out
