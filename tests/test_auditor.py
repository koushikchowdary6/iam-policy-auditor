import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def _titles(report):
    return {f.title for f in report.findings}


def test_full_admin_wildcard_is_high():
    policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
    report = audit_policy(policy)
    assert report.highest_severity == "HIGH"
    assert "Full administrative wildcard" in _titles(report)


def test_privilege_escalation_flagged():
    policy = {"Statement": [{"Effect": "Allow", "Action": ["iam:CreatePolicyVersion"],
                             "Resource": "arn:aws:iam::123:policy/x"}]}
    report = audit_policy(policy)
    assert "Privilege-escalation action" in _titles(report)
    assert report.highest_severity == "HIGH"


def test_public_principal_without_condition_is_high():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*",
                             "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*"}]}
    report = audit_policy(policy)
    assert "Public principal" in _titles(report)
    assert report.highest_severity == "HIGH"


def test_public_principal_with_condition_is_downgraded():
    policy = {"Statement": [{"Effect": "Allow", "Principal": "*",
                             "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::b/*",
                             "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]}
    report = audit_policy(policy)
    pub = [f for f in report.findings if f.title == "Public principal"][0]
    assert pub.severity == "MEDIUM"


def test_least_privilege_policy_is_clean():
    policy = {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"],
                             "Resource": "arn:aws:s3:::b/reports/*",
                             "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}
    report = audit_policy(policy)
    assert report.findings == []
    assert report.highest_severity == "NONE"


def test_deny_statements_are_ignored():
    policy = {"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}
    assert audit_policy(policy).findings == []


def test_wildcard_action_is_medium():
    policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*",
                             "Resource": "arn:aws:s3:::b/*"}]}
    assert "Wildcard action" in _titles(audit_policy(policy))


def test_not_action_with_global_resource_is_high():
    policy = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    report = audit_policy(policy)
    finding = [f for f in report.findings if f.title == "Broad NotAction allow"][0]
    assert finding.severity == "HIGH"


def test_not_action_scoped_resource_is_medium():
    policy = {"Statement": [{"Effect": "Allow", "NotAction": ["s3:DeleteObject"],
                             "Resource": "arn:aws:s3:::reports/*"}]}
    finding = [f for f in audit_policy(policy).findings
               if f.title == "Broad NotAction allow"][0]
    assert finding.severity == "MEDIUM"


def test_invalid_statement_shape_is_rejected():
    with pytest.raises(ValueError, match="Statement"):
        audit_policy({"Statement": "not-an-object"})


def test_non_object_policy_is_rejected():
    with pytest.raises(ValueError, match="JSON object"):
        audit_policy([])


def test_example_files_parse_and_audit():
    examples = Path(__file__).resolve().parent.parent / "examples"
    for path in examples.glob("*.json"):
        audit_policy(json.loads(path.read_text()))


def test_public_principal_nested_aws_list_is_high():
    policy = {"Statement": [{"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::123:root", "*"]},
                             "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
    report = audit_policy(policy)
    assert "Public principal" in _titles(report)
    assert report.highest_severity == "HIGH"
