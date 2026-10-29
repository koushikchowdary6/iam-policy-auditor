"""Global Resource '*' is broad even for narrowly named non-sensitive actions."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import audit_policy


def findings(action, resource="*", effect="Allow"):
    report = audit_policy({
        "Statement": [{"Effect": effect, "Action": action, "Resource": resource}]
    })
    return {item.title: item.severity for item in report.findings}


@pytest.mark.parametrize("action", [
    "lambda:InvokeFunction",
    "sqs:SendMessage",
    "sns:Publish",
    "dynamodb:PutItem",
])
def test_narrow_non_sensitive_action_on_all_resources_is_flagged(action):
    assert findings(action)["Wildcard resource across services"] == "MEDIUM"


def test_sensitive_service_keeps_existing_finding_without_duplicate():
    result = findings("s3:GetObject")
    assert result["Wildcard resource on sensitive service"] == "MEDIUM"
    assert "Wildcard resource across services" not in result


def test_full_admin_keeps_dedicated_high_finding():
    result = findings("*")
    assert result["Full administrative wildcard"] == "HIGH"
    assert "Wildcard resource across services" not in result


def test_scoped_resource_does_not_trigger_global_resource_finding():
    result = findings(
        "lambda:InvokeFunction",
        "arn:aws:lambda:us-east-1:123456789012:function:billing",
    )
    assert "Wildcard resource across services" not in result


def test_deny_global_resource_does_not_generate_allow_risk():
    assert findings("lambda:InvokeFunction", effect="Deny") == {}


def test_mixed_action_list_keeps_sensitive_service_warning():
    result = findings(["lambda:InvokeFunction", "s3:GetObject"])
    assert result["Wildcard resource on sensitive service"] == "MEDIUM"
    assert "Wildcard resource across services" not in result
