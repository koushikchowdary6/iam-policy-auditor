"""Reject shortened fixed AWS account IDs without banning wildcard ARN patterns."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def _policy(resource, field="Resource", effect="Allow"):
    return {"Statement": [{"Effect": effect, "Action": "s3:GetObject", field: resource}]}


@pytest.mark.parametrize("resource", [
    "arn:aws:iam::12345678901:role/Admin",
    "arn:aws:iam::123:role/Admin",
    "arn:aws:s3:us-east-1:12345678901:accesspoint/team",
    "arn:aws:s3::12345678901:accesspoint/team.mrap",
    "arn:aws:s3:us-east-1:123:job/batch",
    # '?' consumes one digit; short patterns without '*' match no AWS account.
    "arn:aws:iam::123?:role/Admin",
    "arn:aws:iam::???????????:role/Admin",
    "arn:aws:s3:us-east-1:123?:accesspoint/team",
    "arn:aws:s3::??:accesspoint/team.mrap",
])
@pytest.mark.parametrize("field", ["Resource", "NotResource"])
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_short_fixed_account_ids_fail_closed(resource, field, effect):
    with pytest.raises(ValueError, match="invalid resource identifier"):
        audit_policy(_policy(resource, field, effect))


@pytest.mark.parametrize("resource", [
    "arn:aws:iam::123456789012:role/Admin",
    "arn:aws:iam::*:role/Admin",
    "arn:aws:iam::123*:role/Admin",
    "arn:aws:iam::12345678901?:role/Admin",
    "arn:aws:s3:us-east-1:123456789012:accesspoint/team",
    "arn:aws:s3:us-east-1:123*:accesspoint/team",
    "arn:aws:s3:us-east-1:12345678901?:accesspoint/team",
    "arn:aws:s3::123456789012:accesspoint/team.mrap",
])
def test_valid_fixed_and_wildcard_selectors_still_parse(resource):
    audit_policy(_policy(resource))


def test_cli_rejects_short_fixed_account_without_clean_report(tmp_path, capsys):
    path = tmp_path / "bad-account.json"
    path.write_text(json.dumps(_policy("arn:aws:iam::123:role/Admin")), encoding="utf-8")
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "invalid resource identifier" in captured.err
    assert "No risky statements found" not in captured.out


def test_cli_rejects_short_question_mark_account_selector(tmp_path, capsys):
    path = tmp_path / "impossible-account-glob.json"
    path.write_text(
        json.dumps(_policy("arn:aws:iam::123?:role/Admin")),
        encoding="utf-8",
    )
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "invalid resource identifier" in captured.err
    assert "No risky statements found" not in captured.out
