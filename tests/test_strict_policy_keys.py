"""Regression tests for IAM policy grammar and typo-safe auditing."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def _statement(**changes):
    statement = {
        "Sid": "ReadReports",
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::reports/*",
    }
    statement.update(changes)
    return statement


@pytest.mark.parametrize("misspelled", [
    "Conditon", "NotPrinciple", "Actions", "Resouce", "Effects",
])
def test_unknown_statement_fields_are_rejected_not_ignored(misspelled):
    policy = {"Statement": [_statement(**{misspelled: "ignored"})]}
    with pytest.raises(ValueError, match=r"Statement #0: unsupported keys"):
        audit_policy(policy)


@pytest.mark.parametrize("misspelled", ["Statment", "Verison", "Policy"])
def test_unknown_policy_fields_are_rejected_not_ignored(misspelled):
    policy = {"Version": "2012-10-17", "Statement": [_statement()]}
    policy[misspelled] = "ignored"
    with pytest.raises(ValueError, match="Policy has unsupported keys"):
        audit_policy(policy)


def test_document_id_statement_sid_and_valid_conditions_still_work():
    report = audit_policy({
        "Version": "2012-10-17",
        "Id": "read-reports",
        "Statement": [_statement(Condition={
            "StringEquals": {"aws:PrincipalOrgID": "o-example"}
        })],
    })
    assert report.highest_severity == "NONE"


def test_cli_returns_validation_error_instead_of_false_clean(tmp_path, capsys):
    path = tmp_path / "typo-policy.json"
    path.write_text(
        '{"Statement":{"Effect":"Allow","Action":"s3:GetObject",'
        '"Resource":"arn:aws:s3:::reports/*","Conditon":{"Bool":{"aws:SecureTransport":"true"}}}}',
        encoding="utf-8",
    )
    assert main([str(path)]) == 2
    captured = capsys.readouterr()
    assert "unsupported keys" in captured.err
    assert "No risky statements found" not in captured.out
