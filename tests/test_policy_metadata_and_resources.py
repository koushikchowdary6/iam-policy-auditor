"""Malformed IAM metadata and padded resources must fail closed."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, main


def _policy(**changes):
    policy = {
        "Version": "2012-10-17",
        "Id": "example-policy",
        "Statement": [{
            "Sid": "ReadReports", "Effect": "Allow",
            "Action": "s3:GetObject", "Resource": "arn:aws:s3:::reports/*",
        }],
    }
    policy.update(changes)
    return policy


@pytest.mark.parametrize("version", ["2026-01-01", "", None, 20121017, True])
def test_unknown_or_malformed_policy_version_is_rejected(version):
    with pytest.raises(ValueError, match="Version"):
        audit_policy(_policy(Version=version))


@pytest.mark.parametrize("version", ["2008-10-17", "2012-10-17"])
def test_supported_iam_versions_are_accepted(version):
    assert audit_policy(_policy(Version=version)).highest_severity == "NONE"


def test_omitted_version_remains_compatible_with_iam_documents():
    policy = _policy()
    del policy["Version"]
    assert audit_policy(policy).highest_severity == "NONE"


@pytest.mark.parametrize("value", ["", " ", " padded", "padded ", "abc\n", 7, None])
def test_invalid_policy_id_is_rejected(value):
    with pytest.raises(ValueError, match="Id"):
        audit_policy(_policy(Id=value))


@pytest.mark.parametrize("value", ["", " ", " leading", "trailing ", "ok\x00bad", 5, None])
def test_invalid_statement_sid_is_rejected(value):
    policy = _policy()
    policy["Statement"][0]["Sid"] = value
    with pytest.raises(ValueError, match="Sid"):
        audit_policy(policy)


@pytest.mark.parametrize("field,value", [
    ("Resource", "* "), ("Resource", " *"),
    ("Resource", "arn:aws:s3:::bucket/*\n"),
    ("NotResource", "arn:aws:s3:::bucket/*\x00"),
    ("NotResource", " arn:aws:s3:::bucket/*"),
])
def test_padded_or_control_bearing_resources_are_rejected(field, value):
    policy = _policy()
    statement = policy["Statement"][0]
    statement.pop("Resource")
    statement[field] = value
    with pytest.raises(ValueError, match=field):
        audit_policy(policy)


def test_cli_fails_instead_of_reporting_malformed_resource_as_clean(tmp_path, capsys):
    path = tmp_path / "bad-resource.json"
    path.write_text('{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"* "}}', encoding="utf-8")
    assert main([str(path)]) == 2
    output = capsys.readouterr()
    assert "Resource" in output.err
    assert "No risky statements found" not in output.out
