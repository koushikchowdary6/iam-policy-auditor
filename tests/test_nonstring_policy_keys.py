"""Malformed direct-dictionary policy keys must fail with a clear policy error."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from iam_auditor import audit_policy, audit_statement


@pytest.mark.parametrize("bad_key", [42, None, (1, 2)])
def test_non_string_top_level_key_fails_closed(bad_key):
    policy = {
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
        bad_key: "unexpected",
    }
    with pytest.raises(ValueError, match="Policy keys must be strings"):
        audit_policy(policy)


@pytest.mark.parametrize("bad_key", [42, None, (1, 2)])
def test_non_string_statement_key_fails_closed(bad_key):
    statement = {"Effect": "Allow", "Action": "*", "Resource": "*", bad_key: "unexpected"}
    with pytest.raises(ValueError, match="Statement #0: keys must be strings"):
        audit_policy({"Statement": statement})


def test_direct_statement_audit_rejects_non_string_key():
    with pytest.raises(ValueError, match="Statement #3: keys must be strings"):
        audit_statement({"Effect": "Deny", 7: "invalid"}, 3)


def test_normal_valid_policy_still_reports_full_admin_wildcard():
    report = audit_policy({
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
    })
    assert any(f.title == "Full administrative wildcard" for f in report.findings)
