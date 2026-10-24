"""Policy JSON must be parsed without ambiguous or non-standard values."""

import io
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from iam_auditor import main, parse_policy_json


@pytest.mark.parametrize("raw", [
    '{"Statement":[{"Effect":"Allow","Effect":"Deny","Action":"*","Resource":"*"}]}',
    '{"Statement":[{"Effect":"Allow","Action":"*","Action":"s3:GetObject","Resource":"*"}]}',
    '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*",'
    '"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-trusted",'
    '"aws:PrincipalOrgID":"*"}}}]}',
])
def test_duplicate_policy_keys_are_rejected_at_every_depth(raw):
    with pytest.raises(ValueError, match="duplicate JSON key"):
        parse_policy_json(raw)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_nonstandard_json_constants_are_rejected(constant):
    with pytest.raises(ValueError, match="non-standard JSON value"):
        parse_policy_json(
            '{"Statement":[{"Effect":"Allow","Action":"s3:GetObject",'
            '"Resource":"*","Condition":{"NumericEquals":{"aws:MultiFactorAuthAge":'
            + constant + '}}}]}'
        )


def test_cli_fails_closed_on_ambiguous_json_file(tmp_path, capsys):
    policy_path = tmp_path / "ambiguous.json"
    policy_path.write_text(
        '{"Statement":[{"Effect":"Allow","Effect":"Deny",'
        '"Action":"*","Resource":"*"}]}',
        encoding="utf-8",
    )
    assert main([str(policy_path), "--json"]) == 2
    captured = capsys.readouterr()
    assert "duplicate JSON key: Effect" in captured.err
    assert not captured.out


def test_cli_fails_closed_on_ambiguous_stdin(monkeypatch, capsys):
    monkeypatch.setattr(
        sys, "stdin",
        io.StringIO('{"Statement":[{"Effect":"Allow","Action":"*",'
                    '"Action":"s3:GetObject","Resource":"*"}]}'),
    )
    assert main(["-", "--json"]) == 2
    captured = capsys.readouterr()
    assert "duplicate JSON key: Action" in captured.err
    assert not captured.out


def test_normal_policy_remains_compatible():
    raw = json.dumps({"Statement": [
        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::safe/*"}
    ]})
    assert parse_policy_json(raw)["Statement"][0]["Action"] == "s3:GetObject"
