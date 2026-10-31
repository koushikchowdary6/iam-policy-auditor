"""CLI policy-file safety: never follow symlinks or block on special files."""
import os
import subprocess
import sys
from pathlib import Path

import pytest

CLI = Path(__file__).resolve().parents[1] / "src" / "iam_auditor.py"
VALID = b'{"Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::reports/*"}}'


def run_cli(path):
    return subprocess.run(
        [sys.executable, str(CLI), str(path), "--json"],
        capture_output=True, text=True, timeout=10, check=False,
    )


def test_regular_policy_file_remains_supported(tmp_path):
    path = tmp_path / "policy.json"
    path.write_bytes(VALID)
    result = run_cli(path)
    assert result.returncode == 0, result.stderr
    assert '"findings"' in result.stdout


def test_symbolic_link_is_not_followed(tmp_path):
    target = tmp_path / "real.json"
    target.write_bytes(VALID)
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    result = run_cli(link)
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert result.stdout == ""


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_fifo_is_rejected_without_waiting_for_writer(tmp_path):
    path = tmp_path / "blocked.pipe"
    os.mkfifo(path)
    result = run_cli(path)
    assert result.returncode == 2
    assert "regular file" in result.stderr
    assert result.stdout == ""


def test_directory_is_rejected(tmp_path):
    result = run_cli(tmp_path)
    assert result.returncode == 2
    assert "regular file" in result.stderr
    assert result.stdout == ""


def test_invalid_utf8_is_a_controlled_audit_error(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_bytes(b"\xff\xfe")
    result = run_cli(path)
    assert result.returncode == 2
    assert "error:" in result.stderr
    assert result.stdout == ""
