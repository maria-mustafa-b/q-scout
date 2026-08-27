"""
tests/test_targets.py

Unit tests for qscan_lib.targets. Pure logic, no network access required.
Run with: python3 -m pytest tests/test_targets.py -v
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qscan_lib.targets import (
    TargetKind,
    is_valid_ipv4,
    is_valid_hostname,
    is_valid_cidr,
    parse_target_argument,
)


def test_valid_ipv4_accepted():
    assert is_valid_ipv4("192.168.56.10") is True


def test_ipv4_out_of_range_rejected():
    assert is_valid_ipv4("999.168.56.10") is False


def test_ipv4_malformed_rejected():
    assert is_valid_ipv4("192.168.56") is False
    assert is_valid_ipv4("not.an.ip.addr") is False


def test_valid_hostname_accepted():
    assert is_valid_hostname("example.local") is True
    assert is_valid_hostname("host1") is True


def test_hostname_with_leading_hyphen_rejected():
    assert is_valid_hostname("-badhost.local") is False


def test_hostname_empty_rejected():
    assert is_valid_hostname("") is False


def test_valid_cidr_accepted():
    assert is_valid_cidr("192.168.56.0/24") is True


def test_invalid_cidr_rejected():
    assert is_valid_cidr("192.168.56.0/40") is False
    assert is_valid_cidr("not-a-cidr") is False


def test_parse_single_ip():
    result = parse_target_argument("192.168.56.10")
    assert len(result.targets) == 1
    assert result.targets[0].kind == TargetKind.IP
    assert result.targets[0].value == "192.168.56.10"
    assert result.skipped == []


def test_parse_single_hostname():
    result = parse_target_argument("example.local")
    assert len(result.targets) == 1
    assert result.targets[0].kind == TargetKind.HOSTNAME


def test_parse_invalid_target_is_skipped_not_crashed():
    result = parse_target_argument("###not valid###")
    assert result.targets == []
    assert len(result.skipped) == 1
    assert "not a valid" in result.skipped[0][1]


def test_parse_cidr_expands_to_hosts():
    result = parse_target_argument("192.168.56.0/30")
    assert len(result.targets) == 2
    assert all(t.kind == TargetKind.CIDR_MEMBER for t in result.targets)
    assert result.truncated is False


def test_parse_cidr_respects_max_targets_and_flags_truncation():
    result = parse_target_argument("10.0.0.0/24", max_targets=5)
    assert len(result.targets) == 5
    assert result.truncated is True


def test_parse_invalid_cidr_is_skipped():
    result = parse_target_argument("192.168.56.0/99")
    assert result.targets == []
    assert "invalid CIDR" in result.skipped[0][1]


def test_parse_target_list_file():
    content = "192.168.56.10\n# a comment line\nexample.local\n\nbadtarget!!!\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        result = parse_target_argument(path)
        values = [t.value for t in result.targets]
        assert "192.168.56.10" in values
        assert "example.local" in values
        assert len(result.skipped) == 1
    finally:
        os.unlink(path)


def test_parse_target_list_file_with_cidr_line():
    content = "192.168.56.0/30\n"
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write(content)
        path = f.name

    try:
        result = parse_target_argument(path)
        assert len(result.targets) == 2
        assert all(t.kind == TargetKind.CIDR_MEMBER for t in result.targets)
    finally:
        os.unlink(path)


def test_parse_missing_file_is_not_treated_as_hostname():
    result = parse_target_argument("/nonexistent/path/file.txt")
    assert result.targets == []
    assert len(result.skipped) == 1
