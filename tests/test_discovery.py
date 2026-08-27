"""
tests/test_discovery.py

Unit tests for qscan_lib.discovery.

These tests avoid scanning external systems. Network-related tests use
localhost or mocked functions so the test suite remains deterministic.
"""

import os
import socket
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from qscan_lib.discovery import (
    DEFAULT_PORTS,
    DiscoveryResult,
    PortResult,
    _safe_decode_banner,
    _service_name,
    discovery_result_to_dict,
    is_same_l2_segment,
    lookup_mac_address,
    resolve_target,
    reverse_dns_lookup,
    scan_ports,
)


# ---------------------------------------------------------------------------
# Basic helper tests
# ---------------------------------------------------------------------------

def test_default_port_list_is_bounded():
    assert len(DEFAULT_PORTS) <= 100
    assert all(1 <= port <= 65535 for port in DEFAULT_PORTS)


def test_service_name_known_port():
    assert _service_name(22) == "ssh"
    assert _service_name(443) == "https"


def test_service_name_unknown_port():
    assert _service_name(9999) is None


def test_banner_decode_handles_utf8():
    data = b"SSH-2.0-OpenSSH_9.0\r\n"
    assert _safe_decode_banner(data) == "SSH-2.0-OpenSSH_9.0"


def test_banner_decode_handles_invalid_bytes():
    data = b"hello\xffworld"
    result = _safe_decode_banner(data)

    assert "hello" in result
    assert "world" in result


def test_banner_decode_is_bounded():
    data = b"A" * 5000
    result = _safe_decode_banner(data)

    assert len(result) <= 512


# ---------------------------------------------------------------------------
# Target resolution tests
# ---------------------------------------------------------------------------

def test_resolve_ipv4_returns_same_address():
    ip, error = resolve_target("127.0.0.1", timeout=1.0)

    assert ip == "127.0.0.1"
    assert error is None


@patch(
    "qscan_lib.discovery.socket.getaddrinfo",
    return_value=[
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("192.168.56.10", 0),
        )
    ],
)
def test_resolve_hostname(mock_getaddrinfo):
    ip, error = resolve_target("example.local", timeout=1.0)

    assert ip == "192.168.56.10"
    assert error is None
    mock_getaddrinfo.assert_called_once()


@patch(
    "qscan_lib.discovery.socket.getaddrinfo",
    side_effect=socket.gaierror("name resolution failed"),
)
def test_resolve_hostname_failure(mock_getaddrinfo):
    ip, error = resolve_target("does-not-exist.invalid", timeout=1.0)

    assert ip is None
    assert error is not None
    assert "DNS resolution failed" in error


# ---------------------------------------------------------------------------
# Reverse DNS tests
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.socket.gethostbyaddr",
    return_value=("localhost", [], ["127.0.0.1"]),
)
def test_reverse_dns_success(mock_gethostbyaddr):
    hostname, error = reverse_dns_lookup("127.0.0.1", timeout=1.0)

    assert hostname == "localhost"
    assert error is None


@patch(
    "qscan_lib.discovery.socket.gethostbyaddr",
    side_effect=socket.herror("no PTR record"),
)
def test_reverse_dns_missing_record_is_not_error(mock_gethostbyaddr):
    hostname, error = reverse_dns_lookup("192.0.2.1", timeout=1.0)

    assert hostname is None
    assert error is None


# ---------------------------------------------------------------------------
# MAC address / L2 tests
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.is_same_l2_segment",
    return_value=False,
)
def test_mac_routed_target_is_not_applicable(mock_same_l2):
    mac, status, error = lookup_mac_address("203.0.113.10")

    assert mac is None
    assert status == "not_applicable"
    assert error is None


@patch(
    "qscan_lib.discovery.is_same_l2_segment",
    return_value=True,
)
@patch(
    "qscan_lib.discovery.subprocess.run",
)
def test_mac_address_observed_from_neighbor_cache(
    mock_run,
    mock_same_l2,
):
    mock_run.return_value.stdout = (
        "192.168.56.10 dev enp0s8 "
        "lladdr 08:00:27:12:34:56 REACHABLE\n"
    )

    mac, status, error = lookup_mac_address("192.168.56.10")

    assert mac == "08:00:27:12:34:56"
    assert status == "observed"
    assert error is None


@patch(
    "qscan_lib.discovery.is_same_l2_segment",
    return_value=True,
)
@patch(
    "qscan_lib.discovery.subprocess.run",
)
def test_mac_missing_from_neighbor_cache_is_not_observed(
    mock_run,
    mock_same_l2,
):
    mock_run.return_value.stdout = (
        "192.168.56.10 dev enp0s8 FAILED\n"
    )

    mac, status, error = lookup_mac_address("192.168.56.10")

    assert mac is None
    assert status == "not_observed"
    assert error is None


# ---------------------------------------------------------------------------
# Port scanning tests
# ---------------------------------------------------------------------------

def test_scan_ports_empty_list():
    results = scan_ports(
        "127.0.0.1",
        ports=(),
        timeout=0.5,
        max_workers=2,
    )

    assert results == []


def test_scan_ports_results_are_sorted():
    results = scan_ports(
        "127.0.0.1",
        ports=(443, 22, 80),
        timeout=0.2,
        max_workers=2,
    )

    port_numbers = [result.port for result in results]

    assert port_numbers == sorted(port_numbers)


def test_scan_ports_respects_port_limit():
    many_ports = tuple(range(1, 201))

    with patch(
        "qscan_lib.discovery.scan_port",
        side_effect=lambda ip, port, timeout: PortResult(
            port=port,
            state="closed_or_filtered",
        ),
    ):
        results = scan_ports(
            "127.0.0.1",
            ports=many_ports,
            timeout=0.1,
            max_workers=5,
        )

    assert len(results) == 100


# ---------------------------------------------------------------------------
# Serialization tests
# ---------------------------------------------------------------------------

def test_discovery_result_serializes_to_dict():
    result = DiscoveryResult(
        target="127.0.0.1",
        resolved_ip="127.0.0.1",
        reachable=True,
        reverse_dns="localhost",
        mac_address=None,
        mac_status="not_applicable",
        ports=[
            PortResult(
                port=22,
                state="open",
                service="ssh",
                banner="SSH-2.0-OpenSSH",
            )
        ],
    )

    data = discovery_result_to_dict(result)

    assert data["target"] == "127.0.0.1"
    assert data["resolved_ip"] == "127.0.0.1"
    assert data["reachable"] is True
    assert data["ports"][0]["port"] == 22
    assert data["ports"][0]["service"] == "ssh"


# ---------------------------------------------------------------------------
# L2 segment safety test
# ---------------------------------------------------------------------------

def test_rfc5737_documentation_ip_is_not_local_l2():
    assert is_same_l2_segment("203.0.113.10") is False
