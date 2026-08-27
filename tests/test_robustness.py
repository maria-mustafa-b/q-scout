"""
tests/test_robustness.py

Failure-mode and robustness tests for Q-SCOUT.

These tests verify that expected network/system failures are recorded
cleanly rather than crashing the complete scan.
"""

import socket
import subprocess
from unittest.mock import MagicMock, patch

from qscan_lib.discovery import (
    discover_target,
    grab_banner,
    lookup_mac_address,
    reverse_dns_lookup,
    scan_port,
)
from qscan_lib.tls_inspect import inspect_tls


# ---------------------------------------------------------------------------
# 1. DNS / hostname resolution failure
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.socket.getaddrinfo",
    side_effect=socket.gaierror("simulated DNS failure"),
)
def test_discovery_dns_failure_does_not_crash(mock_getaddrinfo):
    result = discover_target(
        "does-not-exist.invalid",
        timeout=0.1,
    )

    assert result.resolved_ip is None
    assert result.scanner_error is not None
    assert "DNS resolution" in result.scanner_error


# ---------------------------------------------------------------------------
# 2. TCP timeout
# ---------------------------------------------------------------------------

@patch("qscan_lib.discovery.socket.socket")
def test_port_timeout_is_handled(mock_socket):
    sock = mock_socket.return_value
    sock.connect_ex.side_effect = socket.timeout()

    result = scan_port(
        "192.0.2.1",
        443,
        timeout=0.1,
    )

    assert result.state == "closed_or_filtered"
    assert result.port == 443


# ---------------------------------------------------------------------------
# 3. Scanner-level socket error
# ---------------------------------------------------------------------------

@patch("qscan_lib.discovery.socket.socket")
def test_socket_error_is_recorded(mock_socket):
    sock = mock_socket.return_value
    sock.connect_ex.side_effect = OSError(
        "simulated socket failure"
    )

    result = scan_port(
        "127.0.0.1",
        443,
        timeout=0.1,
    )

    assert result.state == "scanner_error"
    assert result.error is not None
    assert "simulated socket failure" in result.error


# ---------------------------------------------------------------------------
# 4. Banner timeout
# ---------------------------------------------------------------------------

@patch("qscan_lib.discovery.socket.socket")
def test_banner_timeout_does_not_crash(mock_socket):
    sock = mock_socket.return_value
    sock.recv.side_effect = socket.timeout()

    banner, error = grab_banner(
        "127.0.0.1",
        22,
        timeout=0.1,
    )

    assert banner is None
    assert error == "banner read timed out"


# ---------------------------------------------------------------------------
# 5. Reverse-DNS timeout
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.socket.gethostbyaddr",
    side_effect=socket.timeout(),
)
def test_reverse_dns_timeout_is_recorded(mock_gethostbyaddr):
    hostname, error = reverse_dns_lookup(
        "192.0.2.10",
        timeout=0.1,
    )

    assert hostname is None
    assert error == "reverse DNS lookup timed out"


# ---------------------------------------------------------------------------
# 6. MAC lookup permission/system failure
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.is_same_l2_segment",
    return_value=True,
)
@patch(
    "qscan_lib.discovery.subprocess.run",
    side_effect=PermissionError("permission denied"),
)
def test_mac_permission_failure_is_recorded(
    mock_run,
    mock_same_l2,
):
    mac, status, error = lookup_mac_address(
        "192.168.56.10"
    )

    assert mac is None
    assert status == "not_observed"
    assert error is not None
    assert "permission denied" in error


# ---------------------------------------------------------------------------
# 7. Routed MAC remains explicitly not applicable
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.is_same_l2_segment",
    return_value=False,
)
def test_routed_mac_is_not_applicable(mock_same_l2):
    mac, status, error = lookup_mac_address(
        "203.0.113.10"
    )

    assert mac is None
    assert status == "not_applicable"
    assert error is None


# ---------------------------------------------------------------------------
# 8. TLS handshake failure
# ---------------------------------------------------------------------------

@patch("qscan_lib.tls_inspect.ssl.create_default_context")
@patch("qscan_lib.tls_inspect.socket.socket")
def test_tls_handshake_failure_is_recorded(
    mock_socket,
    mock_context_factory,
):
    raw_socket = mock_socket.return_value

    context = MagicMock()
    context.wrap_socket.side_effect = socket.error(
        "simulated TLS failure"
    )
    mock_context_factory.return_value = context

    result = inspect_tls(
        "127.0.0.1",
        443,
        timeout=0.1,
    )

    assert result.tls_supported is not True
    assert result.error is not None


# ---------------------------------------------------------------------------
# 9. TLS connection timeout
# ---------------------------------------------------------------------------

@patch("qscan_lib.tls_inspect.socket.socket")
def test_tls_connection_timeout_is_recorded(
    mock_socket,
):
    raw_socket = mock_socket.return_value
    raw_socket.connect.side_effect = socket.timeout()

    result = inspect_tls(
        "127.0.0.1",
        443,
        timeout=0.1,
    )

    assert result.tls_supported is not True
    assert result.error == "TLS connection timed out"


# ---------------------------------------------------------------------------
# 10. TLS connection refusal
# ---------------------------------------------------------------------------

@patch("qscan_lib.tls_inspect.socket.socket")
def test_tls_connection_refusal_is_recorded(
    mock_socket,
):
    raw_socket = mock_socket.return_value
    raw_socket.connect.side_effect = ConnectionRefusedError()

    result = inspect_tls(
        "127.0.0.1",
        443,
        timeout=0.1,
    )

    assert result.tls_supported is not True
    assert result.error == "TCP connection refused"


# ---------------------------------------------------------------------------
# 11. Neighbor command timeout
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.discovery.is_same_l2_segment",
    return_value=True,
)
@patch(
    "qscan_lib.discovery.subprocess.run",
    side_effect=subprocess.TimeoutExpired(
        cmd=["ip", "neigh"],
        timeout=2,
    ),
)
def test_neighbor_lookup_timeout_is_recorded(
    mock_run,
    mock_same_l2,
):
    mac, status, error = lookup_mac_address(
        "192.168.56.10"
    )

    assert mac is None
    assert status == "not_observed"
    assert error == "neighbor lookup timed out"

