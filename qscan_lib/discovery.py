"""
qscan_lib.discovery

Network and asset discovery for Q-SCOUT.

Responsibilities:
  - TCP connect scanning over a fixed, bounded port list
  - Best-effort service identification
  - Safe, bounded banner grabbing
  - Reverse DNS lookup
  - Same-L2 MAC address lookup using the local neighbor/ARP cache
  - Per-operation timeouts
  - Bounded concurrency

This module performs defensive discovery only. It does not perform:
  - exploitation
  - brute force
  - authentication attempts
  - stealth/evasion
  - persistence
  - vulnerability exploitation
"""

from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Bounded scan configuration
# ---------------------------------------------------------------------------

# Small, defined list of commonly encountered TCP services.
# This is intentionally NOT a 1-65535 port scan.
DEFAULT_PORTS: Tuple[int, ...] = (
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    587,   # SMTP submission
    993,   # IMAPS
    995,   # POP3S
    1433,  # Microsoft SQL Server
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP alternate
    8443,  # HTTPS alternate
)

MAX_PORTS = 100
DEFAULT_BANNER_TIMEOUT = 1.5
MAX_BANNER_LENGTH = 512


# ---------------------------------------------------------------------------
# Service identification
# ---------------------------------------------------------------------------

SERVICE_NAMES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
}


# ---------------------------------------------------------------------------
# Result data structures
# ---------------------------------------------------------------------------

@dataclass
class PortResult:
    """Result of checking one TCP port."""

    port: int
    protocol: str = "tcp"
    state: str = "closed_or_filtered"
    service: Optional[str] = None
    banner: Optional[str] = None
    error: Optional[str] = None


@dataclass
class DiscoveryResult:
    """Complete discovery result for one target."""

    target: str
    resolved_ip: Optional[str] = None

    reachable: Optional[bool] = None
    reachability_error: Optional[str] = None

    reverse_dns: Optional[str] = None
    reverse_dns_error: Optional[str] = None

    mac_address: Optional[str] = None
    mac_status: str = "not_applicable"
    mac_error: Optional[str] = None

    ports: List[PortResult] = None

    scanner_error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.ports is None:
            self.ports = []


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_decode_banner(data: bytes) -> str:
    """
    Decode banner bytes defensively.

    Invalid UTF-8 bytes are replaced rather than causing the scanner
    to crash. Whitespace/control characters are normalized and the
    result is bounded in length.
    """
    text = data.decode("utf-8", errors="replace")

    # Remove common terminal/control characters while preserving
    # useful printable banner information.
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

    text = " ".join(text.split())

    return text[:MAX_BANNER_LENGTH] if text else ""


def _service_name(port: int) -> Optional[str]:
    """Return our best-guess service name for a known TCP port."""
    return SERVICE_NAMES.get(port)


# ---------------------------------------------------------------------------
# Target resolution
# ---------------------------------------------------------------------------

def resolve_target(target: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve an IPv4 address or hostname to an IPv4 address.

    Returns:
        (resolved_ip, error)

    An already-valid IPv4 address is returned directly.
    Hostname resolution uses socket.getaddrinfo with AF_INET so that
    the scanner remains IPv4-focused.
    """
    try:
        ipaddress.IPv4Address(target)
        return target, None
    except ValueError:
        pass

    try:
        # Python's getaddrinfo does not expose a timeout parameter,
        # so set a temporary process-level socket default timeout.
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        try:
            results = socket.getaddrinfo(
                target,
                None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
        finally:
            socket.setdefaulttimeout(old_timeout)

        if not results:
            return None, "DNS resolution returned no IPv4 addresses"

        return results[0][4][0], None

    except socket.timeout:
        return None, "DNS resolution timed out"

    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc}"

    except OSError as exc:
        return None, f"DNS resolution error: {exc}"


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

def check_reachability(
    ip: str,
    timeout: float,
    probe_port: int = 443,
) -> Tuple[Optional[bool], Optional[str]]:
    """
    Perform a simple TCP reachability check.

    A successful TCP connection means the host is reachable on the
    selected probe port.

    Connection refusal is interpreted as evidence that the host is
    reachable but that particular port is closed.

    Timeout is reported as indeterminate rather than automatically
    declaring the host unreachable.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((ip, probe_port))

        if result == 0:
            return True, None

        # ECONNREFUSED means the destination actively rejected the
        # connection, which is useful evidence that the host is reachable.
        if result == 111:  # Linux ECONNREFUSED
            return True, None

        return None, f"TCP reachability probe returned error code {result}"

    except socket.timeout:
        return None, "TCP reachability probe timed out"

    except OSError as exc:
        return None, f"TCP reachability probe failed: {exc}"

    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Port scanning and banner grabbing
# ---------------------------------------------------------------------------

def grab_banner(
    ip: str,
    port: int,
    timeout: float = DEFAULT_BANNER_TIMEOUT,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Attempt a safe, bounded banner read from an already-open TCP port.

    The scanner sends no application-level commands. It only connects
    and attempts to read whatever the service voluntarily presents.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((ip, port))

        data = sock.recv(MAX_BANNER_LENGTH)

        if not data:
            return None, None

        banner = _safe_decode_banner(data)

        return banner or None, None

    except socket.timeout:
        return None, "banner read timed out"

    except OSError as exc:
        return None, f"banner grab failed: {exc}"

    finally:
        sock.close()


def scan_port(
    ip: str,
    port: int,
    timeout: float,
) -> PortResult:
    """
    Perform a TCP connect scan against one port.

    This uses normal TCP connections rather than raw SYN packets,
    so root privileges are not required.
    """
    result = PortResult(
        port=port,
        protocol="tcp",
        service=_service_name(port),
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        connect_result = sock.connect_ex((ip, port))

        if connect_result == 0:
            result.state = "open"
        else:
            result.state = "closed_or_filtered"

            # Do not expose platform-specific numeric socket errors
            # as scanner failures for normal closed/filtered ports.
            return result

    except socket.timeout:
        result.state = "closed_or_filtered"
        return result

    except OSError as exc:
        result.state = "scanner_error"
        result.error = str(exc)
        return result

    finally:
        sock.close()

    # Only attempt a banner when the port was confirmed open.
    banner, banner_error = grab_banner(
        ip,
        port,
        timeout=min(timeout, DEFAULT_BANNER_TIMEOUT),
    )

    result.banner = banner

    # A banner failure does not turn an otherwise-open port into a
    # scanner failure. The port itself was successfully observed.
    if banner_error:
        result.error = banner_error

    return result


def scan_ports(
    ip: str,
    ports: Tuple[int, ...] = DEFAULT_PORTS,
    timeout: float = 3.0,
    max_workers: int = 20,
) -> List[PortResult]:
    """
    Scan a bounded list of TCP ports concurrently.

    The port list is capped at MAX_PORTS and worker count is bounded
    by the number of ports actually being scanned.
    """
    ports = tuple(ports[:MAX_PORTS])

    if not ports:
        return []

    worker_count = max(1, min(max_workers, len(ports)))

    results: List[PortResult] = []

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {
            executor.submit(scan_port, ip, port, timeout): port
            for port in ports
        }

        for future in as_completed(future_map):
            port = future_map[future]

            try:
                result = future.result()
            except Exception as exc:
                # One port must never crash the entire target scan.
                result = PortResult(
                    port=port,
                    protocol="tcp",
                    state="scanner_error",
                    service=_service_name(port),
                    error=f"unexpected scanner error: {exc}",
                )

            results.append(result)

    # Deterministic ordering is important for JSON output and tests.
    results.sort(key=lambda item: item.port)

    return results


# ---------------------------------------------------------------------------
# Reverse DNS
# ---------------------------------------------------------------------------

def reverse_dns_lookup(
    ip: str,
    timeout: float,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Perform reverse DNS lookup.

    Returns:
        (hostname, error)

    A missing PTR record is treated as "not observed" rather than
    a scanner failure.
    """
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname, None

    except socket.herror:
        return None, None

    except socket.gaierror:
        return None, None

    except socket.timeout:
        return None, "reverse DNS lookup timed out"

    except OSError as exc:
        return None, f"reverse DNS lookup failed: {exc}"

    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------------
# MAC address / same-L2 detection
# ---------------------------------------------------------------------------

def _get_local_ipv4_networks() -> List[ipaddress.IPv4Network]:
    """
    Obtain IPv4 networks assigned to local interfaces.

    Uses `ip -4 addr` because Python's standard library does not provide
    a portable API for enumerating interface addresses and netmasks.
    """
    try:
        completed = subprocess.run(
            ["ip", "-4", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )

    except (OSError, subprocess.TimeoutExpired):
        return []

    networks: List[ipaddress.IPv4Network] = []

    # Example:
    # inet 192.168.56.10/24 brd 192.168.56.255 scope global ...
    pattern = re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\b")

    for match in pattern.finditer(completed.stdout):
        try:
            address = ipaddress.IPv4Address(match.group(1))
            prefix = int(match.group(2))
            networks.append(
                ipaddress.IPv4Network(
                    f"{address}/{prefix}",
                    strict=False,
                )
            )
        except ValueError:
            continue

    return networks


def is_same_l2_segment(ip: str) -> bool:
    """
    Determine whether an IPv4 target appears to be on one of the
    scanner's directly connected IPv4 networks.

    This is deliberately conservative. If the local interface
    information cannot be obtained, return False.
    """
    try:
        target_ip = ipaddress.IPv4Address(ip)
    except ValueError:
        return False

    networks = _get_local_ipv4_networks()

    return any(target_ip in network for network in networks)


def lookup_mac_address(
    ip: str,
) -> Tuple[Optional[str], str, Optional[str]]:
    """
    Look up a MAC address from the local Linux neighbor/ARP cache.

    Returns:
        (mac_address, status, error)

    Status values:
      - "observed"
      - "not_observed"
      - "not_applicable"

    A routed target gets "not_applicable", because the scanner cannot
    legitimately observe the remote host's Layer-2 MAC address.
    """
    if not is_same_l2_segment(ip):
        return None, "not_applicable", None

    try:
        completed = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )

    except subprocess.TimeoutExpired:
        return None, "not_observed", "neighbor lookup timed out"

    except OSError as exc:
        return None, "not_observed", f"neighbor lookup failed: {exc}"

    output = completed.stdout.strip()

    if not output:
        return None, "not_observed", None

    # Typical output:
    # 192.168.56.10 dev enp0s8 lladdr 08:00:27:12:34:56 REACHABLE
    match = re.search(
        r"\blladdr\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b",
        output,
    )

    if not match:
        return None, "not_observed", None

    return match.group(1).lower(), "observed", None


# ---------------------------------------------------------------------------
# Complete target discovery
# ---------------------------------------------------------------------------

def discover_target(
    target: str,
    timeout: float = 3.0,
    max_workers: int = 20,
    ports: Tuple[int, ...] = DEFAULT_PORTS,
) -> DiscoveryResult:
    """
    Run the complete discovery workflow for one validated target.

    Workflow:
      1. Resolve hostname -> IPv4 if necessary.
      2. Attempt TCP reachability probe.
      3. Perform reverse DNS.
      4. Perform same-L2 MAC lookup.
      5. Scan the bounded TCP port list.

    Individual failures are recorded in their corresponding fields
    rather than crashing the complete scan.
    """
    result = DiscoveryResult(target=target)

    # ---------------------------------------------------------------
    # Resolve
    # ---------------------------------------------------------------

    ip, resolution_error = resolve_target(target, timeout)

    if resolution_error:
        result.scanner_error = resolution_error
        return result

    result.resolved_ip = ip

    if ip is None:
        result.scanner_error = "target did not resolve to an IPv4 address"
        return result

    # ---------------------------------------------------------------
    # Reachability
    # ---------------------------------------------------------------

    reachable, reachability_error = check_reachability(
        ip,
        timeout,
    )

    result.reachable = reachable
    result.reachability_error = reachability_error

    # ---------------------------------------------------------------
    # Reverse DNS
    # ---------------------------------------------------------------

    reverse_name, reverse_error = reverse_dns_lookup(
        ip,
        timeout,
    )

    result.reverse_dns = reverse_name
    result.reverse_dns_error = reverse_error

    # ---------------------------------------------------------------
    # MAC address
    # ---------------------------------------------------------------

    mac, mac_status, mac_error = lookup_mac_address(ip)

    result.mac_address = mac
    result.mac_status = mac_status
    result.mac_error = mac_error

    # ---------------------------------------------------------------
    # Port scan
    # ---------------------------------------------------------------

    try:
        result.ports = scan_ports(
            ip,
            ports=ports,
            timeout=timeout,
            max_workers=max_workers,
        )

    except Exception as exc:
        result.scanner_error = f"port scanning failed: {exc}"

    return result


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def discovery_result_to_dict(result: DiscoveryResult) -> dict:
    """
    Convert a DiscoveryResult into a JSON-serializable dictionary.

    This helper intentionally does not write files. File generation
    belongs in report.py.
    """
    return asdict(result)
