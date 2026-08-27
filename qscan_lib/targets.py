"""
qscan_lib.targets

Parses and validates the --target argument, which may be:
  - a single IPv4 address           e.g. 192.168.56.10
  - a hostname                      e.g. example.local
  - a CIDR range                    e.g. 192.168.56.0/24
  - a path to a target-list file    one target per line, '#' comments allowed

Produces a bounded, validated list of Target objects. No network calls
happen in this module — resolution and reachability are handled later
in discovery.py. Keeping parsing/validation separate from resolution
makes errors easier to attribute: a bad entry here is a syntax problem,
not a network problem.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


# Hard safety bound: prevents an accidental large CIDR (e.g. /16) from
# blowing up the amount of work the scanner attempts. Overridable via
# --force at the CLI level, not from inside this module.
DEFAULT_MAX_TARGETS = 1024

# Fairly permissive but sane hostname pattern (labels separated by dots,
# letters/digits/hyphens, no leading/trailing hyphen per label).
_HOSTNAME_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class TargetKind(str, Enum):
    IP = "ip"
    HOSTNAME = "hostname"
    CIDR_MEMBER = "cidr_member"


@dataclass
class Target:
    """A single validated scan target."""
    value: str            # the IP or hostname string to scan
    kind: TargetKind
    source: str            # where it came from: "cli", "file:<path>", or a CIDR string


@dataclass
class ParseResult:
    """Result of parsing --target: valid targets plus any skipped input."""
    targets: List[Target] = field(default_factory=list)
    skipped: List[Tuple[str, str]] = field(default_factory=list)  # (raw_value, reason)
    truncated: bool = False  # True if a CIDR/file exceeded max_targets and was cut off


def is_valid_ipv4(value: str) -> bool:
    """Return True if value is a syntactically valid IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    """
    Return True if value looks like a syntactically valid hostname.
    This is a syntax check only — it does not attempt DNS resolution.
    """
    if not value or len(value) > 253:
        return False
    # Strip a single trailing dot (valid in FQDNs)
    hostname = value[:-1] if value.endswith(".") else value
    labels = hostname.split(".")
    if len(labels) < 1:
        return False
    return all(_HOSTNAME_LABEL_RE.match(label) for label in labels)


def is_valid_cidr(value: str) -> bool:
    """Return True if value is a syntactically valid IPv4 CIDR range."""
    try:
        ipaddress.IPv4Network(value, strict=False)
        return True
    except ValueError:
        return False


def _expand_cidr(cidr: str, max_targets: int) -> Tuple[List[Target], bool]:
    """
    Expand a CIDR into individual host Targets, excluding network/broadcast
    addresses for networks larger than /31. Bounded by max_targets.
    Returns (targets, was_truncated).
    """
    network = ipaddress.IPv4Network(cidr, strict=False)
    hosts = list(network.hosts()) if network.prefixlen < 31 else list(network)

    truncated = len(hosts) > max_targets
    hosts = hosts[:max_targets]

    targets = [
        Target(value=str(ip), kind=TargetKind.CIDR_MEMBER, source=cidr)
        for ip in hosts
    ]
    return targets, truncated


def _classify_single_value(value: str):
    """Classify a single (non-CIDR, non-file) target string. Returns None if invalid."""
    if is_valid_ipv4(value):
        return TargetKind.IP
    if is_valid_hostname(value):
        return TargetKind.HOSTNAME
    return None


def _parse_list_file(path: str, max_targets: int) -> ParseResult:
    """Parse a target-list file: one target per line, '#' starts a comment."""
    result = ParseResult()

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        result.skipped.append((path, f"could not read file: {exc}"))
        return result

    for raw_line in lines:
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if len(result.targets) >= max_targets:
            result.truncated = True
            result.skipped.append((line, "max target limit reached, skipped"))
            continue

        if is_valid_cidr(line) and "/" in line:
            cidr_targets, cidr_truncated = _expand_cidr(
                line, max_targets - len(result.targets)
            )
            result.targets.extend(cidr_targets)
            result.truncated = result.truncated or cidr_truncated
            continue

        kind = _classify_single_value(line)
        if kind is None:
            result.skipped.append((line, "not a valid IPv4 address, hostname, or CIDR"))
            continue

        result.targets.append(Target(value=line, kind=kind, source=f"file:{path}"))

    return result


def parse_target_argument(raw_target: str, max_targets: int = DEFAULT_MAX_TARGETS) -> ParseResult:
    """
    Main entry point: given the raw --target string, return a ParseResult
    containing validated Targets plus any skipped/invalid entries.

    Handles, in order:
      1. Path to an existing file -> treated as a target list
      2. CIDR notation (contains '/') -> expanded to individual hosts
      3. Single IPv4 address
      4. Single hostname
      Anything else is recorded as skipped with a reason.
    """
    result = ParseResult()
    value = raw_target.strip()

    if not value:
        result.skipped.append((raw_target, "empty target value"))
        return result

    if os.path.isfile(value):
        return _parse_list_file(value, max_targets)

    if "/" in value:
        if not is_valid_cidr(value):
            result.skipped.append((value, "invalid CIDR notation"))
            return result
        targets, truncated = _expand_cidr(value, max_targets)
        result.targets = targets
        result.truncated = truncated
        return result

    kind = _classify_single_value(value)
    if kind is None:
        result.skipped.append(
            (value, "not a valid IPv4 address, hostname, CIDR, or existing file path")
        )
        return result

    result.targets.append(Target(value=value, kind=kind, source="cli"))
    return result
