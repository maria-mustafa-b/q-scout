#!/usr/bin/env python3
"""
Q-SCOUT — Quantum Crypto Discovery Mini-Scanner

CLI entry point.

Current pipeline:
    target input
        -> target parsing/validation
        -> network discovery

Later stages will add:
    -> TLS inspection
    -> cryptographic classification
    -> reporting
"""

from __future__ import annotations

import argparse
import sys

from qscan_lib.discovery import DEFAULT_PORTS, discover_target
from qscan_lib.targets import DEFAULT_MAX_TARGETS, parse_target_argument
from qscan_lib.tls_inspect import DEFAULT_TLS_PORTS, inspect_tls
from qscan_lib.classify import (
    classify_cipher_suite,
    classify_public_key,
    classify_signature_algorithm,
)

def build_arg_parser() -> argparse.ArgumentParser:
    """Construct and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="qscan.py",
        description=(
            "Q-SCOUT: discovers hosts in an authorized scope, inspects "
            "TLS metadata, and produces a quantum-readiness crypto inventory."
        ),
    )

    parser.add_argument(
        "--target",
        required=True,
        help=(
            "Scan target: single IPv4 address, hostname, CIDR range "
            "(e.g. 192.168.56.0/24), or path to a target list file."
        ),
    )

    parser.add_argument(
        "--output",
        default="results.json",
        help="Path to write JSON results (default: results.json).",
    )

    parser.add_argument(
        "--csv",
        default=None,
        help="Optional path to also write CSV results.",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Per-network-operation timeout in seconds (default: 3.0).",
    )

    parser.add_argument(
        "--max-workers",
        type=int,
        default=20,
        help="Maximum concurrent port-scan workers (default: 20).",
    )

    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Allow a larger target count than the default limit of "
            f"{DEFAULT_MAX_TARGETS}."
        ),
    )

    return parser


def print_discovery_summary(result) -> None:
    """Print a concise human-readable discovery result."""

    print()
    print("=" * 60)
    print(f"Target:        {result.target}")
    print(f"Resolved IP:   {result.resolved_ip or 'null'}")
    print(f"Reachable:     {result.reachable}")

    if result.reachability_error:
        print(f"Reachability:  {result.reachability_error}")

    print(f"Reverse DNS:   {result.reverse_dns or 'null'}")

    if result.reverse_dns_error:
        print(f"rDNS error:    {result.reverse_dns_error}")

    print(f"MAC address:   {result.mac_address or 'null'}")
    print(f"MAC status:    {result.mac_status}")

    if result.mac_error:
        print(f"MAC error:     {result.mac_error}")

    open_ports = [
        port
        for port in result.ports
        if port.state == "open"
    ]

    print(f"Open ports:    {len(open_ports)}")

    if open_ports:
        for port in open_ports:
            print(
                f"  - {port.port}/tcp"
                f"  service={port.service or 'unknown'}"
                f"  banner={port.banner or 'null'}"
            )
    else:
        print("  - none observed")

    if result.scanner_error:
        print(f"Scanner error: {result.scanner_error}")

    print("=" * 60)


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # ---------------------------------------------------------------
    # Validate CLI arguments that affect bounded work.
    # ---------------------------------------------------------------

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if args.max_workers <= 0:
        parser.error("--max-workers must be greater than 0")

    max_targets = (
        DEFAULT_MAX_TARGETS * 50
        if args.force
        else DEFAULT_MAX_TARGETS
    )

    # ---------------------------------------------------------------
    # Stage 1: target parsing and validation
    # ---------------------------------------------------------------

    parse_result = parse_target_argument(
        args.target,
        max_targets=max_targets,
    )

    print(f"[qscan] target scope input: {args.target}")
    print(f"[qscan] valid targets:      {len(parse_result.targets)}")
    print(f"[qscan] skipped entries:    {len(parse_result.skipped)}")

    if parse_result.truncated:
        print(
            f"[qscan] WARNING: target list truncated at "
            f"{max_targets} hosts."
        )

    if parse_result.skipped:
        print("[qscan] skipped details:")

        for raw_value, reason in parse_result.skipped[:10]:
            print(f"    - {raw_value!r}: {reason}")

        if len(parse_result.skipped) > 10:
            print(
                f"    ... and {len(parse_result.skipped) - 10} more"
            )

    if not parse_result.targets:
        print(
            "[qscan] ERROR: no valid targets to scan. Exiting.",
            file=sys.stderr,
        )
        return 1

    # ---------------------------------------------------------------
    # Stage 3: network discovery
    # ---------------------------------------------------------------

    print()
    print("[qscan] Starting network discovery...")
    print(f"[qscan] Ports:        {len(DEFAULT_PORTS)} defined")
    print(f"[qscan] Timeout:      {args.timeout}s")
    print(f"[qscan] Max workers:  {args.max_workers}")

    for index, target in enumerate(parse_result.targets, start=1):
        print()
        print(
            f"[qscan] [{index}/{len(parse_result.targets)}] "
            f"Discovering {target.value}..."
        )

        result = discover_target(
            target.value,
            timeout=args.timeout,
            max_workers=args.max_workers,
            ports=DEFAULT_PORTS,
        )

        print_discovery_summary(result)
        # -----------------------------------------------------------
        # Stage 4: TLS inspection
        # -----------------------------------------------------------

        open_tls_ports = [
            port
            for port in result.ports
            if port.state == "open"
            and port.port in DEFAULT_TLS_PORTS
        ]

        if open_tls_ports:
            print()
            print("[qscan] TLS inspection:")

            for port_result in open_tls_ports:
                print(
                    f"  - Inspecting TLS on "
                    f"{result.resolved_ip or target.value}:{port_result.port}..."
                )

                tls_result = inspect_tls(
                    result.resolved_ip or target.value,
                    port_result.port,
                    timeout=args.timeout,
                )

                if tls_result.tls_supported:
                    print("    Crypto classification:")

                    public_key_classification = classify_public_key(
                        tls_result.public_key_algorithm,
                        key_size=tls_result.public_key_size,
                        curve=tls_result.public_key_curve,
                    )

                    print(
                        f"      Public key: "
                        f"{public_key_classification.category}"
                    )
                    print(
                        f"        Reason: "
                        f"{public_key_classification.reasoning}"
                    )

                    cipher_classifications = classify_cipher_suite(
                        tls_result.cipher_suite
                    )

                    for classification in cipher_classifications:
                        print(
                            f"      {classification.algorithm}: "
                            f"{classification.category}"
                        )
                        print(
                            f"        Reason: "
                            f"{classification.reasoning}"
                        )

                    signature_classification = (
                        classify_signature_algorithm(
                            tls_result.signature_algorithm
                        )
                    )

                    print(
                        f"      Signature: "
                        f"{signature_classification.category}"
                    )
                    print(
                        f"        Reason: "
                        f"{signature_classification.reasoning}"
                    )
                    print(
                        f"    TLS supported: {tls_result.tls_supported}"
                    )
                    print(
                        f"    TLS version:   "
                        f"{tls_result.tls_version or 'unknown'}"
                    )
                    print(
                        f"    Cipher:        "
                        f"{tls_result.cipher_suite or 'unknown'}"
                    )
                    print(
                        f"    Certificate:   "
                        f"{tls_result.certificate_present}"
                    )

                    if tls_result.subject:
                        print(
                            f"    Subject:       {tls_result.subject}"
                        )

                    if tls_result.issuer:
                        print(
                            f"    Issuer:        {tls_result.issuer}"
                        )

                    if tls_result.public_key_algorithm:
                        print(
                            f"    Public key:    "
                            f"{tls_result.public_key_algorithm}"
                        )

                    if tls_result.public_key_size:
                        print(
                            f"    Key size:      "
                            f"{tls_result.public_key_size}"
                        )

                    if tls_result.public_key_curve:
                        print(
                            f"    Curve:         "
                            f"{tls_result.public_key_curve}"
                        )

                    if tls_result.signature_algorithm:
                        print(
                            f"    Signature:     "
                            f"{tls_result.signature_algorithm}"
                        )

                else:
                    print(
                        f"    TLS inspection failed: "
                        f"{tls_result.error or 'unknown error'}"
                    )
        else:
            print()
            print("[qscan] No open TLS-designated ports observed.")
    print()
    print("[qscan] Discovery complete.")

    # Reporting is intentionally not implemented yet.
    print(
        "[qscan] JSON/CSV reporting will be added in a later stage."
    )

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())

    except KeyboardInterrupt:
        print(
            "\n[qscan] Interrupted by user. Exiting cleanly.",
            file=sys.stderr,
        )
        sys.exit(130)
