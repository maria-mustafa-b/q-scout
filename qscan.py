#!/usr/bin/env python3
"""
Q-SCOUT — Quantum Crypto Discovery Mini-Scanner

CLI pipeline:
    target parsing
        -> network discovery
        -> TLS inspection
        -> cryptographic classification
        -> deterministic JSON/CSV reporting
"""

from __future__ import annotations

import argparse
import sys

from qscan_lib.classify import (
    classify_cipher_suite,
    classify_public_key,
    classify_signature_algorithm,
)
from qscan_lib.discovery import DEFAULT_PORTS, discover_target
from qscan_lib.report import (
    build_scan_report,
    write_csv_report,
    write_json_report,
)
from qscan_lib.targets import DEFAULT_MAX_TARGETS, parse_target_argument
from qscan_lib.tls_inspect import DEFAULT_TLS_PORTS, inspect_tls


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
    """Print a concise human-readable discovery summary."""
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
        port for port in result.ports
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


def build_tls_report(tls_result) -> dict:
    """
    Build TLS/classification data for one inspected service.
    """

    tls_data = {
        "tls_supported": tls_result.tls_supported,
        "tls_version": tls_result.tls_version,
        "cipher_suite": tls_result.cipher_suite,
        "certificate_present": tls_result.certificate_present,
        "subject": tls_result.subject,
        "issuer": tls_result.issuer,
        "valid_from": tls_result.valid_from,
        "valid_until": tls_result.valid_until,
        "sans": tls_result.sans,
        "sha256_fingerprint": tls_result.sha256_fingerprint,
        "self_signed": tls_result.self_signed,
        "error": tls_result.error,
        "public_key": None,
        "signature": None,
        "cipher_classifications": [],
    }

    if not tls_result.tls_supported:
        return tls_data

    public_key_classification = classify_public_key(
        tls_result.public_key_algorithm,
        key_size=tls_result.public_key_size,
        curve=tls_result.public_key_curve,
    )

    signature_classification = classify_signature_algorithm(
        tls_result.signature_algorithm
    )

    cipher_classifications = classify_cipher_suite(
        tls_result.cipher_suite
    )

    tls_data["public_key"] = {
        "algorithm": tls_result.public_key_algorithm,
        "key_size": tls_result.public_key_size,
        "curve": tls_result.public_key_curve,
        "classification": {
            "algorithm": public_key_classification.algorithm,
            "category": public_key_classification.category,
            "reasoning": public_key_classification.reasoning,
        },
    }

    tls_data["signature"] = {
        "algorithm": tls_result.signature_algorithm,
        "classification": {
            "algorithm": signature_classification.algorithm,
            "category": signature_classification.category,
            "reasoning": signature_classification.reasoning,
        },
    }

    tls_data["cipher_classifications"] = [
        {
            "algorithm": item.algorithm,
            "category": item.category,
            "reasoning": item.reasoning,
        }
        for item in cipher_classifications
    ]

    return tls_data


def print_tls_summary(tls_result) -> None:
    """Print TLS metadata and per-algorithm classifications."""

    if not tls_result.tls_supported:
        print(
            f"    TLS inspection failed: "
            f"{tls_result.error or 'unknown error'}"
        )
        return

    print(f"    TLS supported: {tls_result.tls_supported}")
    print(f"    TLS version:   {tls_result.tls_version or 'unknown'}")
    print(f"    Cipher:        {tls_result.cipher_suite or 'unknown'}")
    print(f"    Certificate:   {tls_result.certificate_present}")

    if tls_result.subject:
        print(f"    Subject:       {tls_result.subject}")

    if tls_result.issuer:
        print(f"    Issuer:        {tls_result.issuer}")

    if tls_result.public_key_algorithm:
        print(f"    Public key:    {tls_result.public_key_algorithm}")

    if tls_result.public_key_size:
        print(f"    Key size:      {tls_result.public_key_size}")

    if tls_result.public_key_curve:
        print(f"    Curve:         {tls_result.public_key_curve}")

    if tls_result.signature_algorithm:
        print(f"    Signature:     {tls_result.signature_algorithm}")

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

    for classification in classify_cipher_suite(
        tls_result.cipher_suite
    ):
        print(
            f"      {classification.algorithm}: "
            f"{classification.category}"
        )
        print(
            f"        Reason: {classification.reasoning}"
        )

    signature_classification = classify_signature_algorithm(
        tls_result.signature_algorithm
    )

    print(
        f"      Signature: "
        f"{signature_classification.category}"
    )
    print(
        f"        Reason: "
        f"{signature_classification.reasoning}"
    )


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    if args.max_workers <= 0:
        parser.error("--max-workers must be greater than 0")

    max_targets = (
        DEFAULT_MAX_TARGETS * 50
        if args.force
        else DEFAULT_MAX_TARGETS
    )

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

    print()
    print("[qscan] Starting network discovery...")
    print(f"[qscan] Ports:        {len(DEFAULT_PORTS)} defined")
    print(f"[qscan] Timeout:      {args.timeout}s")
    print(f"[qscan] Max workers:  {args.max_workers}")

    scan_results = []

    # ---------------------------------------------------------------
    # One complete discovery/report cycle per validated target.
    # ---------------------------------------------------------------

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

        target_report = {
            "target": result.target,
            "resolved_ip": result.resolved_ip,
            "reachable": result.reachable,
            "reachability_error": result.reachability_error,
            "reverse_dns": result.reverse_dns,
            "reverse_dns_error": result.reverse_dns_error,
            "mac_address": result.mac_address,
            "mac_status": result.mac_status,
            "mac_error": result.mac_error,
            "scanner_error": result.scanner_error,
            "ports": [],
        }

        tls_found = False

        for port_result in result.ports:
            port_entry = {
                "port": port_result.port,
                "protocol": port_result.protocol,
                "state": port_result.state,
                "service": port_result.service,
                "banner": port_result.banner,
                "error": port_result.error,
                "tls": None,
            }

            if (
                port_result.state == "open"
                and port_result.port in DEFAULT_TLS_PORTS
            ):
                if not tls_found:
                    print()
                    print("[qscan] TLS inspection:")
                    tls_found = True

                print(
                    f"  - Inspecting TLS on "
                    f"{result.resolved_ip or target.value}:"
                    f"{port_result.port}..."
                )

                tls_result = inspect_tls(
                    result.resolved_ip or target.value,
                    port_result.port,
                    timeout=args.timeout,
                )

                print_tls_summary(tls_result)

                port_entry["tls"] = build_tls_report(
                    tls_result
                )

            target_report["ports"].append(
                port_entry
            )

        if not tls_found:
            print()
            print(
                "[qscan] No open TLS-designated ports observed."
            )

        scan_results.append(
            target_report
        )

    print()
    print("[qscan] Discovery complete.")

    skipped_targets = [
        {
            "value": value,
            "reason": reason,
        }
        for value, reason in parse_result.skipped
    ]

    report = build_scan_report(
        target_input=args.target,
        scan_results=scan_results,
        skipped_targets=skipped_targets,
    )

    try:
        write_json_report(
            report,
            args.output,
        )
    except OSError as exc:
        print(
            f"[qscan] ERROR: could not write JSON report: {exc}",
            file=sys.stderr,
        )
        return 2

    print(
        f"[qscan] JSON report written to {args.output}"
    )

    if args.csv:
        try:
            write_csv_report(
                scan_results,
                args.csv,
            )
        except OSError as exc:
            print(
                f"[qscan] ERROR: could not write CSV report: {exc}",
                file=sys.stderr,
            )
            return 2

        print(
            f"[qscan] CSV report written to {args.csv}"
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
