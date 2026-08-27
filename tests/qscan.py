#!/usr/bin/env python3
"""
Q-SCOUT — Quantum Crypto Discovery Mini-Scanner

Entry point for the CLI. Parses arguments, validates the target scope,
and will orchestrate discovery, TLS inspection, classification, and
reporting as those modules are added in later stages.
"""

import argparse
import sys

from qscan_lib.targets import parse_target_argument, DEFAULT_MAX_TARGETS


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
        help="Per-connection timeout in seconds (default: 3.0).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=20,
        help="Maximum concurrent scan threads (default: 20).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Allow more than the default max target count "
            f"({DEFAULT_MAX_TARGETS}) when expanding a CIDR or list file."
        ),
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    max_targets = DEFAULT_MAX_TARGETS * 50 if args.force else DEFAULT_MAX_TARGETS
    parse_result = parse_target_argument(args.target, max_targets=max_targets)

    print(f"[qscan] target scope input: {args.target}")
    print(f"[qscan] valid targets:      {len(parse_result.targets)}")
    print(f"[qscan] skipped entries:    {len(parse_result.skipped)}")
    if parse_result.truncated:
        print(
            f"[qscan] WARNING: target list truncated at {max_targets} "
            "hosts. Use --force to raise this limit."
        )

    if parse_result.skipped:
        print("[qscan] skipped details:")
        for raw_value, reason in parse_result.skipped[:10]:
            print(f"    - {raw_value!r}: {reason}")
        if len(parse_result.skipped) > 10:
            print(f"    ... and {len(parse_result.skipped) - 10} more")

    if not parse_result.targets:
        print("[qscan] ERROR: no valid targets to scan. Exiting.", file=sys.stderr)
        return 1

    print(f"[qscan] output file:  {args.output}")
    print(f"[qscan] timeout:      {args.timeout}s")
    print(f"[qscan] max_workers:  {args.max_workers}")
    print("[qscan] (discovery/TLS/classification not yet implemented)")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[qscan] Interrupted by user. Exiting cleanly.", file=sys.stderr)
        sys.exit(130)
