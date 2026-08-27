#!/usr/bin/env python3
"""
Q-SCOUT — Quantum Crypto Discovery Mini-Scanner

Entry point for the CLI. Parses arguments and will orchestrate
target parsing, discovery, TLS inspection, classification, and
reporting as those modules are added in later stages.
"""

import argparse
import sys


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
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # Stage 1: skeleton only — just prove argument parsing works.
    print(f"[qscan] target scope: {args.target}")
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
