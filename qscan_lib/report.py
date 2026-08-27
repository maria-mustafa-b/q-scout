"""
qscan_lib.report

Deterministic report generation for Q-SCOUT.

Responsibilities:
  - Build a stable JSON schema
  - Serialize discovery, TLS, and classification results
  - Write JSON output
  - Optionally write a flat CSV summary
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


SCHEMA_VERSION = "1.0"


def build_scan_report(
    *,
    target_input: str,
    scan_results: List[Dict[str, Any]],
    skipped_targets: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """
    Build the top-level deterministic Q-SCOUT report structure.
    """

    skipped_targets = skipped_targets or []

    return {
        "schema_version": SCHEMA_VERSION,
        "scanner": {
            "name": "Q-SCOUT",
            "purpose": (
                "Authorized defensive discovery and cryptographic "
                "inventory for quantum-readiness assessment."
            ),
        },
        "input": {
            "target": target_input,
        },
        "summary": {
            "targets_reported": len(scan_results),
            "targets_skipped": len(skipped_targets),
        },
        "skipped_targets": skipped_targets,
        "results": scan_results,
    }


def write_json_report(
    report: Dict[str, Any],
    output_path: str,
) -> None:
    """
    Write deterministic, human-readable JSON.
    """

    path = Path(output_path)

    if path.parent != Path("."):
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    with path.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            report,
            f,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        f.write("\n")


def _classification_category(
    item: Dict[str, Any],
) -> Optional[str]:
    """
    Safely extract a classification category from a dictionary.
    """

    classification = item.get("classification")

    if not isinstance(classification, dict):
        return None

    return classification.get("category")


def _flatten_result_for_csv(
    result: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Convert one host result into one-or-more CSV rows.

    CSV is intentionally a summary/stretch format.
    JSON remains the canonical output.
    """

    rows: List[Dict[str, Any]] = []

    target = result.get("target")
    resolved_ip = result.get("resolved_ip")
    reverse_dns = result.get("reverse_dns")
    reachable = result.get("reachable")
    mac_address = result.get("mac_address")
    mac_status = result.get("mac_status")

    ports = result.get("ports") or []

    if not ports:
        rows.append(
            {
                "target": target,
                "resolved_ip": resolved_ip,
                "reverse_dns": reverse_dns,
                "reachable": reachable,
                "mac_address": mac_address,
                "mac_status": mac_status,
                "port": None,
                "service": None,
                "state": None,
                "tls_version": None,
                "cipher_suite": None,
                "public_key_algorithm": None,
                "public_key_category": None,
                "signature_algorithm": None,
                "signature_category": None,
            }
        )

        return rows

    for port in ports:
        tls = port.get("tls") or {}

        public_key = tls.get("public_key") or {}
        signature = tls.get("signature") or {}

        rows.append(
            {
                "target": target,
                "resolved_ip": resolved_ip,
                "reverse_dns": reverse_dns,
                "reachable": reachable,
                "mac_address": mac_address,
                "mac_status": mac_status,
                "port": port.get("port"),
                "service": port.get("service"),
                "state": port.get("state"),
                "tls_version": tls.get("tls_version"),
                "cipher_suite": tls.get("cipher_suite"),
                "public_key_algorithm": public_key.get("algorithm"),
                "public_key_category": _classification_category(
                    public_key
                ),
                "signature_algorithm": signature.get("algorithm"),
                "signature_category": _classification_category(
                    signature
                ),
            }
        )

    return rows


def write_csv_report(
    scan_results: Iterable[Dict[str, Any]],
    output_path: str,
) -> None:
    """
    Write a flat CSV summary.

    JSON remains the authoritative representation because TLS and
    classification data are naturally nested.
    """

    fieldnames = [
        "target",
        "resolved_ip",
        "reverse_dns",
        "reachable",
        "mac_address",
        "mac_status",
        "port",
        "service",
        "state",
        "tls_version",
        "cipher_suite",
        "public_key_algorithm",
        "public_key_category",
        "signature_algorithm",
        "signature_category",
    ]

    rows: List[Dict[str, Any]] = []

    for result in scan_results:
        rows.extend(
            _flatten_result_for_csv(result)
        )

    path = Path(output_path)

    if path.parent != Path("."):
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)
