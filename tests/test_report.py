import csv
import json

from qscan_lib.report import (
    SCHEMA_VERSION,
    build_scan_report,
    write_csv_report,
    write_json_report,
)


def sample_result():
    return {
        "target": "example.com",
        "resolved_ip": "93.184.216.34",
        "reachable": True,
        "reverse_dns": None,
        "mac_address": None,
        "mac_status": "not_applicable",
        "ports": [
            {
                "port": 443,
                "protocol": "tcp",
                "state": "open",
                "service": "https",
                "banner": None,
                "error": None,
                "tls": {
                    "tls_supported": True,
                    "tls_version": "TLSv1.3",
                    "cipher_suite": "TLS_AES_256_GCM_SHA384",
                    "public_key": {
                        "algorithm": "RSA",
                        "key_size": 2048,
                        "curve": None,
                        "classification": {
                            "algorithm": "RSA",
                            "category": "quantum-vulnerable",
                            "reasoning": "RSA is vulnerable to Shor's algorithm.",
                        },
                    },
                    "signature": {
                        "algorithm": "sha256WithRSAEncryption",
                        "classification": {
                            "algorithm": "sha256WithRSAEncryption",
                            "category": "quantum-vulnerable",
                            "reasoning": "RSA signatures are quantum-vulnerable.",
                        },
                    },
                    "cipher_classifications": [
                        {
                            "algorithm": "AES-256",
                            "category": "symmetric-safe",
                            "reasoning": "AES-256 retains a strong margin.",
                        }
                    ],
                },
            }
        ],
    }


def test_build_scan_report_schema():
    result = sample_result()

    report = build_scan_report(
        target_input="example.com",
        scan_results=[result],
        skipped_targets=[],
    )

    assert report["schema_version"] == SCHEMA_VERSION
    assert report["scanner"]["name"] == "Q-SCOUT"
    assert report["input"]["target"] == "example.com"
    assert report["summary"]["targets_reported"] == 1
    assert report["summary"]["targets_skipped"] == 0
    assert len(report["results"]) == 1


def test_skipped_target_count():
    report = build_scan_report(
        target_input="targets.txt",
        scan_results=[],
        skipped_targets=[
            {
                "value": "bad!!!",
                "reason": "invalid target",
            }
        ],
    )

    assert report["summary"]["targets_reported"] == 0
    assert report["summary"]["targets_skipped"] == 1


def test_json_report_written(tmp_path):
    output = tmp_path / "results.json"

    report = build_scan_report(
        target_input="example.com",
        scan_results=[sample_result()],
    )

    write_json_report(
        report,
        str(output),
    )

    assert output.exists()

    data = json.loads(
        output.read_text(
            encoding="utf-8"
        )
    )

    assert data["schema_version"] == SCHEMA_VERSION
    assert data["results"][0]["target"] == "example.com"


def test_json_output_is_deterministic(tmp_path):
    output1 = tmp_path / "one.json"
    output2 = tmp_path / "two.json"

    report = build_scan_report(
        target_input="example.com",
        scan_results=[sample_result()],
    )

    write_json_report(report, str(output1))
    write_json_report(report, str(output2))

    assert (
        output1.read_text(encoding="utf-8")
        ==
        output2.read_text(encoding="utf-8")
    )


def test_csv_report_written(tmp_path):
    output = tmp_path / "results.csv"

    write_csv_report(
        [sample_result()],
        str(output),
    )

    assert output.exists()

    with output.open(
        newline="",
        encoding="utf-8",
    ) as f:
        rows = list(
            csv.DictReader(f)
        )

    assert len(rows) == 1
    assert rows[0]["target"] == "example.com"
    assert rows[0]["port"] == "443"
    assert rows[0]["public_key_algorithm"] == "RSA"
    assert rows[0]["public_key_category"] == "quantum-vulnerable"
