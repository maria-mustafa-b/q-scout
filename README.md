# Q-SCOUT — Quantum Crypto Discovery Mini-Scanner

Q-SCOUT is a lightweight defensive command-line scanner for authorized environments. It discovers reachable assets, inspects selected TCP services, extracts TLS certificate and cryptographic metadata, and classifies observed algorithms from a post-quantum readiness perspective.

It does **not** exploit vulnerabilities, brute-force credentials, bypass security controls, evade detection, or modify target systems.

## Features

- IPv4, hostname, CIDR, and target-list file input
- Input validation and bounded CIDR expansion
- TCP connect scanning over a defined port list
- Reverse DNS lookup
- Best-effort banner grabbing
- Same-L2 MAC lookup using the local neighbor cache
- TLS version and negotiated cipher suite inspection
- X.509 subject, issuer, validity, SANs, signature algorithm, and SHA-256 fingerprint
- Public-key algorithm, key size, and EC curve extraction
- Per-algorithm quantum-readiness classification
- Deterministic JSON output
- Optional CSV summary
- Bounded concurrency and per-operation timeouts
- Clean Ctrl+C handling and meaningful exit codes

## Included Result Samples

The repository contains separate outputs for different validation purposes.

### `results.json`

Primary scanner output generated from the selected assessment/demo target.
This file is kept separate from controlled test fixtures.

### `results_scanme.json`

Supplemental network-discovery validation performed against
`scanme.nmap.org`. It demonstrates TCP service discovery, banner collection,
and reachability inference from an observed open port.

This result is not intended as the TLS demonstration because no
TLS-designated open port was observed during the test.

### `results_tls_demo.json`

Controlled TLS functional demonstration generated against a temporary local
TLS endpoint on `127.0.0.1:8443`.

The endpoint uses a temporary self-signed certificate and exists solely to
demonstrate Q-SCOUT's certificate inspection, cryptographic inventory, and
per-algorithm quantum-readiness classification.


=> The controlled nature of this demonstration is documented further in
`ASSUMPTIONS.md`.

## Project Structure

```text
q-scout/
├── qscan.py
├── qscan_lib/
│   ├── __init__.py
│   ├── targets.py
│   ├── discovery.py
│   ├── tls_inspect.py
│   ├── classify.py
│   └── report.py
├── tests/
│   ├── test_targets.py
│   ├── test_discovery.py
│   ├── test_tls_inspect.py
│   ├── test_classify.py
│   ├── test_report.py
│   └── test_robustness.py
├── results/
│   ├── results.json
│   ├── results_scanme.json
│   └── results_tls_demo.json
├── presentation/
├── requirements.txt
├── ASSUMPTIONS.md
├── AI_DISCLOSURE.md
└── README.md

