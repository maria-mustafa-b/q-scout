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
├── presentation/
├── requirements.txt
├── ASSUMPTIONS.md
├── AI_DISCLOSURE.md
├── README.md
└── results.json
