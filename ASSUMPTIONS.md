# Q-SCOUT Assumptions and Limitations

## Scope Assumptions

Q-SCOUT assumes the operator has explicit authorization to scan every supplied target.

The scanner is designed for defensive asset and cryptographic inventory only.

## IPv4

The current implementation focuses on IPv4.

IPv6 discovery and inspection are outside the current assessment scope.

## Port Coverage

Q-SCOUT scans a fixed, bounded list of common TCP ports rather than the full TCP port range.

Therefore, a service running on an unlisted port may not be discovered.

This is an intentional safety and runtime bound.

## Reachability

Reachability is inferred from TCP behavior rather than ICMP echo.

A successful connection or active refusal can indicate that a host is reachable.

A timeout does not conclusively prove that a host is offline because firewalls and packet filtering can produce the same behavior.

## Service Identification

Service names are best guesses based primarily on commonly associated TCP port numbers.

Q-SCOUT does not claim application-level service fingerprinting accuracy.

## Banner Grabbing

Banner grabbing is best-effort and passive after a normal TCP connection.

No authentication or application-specific probing is performed.

Some services will therefore return no banner.

## MAC Addresses

MAC address information is only meaningful for hosts on a directly connected Layer-2 segment.

For routed targets, `mac_address` is `null` and the status is `not_applicable`.

A same-L2 host can still return `not_observed` if the operating system neighbor cache does not currently contain a usable entry.

## TLS Port Detection

TLS inspection is automatically attempted only on a defined list of commonly TLS-enabled ports.

TLS running on an unusual port may therefore be missed.

STARTTLS negotiation for protocols such as SMTP, IMAP, and POP3 is not implemented in the current version.

## TLS Certificate Validation

Certificate trust and hostname validation are intentionally disabled during TLS inventory collection.

This allows Q-SCOUT to inspect metadata from self-signed, expired, or otherwise untrusted certificates.

Q-SCOUT therefore does not claim that an observed certificate is trusted or correctly deployed.

## TLS Negotiation

The TLS version and cipher suite shown are those negotiated between the scanner's local Python/OpenSSL stack and the target.

They do not represent every protocol version or cipher suite supported by the server.

Q-SCOUT does not brute-force or enumerate the complete TLS configuration.

## Quantum Classification

Quantum classifications are applied per observed cryptographic algorithm.

Q-SCOUT does not produce a single host-level "quantum-safe" result.

The categories are intended as inventory guidance, not as a formal cryptographic certification.

## PQC Detection

PQC classification recognizes a limited set of known names and aliases, including families such as ML-KEM, ML-DSA, SLH-DSA, Kyber, Dilithium, and SPHINCS+.

An unrecognized or vendor-specific name may be classified as `unknown`.

## Symmetric Cryptography

The `symmetric-safe` category means that the primitive is not directly broken by Shor's algorithm and retains a meaningful security margin against known generic quantum attacks.

It does not mean the overall connection or host is quantum-safe.

## Operating System

Development and testing were performed on Ubuntu Linux.

MAC/neighbor lookup depends on the Linux `ip` command.

## Timeouts and Network Conditions

Results may vary because of latency, firewall behavior, DNS availability, routing, and transient service state.

Each network operation is bounded by a timeout to prevent indefinite blocking.

## CSV

CSV is a convenience summary.

JSON is the authoritative output because the scanner's TLS and classification results are naturally nested.

## Controlled TLS Demonstration

`results_tls_demo.json` was generated against a temporary TLS service
running locally on `127.0.0.1:8443`.

The service was created solely as a controlled validation environment to
demonstrate Q-SCOUT's TLS inventory functionality when an observable TLS
endpoint is available.

A temporary self-signed RSA certificate was generated using OpenSSL and
served with `openssl s_server`. This allows the scanner to exercise its
TLS inspection pipeline, including:

- TLS version detection
- negotiated cipher-suite collection
- certificate subject and issuer extraction
- certificate validity dates
- Subject Alternative Name extraction
- public-key algorithm and key size extraction
- signature-algorithm extraction
- SHA-256 certificate fingerprinting
- per-algorithm quantum-readiness classification

The TLS service was not part of the scanned environment and was not created
to represent a naturally discovered production service. It is explicitly a
controlled functional demonstration of the scanner.

The private key used for the demonstration is excluded from version control.

## External Discovery Validation

`results_scanme.json` records a limited functional discovery test against
`scanme.nmap.org`.

This target is provided by the Nmap Project for network-scanning practice.
The test was used only to validate normal network discovery behavior and did
not involve exploitation, authentication attempts, or denial-of-service
activity.

During this test, Q-SCOUT observed open TCP services including SSH and HTTP.
The result also validates the reachability logic: an observed open TCP port
can establish that a target is reachable even when the initial TCP
reachability probe on port 443 is inconclusive.

No TLS-designated open port was observed during this test, so
`results_scanme.json` is not intended to demonstrate TLS inventory.
`results_tls_demo.json` provides the separate controlled TLS validation.

## Duplicate certificates
Q-SCOUT records certificate observations separately for each discovered service rather than deduplicating them globally. The SHA-256 certificate fingerprint can be used to identify the same certificate when it is shared across multiple hosts or services.

##Self-signed certificate indication 
Q-SCOUT uses equality between the certificate subject and issuer as a heuristic indication that a certificate may be self-signed. It does not currently perform cryptographic verification of the certificate's self-signature.
