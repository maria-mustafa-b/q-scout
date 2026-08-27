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
