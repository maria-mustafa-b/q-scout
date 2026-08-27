"""
qscan_lib.tls_inspect

TLS inspection for Q-SCOUT.

Responsibilities:
  - Establish a TLS connection to a discovered TCP service
  - Record negotiated TLS version and cipher suite
  - Extract and parse the peer certificate
  - Extract certificate subject, issuer, validity, and SANs
  - Identify public-key algorithm and key size/curve
  - Identify certificate signature algorithm
  - Calculate SHA-256 certificate fingerprint
  - Distinguish TLS handshake/inspection errors from unavailable data

The module performs inspection only. It does not:
  - exploit TLS vulnerabilities
  - brute-force cipher suites
  - bypass certificate validation
  - modify server state
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)
from cryptography.hazmat.primitives.serialization import Encoding


# ---------------------------------------------------------------------------
# TLS configuration
# ---------------------------------------------------------------------------

DEFAULT_TLS_TIMEOUT = 5.0

# Ports where TLS is commonly expected.
DEFAULT_TLS_PORTS = {
    443,
    465,
    636,
    853,
    993,
    995,
    8443,
}


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

@dataclass
class TLSResult:
    """Structured TLS inspection result for one host/port."""

    host: str
    port: int

    tls_supported: Optional[bool] = None
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None

    certificate_present: Optional[bool] = None

    subject: Optional[str] = None
    issuer: Optional[str] = None

    valid_from: Optional[str] = None
    valid_until: Optional[str] = None

    sans: Optional[List[str]] = None

    public_key_algorithm: Optional[str] = None
    public_key_size: Optional[int] = None
    public_key_curve: Optional[str] = None

    signature_algorithm: Optional[str] = None

    sha256_fingerprint: Optional[str] = None

    self_signed: Optional[bool] = None

    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Host validation / resolution
# ---------------------------------------------------------------------------

def _is_ipv4(value: str) -> bool:
    """Return True if value is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _resolve_ipv4(host: str, timeout: float) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve a hostname to IPv4.

    An IPv4 address is returned unchanged.

    Returns:
        (resolved_ip, error)
    """
    if _is_ipv4(host):
        return host, None

    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        results = socket.getaddrinfo(
            host,
            None,
            family=socket.AF_INET,
            type=socket.SOCK_STREAM,
        )

        if not results:
            return None, "hostname resolved to no IPv4 addresses"

        return results[0][4][0], None

    except socket.timeout:
        return None, "DNS resolution timed out"

    except socket.gaierror as exc:
        return None, f"DNS resolution failed: {exc}"

    except OSError as exc:
        return None, f"DNS resolution error: {exc}"

    finally:
        socket.setdefaulttimeout(old_timeout)


# ---------------------------------------------------------------------------
# Certificate formatting
# ---------------------------------------------------------------------------

def _format_name(name: x509.Name) -> str:
    """
    Convert an X.509 Name into a compact deterministic string.

    Example:
        CN=example.com,O=Example Inc,C=US
    """
    parts = []

    for attribute in name:
        parts.append(
            f"{attribute.oid._name or attribute.oid.dotted_string}="
            f"{attribute.value}"
        )

    return ",".join(parts)


def _extract_sans(cert: x509.Certificate) -> List[str]:
    """
    Extract DNS names and IP addresses from Subject Alternative Name.

    Other SAN types are intentionally ignored because the scanner's
    current inventory requirement concerns host identity.
    """
    try:
        extension = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
    except x509.ExtensionNotFound:
        return []

    values: List[str] = []

    for name in extension.value:
        if isinstance(name, x509.DNSName):
            values.append(str(name.value))

        elif isinstance(name, x509.IPAddress):
            values.append(str(name.value))

    return sorted(set(values))


# ---------------------------------------------------------------------------
# Public-key inspection
# ---------------------------------------------------------------------------

def _inspect_public_key(
    cert: x509.Certificate,
) -> Tuple[
    Optional[str],
    Optional[int],
    Optional[str],
]:
    """
    Inspect the certificate public key.

    Returns:
        (algorithm, size, curve)

    Supported explicit classifications:
      RSA
      DSA
      ECDSA / EC
      Ed25519
      Ed448

    Unknown key implementations are reported as "unknown".
    """
    key = cert.public_key()

    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size, None

    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size, None

    if isinstance(key, ec.EllipticCurvePublicKey):
        return "EC", key.key_size, key.curve.name

    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", None, None

    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", None, None

    return "unknown", None, None


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

def parse_certificate(
    certificate_der: bytes,
) -> TLSResult:
    """
    Parse a DER-encoded X.509 certificate.

    The host and port fields are intentionally placeholders here.
    The complete TLS inspection workflow fills them in later.
    """
    cert = x509.load_der_x509_certificate(certificate_der)

    algorithm, key_size, curve = _inspect_public_key(cert)

    fingerprint = cert.fingerprint(
        hashes.SHA256()
    )

    # The cryptography API normally returns a bytes digest.
    fingerprint_hex = fingerprint.hex().upper()

    self_signed = cert.subject == cert.issuer

    return TLSResult(
        host="",
        port=0,
        certificate_present=True,
        subject=_format_name(cert.subject),
        issuer=_format_name(cert.issuer),
        valid_from=_certificate_datetime(cert.not_valid_before_utc),
        valid_until=_certificate_datetime(cert.not_valid_after_utc),
        sans=_extract_sans(cert),
        public_key_algorithm=algorithm,
        public_key_size=key_size,
        public_key_curve=curve,
        signature_algorithm=cert.signature_algorithm_oid._name
        or cert.signature_algorithm_oid.dotted_string,
        sha256_fingerprint=fingerprint_hex,
        self_signed=self_signed,
    )


def _certificate_datetime(value: datetime) -> str:
    """Return a deterministic UTC ISO-8601 timestamp."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# TLS connection
# ---------------------------------------------------------------------------

def inspect_tls(
    host: str,
    port: int,
    timeout: float = DEFAULT_TLS_TIMEOUT,
) -> TLSResult:
    """
    Establish a TLS connection and inspect the peer certificate.

    Certificate verification is intentionally disabled because Q-SCOUT
    is performing inventory/metadata inspection rather than validating
    whether the certificate should be trusted.

    Hostname checking is therefore also disabled.

    TLS protocol negotiation is still performed by Python/OpenSSL.
    """
    result = TLSResult(
        host=host,
        port=port,
    )

    if timeout <= 0:
        result.error = "TLS timeout must be greater than 0"
        return result

    resolved_ip, resolution_error = _resolve_ipv4(host, timeout)

    if resolution_error:
        result.error = resolution_error
        return result

    if resolved_ip is None:
        result.error = "host did not resolve to an IPv4 address"
        return result

    context = ssl.create_default_context()

    # We are inspecting certificates, including expired/self-signed ones.
    # Trust verification would prevent us from retrieving useful metadata
    # from exactly those certificates.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.settimeout(timeout)

    tls_sock: Optional[ssl.SSLSocket] = None

    try:
        raw_sock.connect((resolved_ip, port))

        tls_sock = context.wrap_socket(
            raw_sock,
            server_hostname=host if not _is_ipv4(host) else None,
        )

        result.tls_supported = True
        result.tls_version = tls_sock.version()

        cipher = tls_sock.cipher()

        if cipher:
            result.cipher_suite = cipher[0]

        certificate_der = tls_sock.getpeercert(binary_form=True)

        if not certificate_der:
            result.certificate_present = False
            return result

        parsed = parse_certificate(certificate_der)

        # Copy parsed certificate fields into the result while preserving
        # the original host and port.
        result.certificate_present = parsed.certificate_present
        result.subject = parsed.subject
        result.issuer = parsed.issuer
        result.valid_from = parsed.valid_from
        result.valid_until = parsed.valid_until
        result.sans = parsed.sans
        result.public_key_algorithm = parsed.public_key_algorithm
        result.public_key_size = parsed.public_key_size
        result.public_key_curve = parsed.public_key_curve
        result.signature_algorithm = parsed.signature_algorithm
        result.sha256_fingerprint = parsed.sha256_fingerprint
        result.self_signed = parsed.self_signed

        return result

    except ssl.SSLCertVerificationError as exc:
        result.tls_supported = True
        result.error = f"certificate verification error: {exc}"
        return result

    except ssl.SSLError as exc:
        result.error = f"TLS handshake failed: {exc}"
        return result

    except socket.timeout:
        result.error = "TLS connection timed out"
        return result

    except ConnectionRefusedError:
        result.error = "TCP connection refused"
        return result

    except OSError as exc:
        result.error = f"TLS connection failed: {exc}"
        return result

    except ValueError as exc:
        result.error = f"TLS configuration error: {exc}"
        return result

    except Exception as exc:
        # Certificate parsing and unusual OpenSSL errors should not crash
        # the complete scanner.
        result.error = f"unexpected TLS inspection error: {exc}"
        return result

    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except OSError:
                pass
        else:
            try:
                raw_sock.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Serialization helper
# ---------------------------------------------------------------------------

def tls_result_to_dict(result: TLSResult) -> dict:
    """
    Convert a TLSResult into a JSON-serializable dictionary.
    """
    return asdict(result)
