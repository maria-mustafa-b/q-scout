"""
tests/test_tls_inspect.py

Unit tests for qscan_lib.tls_inspect.

The tests generate small certificates locally using cryptography, so
certificate parsing can be tested without depending on the internet.
"""

import os
import socket
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from qscan_lib.tls_inspect import (
    TLSResult,
    _certificate_datetime,
    _extract_sans,
    _inspect_public_key,
    inspect_tls,
    parse_certificate,
    tls_result_to_dict,
)

# ---------------------------------------------------------------------------
# Certificate generation helpers
# ---------------------------------------------------------------------------

def make_rsa_certificate(
    common_name="example.com",
    expired=False,
    self_signed=True,
):
    """Generate a small self-signed RSA certificate for testing."""

    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                common_name,
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                "Q-SCOUT Test",
            ),
        ]
    )

    now = datetime.now(timezone.utc)

    if expired:
        not_before = now - timedelta(days=30)
        not_after = now - timedelta(days=1)
    else:
        not_before = now - timedelta(days=1)
        not_after = now + timedelta(days=365)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName(common_name),
                    x509.DNSName("www." + common_name),
                    x509.IPAddress(
                        __import__("ipaddress").IPv4Address("192.168.56.10")
                    ),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(
                ca=True,
                path_length=None,
            ),
            critical=True,
        )
    )

    certificate = builder.sign(
        private_key=key,
        algorithm=hashes.SHA256(),
    )

    return key, certificate


def make_ec_certificate():
    """Generate a self-signed ECDSA certificate for testing."""

    key = ec.generate_private_key(ec.SECP256R1())

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "ec.example.com",
            )
        ]
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(
            private_key=key,
            algorithm=hashes.SHA256(),
        )
    )

    return key, certificate


def make_ed25519_certificate():
    """Generate a self-signed Ed25519 certificate for testing."""

    key = ed25519.Ed25519PrivateKey.generate()

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "ed.example.com",
            )
        ]
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .sign(
            private_key=key,
            algorithm=None,
        )
    )

    return key, certificate


# ---------------------------------------------------------------------------
# Certificate parsing
# ---------------------------------------------------------------------------

def test_parse_rsa_certificate():
    _, certificate = make_rsa_certificate()

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = parse_certificate(der)

    assert result.certificate_present is True
    assert result.public_key_algorithm == "RSA"
    assert result.public_key_size == 2048
    assert result.public_key_curve is None
    assert result.subject is not None
    assert result.issuer is not None
    assert result.signature_algorithm is not None
    assert result.sha256_fingerprint is not None
    assert len(result.sha256_fingerprint) == 64
    assert result.self_signed is True


def test_parse_ec_certificate():
    _, certificate = make_ec_certificate()

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = parse_certificate(der)

    assert result.public_key_algorithm == "EC"
    assert result.public_key_size == 256
    assert result.public_key_curve == "secp256r1"


def test_parse_ed25519_certificate():
    _, certificate = make_ed25519_certificate()

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = parse_certificate(der)

    assert result.public_key_algorithm == "Ed25519"
    assert result.public_key_size is None
    assert result.public_key_curve is None


def test_certificate_fingerprint_is_sha256():
    _, certificate = make_rsa_certificate()

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = parse_certificate(der)

    expected = certificate.fingerprint(
        hashes.SHA256()
    ).hex().upper()

    assert result.sha256_fingerprint == expected


def test_subject_and_issuer_are_extracted():
    _, certificate = make_rsa_certificate()

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = parse_certificate(der)

    assert "commonName=example.com" in result.subject
    assert "organizationName=Q-SCOUT Test" in result.subject
    assert result.subject == result.issuer


# ---------------------------------------------------------------------------
# SAN tests
# ---------------------------------------------------------------------------

def test_sans_are_extracted():
    _, certificate = make_rsa_certificate()

    sans = _extract_sans(certificate)

    assert "example.com" in sans
    assert "www.example.com" in sans
    assert "192.168.56.10" in sans


def test_sans_are_sorted_and_unique():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = x509.Name(
        [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                "example.com",
            )
        ]
    )

    now = datetime.now(timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("z.example.com"),
                    x509.DNSName("a.example.com"),
                    x509.DNSName("a.example.com"),
                ]
            ),
            critical=False,
        )
        .sign(
            key,
            hashes.SHA256(),
        )
    )

    sans = _extract_sans(certificate)

    assert sans == [
        "a.example.com",
        "z.example.com",
    ]


# ---------------------------------------------------------------------------
# Certificate validity tests
# ---------------------------------------------------------------------------

def test_validity_dates_are_present():
    _, certificate = make_rsa_certificate()

    der = certificate.public_bytes(serialization.Encoding.DER)

    result = parse_certificate(der)

    assert result.valid_from is not None
    assert result.valid_until is not None
    assert "T" in result.valid_from
    assert "T" in result.valid_until


def test_certificate_datetime_is_utc():
    value = datetime(
        2026,
        8,
        27,
        12,
        30,
        tzinfo=timezone.utc,
    )

    formatted = _certificate_datetime(value)

    assert formatted == "2026-08-27T12:30:00+00:00"


# ---------------------------------------------------------------------------
# Public key inspection tests
# ---------------------------------------------------------------------------

def test_rsa_key_properties():
    _, certificate = make_rsa_certificate()

    algorithm, size, curve = _inspect_public_key(certificate)

    assert algorithm == "RSA"
    assert size == 2048
    assert curve is None


def test_ec_key_properties():
    _, certificate = make_ec_certificate()

    algorithm, size, curve = _inspect_public_key(certificate)

    assert algorithm == "EC"
    assert size == 256
    assert curve == "secp256r1"


def test_ed25519_key_properties():
    _, certificate = make_ed25519_certificate()

    algorithm, size, curve = _inspect_public_key(certificate)

    assert algorithm == "Ed25519"
    assert size is None
    assert curve is None


# ---------------------------------------------------------------------------
# TLS failure handling
# ---------------------------------------------------------------------------

@patch(
    "qscan_lib.tls_inspect.socket.getaddrinfo",
    side_effect=socket.gaierror("DNS failure"),
)
def test_tls_dns_failure_is_recorded(mock_getaddrinfo):
    result = inspect_tls(
        "does-not-exist.invalid",
        443,
        timeout=1,
    )

    assert result.tls_supported is None
    assert result.error is not None
    assert "DNS resolution failed" in result.error


@patch(
    "qscan_lib.tls_inspect.socket.socket",
)
def test_tls_connection_failure_does_not_crash(mock_socket):
    mock_socket_instance = mock_socket.return_value
    mock_socket_instance.connect.side_effect = ConnectionRefusedError()

    result = inspect_tls(
        "127.0.0.1",
        443,
        timeout=1,
    )

    assert result.tls_supported is None
    assert result.error is not None


def test_tls_invalid_timeout_is_rejected():
    result = inspect_tls(
        "127.0.0.1",
        443,
        timeout=0,
    )

    assert result.error is not None
    assert "timeout" in result.error.lower()


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------

def test_tls_result_serializes_to_dict():
    result = TLSResult(
        host="example.com",
        port=443,
        tls_supported=True,
        tls_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        certificate_present=True,
        subject="CN=example.com",
        issuer="CN=Test CA",
        valid_from="2026-08-01T00:00:00+00:00",
        valid_until="2027-08-01T00:00:00+00:00",
        sans=["example.com"],
        public_key_algorithm="RSA",
        public_key_size=2048,
        signature_algorithm="sha256WithRSAEncryption",
        sha256_fingerprint="A" * 64,
        self_signed=False,
    )

    data = tls_result_to_dict(result)

    assert data["host"] == "example.com"
    assert data["port"] == 443
    assert data["tls_version"] == "TLSv1.3"
    assert data["public_key_algorithm"] == "RSA"
    assert len(data["sha256_fingerprint"]) == 64
