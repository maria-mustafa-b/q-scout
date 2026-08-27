"""
tests/test_classify.py

Unit tests for Q-SCOUT cryptographic classification.
"""

from qscan_lib.classify import (
    LEGACY_INSECURE,
    PQC,
    QUANTUM_VULNERABLE,
    SYMMETRIC_SAFE,
    UNKNOWN,
    classify_cipher_suite,
    classify_public_key,
    classify_signature_algorithm,
)


def test_rsa_is_quantum_vulnerable():
    result = classify_public_key("RSA", key_size=2048)

    assert result.category == QUANTUM_VULNERABLE
    assert "Shor" in result.reasoning


def test_ec_is_quantum_vulnerable():
    result = classify_public_key(
        "EC",
        key_size=256,
        curve="secp256r1",
    )

    assert result.category == QUANTUM_VULNERABLE
    assert "secp256r1" in result.reasoning


def test_ed25519_is_quantum_vulnerable():
    result = classify_public_key("Ed25519")

    assert result.category == QUANTUM_VULNERABLE


def test_mlkem_is_pqc():
    result = classify_public_key("ML-KEM-768")

    assert result.category == PQC


def test_kyber_alias_is_pqc():
    result = classify_public_key("Kyber768")

    assert result.category == PQC


def test_unknown_public_key_is_unknown():
    result = classify_public_key("MysteryAlgo")

    assert result.category == UNKNOWN


def test_tls_aes256_suite_classification():
    results = classify_cipher_suite(
        "TLS_AES_256_GCM_SHA384"
    )

    categories = {
        result.algorithm: result.category
        for result in results
    }

    assert categories["AES-256"] == SYMMETRIC_SAFE
    assert categories["SHA-384"] == SYMMETRIC_SAFE


def test_tls_aes128_suite_classification():
    results = classify_cipher_suite(
        "TLS_AES_128_GCM_SHA256"
    )

    categories = {
        result.algorithm: result.category
        for result in results
    }

    assert categories["AES-128"] == SYMMETRIC_SAFE
    assert categories["SHA-256"] == SYMMETRIC_SAFE


def test_chacha20_is_symmetric_safe():
    results = classify_cipher_suite(
        "TLS_CHACHA20_POLY1305_SHA256"
    )

    categories = {
        result.algorithm: result.category
        for result in results
    }

    assert categories["ChaCha20"] == SYMMETRIC_SAFE


def test_legacy_3des_is_insecure():
    results = classify_cipher_suite(
        "TLS_RSA_WITH_3DES_EDE_CBC_SHA"
    )

    assert any(
        result.category == LEGACY_INSECURE
        for result in results
    )


def test_unknown_cipher_suite_is_unknown():
    results = classify_cipher_suite(
        "TLS_MYSTERY_CIPHER"
    )

    assert len(results) == 1
    assert results[0].category == UNKNOWN


def test_rsa_signature_is_quantum_vulnerable():
    result = classify_signature_algorithm(
        "sha256WithRSAEncryption"
    )

    assert result.category == QUANTUM_VULNERABLE


def test_ecdsa_signature_is_quantum_vulnerable():
    result = classify_signature_algorithm(
        "ecdsa-with-SHA256"
    )

    assert result.category == QUANTUM_VULNERABLE


def test_ed25519_signature_is_quantum_vulnerable():
    result = classify_signature_algorithm(
        "Ed25519"
    )

    assert result.category == QUANTUM_VULNERABLE


def test_sha1_signature_is_legacy_insecure():
    result = classify_signature_algorithm(
        "sha1WithRSAEncryption"
    )

    assert result.category == LEGACY_INSECURE


def test_md5_signature_is_legacy_insecure():
    result = classify_signature_algorithm(
        "md5WithRSAEncryption"
    )

    assert result.category == LEGACY_INSECURE


def test_mldsa_signature_is_pqc():
    result = classify_signature_algorithm(
        "ML-DSA-65"
    )

    assert result.category == PQC


def test_unknown_signature_is_unknown():
    result = classify_signature_algorithm(
        "MysterySignature"
    )

    assert result.category == UNKNOWN


def test_reasoning_always_present():
    checks = [
        classify_public_key("RSA"),
        classify_public_key("unknown-algo"),
        classify_signature_algorithm(
            "sha256WithRSAEncryption"
        ),
    ]

    for result in checks:
        assert result.reasoning
        assert len(result.reasoning.strip()) > 0
