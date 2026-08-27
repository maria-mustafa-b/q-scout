"""
qscan_lib.classify

Cryptographic algorithm classification for Q-SCOUT.

This module classifies individual observed cryptographic algorithms from
TLS metadata. It deliberately does NOT produce a single host-level
"quantum-safe" verdict because one resistant primitive does not make an
entire protocol stack quantum resistant.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import List, Optional


QUANTUM_VULNERABLE = "quantum-vulnerable"
PQC = "PQC"
SYMMETRIC_SAFE = "symmetric-safe"
LEGACY_INSECURE = "legacy-insecure"
UNKNOWN = "unknown"


@dataclass(frozen=True)
class Classification:
    """Classification of one observed cryptographic algorithm."""

    algorithm: str
    category: str
    reasoning: str


def _normalize(value: Optional[str]) -> str:
    """Normalize an algorithm name for matching."""
    if value is None:
        return ""

    return re.sub(r"[^A-Z0-9]", "", value.upper())


def classify_public_key(
    algorithm: Optional[str],
    key_size: Optional[int] = None,
    curve: Optional[str] = None,
) -> Classification:
    """Classify an asymmetric public-key algorithm."""

    original = algorithm or "unknown"
    normalized = _normalize(algorithm)

    if normalized == "RSA":
        detail = (
            f" ({key_size}-bit key)" if key_size is not None else ""
        )
        return Classification(
            algorithm=original,
            category=QUANTUM_VULNERABLE,
            reasoning=(
                f"RSA{detail} relies on integer factorization and is "
                "vulnerable to Shor's algorithm on a sufficiently capable "
                "cryptographically relevant quantum computer."
            ),
        )

    if normalized == "DSA":
        return Classification(
            algorithm=original,
            category=QUANTUM_VULNERABLE,
            reasoning=(
                "DSA relies on the discrete logarithm problem and is "
                "vulnerable to Shor's algorithm."
            ),
        )

    if normalized in {"EC", "ECDSA", "ECDH", "ECDHE"}:
        curve_detail = f" using {curve}" if curve else ""

        return Classification(
            algorithm=original,
            category=QUANTUM_VULNERABLE,
            reasoning=(
                f"Elliptic-curve cryptography{curve_detail} relies on the "
                "elliptic-curve discrete logarithm problem and is vulnerable "
                "to Shor's algorithm."
            ),
        )

    if normalized in {"ED25519", "ED448", "EDDSA"}:
        return Classification(
            algorithm=original,
            category=QUANTUM_VULNERABLE,
            reasoning=(
                f"{original} is elliptic-curve public-key cryptography and "
                "is vulnerable to Shor's algorithm."
            ),
        )

    # NIST-standardized post-quantum algorithm names and common aliases.
    if (
        normalized.startswith("MLKEM")
        or normalized.startswith("MLDSA")
        or normalized.startswith("SLHDSA")
        or normalized.startswith("KYBER")
        or normalized.startswith("DILITHIUM")
        or normalized.startswith("SPHINCS")
    ):
        return Classification(
            algorithm=original,
            category=PQC,
            reasoning=(
                f"{original} is a post-quantum cryptographic algorithm "
                "designed around mathematical problems not known to be "
                "efficiently solved by Shor's algorithm."
            ),
        )

    return Classification(
        algorithm=original,
        category=UNKNOWN,
        reasoning=(
            "The public-key algorithm was not recognized by Q-SCOUT's "
            "current classification rules."
        ),
    )


def classify_cipher_suite(
    cipher_suite: Optional[str],
) -> List[Classification]:
    """
    Classify symmetric primitives visible in a negotiated TLS cipher suite.

    Multiple classifications may be returned because a cipher suite can
    expose both an encryption primitive and a hash/MAC primitive.
    """

    if not cipher_suite:
        return [
            Classification(
                algorithm="unknown",
                category=UNKNOWN,
                reasoning="No negotiated cipher suite was observed.",
            )
        ]

    normalized = _normalize(cipher_suite)
    results: List[Classification] = []

    if "AES256" in normalized:
        results.append(
            Classification(
                algorithm="AES-256",
                category=SYMMETRIC_SAFE,
                reasoning=(
                    "AES-256 is symmetric cryptography. Grover's algorithm "
                    "provides a quadratic search speedup, but a 256-bit key "
                    "retains an appropriate post-quantum security margin."
                ),
            )
        )

    elif "AES128" in normalized:
        results.append(
            Classification(
                algorithm="AES-128",
                category=SYMMETRIC_SAFE,
                reasoning=(
                    "AES-128 is not broken by Shor's algorithm. Grover's "
                    "algorithm can reduce its ideal brute-force security "
                    "margin, so larger symmetric keys are preferable for "
                    "long-term post-quantum planning."
                ),
            )
        )

    elif "CHACHA20" in normalized:
        results.append(
            Classification(
                algorithm="ChaCha20",
                category=SYMMETRIC_SAFE,
                reasoning=(
                    "ChaCha20 uses a 256-bit symmetric key and is not "
                    "directly vulnerable to Shor's algorithm; generic "
                    "quantum search provides at most a quadratic speedup."
                ),
            )
        )

    elif any(
        legacy in normalized
        for legacy in ("3DES", "TRIPLEDES", "RC4", "DES")
    ):
        results.append(
            Classification(
                algorithm=cipher_suite,
                category=LEGACY_INSECURE,
                reasoning=(
                    "The negotiated suite contains a legacy symmetric "
                    "primitive that is considered insecure independently "
                    "of the quantum threat."
                ),
            )
        )

    if "SHA384" in normalized:
        results.append(
            Classification(
                algorithm="SHA-384",
                category=SYMMETRIC_SAFE,
                reasoning=(
                    "SHA-384 provides a large security margin against known "
                    "classical and generic quantum attacks."
                ),
            )
        )

    elif "SHA256" in normalized:
        results.append(
            Classification(
                algorithm="SHA-256",
                category=SYMMETRIC_SAFE,
                reasoning=(
                    "SHA-256 remains suitable against known generic quantum "
                    "attacks, although quantum collision/search algorithms "
                    "reduce theoretical security margins."
                ),
            )
        )

    if not results:
        results.append(
            Classification(
                algorithm=cipher_suite,
                category=UNKNOWN,
                reasoning=(
                    "The negotiated cipher suite did not match Q-SCOUT's "
                    "current symmetric classification rules."
                ),
            )
        )

    return results


def classify_signature_algorithm(
    algorithm: Optional[str],
) -> Classification:
    """Classify the certificate's signature algorithm."""

    original = algorithm or "unknown"
    normalized = _normalize(algorithm)

    if "MD5" in normalized:
        return Classification(
            algorithm=original,
            category=LEGACY_INSECURE,
            reasoning=(
                "MD5 is cryptographically broken and unsuitable for "
                "certificate signatures independently of quantum computing."
            ),
        )

    if "SHA1" in normalized:
        return Classification(
            algorithm=original,
            category=LEGACY_INSECURE,
            reasoning=(
                "SHA-1 has practical collision attacks and is unsuitable "
                "for modern certificate signatures."
            ),
        )

    if "RSA" in normalized:
        return Classification(
            algorithm=original,
            category=QUANTUM_VULNERABLE,
            reasoning=(
                "The certificate signature relies on RSA, whose security "
                "against forgery would be undermined by Shor's algorithm."
            ),
        )

    if (
        "ECDSA" in normalized
        or "ED25519" in normalized
        or "ED448" in normalized
        or "EDDSA" in normalized
    ):
        return Classification(
            algorithm=original,
            category=QUANTUM_VULNERABLE,
            reasoning=(
                "The certificate signature relies on elliptic-curve "
                "public-key cryptography, which is vulnerable to "
                "Shor's algorithm."
            ),
        )

    if (
        normalized.startswith("MLDSA")
        or normalized.startswith("SLHDSA")
        or normalized.startswith("DILITHIUM")
        or normalized.startswith("SPHINCS")
    ):
        return Classification(
            algorithm=original,
            category=PQC,
            reasoning=(
                f"{original} is a post-quantum digital-signature algorithm."
            ),
        )

    return Classification(
        algorithm=original,
        category=UNKNOWN,
        reasoning=(
            "The signature algorithm was not recognized by Q-SCOUT's "
            "current classification rules."
        ),
    )


def classification_to_dict(
    classification: Classification,
) -> dict:
    """Convert a Classification into a JSON-serializable dictionary."""
    return asdict(classification)
