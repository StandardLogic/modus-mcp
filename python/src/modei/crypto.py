"""Cryptographic utilities: Ed25519 verification and RFC 8785 content hashing.

As of modei-python 1.1.0a1, the canonicalizer is ``jcs==0.2.1`` (via
``modei.passport.canonicalize_strict``) rather than ``canonicaljson``. Output
is byte-identical for all realistic JSON; two edge cases differ where the
previous behavior was a bug:

1. Non-finite floats (``NaN``, ``+Infinity``, ``-Infinity``) now raise
   :class:`modei.passport.CanonicalizationError` instead of silently
   coercing to ``null``. RFC 8785 §3.2.2.4 mandates rejection.
2. IEEE 754 negative zero (``-0.0``) serializes as ``"0"`` (RFC 8785
   §3.2.2.3) instead of ``"-0.0"``. Content hashes containing ``-0.0``
   now match the Modei backend (which uses the same canonicalizer family).
"""

from __future__ import annotations

import hashlib
from typing import Any

import nacl.signing

from .passport.canonical import canonicalize_strict


def verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: 32-byte Ed25519 public key.
        message: The signed message bytes.
        signature: 64-byte Ed25519 signature.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        verify_key = nacl.signing.VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False


def compute_content_hash(obj: Any) -> str:
    """Compute the SHA-256 hex digest of the RFC 8785 canonical JSON encoding.

    Args:
        obj: Any JSON-serializable value.

    Returns:
        Hex-encoded SHA-256 hash string.

    Raises:
        modei.passport.CanonicalizationError: ``obj`` contains ``NaN``,
            ``+Infinity``, or ``-Infinity`` anywhere in its tree.
    """
    canonical = canonicalize_strict(obj)
    return hashlib.sha256(canonical).hexdigest()


def verify_attestation_signature(
    attestation_json: str,
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """Verify an attestation's Ed25519 signature.

    Args:
        attestation_json: The canonical JSON string that was signed.
        signature_b64: Base64-encoded Ed25519 signature.
        public_key_b64: Base64-encoded Ed25519 public key.

    Returns:
        True if the signature is valid.
    """
    import base64

    public_key = base64.b64decode(public_key_b64)
    signature = base64.b64decode(signature_b64)
    message = attestation_json.encode("utf-8")
    return verify_ed25519(public_key, message, signature)


def verify_content_hash(obj: Any, expected_hash: str) -> bool:
    """Verify that a JSON object matches an expected content hash.

    Args:
        obj: The JSON-serializable object.
        expected_hash: The expected hex SHA-256 hash.

    Returns:
        True if the computed hash matches.

    Raises:
        modei.passport.CanonicalizationError: ``obj`` contains non-finite
            floats. Since this wraps :func:`compute_content_hash`, the
            same rejection applies.
    """
    return compute_content_hash(obj) == expected_hash
