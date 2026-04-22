"""Self-issued agent_id derivation.

Mirrors backend ``src/lib/passports/agent_id.ts`` byte-for-byte:

    agent_id = "agent_self_" + base64url(sha256(pubkey_bytes))[:32]

32 base64url characters = 192 bits of entropy (spec §14 A9).

BEHAVIOR DIVERGENCE FROM BACKEND (intentional hardening, 1.1.0a1):
``derive_self_agent_id`` raises ``ValueError`` on malformed base64 input.
Backend ``Buffer.from(..., 'base64')`` silently drops invalid chars and
produces a real-but-wrong agent_id. SDK fail-fast is preferred; backend
behavior should be tightened in a future cleanup.
"""

from __future__ import annotations

import base64
import hashlib

SELF_AGENT_ID_PREFIX = "agent_self_"


def derive_self_agent_id(public_key_b64: str) -> str:
    """Derive the self-issued ``agent_id`` from a base64-encoded public key.

    Args:
        public_key_b64: Standard base64 (not URL-safe) of the raw public key
            bytes. Typically 32 bytes for Ed25519, but length is NOT enforced
            here — signature verification catches length mismatches.

    Returns:
        ``"agent_self_" + base64url(sha256(pubkey))[:32]``. Always 43 chars.

    Raises:
        ValueError: ``public_key_b64`` is not valid base64.
    """
    pk_bytes = base64.b64decode(public_key_b64, validate=True)
    digest = hashlib.sha256(pk_bytes).digest()
    b64url = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return SELF_AGENT_ID_PREFIX + b64url[:32]
