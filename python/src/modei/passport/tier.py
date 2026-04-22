"""Trust tier enum + derivation.

Mirrors backend ``src/lib/passports/tier.ts`` (``deriveTier``) and
``src/lib/passports/inline.ts`` (``TIER_ORDER`` / ``tierRank``).

Tier is NOT a signed envelope field — it is derived from
``provenance.issuer.type`` at verify time so that any tampering with
``issuer.type`` invalidates the signature (spec §3.2, §14 A5).

Tier ordering is pinned via an explicit rank dict, not enum or string
comparison. String comparison works by accident for this alphabet but
is not a contract — a future tier like ``"L4"`` or ``"L10"`` would break
it. Mirror backend's explicit dict.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .envelope import Envelope


class TrustTier(str, Enum):
    """Trust tier values (spec §3.2). Member names follow spec §11.1."""

    L0 = "L0"
    L0_5 = "L0.5"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


_TIER_RANK: dict[TrustTier, int] = {
    TrustTier.L0: 0,
    TrustTier.L0_5: 1,
    TrustTier.L1: 2,
    TrustTier.L2: 3,
    TrustTier.L3: 4,
}


def tier_rank(tier: TrustTier) -> int:
    """Return the integer rank of ``tier``. Higher = more trust."""
    return _TIER_RANK[tier]


def derive_tier(envelope: "Envelope") -> TrustTier:
    """Derive the trust tier of a well-formed envelope.

    Caller contract: ``envelope`` is structurally valid. The chain verifier
    (C19.4) validates shape + chain invariants BEFORE calling this. If
    ``issuer.type == 'delegate'`` with a null/empty ``delegation_chain``,
    that's a caller bug and we raise ``ValueError`` rather than silently
    coerce a tier. Mirrors backend's ``throw new Error``.
    """
    issuer_type = envelope.provenance.issuer.type

    if issuer_type == "self":
        return TrustTier.L0
    if issuer_type == "platform":
        return TrustTier.L1
    if issuer_type == "gate":
        return TrustTier.L2
    if issuer_type == "delegate":
        chain = envelope.provenance.delegation_chain
        if not chain:
            raise ValueError(
                "derive_tier: envelope has issuer.type='delegate' but "
                "delegation_chain is null/empty; chain verification must run "
                "before tier derivation",
            )
        return derive_tier(chain[0].passport_json)

    raise ValueError(f"derive_tier: unknown issuer.type={issuer_type!r}")
