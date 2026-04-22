"""Self-issued passport primitives (spec §2 Self-Issued L1 Passports).

Public API surface per spec §11.1. Also exports utility functions and
error types for power users and error-handling code.

Typical usage::

    from modei.passport import PassportIssuer, AgentCredentials, DelegationBuilder
    # (the same symbols are also re-exported at top-level modei.*)
"""

from .agent_id import derive_self_agent_id
from .canonical import CanonicalizationError, canonicalize_strict
from .credentials import AgentCredentials
from .delegation import (
    DelegationAuthorityMissingError,
    DelegationBuilder,
    DelegationChainTooDeepError,
    DelegationError,
    DelegationSubsetError,
)
from .envelope import (
    DelegationChainEntry,
    Envelope,
    EnvelopeIssuer,
    PassportIdentity,
    PassportPermission,
    PassportProvenance,
    SignedPassport,
)
from .issuer import PassportIssuer
from .reasons import PASSPORT_VERIFY_REASON_CODES, PassportVerifyReasonCode
from .tier import TrustTier, derive_tier, tier_rank
from .verifier import ChainVerifyResult, PassportVerifier

__all__ = [
    # Core Spec 2 classes (re-exported at top-level modei.*).
    "AgentCredentials",
    "ChainVerifyResult",
    "DelegationBuilder",
    "Envelope",
    "PassportIssuer",
    "PassportVerifier",
    "SignedPassport",
    "TrustTier",
    # Envelope submodels (typed dicts for constructing envelopes manually).
    "DelegationChainEntry",
    "EnvelopeIssuer",
    "PassportIdentity",
    "PassportPermission",
    "PassportProvenance",
    # Error types.
    "CanonicalizationError",
    "DelegationAuthorityMissingError",
    "DelegationChainTooDeepError",
    "DelegationError",
    "DelegationSubsetError",
    # Reason codes (for interpreting backend responses).
    "PASSPORT_VERIFY_REASON_CODES",
    "PassportVerifyReasonCode",
    # Utilities.
    "canonicalize_strict",
    "derive_self_agent_id",
    "derive_tier",
    "tier_rank",
]
