"""Passport verify reason codes — mirrors backend `PassportVerifyReasonCode`.

Source of truth: `src/lib/passports/types.ts` in the modei backend. Every
string here must match a backend code exactly; drift is a spec-parity bug.

Register-endpoint input-validation codes (e.g., `issuer_id_mismatch`) are
intentionally excluded — they are not emitted by the verify pipeline. If
a future taxonomy needs them, introduce `PASSPORT_REGISTER_REASON_CODES`
separately.

Canonicalization reason codes are not in this set either — see
`canonical.CanonicalizationError.reason_code`. Introduce
`CANONICALIZATION_REASON_CODES` if a second value ever appears.
"""

from __future__ import annotations

from typing import Literal, get_args

PassportVerifyReasonCode = Literal[
    "invalid_envelope_shape",
    "unsupported_schema_version",
    "signature_malformed",
    "signature_invalid",
    "public_key_malformed",
    "signature_key_unavailable",
    "unsupported_issuer_type",
    "envelope_too_large",
    "delegation_chain_too_deep",
    "delegation_chain_invalid_root",
    "delegation_authority_missing",
    "permission_elevation_in_chain",
    "expiry_extension_in_chain",
    "assertion_mismatch",
    "missing_assertion",
    "passport_not_found",
    "passport_expired",
    "trust_tier_insufficient",
    "inline_expires_at_out_of_range",
    "inline_envelope_rate_limited",
    "invalid_passport_reference",
    "passport_revoked",
    "self_issued_platform_ceiling_exceeded",
]

PASSPORT_VERIFY_REASON_CODES: frozenset[str] = frozenset(get_args(PassportVerifyReasonCode))
