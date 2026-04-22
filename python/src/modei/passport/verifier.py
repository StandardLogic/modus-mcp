"""PassportVerifier — local signature + chain verification.

Spec §5.1, §5.2. Local-only: no DB, no HTTP. Platform- and gate-issued
envelopes (or delegated envelopes whose chain root is platform/gate)
return ``signature_key_unavailable`` — backend key resolution is required.

Behavior mirrors backend ``verifyPassportWithChain``
(``src/lib/passports/chain.ts``):

  * shape check → size cap → single-passport path or chain path
  * chain path: depth ≤ 5, root-not-delegate, per-link
    delegation_authority, per-link signature, pairwise subset
    permissions (§3.4) + constraints tightening (§3.5) + expiry
    non-extension (§3.3)

See ``ChainVerifyResult`` for the return shape.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Optional

import nacl.exceptions
import nacl.signing
from pydantic import ValidationError

from .canonical import canonicalize_strict
from .envelope import DelegationChainEntry, Envelope
from .reasons import PassportVerifyReasonCode
from .tier import TrustTier, derive_tier

MAX_DELEGATION_DEPTH = 5  # spec §3.3
MAX_CANONICAL_ENVELOPE_BYTES = 64 * 1024  # spec §2.1
ED25519_SIGNATURE_BYTES = 64
ED25519_PUBLIC_KEY_BYTES = 32


@dataclass(frozen=True)
class ChainVerifyResult:
    valid: bool
    tier: Optional[TrustTier] = None
    reason_code: Optional[PassportVerifyReasonCode] = None
    detail: Optional[str] = None


def _ok(tier: TrustTier) -> ChainVerifyResult:
    return ChainVerifyResult(valid=True, tier=tier)


def _err(reason_code: PassportVerifyReasonCode, detail: Optional[str] = None) -> ChainVerifyResult:
    return ChainVerifyResult(valid=False, reason_code=reason_code, detail=detail)


def _decode_b64_fixed_length(s: Any, expected_len: int) -> Optional[bytes]:
    """Strict base64 decode, returning None on any failure."""
    if not isinstance(s, str) or not s:
        return None
    try:
        decoded = base64.b64decode(s, validate=True)
    except Exception:
        return None
    if len(decoded) != expected_len:
        return None
    return decoded


def _parse_envelope(obj: Any) -> tuple[Optional[Envelope], Optional[ChainVerifyResult]]:
    """Parse an envelope with schema_version pre-validation.

    Pydantic's ``Literal[2]`` surfaces any deviation as a generic shape
    error. Backend distinguishes ``unsupported_schema_version`` from
    ``invalid_envelope_shape`` — we mirror by peeking at the raw input's
    ``schema_version`` BEFORE constructing the model. The peek decouples
    us from Pydantic's internal error representation (which changes
    across minor versions); a dedicated test pins the distinction.
    """
    if isinstance(obj, dict) and "schema_version" in obj:
        sv = obj["schema_version"]
        # An int that isn't 2 is specifically "unsupported version". A
        # non-int, missing key, or other shape issue falls through to
        # Pydantic and surfaces as invalid_envelope_shape.
        if isinstance(sv, int) and not isinstance(sv, bool) and sv != 2:
            return None, _err(
                "unsupported_schema_version",
                f"schema_version={sv}, expected 2",
            )

    try:
        return Envelope.model_validate(obj), None
    except ValidationError as exc:
        return None, _err("invalid_envelope_shape", str(exc.errors()[0] if exc.errors() else exc))


def _assert_canonical_size(envelope: Envelope) -> Optional[ChainVerifyResult]:
    """Size the envelope's own bytes with delegation_chain stripped.

    Mirrors backend ``chain.ts`` lines 76–87. The chain's bytes are
    counted per-link separately; sizing the outer envelope WITH the
    chain would double-count and reject legitimate deep chains.
    """
    dumped = envelope.model_dump(mode="json")
    # Strip chain for the outer-envelope sizing.
    if isinstance(dumped.get("provenance"), dict):
        dumped["provenance"] = {**dumped["provenance"], "delegation_chain": None}
    canonical_bytes = canonicalize_strict(dumped)
    if len(canonical_bytes) > MAX_CANONICAL_ENVELOPE_BYTES:
        return _err(
            "envelope_too_large",
            f"canonical envelope is {len(canonical_bytes)} bytes, max {MAX_CANONICAL_ENVELOPE_BYTES}",
        )
    return None


def _verify_signature_over_envelope(
    envelope: Envelope,
    signature_b64: str,
    signer_public_key_b64: str,
) -> Optional[ChainVerifyResult]:
    """Run the Ed25519 verify. Returns None on success, an error result otherwise."""
    sig_bytes = _decode_b64_fixed_length(signature_b64, ED25519_SIGNATURE_BYTES)
    if sig_bytes is None:
        return _err("signature_malformed")

    pub_bytes = _decode_b64_fixed_length(signer_public_key_b64, ED25519_PUBLIC_KEY_BYTES)
    if pub_bytes is None:
        return _err("public_key_malformed")

    canonical_bytes = canonicalize_strict(envelope.model_dump(mode="json"))

    try:
        nacl.signing.VerifyKey(pub_bytes).verify(canonical_bytes, sig_bytes)
    except nacl.exceptions.BadSignatureError:
        return _err("signature_invalid")
    except Exception as exc:
        return _err("signature_invalid", f"crypto verify raised: {type(exc).__name__}")
    return None


def _resolve_signer_local(envelope: Envelope) -> tuple[Optional[str], Optional[ChainVerifyResult]]:
    """Return the signer pubkey for an envelope's own signature, local-only.

    - ``self``     → envelope.identity.public_key
    - ``delegate`` → chain[-1].passport_json.identity.public_key
    - ``platform`` / ``gate`` → cannot resolve locally; signature_key_unavailable
    """
    issuer_type = envelope.provenance.issuer.type
    if issuer_type == "self":
        return envelope.identity.public_key, None
    if issuer_type == "delegate":
        chain = envelope.provenance.delegation_chain
        if not chain:
            return None, _err(
                "delegation_chain_invalid_root",
                "issuer.type='delegate' but delegation_chain is null/empty",
            )
        return chain[-1].passport_json.identity.public_key, None
    if issuer_type in ("platform", "gate"):
        return None, _err(
            "signature_key_unavailable",
            f"issuer type '{issuer_type}' requires backend key resolution; "
            "PassportVerifier is local-only in v1.1",
        )
    # Pydantic Literal rules this out, but handle defensively.
    return None, _err("invalid_envelope_shape", f"unknown issuer.type={issuer_type!r}")


# ---------------------------------------------------------------------------
# subset + constraints + expiry (mirror of backend chain.ts 285–446)
# ---------------------------------------------------------------------------


def _deep_equal(a: Any, b: Any) -> bool:
    return a == b  # Python dict / list equality is structural, matches backend deepEqual semantics.


_NUMERIC_TIGHTEN = frozenset(
    {
        "max_per_action_cost",
        "max_daily_cost",
        "max_total_cost",
        "rate_limit_per_minute",
        "rate_limit_per_hour",
    }
)
_SET_INCLUDE = frozenset({"allowed_domains", "allowed_paths", "allowed_models"})


def _check_constraint_dimension(
    dim: str, ancestor_val: Any, descendant_val: Any
) -> Optional[str]:
    """Return None if descendant tightens-or-equals ancestor; else detail message."""
    if dim in _NUMERIC_TIGHTEN:
        if not isinstance(ancestor_val, (int, float)) or isinstance(ancestor_val, bool):
            return f"'{dim}' must be numeric on both sides"
        if not isinstance(descendant_val, (int, float)) or isinstance(descendant_val, bool):
            return f"'{dim}' must be numeric on both sides"
        if descendant_val > ancestor_val:
            return f"'{dim}' descendant={descendant_val} > ancestor={ancestor_val}"
        return None

    if dim in _SET_INCLUDE:
        if not isinstance(ancestor_val, list) or not isinstance(descendant_val, list):
            return f"'{dim}' must be an array on both sides"
        anc_set = set(ancestor_val)
        for v in descendant_val:
            if v not in anc_set:
                return f"'{dim}' descendant entry {v!r} not in ancestor"
        return None

    # operating_hours: deep-equality (backend chain.ts line 393 convention).
    # Unknown dimensions also fall back to deep-equality.
    if not _deep_equal(ancestor_val, descendant_val):
        if dim == "operating_hours":
            return "'operating_hours' descendant differs from ancestor (deep-equality required)"
        return f"unknown constraint dimension '{dim}' must match ancestor exactly"
    return None


def _enforce_subset_permissions(
    ancestor: Envelope, descendant: Envelope
) -> Optional[str]:
    """None on success; detail message on subset violation."""
    ancestor_by_key = {p.permission_key: p for p in ancestor.permissions}
    for desc_perm in descendant.permissions:
        anc_perm = ancestor_by_key.get(desc_perm.permission_key)
        if anc_perm is None:
            return f"descendant permission {desc_perm.permission_key!r} not present in ancestor"
        # Any dimension in descendant must also exist in ancestor and tighten.
        for dim, desc_val in desc_perm.constraints.items():
            if dim not in anc_perm.constraints:
                return (
                    f"permission '{desc_perm.permission_key}': constraint '{dim}' absent "
                    "in ancestor; descendant cannot add it"
                )
            err = _check_constraint_dimension(dim, anc_perm.constraints[dim], desc_val)
            if err is not None:
                return f"permission '{desc_perm.permission_key}': {err}"
    return None


def _is_expiry_non_extending(ancestor: Envelope, descendant: Envelope) -> bool:
    # Compare as strings first (ISO 8601 UTC Z lexicographic == chronological).
    # Falls back to string compare which is sound for the Z-suffixed millisecond
    # format the SDK emits. Backend parses via Date.parse; equivalent result.
    return descendant.provenance.expires_at <= ancestor.provenance.expires_at


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------


class PassportVerifier:
    """Local signature + chain verification of v2 passport envelopes.

    No DB, no HTTP. ``issuer.type`` of ``platform`` or ``gate`` (including
    a delegated envelope whose chain root is platform/gate) returns
    ``signature_key_unavailable``.
    """

    def verify(self, envelope_or_dict: Any, signature_b64: str) -> ChainVerifyResult:
        """Verify an envelope + detached signature.

        ``envelope_or_dict`` accepts either an :class:`Envelope` instance
        or a raw dict. Dict inputs are shape-validated first; shape
        failures return ``invalid_envelope_shape`` (or
        ``unsupported_schema_version`` for an int schema_version != 2).
        """
        if isinstance(envelope_or_dict, Envelope):
            envelope = envelope_or_dict
        else:
            envelope, err = _parse_envelope(envelope_or_dict)
            if err is not None:
                return err
            assert envelope is not None

        size_err = _assert_canonical_size(envelope)
        if size_err is not None:
            return size_err

        chain = envelope.provenance.delegation_chain

        if chain is None:
            return self._verify_single(envelope, signature_b64)
        return self._verify_chain(envelope, signature_b64, chain)

    def _verify_single(self, envelope: Envelope, signature_b64: str) -> ChainVerifyResult:
        signer_key, err = _resolve_signer_local(envelope)
        if err is not None:
            return err
        assert signer_key is not None
        sig_err = _verify_signature_over_envelope(envelope, signature_b64, signer_key)
        if sig_err is not None:
            return sig_err
        return _ok(derive_tier(envelope))

    def _verify_chain(
        self,
        leaf: Envelope,
        leaf_signature_b64: str,
        chain: list[DelegationChainEntry],
    ) -> ChainVerifyResult:
        if len(chain) > MAX_DELEGATION_DEPTH:
            return _err(
                "delegation_chain_too_deep",
                f"chain length {len(chain)} exceeds max {MAX_DELEGATION_DEPTH}",
            )
        if len(chain) == 0:
            return _err("delegation_chain_invalid_root", "delegation_chain is empty array")

        if chain[0].passport_json.provenance.delegation_chain is not None:
            return _err(
                "delegation_chain_invalid_root",
                "chain[0].provenance.delegation_chain is not null",
            )

        # Per-link delegation_authority + per-link size cap.
        for i, link in enumerate(chain):
            size_err = _assert_canonical_size(link.passport_json)
            if size_err is not None:
                return ChainVerifyResult(
                    valid=False,
                    reason_code=size_err.reason_code,
                    detail=f"chain[{i}]: {size_err.detail}",
                )
            if not link.passport_json.delegation_authority:
                return _err(
                    "delegation_authority_missing",
                    f"chain[{i}].delegation_authority is not true",
                )

        # chain[0] signer resolved via same logic as a single-passport verify.
        root_signer_key, err = _resolve_signer_local(chain[0].passport_json)
        if err is not None:
            return ChainVerifyResult(
                valid=False,
                reason_code=err.reason_code,
                detail=f"chain[0]: {err.detail}",
            )
        assert root_signer_key is not None
        root_sig_err = _verify_signature_over_envelope(
            chain[0].passport_json, chain[0].signature, root_signer_key
        )
        if root_sig_err is not None:
            return ChainVerifyResult(
                valid=False,
                reason_code=root_sig_err.reason_code,
                detail=f"chain[0]: {root_sig_err.detail}",
            )

        # chain[i] for i≥1 is signed by chain[i-1].identity.public_key.
        for i in range(1, len(chain)):
            signer_key = chain[i - 1].passport_json.identity.public_key
            err = _verify_signature_over_envelope(
                chain[i].passport_json, chain[i].signature, signer_key
            )
            if err is not None:
                return ChainVerifyResult(
                    valid=False,
                    reason_code=err.reason_code,
                    detail=f"chain[{i}]: {err.detail}",
                )

        # Leaf signer = last chain entry's identity.
        leaf_signer_key = chain[-1].passport_json.identity.public_key
        leaf_err = _verify_signature_over_envelope(leaf, leaf_signature_b64, leaf_signer_key)
        if leaf_err is not None:
            return ChainVerifyResult(
                valid=False,
                reason_code=leaf_err.reason_code,
                detail=f"leaf: {leaf_err.detail}",
            )

        # Pairwise subset + expiry walk: chain[0] → chain[1] → ... → chain[last] → leaf.
        for i in range(len(chain) - 1):
            subset_detail = _enforce_subset_permissions(
                chain[i].passport_json, chain[i + 1].passport_json
            )
            if subset_detail is not None:
                return _err(
                    "permission_elevation_in_chain",
                    f"chain[{i}]→chain[{i + 1}]: {subset_detail}",
                )
            if not _is_expiry_non_extending(
                chain[i].passport_json, chain[i + 1].passport_json
            ):
                return _err(
                    "expiry_extension_in_chain",
                    f"chain[{i}]→chain[{i + 1}]",
                )
        last_ancestor = chain[-1].passport_json
        leaf_subset_detail = _enforce_subset_permissions(last_ancestor, leaf)
        if leaf_subset_detail is not None:
            return _err(
                "permission_elevation_in_chain",
                f"chain[{len(chain) - 1}]→leaf: {leaf_subset_detail}",
            )
        if not _is_expiry_non_extending(last_ancestor, leaf):
            return _err(
                "expiry_extension_in_chain",
                f"chain[{len(chain) - 1}]→leaf",
            )

        return _ok(derive_tier(chain[0].passport_json))
