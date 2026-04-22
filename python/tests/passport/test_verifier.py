"""C19.4 tests — PassportVerifier local verification.

17 tests. Covers single-passport path (issuer.type=self and platform/gate
sentinel) and full chain path. Spec §13 rows 10–16 covered locally.
Rows 17, 18 (platform/gate root delegation) are deferred to C19.7
because they require backend key resolution.
"""

from __future__ import annotations

import base64
import copy
from datetime import timedelta
from typing import Any

import nacl.signing
import pytest
from pydantic import ValidationError

from modei.passport.canonical import canonicalize_strict
from modei.passport.credentials import AgentCredentials
from modei.passport.envelope import (
    DelegationChainEntry,
    Envelope,
    EnvelopeIssuer,
    PassportIdentity,
    PassportPermission,
    PassportProvenance,
)
from modei.passport.issuer import PassportIssuer
from modei.passport.tier import TrustTier
from modei.passport.verifier import PassportVerifier


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _sign(env: Envelope, priv_seed: bytes) -> str:
    canonical = canonicalize_strict(env.model_dump(mode="json"))
    sig_bytes = nacl.signing.SigningKey(priv_seed).sign(canonical).signature
    return base64.b64encode(sig_bytes).decode("ascii")


def _issue_self(
    creds: AgentCredentials, *, delegation_authority: bool = False,
    permissions: Any = None, expires_in: timedelta = timedelta(days=30),
    identity_claim: str = "a@example.com",
) -> tuple[Envelope, str]:
    issuer = PassportIssuer(creds, identity_claim=identity_claim)
    return issuer.self_issue(
        permissions=permissions or [{"permission_key": "api:read", "constraints": {}}],
        expires_in=expires_in,
        delegation_authority=delegation_authority,
    )


def _build_delegate_chain_from_root(
    depth: int,
    root_creds: AgentCredentials,
    *,
    root_permissions: list[dict[str, Any]] | None = None,
    leaf_permissions: list[dict[str, Any]] | None = None,
    link_expires_at: str | None = None,
    leaf_expires_at: str | None = None,
    all_have_authority: bool = True,
    authority_missing_at_index: int | None = None,
) -> tuple[Envelope, str, list[AgentCredentials]]:
    """Construct a self-rooted delegation chain of ``depth`` links plus a leaf.

    Returns ``(leaf_envelope, leaf_signature_b64, [root_creds, ..., leaf_creds])``.
    """
    from modei.passport.issuer import _format_iso_ms_z  # type: ignore
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    link_expires = link_expires_at or _format_iso_ms_z(now + timedelta(days=30))
    leaf_expires = leaf_expires_at or _format_iso_ms_z(now + timedelta(days=29))
    issued = _format_iso_ms_z(now)

    root_perms = root_permissions or [{"permission_key": "api:read", "constraints": {}}]

    # Root (chain[0]): self-issued.
    root_env = Envelope(
        schema_version=2,
        passport_id=f"pp_self_root",
        identity=PassportIdentity(
            agent_id=root_creds.agent_id,
            agent_name="root@example.com",
            public_key=root_creds.public_key_b64,
        ),
        permissions=[PassportPermission(**p) for p in root_perms],
        provenance=PassportProvenance(
            issuer=EnvelopeIssuer(
                type="self",
                id="self:" + __import__("hashlib").sha256(
                    base64.b64decode(root_creds.public_key_b64)
                ).hexdigest(),
                key_id="self",
            ),
            gate_id=None,
            catalog_content_hash=None,
            catalog_version=None,
            delegation_chain=None,
            issued_at=issued,
            expires_at=link_expires,
        ),
        delegation_authority=all_have_authority and authority_missing_at_index != 0,
        verification_evidence=[],
    )
    root_sig = _sign(root_env, root_creds.private_key_bytes)

    chain_entries: list[DelegationChainEntry] = [
        DelegationChainEntry(passport_json=root_env, signature=root_sig)
    ]
    all_creds: list[AgentCredentials] = [root_creds]

    # Build intermediate delegate links, each signed by its parent.
    for i in range(1, depth):
        child_creds = AgentCredentials.generate()
        # chain entries so far are chain[0..i-1]. Building chain entry i.
        parent_chain: list[DelegationChainEntry] = list(chain_entries)
        child_env = Envelope(
            schema_version=2,
            passport_id=f"pp_self_link_{i}",
            identity=PassportIdentity(
                agent_id=child_creds.agent_id,
                agent_name=f"link{i}@example.com",
                public_key=child_creds.public_key_b64,
            ),
            permissions=[PassportPermission(**p) for p in root_perms],
            provenance=PassportProvenance(
                issuer=EnvelopeIssuer(
                    type="delegate", id=f"delegate:pp_self_root", key_id="self"
                ),
                gate_id=None,
                catalog_content_hash=None,
                catalog_version=None,
                delegation_chain=parent_chain,
                issued_at=issued,
                expires_at=link_expires,
            ),
            delegation_authority=all_have_authority and authority_missing_at_index != i,
            verification_evidence=[],
        )
        parent_priv_seed = all_creds[i - 1].private_key_bytes
        child_sig = _sign(child_env, parent_priv_seed)

        chain_entries.append(DelegationChainEntry(passport_json=child_env, signature=child_sig))
        all_creds.append(child_creds)

    # Build the LEAF (not in chain itself). Its chain = all the links we built.
    leaf_creds = AgentCredentials.generate()
    leaf_perms_final = leaf_permissions or root_perms
    leaf_env = Envelope(
        schema_version=2,
        passport_id="pp_self_leaf",
        identity=PassportIdentity(
            agent_id=leaf_creds.agent_id,
            agent_name="leaf@example.com",
            public_key=leaf_creds.public_key_b64,
        ),
        permissions=[PassportPermission(**p) for p in leaf_perms_final],
        provenance=PassportProvenance(
            issuer=EnvelopeIssuer(
                type="delegate", id="delegate:pp_self_root", key_id="self"
            ),
            gate_id=None,
            catalog_content_hash=None,
            catalog_version=None,
            delegation_chain=chain_entries,
            issued_at=issued,
            expires_at=leaf_expires,
        ),
        delegation_authority=False,
        verification_evidence=[],
    )
    # Leaf is signed by last chain entry's private key.
    leaf_sig = _sign(leaf_env, all_creds[-1].private_key_bytes)
    all_creds.append(leaf_creds)
    return leaf_env, leaf_sig, all_creds


def _as_dict(env: Envelope) -> dict[str, Any]:
    return env.model_dump(mode="json")


# ---------------------------------------------------------------------------
# single-passport path
# ---------------------------------------------------------------------------


def test_verify_self_issued_valid() -> None:
    creds = AgentCredentials.generate()
    env, sig = _issue_self(creds)
    result = PassportVerifier().verify(env, sig)
    assert result.valid is True
    assert result.tier == TrustTier.L0


def test_verify_self_issued_tampered_signature() -> None:
    creds = AgentCredentials.generate()
    env, sig = _issue_self(creds)
    # Flip a bit in the signature.
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 0x01
    bad_sig = base64.b64encode(bytes(raw)).decode("ascii")
    result = PassportVerifier().verify(env, bad_sig)
    assert result.valid is False
    assert result.reason_code == "signature_invalid"


def test_verify_self_issued_tampered_envelope() -> None:
    creds = AgentCredentials.generate()
    env, sig = _issue_self(creds)
    # Mutate envelope after signing.
    tampered = copy.deepcopy(env)
    tampered = tampered.model_copy(update={"passport_id": env.passport_id + "x"})
    result = PassportVerifier().verify(tampered, sig)
    assert result.valid is False
    assert result.reason_code == "signature_invalid"


def test_verify_invalid_envelope_shape() -> None:
    result = PassportVerifier().verify({"not": "a valid envelope"}, "somesig")
    assert result.valid is False
    assert result.reason_code == "invalid_envelope_shape"


def test_verify_unsupported_schema_version() -> None:
    # schema_version=1 is a wrong integer — backend distinguishes this from shape errors.
    # SDK pre-validates the raw input before Pydantic construction to preserve the distinction.
    bad = {
        "schema_version": 1,
        "passport_id": "pp_x",
        "identity": {"agent_id": "a", "agent_name": None, "public_key": "k"},
        "permissions": [],
        "provenance": {
            "issuer": {"type": "self", "id": "self:x", "key_id": "self"},
            "gate_id": None, "catalog_content_hash": None, "catalog_version": None,
            "delegation_chain": None, "issued_at": "t", "expires_at": "t",
        },
        "delegation_authority": False,
        "verification_evidence": [],
    }
    result = PassportVerifier().verify(bad, "sig")
    assert result.valid is False
    assert result.reason_code == "unsupported_schema_version"


def test_verify_pydantic_error_structure_pinned() -> None:
    """Pin Pydantic v2 error structure for schema_version Literal failures.

    A Pydantic upgrade that changes error representation should break THIS
    test (the pinned contract) rather than silently break
    test_verify_unsupported_schema_version's distinction logic. This is the
    canary: if this test fails after a pydantic bump, look at
    verifier._parse_envelope to confirm the peek-before-construct logic is
    still sufficient.
    """
    bad = {
        "schema_version": 99,
        "passport_id": "pp_x",
        "identity": {"agent_id": "a", "agent_name": None, "public_key": "k"},
        "permissions": [],
        "provenance": {
            "issuer": {"type": "self", "id": "self:x", "key_id": "self"},
            "gate_id": None, "catalog_content_hash": None, "catalog_version": None,
            "delegation_chain": None, "issued_at": "t", "expires_at": "t",
        },
        "delegation_authority": False,
        "verification_evidence": [],
    }
    with pytest.raises(ValidationError) as exc_info:
        Envelope.model_validate(bad)
    errors = exc_info.value.errors()
    # Pin the structure our verifier relies on indirectly:
    # - .errors() is a list of dicts
    # - each error has a 'loc' tuple
    # - failure on schema_version reports 'schema_version' somewhere in loc
    assert isinstance(errors, list) and len(errors) >= 1
    schema_version_errors = [e for e in errors if "schema_version" in tuple(e.get("loc", ()))]
    assert schema_version_errors, (
        "pydantic no longer reports schema_version failures with loc=('schema_version',); "
        "check verifier._parse_envelope peek logic"
    )


def test_verify_signature_malformed_not_base64() -> None:
    creds = AgentCredentials.generate()
    env, _ = _issue_self(creds)
    result = PassportVerifier().verify(env, "!!!not-base64!!!")
    assert result.valid is False
    assert result.reason_code == "signature_malformed"


def test_verify_signature_wrong_length() -> None:
    creds = AgentCredentials.generate()
    env, _ = _issue_self(creds)
    short = base64.b64encode(b"A" * 32).decode("ascii")  # 32 bytes, not 64
    result = PassportVerifier().verify(env, short)
    assert result.valid is False
    assert result.reason_code == "signature_malformed"


def test_verify_public_key_malformed() -> None:
    creds = AgentCredentials.generate()
    env, sig = _issue_self(creds)
    # Swap in a garbage pubkey in the identity.
    bad_env = env.model_copy(
        update={"identity": env.identity.model_copy(update={"public_key": "!!!not-base64!!!"})}
    )
    # Caution: tampering the envelope changes its canonical bytes; the
    # signature will also be invalid. The verifier short-circuits on
    # public_key_malformed before reaching signature verification, which
    # is what we want to exercise.
    result = PassportVerifier().verify(bad_env, sig)
    assert result.valid is False
    assert result.reason_code == "public_key_malformed"


def test_verify_envelope_too_large() -> None:
    # Construct an envelope whose canonicalized size exceeds 64KB.
    # permissions list with large permission_key strings does the job.
    creds = AgentCredentials.generate()
    big_perms = [
        {"permission_key": "x" * 200, "constraints": {"k": "v" * 200}}
        for _ in range(200)  # ~80KB of permission strings
    ]
    issuer = PassportIssuer(creds, identity_claim="x@y.z")
    with pytest.raises(ValueError, match="envelope_too_large"):
        issuer.self_issue(permissions=big_perms, expires_in=timedelta(days=1))


def test_verify_platform_issuer_returns_key_unavailable() -> None:
    # Manually build a platform-issued envelope shape — signature doesn't
    # need to be real because we expect the verifier to bail early.
    env_dict = {
        "schema_version": 2,
        "passport_id": "pp_platform_x",
        "identity": {"agent_id": "a", "agent_name": "x", "public_key": "a" * 44},
        "permissions": [{"permission_key": "api:read", "constraints": {}}],
        "provenance": {
            "issuer": {"type": "platform", "id": "issuer:org_1", "key_id": "ik_1"},
            "gate_id": None, "catalog_content_hash": None, "catalog_version": None,
            "delegation_chain": None,
            "issued_at": "2026-04-22T00:00:00.000Z",
            "expires_at": "2026-05-22T00:00:00.000Z",
        },
        "delegation_authority": False,
        "verification_evidence": [],
    }
    result = PassportVerifier().verify(env_dict, "any_sig")
    assert result.valid is False
    assert result.reason_code == "signature_key_unavailable"
    assert result.detail is not None
    assert "platform" in result.detail


def test_verify_gate_issuer_returns_key_unavailable() -> None:
    env_dict = {
        "schema_version": 2,
        "passport_id": "pp_gate_x",
        "identity": {"agent_id": "a", "agent_name": "x", "public_key": "a" * 44},
        "permissions": [{"permission_key": "api:read", "constraints": {}}],
        "provenance": {
            "issuer": {"type": "gate", "id": "gate_1", "key_id": "gk_1"},
            "gate_id": "gate_1", "catalog_content_hash": None, "catalog_version": None,
            "delegation_chain": None,
            "issued_at": "2026-04-22T00:00:00.000Z",
            "expires_at": "2026-05-22T00:00:00.000Z",
        },
        "delegation_authority": False,
        "verification_evidence": [],
    }
    result = PassportVerifier().verify(env_dict, "any_sig")
    assert result.valid is False
    assert result.reason_code == "signature_key_unavailable"
    assert result.detail is not None
    assert "gate" in result.detail


# ---------------------------------------------------------------------------
# delegation chain path (spec §13 rows 10–16)
# ---------------------------------------------------------------------------


def test_verify_delegation_depth_1_self_root_permit() -> None:
    """Spec §13 row 10: 1-link chain (just the root), self-rooted."""
    root_creds = AgentCredentials.generate()
    leaf, sig, _ = _build_delegate_chain_from_root(depth=1, root_creds=root_creds)
    result = PassportVerifier().verify(leaf, sig)
    assert result.valid is True, f"unexpected BLOCK: {result.reason_code} {result.detail}"
    assert result.tier == TrustTier.L0


def test_verify_delegation_depth_3_self_root_permit() -> None:
    """Spec §13 row 11: 3-link chain."""
    root_creds = AgentCredentials.generate()
    leaf, sig, _ = _build_delegate_chain_from_root(depth=3, root_creds=root_creds)
    result = PassportVerifier().verify(leaf, sig)
    assert result.valid is True, f"unexpected BLOCK: {result.reason_code} {result.detail}"
    assert result.tier == TrustTier.L0


def test_verify_delegation_depth_6_rejects() -> None:
    """Spec §13 row 12: 6-link chain exceeds max depth 5."""
    root_creds = AgentCredentials.generate()
    leaf, sig, _ = _build_delegate_chain_from_root(depth=6, root_creds=root_creds)
    result = PassportVerifier().verify(leaf, sig)
    assert result.valid is False
    assert result.reason_code == "delegation_chain_too_deep"


def test_verify_delegation_authority_missing() -> None:
    """Spec §13 row 13: middle link lacks delegation_authority."""
    root_creds = AgentCredentials.generate()
    leaf, sig, _ = _build_delegate_chain_from_root(
        depth=3, root_creds=root_creds, authority_missing_at_index=1,
    )
    result = PassportVerifier().verify(leaf, sig)
    assert result.valid is False
    assert result.reason_code == "delegation_authority_missing"


def test_verify_permission_elevation_in_chain() -> None:
    """Spec §13 rows 14+15: leaf adds a permission parent lacks, OR loosens a constraint."""
    root_creds = AgentCredentials.generate()
    # Row 14 path: leaf has a permission_key absent from root.
    leaf, sig, all_creds = _build_delegate_chain_from_root(
        depth=2,
        root_creds=root_creds,
        root_permissions=[{"permission_key": "api:read", "constraints": {}}],
        leaf_permissions=[{"permission_key": "api:write", "constraints": {}}],
    )
    # Resign leaf with the last chain cred's key (the build helper already did),
    # but we mutated leaf permissions via the helper params — signature is over
    # the tampered permissions, so signature is valid; subset check must catch.
    result = PassportVerifier().verify(leaf, sig)
    assert result.valid is False
    assert result.reason_code == "permission_elevation_in_chain"

    # Row 15 path: leaf loosens a numeric constraint.
    leaf2, sig2, _ = _build_delegate_chain_from_root(
        depth=2,
        root_creds=AgentCredentials.generate(),
        root_permissions=[{"permission_key": "api:read", "constraints": {"max_per_action_cost": 100}}],
        leaf_permissions=[{"permission_key": "api:read", "constraints": {"max_per_action_cost": 500}}],
    )
    result2 = PassportVerifier().verify(leaf2, sig2)
    assert result2.valid is False
    assert result2.reason_code == "permission_elevation_in_chain"


def test_verify_expiry_extension_in_chain() -> None:
    """Spec §13 row 16: leaf expiry is later than ancestor expiry."""
    from modei.passport.issuer import _format_iso_ms_z  # type: ignore
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    # Ancestor expires in 1 hour; leaf expires in 24 hours (extension).
    root_creds = AgentCredentials.generate()
    leaf, sig, _ = _build_delegate_chain_from_root(
        depth=2,
        root_creds=root_creds,
        link_expires_at=_format_iso_ms_z(now + timedelta(hours=1)),
        leaf_expires_at=_format_iso_ms_z(now + timedelta(hours=24)),
    )
    result = PassportVerifier().verify(leaf, sig)
    assert result.valid is False
    assert result.reason_code == "expiry_extension_in_chain"
