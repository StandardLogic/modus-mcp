"""C19.4 tests — PassportIssuer self-issuance.

8 tests. Test 8 is the cross-backend signature parity fixture — proves
the canonicalize + sign primitives produce byte-identical output to the
backend's ``json-canonicalize`` + ``@noble/ed25519``.
"""

from __future__ import annotations

import base64
import hashlib
import re
from datetime import timedelta
from typing import Any

import pytest

from modei.passport.credentials import AgentCredentials
from modei.passport.envelope import Envelope
from modei.passport.issuer import PassportIssuer
from modei.passport.tier import TrustTier
from modei.passport.verifier import PassportVerifier


# ---------------------------------------------------------------------------
# 1. self-issue envelope shape
# ---------------------------------------------------------------------------


def _issue(
    *,
    identity_claim: Any = "alice@dev.local",
    permissions: Any = None,
    expires_in: timedelta = timedelta(days=30),
    delegation_authority: bool = False,
) -> tuple[Envelope, str, AgentCredentials]:
    creds = AgentCredentials.generate()
    issuer = PassportIssuer(creds, identity_claim=identity_claim)
    env, sig = issuer.self_issue(
        permissions=permissions or [{"permission_key": "api:read", "constraints": {}}],
        expires_in=expires_in,
        delegation_authority=delegation_authority,
    )
    return env, sig, creds


def test_self_issue_produces_valid_envelope_shape() -> None:
    env, sig, _ = _issue()
    assert env.schema_version == 2
    assert re.fullmatch(r"pp_self_[0-9a-f]{32}", env.passport_id)
    assert env.provenance.issuer.type == "self"
    assert env.provenance.issuer.key_id == "self"
    assert env.provenance.delegation_chain is None
    assert env.provenance.gate_id is None
    assert env.provenance.catalog_content_hash is None
    assert env.provenance.catalog_version is None
    assert env.verification_evidence == []
    # Signature is 64 bytes → 88-char base64 (including one '=' padding at 44-byte digest; 64 bytes → 88 chars).
    assert len(base64.b64decode(sig, validate=True)) == 64


def test_self_issue_agent_id_matches_credentials() -> None:
    env, _, creds = _issue()
    assert env.identity.agent_id == creds.agent_id
    assert env.identity.public_key == creds.public_key_b64


def test_self_issue_issuer_id_is_self_sha256_hex() -> None:
    env, _, creds = _issue()
    pk_bytes = base64.b64decode(creds.public_key_b64, validate=True)
    expected = "self:" + hashlib.sha256(pk_bytes).hexdigest()
    assert env.provenance.issuer.id == expected


def test_self_issue_expires_at_honors_expires_in() -> None:
    env, _, _ = _issue(expires_in=timedelta(days=7))
    # Parse the ISO 8601 millisecond format.
    # "2026-04-22T00:00:00.000Z" → strip the Z, fromisoformat.
    from datetime import datetime, timezone

    def parse(s: str) -> datetime:
        assert s.endswith("Z")
        return datetime.fromisoformat(s[:-1]).replace(tzinfo=timezone.utc)

    issued = parse(env.provenance.issued_at)
    expires = parse(env.provenance.expires_at)
    delta = expires - issued
    assert abs(delta - timedelta(days=7)) < timedelta(seconds=1)


def test_self_issue_delegation_authority_default_false() -> None:
    env, _, _ = _issue()
    assert env.delegation_authority is False


def test_self_issue_delegation_authority_true_when_set() -> None:
    env, _, _ = _issue(delegation_authority=True)
    assert env.delegation_authority is True


def test_self_issue_signature_verifies_locally_and_none_identity_claim() -> None:
    # Round-trip: issue → verify → valid L0. Also pins that identity_claim=None
    # produces identity.agent_name=None (SDK permissive; server-side rejects).
    creds = AgentCredentials.generate()
    issuer = PassportIssuer(creds, identity_claim=None)
    env, sig = issuer.self_issue(
        permissions=[{"permission_key": "api:read", "constraints": {}}],
        expires_in=timedelta(days=1),
    )
    assert env.identity.agent_name is None

    result = PassportVerifier().verify(env, sig)
    assert result.valid is True
    assert result.tier == TrustTier.L0


# ---------------------------------------------------------------------------
# 2. Cross-backend signature parity fixture
# ---------------------------------------------------------------------------
#
# Ground truth generated 2026-04-22 via
# ``~/Projects/modei/scripts/sdk_parity_fixture.ts``. Deterministic: the
# Ed25519 seed is 32 zero bytes, so sign() is reproducible across runs
# and across SDK implementations. Backend round-trip result was
# ``{"valid": true}``.
#
# Recipe to regenerate:
#   $ cd ~/Projects/modei
#   $ npx tsx scripts/sdk_parity_fixture.ts
#
# If this test fails, STOP. Either the canonicalizer or the signer
# drifted from backend parity — that's a release-blocker condition per
# spec §11.2 (pinned canonicalizer) and §13 row 26 (cross-SDK parity).

# Deterministic keypair — 32-byte zero seed.
FIXTURE_PUB_B64 = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik="
FIXTURE_PRIV_SEED = bytes(32)
FIXTURE_AGENT_ID = "agent_self_E545QOZLVJFyIIjZoNdBYo_IJuCUddNB"
FIXTURE_ISSUER_ID = (
    "self:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"
)
FIXTURE_ISSUED_AT = "2026-04-22T00:00:00.000Z"
FIXTURE_EXPIRES_AT = "2026-05-22T00:00:00.000Z"
FIXTURE_PASSPORT_ID = "pp_self_fixture_00000001"
FIXTURE_AGENT_NAME = "fixture@dev.local"
FIXTURE_SIGNATURE_B64 = (
    "KGMwOp9+holhnLRlZwLpUardsQx2E+QWGT2/q27OrfGieXpFEA705UTkLs1hAYd3OkB9/6DuGVI2VfV9iYSHDA=="
)
FIXTURE_CANONICAL_HEX = (
    "7b2264656c65676174696f6e5f617574686f72697479223a66616c73652c22696465"
    "6e74697479223a7b226167656e745f6964223a226167656e745f73656c665f453534"
    "35514f5a4c564a467949496a5a6f4e6442596f5f494a75435564644e42222c226167"
    "656e745f6e616d65223a2266697874757265406465762e6c6f63616c222c22707562"
    "6c69635f6b6579223a224f326f6e764d3632704331696f366a514b6d384e63325579"
    "46586364346b4f6d4f7342496f59745a32696b3d227d2c2270617373706f72745f69"
    "64223a2270705f73656c665f666978747572655f3030303030303031222c22706572"
    "6d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b7d2c227065726d"
    "697373696f6e5f6b6579223a226170693a72656164227d5d2c2270726f76656e616e"
    "6365223a7b22636174616c6f675f636f6e74656e745f68617368223a6e756c6c2c22"
    "636174616c6f675f76657273696f6e223a6e756c6c2c2264656c65676174696f6e5f"
    "636861696e223a6e756c6c2c22657870697265735f6174223a22323032362d30352d"
    "32325430303a30303a30302e3030305a222c22676174655f6964223a6e756c6c2c22"
    "6973737565645f6174223a22323032362d30342d32325430303a30303a30302e3030"
    "305a222c22697373756572223a7b226964223a2273656c663a313339653339343065"
    "36346235343931373232303838643961306437343136323866633832366530393437"
    "356433343161373830616364653363346238303730222c226b65795f6964223a2273"
    "656c66222c2274797065223a2273656c66227d7d2c22736368656d615f7665727369"
    "6f6e223a322c22766572696669636174696f6e5f65766964656e6365223a5b5d7d"
)


def test_self_issue_cross_backend_signature_parity() -> None:
    """Backend ground-truth byte equality for canonicalize + sign.

    Manually constructs the fixture envelope (fixed timestamps + passport_id,
    bypassing ``PassportIssuer.self_issue()`` so no random fields enter).
    Canonicalizes, signs with the deterministic zero-seed key, and asserts
    both (a) canonical bytes match backend hex, (b) Ed25519 signature
    matches backend b64. Ed25519 over a fixed message is deterministic;
    any drift is a release blocker.
    """
    import nacl.signing

    from modei.passport.canonical import canonicalize_strict
    from modei.passport.envelope import (
        EnvelopeIssuer,
        PassportIdentity,
        PassportPermission,
        PassportProvenance,
    )

    env = Envelope(
        schema_version=2,
        passport_id=FIXTURE_PASSPORT_ID,
        identity=PassportIdentity(
            agent_id=FIXTURE_AGENT_ID,
            agent_name=FIXTURE_AGENT_NAME,
            public_key=FIXTURE_PUB_B64,
        ),
        permissions=[
            PassportPermission(permission_key="api:read", constraints={}),
        ],
        provenance=PassportProvenance(
            issuer=EnvelopeIssuer(type="self", id=FIXTURE_ISSUER_ID, key_id="self"),
            gate_id=None,
            catalog_content_hash=None,
            catalog_version=None,
            delegation_chain=None,
            issued_at=FIXTURE_ISSUED_AT,
            expires_at=FIXTURE_EXPIRES_AT,
        ),
        delegation_authority=False,
        verification_evidence=[],
    )

    canonical_bytes = canonicalize_strict(env.model_dump(mode="json"))
    assert canonical_bytes.hex() == FIXTURE_CANONICAL_HEX, (
        "canonical bytes diverged from backend — release blocker"
    )

    signing_key = nacl.signing.SigningKey(FIXTURE_PRIV_SEED)
    signature_b64 = base64.b64encode(signing_key.sign(canonical_bytes).signature).decode("ascii")
    assert signature_b64 == FIXTURE_SIGNATURE_B64, (
        "signature diverged from backend — release blocker"
    )

    # Local round-trip: SDK verifier accepts the backend-matching signature.
    result = PassportVerifier().verify(env, signature_b64)
    assert result.valid is True
    assert result.tier == TrustTier.L0
