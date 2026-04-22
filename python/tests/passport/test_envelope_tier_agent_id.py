"""C19.2 tests — agent_id derivation, trust tier, envelope model.

Single file by design (plan approval). Sections:
  1. derive_self_agent_id  (5 tests)
  2. TrustTier / derive_tier / tier_rank  (8 tests)
  3. Envelope Pydantic model  (6 tests — includes canonicalization round-trip)

Ground-truth agent_id fixtures were lifted from backend `deriveSelfAgentId`
via a one-shot ``tsx`` invocation (see AGENT_ID_FIXTURES docstring).
"""

from __future__ import annotations

import base64
import json
from typing import Any

import jcs
import pytest
from pydantic import ValidationError

from modei.passport.agent_id import derive_self_agent_id
from modei.passport.canonical import canonicalize_strict
from modei.passport.envelope import (
    DelegationChainEntry,
    Envelope,
    EnvelopeIssuer,
    PassportIdentity,
    PassportPermission,
    PassportProvenance,
)
from modei.passport.tier import TrustTier, derive_tier, tier_rank

# ---------------------------------------------------------------------------
# Ground-truth agent_id fixtures
# ---------------------------------------------------------------------------
#
# Generated 2026-04-22 via backend src/lib/passports/agent_id.ts — the
# authoritative TypeScript implementation. To reproduce:
#
#   $ cd ~/Projects/modei
#   $ cat > /tmp/derive_fixture.ts << 'EOF'
#   import { deriveSelfAgentId } from '/Users/jason/Projects/modei/src/lib/passports/agent_id'
#   const pk1 = Buffer.alloc(32, 0).toString('base64')
#   const pk2 = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64')
#   console.log('pk1_base64:', pk1)
#   console.log('pk1_agent_id:', deriveSelfAgentId(pk1))
#   console.log('pk2_base64:', pk2)
#   console.log('pk2_agent_id:', deriveSelfAgentId(pk2))
#   EOF
#   $ npx tsx /tmp/derive_fixture.ts
#
# stdout:
#   pk1_base64: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
#   pk1_agent_id: agent_self_Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOz
#   pk2_base64: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
#   pk2_agent_id: agent_self_Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLI
#
# These constants MUST match. Any drift is a spec-parity bug — STOP,
# investigate, do not rubber-stamp by regenerating.

PK1_BASE64 = base64.b64encode(bytes(32)).decode()
PK1_AGENT_ID = "agent_self_Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOz"
PK2_BASE64 = base64.b64encode(bytes(range(32))).decode()
PK2_AGENT_ID = "agent_self_Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLI"


# ---------------------------------------------------------------------------
# 1. derive_self_agent_id
# ---------------------------------------------------------------------------


def test_derive_self_agent_id_zero_key() -> None:
    assert derive_self_agent_id(PK1_BASE64) == PK1_AGENT_ID


def test_derive_self_agent_id_deterministic_random_key() -> None:
    assert derive_self_agent_id(PK2_BASE64) == PK2_AGENT_ID


def test_derive_self_agent_id_always_has_prefix_and_length() -> None:
    result = derive_self_agent_id(PK1_BASE64)
    assert result.startswith("agent_self_")
    assert len(result) == len("agent_self_") + 32 == 43


def test_derive_self_agent_id_rejects_invalid_base64() -> None:
    # validate=True rejects non-base64 alphabet (binascii.Error extends ValueError).
    with pytest.raises(ValueError):
        derive_self_agent_id("!!!not-base64!!!")


def test_derive_self_agent_id_does_not_enforce_32_byte_pubkey() -> None:
    # Backend parity: deriveSelfAgentId does not check pubkey length.
    # Signature verification catches length mismatches. Pin current
    # behavior so future changes are intentional.
    short_pubkey = base64.b64encode(b"short").decode()
    result = derive_self_agent_id(short_pubkey)
    assert result.startswith("agent_self_")
    assert len(result) == 43


# ---------------------------------------------------------------------------
# 2. TrustTier / derive_tier / tier_rank
# ---------------------------------------------------------------------------


def _minimal_envelope(
    issuer_type: str,
    *,
    delegation_chain: list[DelegationChainEntry] | None = None,
    permissions: list[PassportPermission] | None = None,
    delegation_authority: bool = False,
    expires_at: str = "2026-05-22T00:00:00Z",
    issued_at: str = "2026-04-22T00:00:00Z",
    passport_id: str = "pp_test",
) -> Envelope:
    return Envelope(
        schema_version=2,
        passport_id=passport_id,
        identity=PassportIdentity(
            agent_id="agent_test",
            agent_name=None,
            public_key=PK1_BASE64,
        ),
        permissions=permissions or [],
        provenance=PassportProvenance(
            issuer=EnvelopeIssuer(type=issuer_type, id=f"{issuer_type}:x", key_id="k"),
            gate_id=None,
            catalog_content_hash=None,
            catalog_version=None,
            delegation_chain=delegation_chain,
            issued_at=issued_at,
            expires_at=expires_at,
        ),
        delegation_authority=delegation_authority,
        verification_evidence=[],
    )


def test_derive_tier_self() -> None:
    assert derive_tier(_minimal_envelope("self")) == TrustTier.L0


def test_derive_tier_platform() -> None:
    assert derive_tier(_minimal_envelope("platform")) == TrustTier.L1


def test_derive_tier_gate() -> None:
    assert derive_tier(_minimal_envelope("gate")) == TrustTier.L2


def _delegate_chain(root_issuer_type: str) -> list[DelegationChainEntry]:
    root = _minimal_envelope(root_issuer_type, passport_id="pp_root")
    return [DelegationChainEntry(passport_json=root, signature="sig_placeholder")]


def test_derive_tier_delegate_root_self() -> None:
    leaf = _minimal_envelope(
        "delegate", delegation_chain=_delegate_chain("self"), passport_id="pp_leaf"
    )
    assert derive_tier(leaf) == TrustTier.L0


def test_derive_tier_delegate_root_platform() -> None:
    leaf = _minimal_envelope(
        "delegate", delegation_chain=_delegate_chain("platform"), passport_id="pp_leaf"
    )
    assert derive_tier(leaf) == TrustTier.L1


def test_derive_tier_delegate_root_gate() -> None:
    leaf = _minimal_envelope(
        "delegate", delegation_chain=_delegate_chain("gate"), passport_id="pp_leaf"
    )
    assert derive_tier(leaf) == TrustTier.L2


def test_derive_tier_delegate_with_null_chain_raises() -> None:
    # Caller-contract violation — mirror backend's `throw new Error`.
    bad = _minimal_envelope("delegate", delegation_chain=None)
    with pytest.raises(ValueError, match="delegation_chain is null/empty"):
        derive_tier(bad)


def test_tier_rank_ordering() -> None:
    assert tier_rank(TrustTier.L0) == 0
    assert tier_rank(TrustTier.L0_5) == 1
    assert tier_rank(TrustTier.L1) == 2
    assert tier_rank(TrustTier.L2) == 3
    assert tier_rank(TrustTier.L3) == 4
    # Monotonic strict ordering.
    tiers = [TrustTier.L0, TrustTier.L0_5, TrustTier.L1, TrustTier.L2, TrustTier.L3]
    ranks = [tier_rank(t) for t in tiers]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


# ---------------------------------------------------------------------------
# 3. Envelope Pydantic model
# ---------------------------------------------------------------------------

_VALID_ENVELOPE_DICT: dict[str, Any] = {
    "schema_version": 2,
    "passport_id": "pp_test_00000001",
    "identity": {
        "agent_id": "agent_self_Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOz",
        "agent_name": "alice@dev.local",
        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    },
    "permissions": [
        {
            "permission_key": "flights:book",
            "constraints": {"max_per_action_cost": 500},
        }
    ],
    "provenance": {
        "issuer": {"type": "self", "id": "self:abc123", "key_id": "self"},
        "gate_id": None,
        "catalog_content_hash": None,
        "catalog_version": None,
        "delegation_chain": None,
        "issued_at": "2026-04-22T00:00:00Z",
        "expires_at": "2026-05-22T00:00:00Z",
    },
    "delegation_authority": False,
    "verification_evidence": [],
}


def test_envelope_parses_valid_self_issued_minimal() -> None:
    env = Envelope.model_validate(_VALID_ENVELOPE_DICT)
    assert env.schema_version == 2
    assert env.provenance.issuer.type == "self"


def test_envelope_rejects_unknown_top_level_field() -> None:
    bad = dict(_VALID_ENVELOPE_DICT, unknown_field="surprise")
    with pytest.raises(ValidationError):
        Envelope.model_validate(bad)


@pytest.mark.parametrize("bad_version", [1, 3, "2"])
def test_envelope_rejects_schema_version_not_2(bad_version: Any) -> None:
    bad = dict(_VALID_ENVELOPE_DICT, schema_version=bad_version)
    with pytest.raises(ValidationError):
        Envelope.model_validate(bad)


def test_envelope_requires_delegation_authority() -> None:
    bad = {k: v for k, v in _VALID_ENVELOPE_DICT.items() if k != "delegation_authority"}
    with pytest.raises(ValidationError):
        Envelope.model_validate(bad)


def test_envelope_requires_verification_evidence() -> None:
    # No default. Matches backend assertCanonicalEnvelope.
    bad = {k: v for k, v in _VALID_ENVELOPE_DICT.items() if k != "verification_evidence"}
    with pytest.raises(ValidationError):
        Envelope.model_validate(bad)


def test_envelope_canonicalization_round_trip_byte_stable() -> None:
    """Pydantic dump + canonicalize must produce the same bytes as
    canonicalizing the source dict directly.

    First SDK-level proof that Pydantic model_dump is canonicalization-
    stable — no field reordering, no number reformatting, no hidden adds.
    The expected hex was generated by ``jcs.canonicalize(_VALID_ENVELOPE_DICT)``
    on 2026-04-22; compare below.
    """
    expected_from_source = jcs.canonicalize(_VALID_ENVELOPE_DICT)

    env = Envelope.model_validate(_VALID_ENVELOPE_DICT)
    dumped = env.model_dump(mode="json")
    actual_via_pydantic = canonicalize_strict(dumped)

    assert actual_via_pydantic == expected_from_source, (
        "Pydantic round-trip diverged from source-dict canonicalization.\n"
        f"  source  : {expected_from_source!r}\n"
        f"  pydantic: {actual_via_pydantic!r}"
    )

    # Second tier: assert the source-dict canonical form matches the
    # pre-computed hex baked into this test. Any change here signals a
    # canonicalizer-or-fixture change that demands attention.
    expected_hex = (
        "7b2264656c65676174696f6e5f617574686f72697479223a66616c73652c2269"
        "64656e74697479223a7b226167656e745f6964223a226167656e745f73656c66"
        "5f5a6d683672666869765864736a38474c6a702d4f4941695846495675346a4f"
        "7a222c226167656e745f6e616d65223a22616c696365406465762e6c6f63616c"
        "222c227075626c69635f6b6579223a2241414141414141414141414141414141"
        "4141414141414141414141414141414141414141414141414141413d227d2c22"
        "70617373706f72745f6964223a2270705f746573745f3030303030303031222c"
        "227065726d697373696f6e73223a5b7b22636f6e73747261696e7473223a7b22"
        "6d61785f7065725f616374696f6e5f636f7374223a3530307d2c227065726d69"
        "7373696f6e5f6b6579223a22666c69676874733a626f6f6b227d5d2c2270726f"
        "76656e616e6365223a7b22636174616c6f675f636f6e74656e745f6861736822"
        "3a6e756c6c2c22636174616c6f675f76657273696f6e223a6e756c6c2c226465"
        "6c65676174696f6e5f636861696e223a6e756c6c2c22657870697265735f6174"
        "223a22323032362d30352d32325430303a30303a30305a222c22676174655f69"
        "64223a6e756c6c2c226973737565645f6174223a22323032362d30342d323254"
        "30303a30303a30305a222c22697373756572223a7b226964223a2273656c663a"
        "616263313233222c226b65795f6964223a2273656c66222c2274797065223a22"
        "73656c66227d7d2c22736368656d615f76657273696f6e223a322c2276657269"
        "6669636174696f6e5f65766964656e6365223a5b5d7d"
    )
    assert actual_via_pydantic == bytes.fromhex(expected_hex)
