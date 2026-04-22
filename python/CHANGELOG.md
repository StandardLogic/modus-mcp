# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [PEP 440](https://peps.python.org/pep-0440/) for
version numbering.

## [Unreleased]

## [1.1.0a1] - 2026-04-22

Prerelease. Install with `pip install modei-python==1.1.0a1 --pre`. A default
`pip install modei-python` will NOT install this version — PEP 440 resolvers
skip prereleases without an explicit `--pre` flag or exact version pin.

### Added

- **Self-issued passport workflows** (spec §2 Self-Issued L1 Passports). New
  submodule `modei.passport` exporting: `PassportIssuer`, `PassportVerifier`,
  `AgentCredentials`, `DelegationBuilder`, `TrustTier`, `Envelope`,
  `SignedPassport`, `ChainVerifyResult`. All eight are also re-exported at
  top-level `modei.*` so `from modei import PassportIssuer, AgentCredentials,
  DelegationBuilder` works verbatim per spec §11.1 example.
- `modei.passport.SignedPassport` — `NamedTuple(envelope, signature)`. Returned
  by `PassportIssuer.self_issue()` and `DelegationBuilder.sign()`; consumed by
  `DelegationBuilder(parent=...)`. Tuple-unpack remains supported
  (`env, sig = issuer.self_issue(...)`) alongside field access
  (`signed.envelope`, `signed.signature`).
- `modei.passport.derive_self_agent_id(public_key_b64)` — mirrors backend
  `deriveSelfAgentId`. Produces
  `"agent_self_" + base64url(sha256(pubkey))[:32]`. **Behavior divergence from
  backend (intentional hardening):** raises `ValueError` on malformed base64
  input. Backend `Buffer.from(..., 'base64')` silently drops invalid characters
  and returns a real-but-wrong agent_id. SDK fail-fast is preferred; backend
  behavior should be tightened in a future cleanup.
- `modei.passport.CanonicalizationError`, `DelegationError`,
  `DelegationSubsetError`, `DelegationChainTooDeepError`,
  `DelegationAuthorityMissingError` — typed exceptions for local validation
  failures. All delegation errors subclass `ValueError` so broad catches still
  work per spec §11.1 example.
- `modei.passport.PassportVerifyReasonCode` (Literal type) +
  `PASSPORT_VERIFY_REASON_CODES` (frozenset) — the 23-code backend taxonomy
  for interpreting `ChainVerifyResult.reason_code` or REST-level verify
  responses.
- `modei.passport.canonicalize_strict`, `derive_tier`, `tier_rank` — utility
  functions for power users composing envelopes manually.

### Changed

- **`modei.compute_content_hash` now raises on non-finite floats.** When the
  input object contains `NaN`, `+Infinity`, or `-Infinity` anywhere in its
  tree, the function raises `modei.passport.CanonicalizationError` with
  `reason_code='non_finite_number_in_canonical_input'` and a JSON path to the
  offending value. Previously, `canonicaljson` silently coerced non-finite
  floats to the JSON token `null`, producing degenerate hash values. The new
  behavior matches the Modei backend canonicalizer and RFC 8785 §3.2.2.4.
  `modei.verify_content_hash(obj, expected_hash)`, which wraps
  `compute_content_hash`, now also raises rather than returning `False` when
  `obj` contains non-finite floats.
- **Canonicalizer migrated from `canonicaljson` to `jcs==0.2.1`.** Output is
  byte-identical for all realistic JSON. Two edge-case divergences where the
  old behavior was a bug: (1) non-finite floats now raise (see entry above);
  (2) IEEE 754 negative zero (`-0.0`) serializes as `"0"` per RFC 8785
  §3.2.2.3, not `"-0.0"`. Content hashes involving `-0.0` were never matching
  backend-computed hashes under 1.0.0; this migration aligns the SDK with the
  backend.

### Removed

- Dependency: `canonicaljson>=2.0.0`. Replaced by `jcs==0.2.1`.

### Added (dependencies)

- `jcs==0.2.1` — exact pin per spec §11.2 cross-SDK byte-parity invariant.
  Canonicalizer upgrade is a coordinated cross-stack change requiring the
  §13 row 23 byte-equality fixture suite to pass; do not loosen this pin.
  `pynacl>=1.5.0` and other transitive deps unchanged.

## [1.0.0]

Initial release. REST client for the Modei platform API.
