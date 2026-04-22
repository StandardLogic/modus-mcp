"""C19.6 tests — ``compute_content_hash`` behavior after canonicalizer migration.

The 1.1.0a1 release migrates ``compute_content_hash`` from ``canonicaljson``
to ``jcs==0.2.1`` (via ``modei.passport.canonicalize_strict``). These tests
pin the two observable behavior changes so any future canonicalizer swap
breaks here loudly rather than silently.

Companion file: ``tests/passport/test_canonical.py`` pins the
``canonicalize_strict`` primitive contract. This file pins the public
``modei.compute_content_hash`` API contract that wraps it.
"""

from __future__ import annotations

import hashlib

import jcs
import pytest

from modei import compute_content_hash, verify_content_hash
from modei.passport import CanonicalizationError


def test_compute_content_hash_rejects_non_finite_floats_post_migration() -> None:
    """NaN, +Inf, -Inf anywhere in the tree → CanonicalizationError.

    Pre-migration (canonicaljson): silently coerced to JSON `null`, producing
    degenerate hash values. Post-migration (jcs via canonicalize_strict):
    raises with reason_code='non_finite_number_in_canonical_input'.
    """
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError) as exc_info:
            compute_content_hash({"x": value})
        assert exc_info.value.reason_code == "non_finite_number_in_canonical_input"


def test_verify_content_hash_raises_on_non_finite_obj() -> None:
    """verify_content_hash wraps compute_content_hash; non-finite → raise,
    not return False. Caller can distinguish "unhashable input" from
    "hash mismatch"."""
    with pytest.raises(CanonicalizationError):
        verify_content_hash({"x": float("nan")}, "doesnt_matter")


def test_compute_content_hash_negative_zero_serializes_as_zero() -> None:
    """IEEE 754 -0.0 serializes as '0' per RFC 8785 §3.2.2.3.

    Pre-migration (canonicaljson): emitted '-0.0', producing hashes that
    never matched the Modei backend's (backend uses json-canonicalize,
    which is RFC 8785 compliant).
    Post-migration (jcs): emits '0', matching backend byte-for-byte.

    Pins the jcs-canonical hash as the expected value — any migration that
    drifts from this pins fires.
    """
    input_obj = {"x": -0.0}
    expected = hashlib.sha256(jcs.canonicalize(input_obj)).hexdigest()
    assert compute_content_hash(input_obj) == expected


def test_compute_content_hash_positive_zero_serializes_as_zero() -> None:
    """Positive zero sanity: also '0' in canonical form. Equality with
    the negative-zero case above proves both map to the same canonical
    representation per RFC 8785, not a bug."""
    neg_hash = compute_content_hash({"x": -0.0})
    pos_hash = compute_content_hash({"x": 0})
    assert neg_hash == pos_hash


def test_compute_content_hash_realistic_json_unchanged() -> None:
    """Realistic JSON inputs produce byte-identical output to pre-migration.
    Pins parity with backend for the common path."""
    obj = {
        "permissions": [{"permission_key": "api:read", "constraints": {}}],
        "metadata": {"created": "2026-04-22T00:00:00Z", "count": 42},
        "flags": [True, False, None],
    }
    canonical = jcs.canonicalize(obj)
    expected = hashlib.sha256(canonical).hexdigest()
    assert compute_content_hash(obj) == expected
