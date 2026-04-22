"""RFC 8785 canonicalizer tests — byte-equality against shared fixture suite.

The fixtures file is a verbatim copy of
``~/Projects/modei/__tests__/canon/rfc8785-fixtures.json``. Cross-SDK
byte-equality is a release invariant (spec §11.2, §13 row 23): if any
fixture diverges between ``jcs`` and the backend's ``json-canonicalize``,
STOP — do not paper over the divergence.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from modei.passport.canonical import CanonicalizationError, canonicalize_strict

FIXTURES_PATH = Path(__file__).parent / "fixtures" / "rfc8785-fixtures.json"

_SENTINEL_DECODE = {
    "NaN": float("nan"),
    "Infinity": float("inf"),
    "-Infinity": float("-inf"),
}


def _load_fixtures() -> list[dict[str, Any]]:
    with FIXTURES_PATH.open() as f:
        return json.load(f)


def _decode_fixture_input(fixture: dict[str, Any]) -> Any:
    if fixture.get("input_is_sentinel"):
        sentinel = fixture["input_sentinel"]
        if sentinel not in _SENTINEL_DECODE:
            raise AssertionError(f"unknown sentinel {sentinel!r} in fixture {fixture['name']!r}")
        return _SENTINEL_DECODE[sentinel]
    return fixture["input"]


_BYTE_EQUAL_FIXTURES = [f for f in _load_fixtures() if not f.get("expected_rejects")]
_REJECT_FIXTURES = [f for f in _load_fixtures() if f.get("expected_rejects")]


@pytest.mark.parametrize(
    "fixture",
    _BYTE_EQUAL_FIXTURES,
    ids=[f["name"] for f in _BYTE_EQUAL_FIXTURES],
)
def test_byte_equal_fixtures_match(fixture: dict[str, Any]) -> None:
    expected = bytes.fromhex(fixture["expected_canonical_bytes_hex"])
    actual = canonicalize_strict(_decode_fixture_input(fixture))
    assert actual == expected, (
        f"fixture {fixture['name']!r} diverged: "
        f"expected={expected!r} actual={actual!r}"
    )


@pytest.mark.parametrize(
    "fixture",
    _REJECT_FIXTURES,
    ids=[f["name"] for f in _REJECT_FIXTURES],
)
def test_reject_fixtures_raise_canonicalization_error(fixture: dict[str, Any]) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_strict(_decode_fixture_input(fixture))


def test_compute_content_hash_raises_on_nonfinite() -> None:
    # Directly exercise the canonicalizer primitive with each non-finite float.
    # (compute_content_hash itself is not migrated until C19.6; this test
    # pins the CanonicalizationError contract that migration will rely on.)
    for value in (float("nan"), float("inf"), float("-inf")):
        with pytest.raises(CanonicalizationError):
            canonicalize_strict(value)


def test_error_contract_type_not_value_error() -> None:
    # Pin the error-type contract against accidental drift:
    # CanonicalizationError must NOT be catchable via `except ValueError`.
    # jcs raises ValueError natively; our pre-walk must intercept first.
    assert not issubclass(CanonicalizationError, ValueError)
    try:
        canonicalize_strict(float("nan"))
    except ValueError:  # pragma: no cover — if this catches, contract is broken
        pytest.fail("CanonicalizationError was caught as ValueError; contract broken")
    except CanonicalizationError:
        pass
    else:
        pytest.fail("expected CanonicalizationError, got no exception")


def test_error_carries_reason_code() -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_strict(float("nan"))
    assert exc_info.value.reason_code == "non_finite_number_in_canonical_input"


def test_error_carries_path() -> None:
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_strict({"a": [1.0, float("nan")]})
    assert exc_info.value.path == ["a", "1"]
