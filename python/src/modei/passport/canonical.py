"""RFC 8785 canonicalizer — strict wrapper around ``jcs``.

Mirrors the backend's ``canonicalizeStrict`` (``src/lib/canon/canonicalize.ts``).
Cross-SDK byte-equality against that backend is a release invariant; see
spec §11.2 and §13 row 23.

Non-finite float handling: the pre-walk rejects ``NaN``, ``+Infinity``, and
``-Infinity`` with a :class:`CanonicalizationError` carrying
``reason_code='non_finite_number_in_canonical_input'`` and a path pointing
at the offending value. Only after a clean walk do we delegate to
``jcs.canonicalize``. ``jcs==0.2.1`` already rejects non-finite floats with
``ValueError``, but the pre-walk guarantees a consistent error type and
structured path across SDKs.

``jcs.canonicalize`` returns UTF-8 bytes; this wrapper returns those bytes
unchanged.
"""

from __future__ import annotations

import math
from typing import Any

import jcs


class CanonicalizationError(Exception):
    """Raised when an input cannot be RFC 8785 canonicalized.

    Deliberately does NOT subclass ``ValueError``. Callers — and tests —
    must catch ``CanonicalizationError`` explicitly to pin the contract.
    A too-broad ``except ValueError`` should NOT swallow this.

    Attributes:
        reason_code: Stable reason identifier. Only ``'non_finite_number_in_canonical_input'``
            today; see module docstring for taxonomy policy.
        path: JSON path (list of string segments) pointing at the offending
            value. Array indices are stringified. Empty list for root.
    """

    reason_code: str
    path: list[str]

    def __init__(
        self,
        reason_code: str,
        path: list[str],
        detail: str | None = None,
    ) -> None:
        self.reason_code = reason_code
        self.path = path
        path_str = ".".join(path) if path else "<root>"
        message = (
            f"{reason_code} at {path_str}: {detail}"
            if detail is not None
            else f"{reason_code} at {path_str}"
        )
        super().__init__(message)


def _walk(value: Any, path: list[str]) -> None:
    # bool is a subclass of int in Python — handle before the numeric branch.
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            if math.isnan(value):
                kind = "NaN"
            elif value > 0:
                kind = "+Infinity"
            else:
                kind = "-Infinity"
            raise CanonicalizationError(
                "non_finite_number_in_canonical_input",
                path,
                kind,
            )
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _walk(item, [*path, str(i)])
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _walk(v, [*path, str(k)])
        return
    # int, str, None, and other scalars are no-ops.


def canonicalize_strict(obj: Any) -> bytes:
    """RFC 8785 canonicalize with non-finite-number rejection.

    Returns the canonical UTF-8 bytes (``jcs.canonicalize``'s output).
    Raises :class:`CanonicalizationError` if ``obj`` contains ``NaN``,
    ``+Infinity``, or ``-Infinity`` anywhere in its tree.
    """
    _walk(obj, [])
    return jcs.canonicalize(obj)
