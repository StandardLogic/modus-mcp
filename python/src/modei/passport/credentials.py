"""File-backed Ed25519 agent credentials (spec §11.3).

Schema (SDK-defined v1 — no backend mirror; TypeScript SDK C20 must
read/write identically):

.. code-block:: json

    {
      "version": 1,
      "agent_id": "agent_self_...",
      "public_key_base64": "<base64 of 32-byte Ed25519 public key>",
      "private_key_base64": "<base64 of 32-byte Ed25519 seed>",
      "created_at": "<ISO 8601 UTC>"
    }

The ``agent_id`` field is a denormalized cache of
``derive_self_agent_id(public_key_base64)``. On load the SDK recomputes
and rejects any mismatch — catches hand-edited files and gross tamper
attempts early (the private key is the ultimate authority; signature
verification would fail regardless).

``private_key_base64`` is the 32-byte Ed25519 seed, not an expanded
private key. ``nacl.signing.SigningKey(seed)`` is deterministic.

Storage path precedence:

1. Explicit ``path=`` argument to every method.
2. ``MODEI_CREDENTIALS_PATH`` env var.
3. No default in v1.1 — raises ``ValueError``. The spec default
   ``$HOME/.config/modei/credentials/<agent_id>.json`` requires the
   agent_id before the key exists, which is a chicken-and-egg for
   ``load_or_create``. Resolved in v1.2 or later.

POSIX file perms enforced strictly: files saved with mode ``0o600``;
loads reject any looser mode with ``PermissionError``. No opt-out.
Windows has no equivalent; writes emit a one-line warning once per
process (spec §11.3 documented limitation).
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

import nacl.signing

from .agent_id import derive_self_agent_id

CREDENTIALS_FORMAT_VERSION = 1
ENV_PATH_VAR = "MODEI_CREDENTIALS_PATH"
REQUIRED_POSIX_MODE = 0o600

PathLike = Union[str, os.PathLike[str]]

_windows_warning_emitted = False


def _resolve_path(path: Optional[PathLike]) -> Path:
    """Apply precedence: explicit path → env var → raise."""
    if path is not None:
        return Path(path).expanduser()
    env_path = os.environ.get(ENV_PATH_VAR)
    if env_path:
        return Path(env_path).expanduser()
    raise ValueError(
        f"AgentCredentials: no path provided and {ENV_PATH_VAR} is not set. "
        "Pass path= explicitly or set the environment variable."
    )


def _check_perms(path: Path) -> None:
    """POSIX-only. Raises ``PermissionError`` on looser-than-0600."""
    if os.name == "nt":
        return
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"credentials file {path} has mode {mode:04o}; require 0600"
        )


def _emit_windows_warning_once() -> None:
    global _windows_warning_emitted
    if os.name == "nt" and not _windows_warning_emitted:
        warnings.warn(
            "modei.passport.credentials: POSIX file permissions (0600) are not "
            "enforced on Windows. Protect credential files via filesystem ACLs "
            "or OS keychain (deferred to v1.2).",
            stacklevel=2,
        )
        _windows_warning_emitted = True


class AgentCredentials:
    """Ed25519 keypair with file-backed storage.

    Construction is intentionally restricted — use :meth:`generate`,
    :meth:`load`, or :meth:`load_or_create`. The ``__init__`` takes raw
    key material for internal use; SDK callers should not depend on it.
    """

    def __init__(
        self,
        *,
        private_key_seed: bytes,
        created_at: Optional[str] = None,
    ) -> None:
        if len(private_key_seed) != 32:
            raise ValueError(
                f"private_key_seed must be exactly 32 bytes, got {len(private_key_seed)}"
            )
        self._signing_key = nacl.signing.SigningKey(private_key_seed)
        self._public_key_bytes = self._signing_key.verify_key.encode()
        self._created_at = created_at or datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    # ----- properties ------------------------------------------------------

    @property
    def public_key_b64(self) -> str:
        """Standard base64 of the 32-byte Ed25519 public key."""
        return base64.b64encode(self._public_key_bytes).decode("ascii")

    @property
    def private_key_bytes(self) -> bytes:
        """Raw 32-byte Ed25519 seed. Used by :class:`PassportIssuer.sign`."""
        return self._signing_key.encode()

    @property
    def agent_id(self) -> str:
        """Derived ``agent_self_...`` id. Never stored as authoritative."""
        return derive_self_agent_id(self.public_key_b64)

    @property
    def created_at(self) -> str:
        return self._created_at

    def __repr__(self) -> str:
        # Must NOT leak the private key.
        return f"<AgentCredentials agent_id={self.agent_id!r}>"

    # ----- construction ----------------------------------------------------

    @classmethod
    def generate(cls) -> "AgentCredentials":
        """Create a new in-memory keypair. Does not touch the filesystem."""
        return cls(private_key_seed=secrets.token_bytes(32))

    @classmethod
    def load(cls, path: Optional[PathLike] = None) -> "AgentCredentials":
        """Load existing credentials. Raises if the file does not exist.

        Never creates a file. Use :meth:`load_or_create` for the create-
        if-missing path.
        """
        resolved = _resolve_path(path)
        if not resolved.exists():
            raise FileNotFoundError(f"credentials file not found: {resolved}")
        _check_perms(resolved)

        try:
            raw = resolved.read_text(encoding="utf-8")
            data: Any = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"credentials file is not valid JSON: {resolved}") from exc

        if not isinstance(data, dict):
            raise ValueError(f"credentials file must contain a JSON object: {resolved}")

        version = data.get("version")
        if version != CREDENTIALS_FORMAT_VERSION:
            raise ValueError(
                f"unsupported credentials format version: {version!r} "
                f"(expected {CREDENTIALS_FORMAT_VERSION})"
            )

        for required in ("agent_id", "public_key_base64", "private_key_base64", "created_at"):
            if required not in data:
                raise ValueError(f"credentials file missing required field: {required!r}")

        priv_b64 = data["private_key_base64"]
        try:
            seed = base64.b64decode(priv_b64, validate=True)
        except Exception as exc:
            raise ValueError("private_key_base64 is not valid base64") from exc
        if len(seed) != 32:
            raise ValueError(
                f"private_key_base64 decodes to {len(seed)} bytes, require 32"
            )

        creds = cls(private_key_seed=seed, created_at=data["created_at"])

        # Tamper check: recompute agent_id from the private key's pubkey.
        expected_pubkey = creds.public_key_b64
        if data["public_key_base64"] != expected_pubkey:
            raise ValueError(
                "public_key_base64 in file does not match key derived from "
                "private_key_base64 (file may be corrupt or tampered)"
            )
        if data["agent_id"] != creds.agent_id:
            raise ValueError(
                f"agent_id mismatch in credentials file: stored "
                f"{data['agent_id']!r}, derived {creds.agent_id!r}"
            )

        return creds

    @classmethod
    def load_or_create(cls, path: Optional[PathLike] = None) -> "AgentCredentials":
        """Load credentials from ``path``; create + save if the file does not exist.

        The only code path that auto-writes. ``load`` raises on missing.
        """
        resolved = _resolve_path(path)
        if resolved.exists():
            return cls.load(resolved)
        creds = cls.generate()
        creds.save(resolved)
        return creds

    # ----- persistence -----------------------------------------------------

    def save(self, path: Optional[PathLike] = None) -> None:
        """Write credentials to ``path`` atomically with 0600 perms.

        Writes to ``path + ".tmp"``, chmods, then ``os.rename``. On crash
        mid-write, the final path is unmodified.
        """
        resolved = _resolve_path(path)
        resolved.parent.mkdir(parents=True, exist_ok=True)

        payload = {
            "version": CREDENTIALS_FORMAT_VERSION,
            "agent_id": self.agent_id,
            "public_key_base64": self.public_key_b64,
            "private_key_base64": base64.b64encode(self.private_key_bytes).decode("ascii"),
            "created_at": self._created_at,
        }
        serialized = json.dumps(payload, indent=2, sort_keys=True)

        tmp = resolved.with_suffix(resolved.suffix + ".tmp")
        try:
            # Create the tmp file with restrictive mode from the start on POSIX.
            # Open with O_CREAT | O_WRONLY | O_TRUNC; mode arg honored under the
            # process umask. chmod afterwards is the authoritative step.
            fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(serialized)
            except BaseException:
                # fdopen took ownership of fd; no manual close needed on error path.
                raise
            if os.name != "nt":
                os.chmod(tmp, REQUIRED_POSIX_MODE)
            else:
                _emit_windows_warning_once()
            os.replace(tmp, resolved)
        except BaseException:
            # Best-effort cleanup of the tmp file if rename failed.
            try:
                tmp.unlink()
            except FileNotFoundError:
                pass
            raise
