"""C19.3 tests — AgentCredentials file-backed Ed25519 storage.

16 tests. POSIX-perm tests skip on Windows.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

from modei.passport.credentials import (
    CREDENTIALS_FORMAT_VERSION,
    ENV_PATH_VAR,
    AgentCredentials,
)

WINDOWS = os.name == "nt"


def _write_file(path: Path, data: dict[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")
    if not WINDOWS:
        os.chmod(path, mode)


def _valid_payload(creds: AgentCredentials) -> dict[str, Any]:
    import base64

    return {
        "version": CREDENTIALS_FORMAT_VERSION,
        "agent_id": creds.agent_id,
        "public_key_base64": creds.public_key_b64,
        "private_key_base64": base64.b64encode(creds.private_key_bytes).decode("ascii"),
        "created_at": creds.created_at,
    }


# ---------------------------------------------------------------------------
# generate + round-trip
# ---------------------------------------------------------------------------


def test_generate_creates_valid_keypair() -> None:
    import base64

    creds = AgentCredentials.generate()
    assert len(base64.b64decode(creds.public_key_b64)) == 32
    assert len(creds.private_key_bytes) == 32
    assert creds.agent_id.startswith("agent_self_")
    assert len(creds.agent_id) == 43


def test_save_then_load_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    original = AgentCredentials.generate()
    original.save(path)

    loaded = AgentCredentials.load(path)
    assert loaded.public_key_b64 == original.public_key_b64
    assert loaded.private_key_bytes == original.private_key_bytes
    assert loaded.agent_id == original.agent_id


# ---------------------------------------------------------------------------
# load_or_create semantics
# ---------------------------------------------------------------------------


def test_load_or_create_missing_file_creates(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    assert not path.exists()
    creds = AgentCredentials.load_or_create(path)
    assert path.exists()
    # Re-load via load_or_create should return the same keys (idempotent).
    again = AgentCredentials.load_or_create(path)
    assert again.public_key_b64 == creds.public_key_b64


def test_load_or_create_existing_file_loads(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    first = AgentCredentials.load_or_create(path)
    second = AgentCredentials.load_or_create(path)
    assert first.public_key_b64 == second.public_key_b64
    assert first.private_key_bytes == second.private_key_bytes


def test_load_missing_file_raises_filenotfound(tmp_path: Path) -> None:
    path = tmp_path / "nope.json"
    with pytest.raises(FileNotFoundError):
        AgentCredentials.load(path)


# ---------------------------------------------------------------------------
# POSIX permissions
# ---------------------------------------------------------------------------


@pytest.mark.skipif(WINDOWS, reason="POSIX-only perm enforcement")
def test_save_file_perms_are_0600(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    AgentCredentials.generate().save(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {mode:04o}"


@pytest.mark.skipif(WINDOWS, reason="POSIX-only perm enforcement")
def test_load_rejects_loose_perms(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    creds = AgentCredentials.generate()
    _write_file(path, _valid_payload(creds), mode=0o644)
    with pytest.raises(PermissionError, match="0644"):
        AgentCredentials.load(path)


# ---------------------------------------------------------------------------
# env override + path precedence
# ---------------------------------------------------------------------------


def test_env_override_takes_precedence_over_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / "via_env.json"
    monkeypatch.setenv(ENV_PATH_VAR, str(env_path))
    creds = AgentCredentials.load_or_create()  # no explicit path
    assert env_path.exists()
    assert creds.agent_id == AgentCredentials.load(env_path).agent_id


def test_explicit_path_overrides_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_path = tmp_path / "env.json"
    explicit_path = tmp_path / "explicit.json"
    monkeypatch.setenv(ENV_PATH_VAR, str(env_path))
    AgentCredentials.load_or_create(explicit_path)
    assert explicit_path.exists()
    assert not env_path.exists(), "explicit path should win; env path should be untouched"


def test_no_path_and_no_env_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(ENV_PATH_VAR, raising=False)
    with pytest.raises(ValueError, match=ENV_PATH_VAR):
        AgentCredentials.load_or_create()


# ---------------------------------------------------------------------------
# tamper detection + format version
# ---------------------------------------------------------------------------


def test_load_detects_agent_id_tamper(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    creds = AgentCredentials.generate()
    payload = _valid_payload(creds)
    payload["agent_id"] = "agent_self_" + "0" * 32  # mismatched
    _write_file(path, payload, mode=0o600)
    with pytest.raises(ValueError, match="agent_id mismatch"):
        AgentCredentials.load(path)


def test_load_rejects_unknown_version(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    creds = AgentCredentials.generate()
    payload = _valid_payload(creds)
    payload["version"] = 2  # future version we don't know
    _write_file(path, payload, mode=0o600)
    with pytest.raises(ValueError, match="unsupported credentials format version"):
        AgentCredentials.load(path)


# ---------------------------------------------------------------------------
# repr does not leak + atomic save
# ---------------------------------------------------------------------------


def test_repr_does_not_leak_private_key() -> None:
    import base64

    creds = AgentCredentials.generate()
    priv_b64 = base64.b64encode(creds.private_key_bytes).decode("ascii")
    rendering = repr(creds)
    assert priv_b64 not in rendering
    assert "agent_self_" in rendering  # agent_id is public, safe to show


def test_atomic_save_does_not_leave_tmp_file(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    AgentCredentials.generate().save(path)
    tmp_residue = path.with_suffix(path.suffix + ".tmp")
    assert path.exists()
    assert not tmp_residue.exists(), f"tmp file residue at {tmp_residue}"


# ---------------------------------------------------------------------------
# extras (15 + 16)
# ---------------------------------------------------------------------------


def test_malformed_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "creds.json"
    path.write_text("{not json", encoding="utf-8")
    if not WINDOWS:
        os.chmod(path, 0o600)
    with pytest.raises(ValueError, match="not valid JSON"):
        AgentCredentials.load(path)


def test_path_expands_tilde(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Point HOME at a scratch dir so `~` expands somewhere we can clean up.
    monkeypatch.setenv("HOME", str(tmp_path))
    creds = AgentCredentials.load_or_create("~/nested/creds.json")
    resolved = tmp_path / "nested" / "creds.json"
    assert resolved.exists()
    assert creds.agent_id.startswith("agent_self_")
