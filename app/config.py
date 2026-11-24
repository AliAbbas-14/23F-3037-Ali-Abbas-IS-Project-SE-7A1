"""Configuration management and storage separation paths for VaultGuard SDMS."""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    """Application security and storage settings."""

    base_dir: Path
    db_path: Path
    blob_dir: Path
    audit_dir: Path
    audit_chain_head_path: Path
    audit_hmac_key: bytes
    cookie_secure: bool = False
    session_ttl_seconds: int = 3600
    idle_timeout_seconds: int = 1800
    max_failed_logins: int = 5
    lockout_seconds: int = 300
    max_upload_bytes: int = 10 * 1024 * 1024  # 10 MB


def _load_or_create_audit_key(audit_dir: Path) -> bytes:
    """Load VAULTGUARD_AUDIT_HMAC_KEY from env or isolated local key file."""
    env_key = os.getenv("VAULTGUARD_AUDIT_HMAC_KEY", "").strip()
    if env_key and not env_key.startswith("replace-with"):
        try:
            raw = bytes.fromhex(env_key)
            if len(raw) >= 32:
                return raw
        except ValueError:
            return env_key.encode("utf-8")

    audit_dir.mkdir(parents=True, exist_ok=True)
    key_file = audit_dir / ".audit_hmac_key"
    if key_file.exists():
        raw_hex = key_file.read_text(encoding="utf-8").strip()
        return bytes.fromhex(raw_hex)

    generated = secrets.token_bytes(32)
    key_file.write_text(generated.hex(), encoding="utf-8")
    return generated


def get_settings(base_dir: Path | None = None) -> Settings:
    """Build runtime Settings, isolating DB, encrypted blobs, and audit anchor."""
    root = Path(
        base_dir
        or os.getenv("VAULTGUARD_STORAGE_ROOT")
        or Path(__file__).resolve().parent.parent / "storage"
    )
    db_dir = root / "db"
    blob_dir = root / "vault_blobs"
    audit_dir = root / "audit"
    db_dir.mkdir(parents=True, exist_ok=True)
    blob_dir.mkdir(parents=True, exist_ok=True)
    audit_dir.mkdir(parents=True, exist_ok=True)

    return Settings(
        base_dir=root,
        db_path=db_dir / "vaultguard.db",
        blob_dir=blob_dir,
        audit_dir=audit_dir,
        audit_chain_head_path=audit_dir / "chain_head.json",
        audit_hmac_key=_load_or_create_audit_key(audit_dir),
        cookie_secure=os.getenv("VAULTGUARD_COOKIE_SECURE", "false").lower() == "true",
        session_ttl_seconds=int(os.getenv("VAULTGUARD_SESSION_TTL_SECONDS", "3600")),
        idle_timeout_seconds=int(os.getenv("VAULTGUARD_IDLE_TIMEOUT_SECONDS", "1800")),
        max_failed_logins=int(os.getenv("VAULTGUARD_MAX_FAILED_LOGINS", "5")),
        lockout_seconds=int(os.getenv("VAULTGUARD_LOCKOUT_SECONDS", "300")),
        max_upload_bytes=int(os.getenv("VAULTGUARD_MAX_UPLOAD_BYTES", str(10 * 1024 * 1024))),
    )
