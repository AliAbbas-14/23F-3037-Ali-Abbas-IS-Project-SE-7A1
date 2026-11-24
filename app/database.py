"""SQLite metadata and access-control database schema and connection helper."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    full_name TEXT NOT NULL,
    system_role TEXT NOT NULL CHECK (system_role IN ('user', 'auditor_admin')),
    password_hash TEXT NOT NULL,
    kdf_salt_b64 TEXT NOT NULL,
    x25519_pub_b64 TEXT NOT NULL,
    ed25519_pub_b64 TEXT NOT NULL,
    enc_private_bundle TEXT NOT NULL,
    recovery_bundle TEXT NOT NULL,
    recovery_code_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    created_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    blob_id TEXT NOT NULL UNIQUE,
    current_version INTEGER NOT NULL DEFAULT 1,
    plaintext_sha256 TEXT NOT NULL,
    ciphertext_sha256 TEXT NOT NULL,
    manifest_signature_b64 TEXT NOT NULL,
    signer_user_id TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_deleted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS document_permissions (
    id TEXT PRIMARY KEY,
    doc_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
    wrapped_dek_json TEXT,
    granted_by TEXT NOT NULL REFERENCES users(id),
    granted_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_active_doc_perm
    ON document_permissions(doc_id, user_id)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS audit_logs (
    seq_no INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    timestamp_utc TEXT NOT NULL,
    actor_user_id TEXT,
    actor_username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    action TEXT NOT NULL,
    target_doc_id TEXT,
    outcome TEXT NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'ALERT')),
    details_json TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    entry_hmac TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor_user_id);
"""


def get_connection(db_path: Path) -> sqlite3.Connection:
    """Open a hardened SQLite connection with WAL mode and foreign key checks."""
    conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


@contextmanager
def db_transaction(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Provide an atomic IMMEDIATE transaction context for safe concurrent writes."""
    conn = get_connection(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE;")
        yield conn
        conn.execute("COMMIT;")
    except Exception:
        conn.execute("ROLLBACK;")
        raise
    finally:
        conn.close()


def init_db(db_path: Path) -> None:
    """Create schema tables and indices if they do not exist."""
    conn = get_connection(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
    finally:
        conn.close()
