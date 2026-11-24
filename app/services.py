"""Core business, authentication, authorization, and cryptographic vault services."""

from __future__ import annotations

import base64
import hashlib
import hmac
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.audit import append_audit_event, utc_now_iso
from app.config import Settings
from app.crypto import (
    CryptoIntegrityError,
    CryptoKeyError,
    UnlockedKeyBundle,
    b64d,
    b64e,
    decrypt_document_blob,
    decrypt_key_bundle,
    derive_kek_from_password,
    derive_kek_from_recovery_code,
    encrypt_document_blob,
    encrypt_key_bundle,
    generate_dek,
    generate_recovery_code,
    generate_user_keypairs,
    hash_password,
    hash_token,
    sign_document_manifest,
    unwrap_dek_for_user,
    unwrap_runtime_bundle,
    verify_document_manifest,
    verify_password,
    wrap_dek_for_user,
    wrap_runtime_bundle,
)
from app.database import db_transaction, get_connection

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "owner": {"read", "download", "verify", "edit", "share", "revoke", "delete"},
    "editor": {"read", "download", "verify", "edit"},
    "viewer": {"read", "download", "verify"},
}


class ServiceError(Exception):
    """Base application error carrying HTTP status code and optional deferred audit event."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        audit: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.audit = audit


class AuthError(ServiceError):
    """Authentication or session failure."""

    def __init__(
        self,
        message: str,
        status_code: int = 401,
        audit: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, audit=audit)


class AccessDeniedError(ServiceError):
    """Authorization failure (object-level or role-level)."""

    def __init__(
        self,
        message: str,
        status_code: int = 403,
        audit: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, audit=audit)


class IntegrityFailureError(ServiceError):
    """Cryptographic integrity or manifest verification failure."""

    def __init__(
        self,
        message: str,
        status_code: int = 409,
        audit: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, status_code=status_code, audit=audit)


@contextmanager
def audited_transaction(settings: Settings):
    """Wrap db_transaction so deferred security audit events commit even after rollback."""
    try:
        with db_transaction(settings.db_path) as conn:
            yield conn
    except ServiceError as exc:
        if exc.audit:
            append_audit_event(settings, **exc.audit)
        raise


@dataclass
class AuthenticatedSession:
    """Resolved authenticated session context."""

    session_hash: str
    user_id: str
    username: str
    email: str
    full_name: str
    system_role: str
    x25519_pub_b64: str
    ed25519_pub_b64: str
    csrf_token: str
    keys: UnlockedKeyBundle


class RuntimeKeyStore:
    """Ephemeral in-memory store holding cookie-encrypted session private keys."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._vaults: dict[str, bytes] = {}

    def put(self, session_hash: str, bundle: UnlockedKeyBundle, session_key: bytes) -> None:
        wrapped = wrap_runtime_bundle(bundle, session_key, session_hash)
        with self._lock:
            self._vaults[session_hash] = wrapped

    def get(self, session_hash: str, session_key: bytes) -> UnlockedKeyBundle:
        with self._lock:
            wrapped = self._vaults.get(session_hash)
        if not wrapped:
            raise AuthError("Session key vault expired; please log in again.", status_code=401)
        try:
            return unwrap_runtime_bundle(wrapped, session_key, session_hash)
        except CryptoKeyError as exc:
            raise AuthError("Invalid session key token; please log in again.", status_code=401) from exc

    def delete(self, session_hash: str) -> None:
        with self._lock:
            self._vaults.pop(session_hash, None)

    def clear_all(self) -> None:
        with self._lock:
            self._vaults.clear()


def _parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _validate_password_strength(password: str) -> None:
    if len(password) < 10:
        raise ServiceError("Password must be at least 10 characters long.")
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    if not (has_upper and has_lower and has_digit and has_special):
        raise ServiceError(
            "Password must include uppercase, lowercase, numeric, and special characters."
        )


def sanitize_filename(raw_name: str) -> str:
    """Strip path traversal components and unsafe characters from uploaded filenames."""
    base = Path(raw_name.replace("\\", "/")).name.strip()
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", base)
    cleaned = cleaned.lstrip(".")
    if not cleaned:
        cleaned = "document.bin"
    return cleaned[:120]


def sanitize_title(raw_title: str, fallback: str) -> str:
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", raw_title).strip()
    if not cleaned:
        return fallback[:120]
    return cleaned[:120]


def register_user(
    settings: Settings,
    *,
    username: str,
    email: str,
    full_name: str,
    password: str,
    system_role: str = "user",
    allow_admin_creation: bool = False,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Create a user with Argon2id auth hash and encrypted X25519/Ed25519 keypairs."""
    username = username.strip()
    email = email.strip().lower()
    full_name = sanitize_title(full_name, username)

    if not USERNAME_RE.match(username):
        raise ServiceError(
            "Username must be 3-32 characters using letters, numbers, '.', '_', or '-'."
        )
    if not EMAIL_RE.match(email):
        raise ServiceError("Please provide a valid email address.")
    _validate_password_strength(password)

    # Prevent privilege escalation via public registration
    effective_role = "auditor_admin" if (allow_admin_creation and system_role == "auditor_admin") else "user"

    user_id = str(uuid.uuid4())
    kdf_salt = os.urandom(16)
    pw_hash = hash_password(password)
    pd_kek = derive_kek_from_password(password, kdf_salt)

    bundle, x_pub_b64, ed_pub_b64 = generate_user_keypairs()
    recovery_code = generate_recovery_code()
    recovery_kek = derive_kek_from_recovery_code(recovery_code, kdf_salt)

    enc_priv_bundle = encrypt_key_bundle(bundle, pd_kek, user_id, "password-kek")
    enc_rec_bundle = encrypt_key_bundle(bundle, recovery_kek, user_id, "recovery-kek")
    rec_code_hash = hash_token(recovery_code)
    created_at = utc_now_iso()

    try:
        with db_transaction(settings.db_path) as conn:
            conn.execute(
                """
                INSERT INTO users (
                    id, username, email, full_name, system_role, password_hash,
                    kdf_salt_b64, x25519_pub_b64, ed25519_pub_b64,
                    enc_private_bundle, recovery_bundle, recovery_code_hash,
                    failed_attempts, locked_until, created_at, is_active
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?, 1)
                """,
                (
                    user_id,
                    username,
                    email,
                    full_name,
                    effective_role,
                    pw_hash,
                    b64e(kdf_salt),
                    x_pub_b64,
                    ed_pub_b64,
                    enc_priv_bundle,
                    enc_rec_bundle,
                    rec_code_hash,
                    created_at,
                ),
            )
            append_audit_event(
                settings,
                action="USER_REGISTERED",
                outcome="SUCCESS",
                actor_user_id=user_id,
                actor_username=username,
                ip_address=ip_address,
                details={"system_role": effective_role},
                conn=conn,
            )
    except sqlite3.IntegrityError as exc:
        raise ServiceError("Username or email is already registered.", status_code=409) from exc

    return {
        "user_id": user_id,
        "username": username,
        "email": email,
        "full_name": full_name,
        "system_role": effective_role,
        "recovery_code": recovery_code,
    }


def login_user(
    settings: Settings,
    key_store: RuntimeKeyStore,
    *,
    username: str,
    password: str,
    ip_address: str = "127.0.0.1",
    user_agent: str = "unknown",
) -> dict[str, Any]:
    """Authenticate user via Argon2id, enforce lockout, unlock keys into ephemeral vault."""
    username_clean = username.strip()
    now = datetime.now(timezone.utc)

    conn_ro = get_connection(settings.db_path)
    try:
        user = conn_ro.execute(
            "SELECT * FROM users WHERE username = ?", (username_clean,)
        ).fetchone()
    finally:
        conn_ro.close()

    if not user:
        append_audit_event(
            settings,
            action="LOGIN_FAILED",
            outcome="DENIED",
            actor_user_id=None,
            actor_username=username_clean or "unknown",
            ip_address=ip_address,
            details={"reason": "unknown_username"},
        )
        raise AuthError("Invalid username or password.")

    if int(user["is_active"]) != 1:
        append_audit_event(
            settings,
            action="LOGIN_FAILED",
            outcome="DENIED",
            actor_user_id=str(user["id"]),
            actor_username=str(user["username"]),
            ip_address=ip_address,
            details={"reason": "account_disabled"},
        )
        raise AuthError("Account is disabled. Contact security administrator.", status_code=403)

    if user["locked_until"]:
        lock_dt = _parse_iso(str(user["locked_until"]))
        if now < lock_dt:
            append_audit_event(
                settings,
                action="LOGIN_BLOCKED_LOCKED",
                outcome="DENIED",
                actor_user_id=str(user["id"]),
                actor_username=str(user["username"]),
                ip_address=ip_address,
                details={"locked_until": str(user["locked_until"])},
            )
            raise AuthError(
                "Account is temporarily locked due to repeated failed login attempts.",
                status_code=429,
            )

    if not verify_password(str(user["password_hash"]), password):
        locked_until = None
        with db_transaction(settings.db_path) as conn:
            fresh_user = conn.execute(
                "SELECT failed_attempts FROM users WHERE id = ?", (user["id"],)
            ).fetchone()
            attempts = (int(fresh_user["failed_attempts"]) if fresh_user else 0) + 1
            action_name = "LOGIN_FAILED"
            outcome = "DENIED"
            if attempts >= settings.max_failed_logins:
                locked_until = (now + timedelta(seconds=settings.lockout_seconds)).isoformat()
                action_name = "ACCOUNT_LOCKED"
                outcome = "ALERT"

            conn.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            append_audit_event(
                settings,
                action=action_name,
                outcome=outcome,
                actor_user_id=str(user["id"]),
                actor_username=str(user["username"]),
                ip_address=ip_address,
                details={"failed_attempts": attempts},
                conn=conn,
            )

        if locked_until:
            raise AuthError(
                "Too many failed login attempts. Account temporarily locked.",
                status_code=429,
            )
        raise AuthError("Invalid username or password.")

    with db_transaction(settings.db_path) as conn:
        # Password verified: derive PD-KEK and unlock user private key bundle
        kdf_salt = b64d(str(user["kdf_salt_b64"]))
        pd_kek = derive_kek_from_password(password, kdf_salt)
        try:
            bundle = decrypt_key_bundle(
                str(user["enc_private_bundle"]), pd_kek, str(user["id"]), "password-kek"
            )
        except CryptoKeyError as exc:
            raise AuthError("Unable to unlock user cryptographic vault.", status_code=500) from exc

        raw_session_token = secrets.token_urlsafe(32)
        session_hash = hash_token(raw_session_token)
        csrf_token = secrets.token_hex(32)
        session_key = os.urandom(32)
        expires_at = (now + timedelta(seconds=settings.session_ttl_seconds)).isoformat()
        now_iso = now.isoformat()

        conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user["id"],),
        )
        conn.execute(
            """
            INSERT INTO sessions (
                token_hash, user_id, csrf_token, created_at, expires_at,
                last_seen_at, ip_address, user_agent, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
            """,
            (
                session_hash,
                user["id"],
                csrf_token,
                now_iso,
                expires_at,
                now_iso,
                ip_address,
                user_agent[:200],
            ),
        )
        append_audit_event(
            settings,
            action="LOGIN_SUCCESS",
            outcome="SUCCESS",
            actor_user_id=str(user["id"]),
            actor_username=str(user["username"]),
            ip_address=ip_address,
            details={"system_role": user["system_role"]},
            conn=conn,
        )

    key_store.put(session_hash, bundle, session_key)
    return {
        "raw_session_token": raw_session_token,
        "session_key_hex": session_key.hex(),
        "csrf_token": csrf_token,
        "user": {
            "id": str(user["id"]),
            "username": str(user["username"]),
            "system_role": str(user["system_role"]),
        },
    }


def resolve_session(
    settings: Settings,
    key_store: RuntimeKeyStore,
    raw_session_token: str | None,
    session_key_hex: str | None,
) -> AuthenticatedSession:
    """Validate opaque session cookie, idle/TTL expiration, and unwrap runtime key vault."""
    if not raw_session_token or not session_key_hex:
        raise AuthError("Authentication required.")

    try:
        session_key = bytes.fromhex(session_key_hex)
    except ValueError as exc:
        raise AuthError("Malformed session vault token.") from exc

    session_hash = hash_token(raw_session_token)
    now = datetime.now(timezone.utc)

    conn = get_connection(settings.db_path)
    try:
        row = conn.execute(
            """
            SELECT s.*, u.username, u.email, u.full_name, u.system_role,
                   u.x25519_pub_b64, u.ed25519_pub_b64, u.is_active
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (session_hash,),
        ).fetchone()
        if not row or row["revoked_at"] is not None or int(row["is_active"]) != 1:
            raise AuthError("Session is invalid or has been logged out.")

        if now > _parse_iso(str(row["expires_at"])):
            conn.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
                (now.isoformat(), session_hash),
            )
            key_store.delete(session_hash)
            raise AuthError("Session expired. Please sign in again.")

        last_seen = _parse_iso(str(row["last_seen_at"]))
        if (now - last_seen).total_seconds() > settings.idle_timeout_seconds:
            conn.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
                (now.isoformat(), session_hash),
            )
            key_store.delete(session_hash)
            raise AuthError("Session timed out due to inactivity.")

        conn.execute(
            "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
            (now.isoformat(), session_hash),
        )
    finally:
        conn.close()

    keys = key_store.get(session_hash, session_key)
    return AuthenticatedSession(
        session_hash=session_hash,
        user_id=str(row["user_id"]),
        username=str(row["username"]),
        email=str(row["email"]),
        full_name=str(row["full_name"]),
        system_role=str(row["system_role"]),
        x25519_pub_b64=str(row["x25519_pub_b64"]),
        ed25519_pub_b64=str(row["ed25519_pub_b64"]),
        csrf_token=str(row["csrf_token"]),
        keys=keys,
    )


def logout_user(
    settings: Settings,
    key_store: RuntimeKeyStore,
    raw_session_token: str | None,
    ip_address: str = "127.0.0.1",
) -> None:
    """Revoke server-side session token and wipe ephemeral runtime keys."""
    if not raw_session_token:
        return
    session_hash = hash_token(raw_session_token)
    key_store.delete(session_hash)

    with db_transaction(settings.db_path) as conn:
        row = conn.execute(
            """
            SELECT s.user_id, u.username
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
            """,
            (session_hash,),
        ).fetchone()
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ?",
            (utc_now_iso(), session_hash),
        )
        if row:
            append_audit_event(
                settings,
                action="LOGOUT",
                outcome="SUCCESS",
                actor_user_id=str(row["user_id"]),
                actor_username=str(row["username"]),
                ip_address=ip_address,
                conn=conn,
            )


def recover_user_password(
    settings: Settings,
    key_store: RuntimeKeyStore,
    *,
    username: str,
    recovery_code: str,
    new_password: str,
    ip_address: str = "127.0.0.1",
) -> str:
    """Self-service key-preserving password reset using the user's one-time recovery code."""
    _validate_password_strength(new_password)
    username_clean = username.strip()
    recovery_clean = recovery_code.strip().upper()

    with audited_transaction(settings) as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username_clean,)
        ).fetchone()
        if not user or not hmac.compare_digest(
            hash_token(recovery_clean), str(user["recovery_code_hash"])
        ):
            raise AuthError(
                "Invalid username or recovery code.",
                status_code=403,
                audit={
                    "action": "PASSWORD_RECOVERY_FAILED",
                    "outcome": "DENIED",
                    "actor_user_id": str(user["id"]) if user else None,
                    "actor_username": username_clean,
                    "ip_address": ip_address,
                },
            )

        old_salt = b64d(str(user["kdf_salt_b64"]))
        old_rec_kek = derive_kek_from_recovery_code(recovery_clean, old_salt)
        try:
            bundle = decrypt_key_bundle(
                str(user["recovery_bundle"]), old_rec_kek, str(user["id"]), "recovery-kek"
            )
        except CryptoKeyError as exc:
            raise AuthError("Recovery bundle decryption failed.", status_code=500) from exc

        new_salt = os.urandom(16)
        new_pw_hash = hash_password(new_password)
        new_pd_kek = derive_kek_from_password(new_password, new_salt)
        new_recovery_code = generate_recovery_code()
        new_rec_kek = derive_kek_from_recovery_code(new_recovery_code, new_salt)

        new_enc_priv = encrypt_key_bundle(bundle, new_pd_kek, str(user["id"]), "password-kek")
        new_rec_bundle = encrypt_key_bundle(bundle, new_rec_kek, str(user["id"]), "recovery-kek")

        # Revoke all prior sessions and rotate stored key wrapping
        sess_rows = conn.execute(
            "SELECT token_hash FROM sessions WHERE user_id = ? AND revoked_at IS NULL",
            (user["id"],),
        ).fetchall()
        for sr in sess_rows:
            key_store.delete(str(sr["token_hash"]))

        now_iso = utc_now_iso()
        conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (now_iso, user["id"]),
        )
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, kdf_salt_b64 = ?, enc_private_bundle = ?,
                recovery_bundle = ?, recovery_code_hash = ?,
                failed_attempts = 0, locked_until = NULL
            WHERE id = ?
            """,
            (
                new_pw_hash,
                b64e(new_salt),
                new_enc_priv,
                new_rec_bundle,
                hash_token(new_recovery_code),
                user["id"],
            ),
        )
        append_audit_event(
            settings,
            action="PASSWORD_RECOVERED",
            outcome="SUCCESS",
            actor_user_id=str(user["id"]),
            actor_username=str(user["username"]),
            ip_address=ip_address,
            details={"sessions_invalidated": len(sess_rows)},
            conn=conn,
        )

    return new_recovery_code


def _authorize_document(
    settings: Settings,
    conn: sqlite3.Connection,
    session: AuthenticatedSession,
    doc_id: str,
    required_action: str,
    ip_address: str,
) -> tuple[sqlite3.Row, sqlite3.Row]:
    """Enforce server-side object-level ACL and role permissions; audit all denials."""
    if not UUID_RE.match(doc_id):
        raise AccessDeniedError(
            "Invalid document identifier.",
            status_code=400,
            audit={
                "action": "IDOR_ATTEMPT",
                "outcome": "DENIED",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": doc_id[:64],
                "details": {"reason": "malformed_document_id", "requested_action": required_action},
            },
        )

    doc = conn.execute(
        "SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,)
    ).fetchone()
    if not doc:
        raise AccessDeniedError(
            "Document not found or access denied.",
            status_code=404,
            audit={
                "action": "IDOR_ATTEMPT",
                "outcome": "DENIED",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": doc_id,
                "details": {"reason": "nonexistent_or_deleted_doc", "requested_action": required_action},
            },
        )

    perm = conn.execute(
        """
        SELECT * FROM document_permissions
        WHERE doc_id = ? AND user_id = ? AND revoked_at IS NULL
        """,
        (doc_id, session.user_id),
    ).fetchone()

    if not perm:
        revoked = conn.execute(
            """
            SELECT revoked_at, role FROM document_permissions
            WHERE doc_id = ? AND user_id = ? AND revoked_at IS NOT NULL
            ORDER BY revoked_at DESC LIMIT 1
            """,
            (doc_id, session.user_id),
        ).fetchone()
        action_name = "REVOKED_ACCESS_ATTEMPT" if revoked else "IDOR_ATTEMPT"
        reason = "permission_revoked" if revoked else "no_document_permission"
        if session.system_role == "auditor_admin":
            reason = f"{reason}_admin_least_privilege"
        raise AccessDeniedError(
            "You do not have permission to access this document.",
            status_code=403,
            audit={
                "action": action_name,
                "outcome": "DENIED",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": doc_id,
                "details": {"reason": reason, "requested_action": required_action},
            },
        )

    if perm["expires_at"]:
        if datetime.now(timezone.utc) > _parse_iso(str(perm["expires_at"])):
            raise AccessDeniedError(
                "Your shared access to this document has expired.",
                status_code=403,
                audit={
                    "action": "ACCESS_DENIED_EXPIRED",
                    "outcome": "DENIED",
                    "actor_user_id": session.user_id,
                    "actor_username": session.username,
                    "ip_address": ip_address,
                    "target_doc_id": doc_id,
                    "details": {"expired_at": perm["expires_at"], "requested_action": required_action},
                },
            )

    allowed_actions = ROLE_PERMISSIONS.get(str(perm["role"]), set())
    if required_action not in allowed_actions:
        raise AccessDeniedError(
            f"Role '{perm['role']}' is not permitted to perform '{required_action}'.",
            status_code=403,
            audit={
                "action": "PRIVILEGE_ESCALATION_ATTEMPT",
                "outcome": "DENIED",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": doc_id,
                "details": {
                    "assigned_role": perm["role"],
                    "attempted_action": required_action,
                },
            },
        )

    return doc, perm


def upload_document(
    settings: Settings,
    session: AuthenticatedSession,
    *,
    title: str,
    filename: str,
    content: bytes,
    mime_type: str | None = None,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Encrypt, sign, and store a new document with per-document random DEK."""
    if not content:
        raise ServiceError("Cannot upload an empty file.")
    if len(content) > settings.max_upload_bytes:
        raise ServiceError(
            f"File exceeds maximum allowed size of {settings.max_upload_bytes // (1024 * 1024)} MB.",
            status_code=413,
        )

    safe_name = sanitize_filename(filename)
    safe_title = sanitize_title(title, safe_name)
    guessed_mime = mime_type or mimetypes.guess_type(safe_name)[0] or "application/octet-stream"

    doc_id = str(uuid.uuid4())
    blob_id = str(uuid.uuid4())
    version = 1
    dek = generate_dek()

    blob_bytes, pt_sha256, ct_sha256 = encrypt_document_blob(
        content, dek, doc_id, version, session.user_id
    )
    signature_b64 = sign_document_manifest(
        session.keys.ed25519_sk, doc_id, version, session.user_id, pt_sha256, ct_sha256
    )
    wrapped_dek_json = wrap_dek_for_user(
        dek, session.x25519_pub_b64, doc_id, version, session.user_id
    )

    blob_path = settings.blob_dir / f"{blob_id}.enc"
    blob_path.write_bytes(blob_bytes)
    now_iso = utc_now_iso()

    try:
        with db_transaction(settings.db_path) as conn:
            conn.execute(
                """
                INSERT INTO documents (
                    id, owner_id, title, original_filename, mime_type, size_bytes,
                    blob_id, current_version, plaintext_sha256, ciphertext_sha256,
                    manifest_signature_b64, signer_user_id, created_at, updated_at, is_deleted
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    doc_id,
                    session.user_id,
                    safe_title,
                    safe_name,
                    guessed_mime,
                    len(content),
                    blob_id,
                    version,
                    pt_sha256,
                    ct_sha256,
                    signature_b64,
                    session.user_id,
                    now_iso,
                    now_iso,
                ),
            )
            conn.execute(
                """
                INSERT INTO document_permissions (
                    id, doc_id, user_id, role, wrapped_dek_json,
                    granted_by, granted_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, 'owner', ?, ?, ?, NULL, NULL)
                """,
                (
                    str(uuid.uuid4()),
                    doc_id,
                    session.user_id,
                    wrapped_dek_json,
                    session.user_id,
                    now_iso,
                ),
            )
            append_audit_event(
                settings,
                action="DOC_UPLOAD",
                outcome="SUCCESS",
                actor_user_id=session.user_id,
                actor_username=session.username,
                ip_address=ip_address,
                target_doc_id=doc_id,
                details={
                    "title": safe_title,
                    "size_bytes": len(content),
                    "version": version,
                    "plaintext_sha256": pt_sha256[:16] + "...",
                },
                conn=conn,
            )
    except Exception:
        blob_path.unlink(missing_ok=True)
        raise

    return {
        "doc_id": doc_id,
        "blob_id": blob_id,
        "title": safe_title,
        "original_filename": safe_name,
        "version": version,
        "plaintext_sha256": pt_sha256,
        "ciphertext_sha256": ct_sha256,
    }


def list_accessible_documents(settings: Settings, session: AuthenticatedSession) -> list[dict[str, Any]]:
    """List only documents for which the user holds a non-revoked, unexpired permission."""
    now_iso = utc_now_iso()
    conn = get_connection(settings.db_path)
    try:
        rows = conn.execute(
            """
            SELECT d.id, d.title, d.original_filename, d.mime_type, d.size_bytes,
                   d.current_version, d.plaintext_sha256, d.ciphertext_sha256,
                   d.created_at, d.updated_at, d.owner_id,
                   owner.username AS owner_username,
                   p.role AS my_role, p.expires_at
            FROM document_permissions p
            JOIN documents d ON d.id = p.doc_id
            JOIN users owner ON owner.id = d.owner_id
            WHERE p.user_id = ?
              AND p.revoked_at IS NULL
              AND (p.expires_at IS NULL OR p.expires_at > ?)
              AND d.is_deleted = 0
            ORDER BY d.updated_at DESC
            """,
            (session.user_id, now_iso),
        ).fetchall()
    finally:
        conn.close()
    return [dict(r) for r in rows]


def _verify_and_decrypt_doc(
    settings: Settings,
    conn: sqlite3.Connection,
    doc: sqlite3.Row,
    perm: sqlite3.Row,
    session: AuthenticatedSession,
    ip_address: str,
) -> bytes:
    """Verify blob ciphertext SHA-256, Ed25519 manifest signature, and AES-GCM decrypt."""
    blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"
    if not blob_path.exists():
        raise IntegrityFailureError(
            "Encrypted blob missing from vault storage.",
            audit={
                "action": "DOCUMENT_INTEGRITY_FAILURE",
                "outcome": "ALERT",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": str(doc["id"]),
                "details": {"reason": "encrypted_blob_missing_on_disk", "blob_id": doc["blob_id"]},
            },
        )

    blob_bytes = blob_path.read_bytes()
    actual_ct_sha256 = hashlib.sha256(blob_bytes).hexdigest()
    if not hmac.compare_digest(actual_ct_sha256, str(doc["ciphertext_sha256"])):
        raise IntegrityFailureError(
            "INTEGRITY ALERT: Encrypted blob on disk was modified outside the application workflow!",
            audit={
                "action": "DOCUMENT_INTEGRITY_FAILURE",
                "outcome": "ALERT",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": str(doc["id"]),
                "details": {
                    "reason": "ciphertext_hash_mismatch",
                    "expected_prefix": str(doc["ciphertext_sha256"])[:16],
                    "actual_prefix": actual_ct_sha256[:16],
                },
            },
        )

    signer = conn.execute(
        "SELECT ed25519_pub_b64 FROM users WHERE id = ?", (doc["signer_user_id"],)
    ).fetchone()
    if not signer or not verify_document_manifest(
        str(signer["ed25519_pub_b64"]),
        str(doc["manifest_signature_b64"]),
        str(doc["id"]),
        int(doc["current_version"]),
        str(doc["owner_id"]),
        str(doc["plaintext_sha256"]),
        str(doc["ciphertext_sha256"]),
    ):
        raise IntegrityFailureError(
            "INTEGRITY ALERT: Document Ed25519 manifest signature verification failed!",
            audit={
                "action": "DOCUMENT_INTEGRITY_FAILURE",
                "outcome": "ALERT",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": str(doc["id"]),
                "details": {"reason": "ed25519_manifest_signature_invalid"},
            },
        )

    try:
        dek = unwrap_dek_for_user(
            str(perm["wrapped_dek_json"]),
            session.keys.x25519_sk,
            str(doc["id"]),
            int(doc["current_version"]),
            session.user_id,
        )
        plaintext = decrypt_document_blob(
            blob_bytes,
            dek,
            str(doc["id"]),
            int(doc["current_version"]),
            str(doc["owner_id"]),
            str(doc["plaintext_sha256"]),
        )
    except (CryptoKeyError, CryptoIntegrityError) as exc:
        raise IntegrityFailureError(
            f"INTEGRITY ALERT: {exc}",
            audit={
                "action": "DOCUMENT_INTEGRITY_FAILURE",
                "outcome": "ALERT",
                "actor_user_id": session.user_id,
                "actor_username": session.username,
                "ip_address": ip_address,
                "target_doc_id": str(doc["id"]),
                "details": {"reason": str(exc)},
            },
        ) from exc

    return plaintext


def retrieve_document(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    *,
    is_download: bool = False,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Authorize, verify cryptographic integrity, decrypt, and audit document access."""
    action = "download" if is_download else "read"
    audit_action = "DOC_DOWNLOAD" if is_download else "DOC_READ"

    with audited_transaction(settings) as conn:
        doc, perm = _authorize_document(settings, conn, session, doc_id, action, ip_address)
        plaintext = _verify_and_decrypt_doc(settings, conn, doc, perm, session, ip_address)

        owner_row = conn.execute(
            "SELECT username FROM users WHERE id = ?", (doc["owner_id"],)
        ).fetchone()
        signer_row = conn.execute(
            "SELECT username FROM users WHERE id = ?", (doc["signer_user_id"],)
        ).fetchone()
        shares = []
        if str(perm["role"]) == "owner":
            share_rows = conn.execute(
                """
                SELECT p.id, p.user_id, u.username, u.full_name, p.role, p.granted_at, p.expires_at
                FROM document_permissions p
                JOIN users u ON u.id = p.user_id
                WHERE p.doc_id = ? AND p.revoked_at IS NULL AND p.role != 'owner'
                ORDER BY p.granted_at DESC
                """,
                (doc_id,),
            ).fetchall()
            shares = [dict(sr) for sr in share_rows]

        append_audit_event(
            settings,
            action=audit_action,
            outcome="SUCCESS",
            actor_user_id=session.user_id,
            actor_username=session.username,
            ip_address=ip_address,
            target_doc_id=doc_id,
            details={"version": doc["current_version"], "role": perm["role"]},
            conn=conn,
        )

    return {
        "doc": dict(doc),
        "owner_username": str(owner_row["username"]) if owner_row else "unknown",
        "signer_username": str(signer_row["username"]) if signer_row else "unknown",
        "my_role": str(perm["role"]),
        "plaintext": plaintext,
        "shares": shares,
    }


def verify_document_integrity_status(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Verify ciphertext SHA-256 and Ed25519 manifest signature (without decrypting if admin)."""
    with audited_transaction(settings) as conn:
        if session.system_role == "auditor_admin":
            if not UUID_RE.match(doc_id):
                raise AccessDeniedError("Invalid document identifier.", status_code=400)
            doc = conn.execute(
                "SELECT * FROM documents WHERE id = ? AND is_deleted = 0", (doc_id,)
            ).fetchone()
            if not doc:
                raise AccessDeniedError("Document not found.", status_code=404)
        else:
            doc, _ = _authorize_document(settings, conn, session, doc_id, "verify", ip_address)

        blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"
        ct_ok = False
        sig_ok = False
        actual_ct_hash = "MISSING"

        if blob_path.exists():
            blob_bytes = blob_path.read_bytes()
            actual_ct_hash = hashlib.sha256(blob_bytes).hexdigest()
            ct_ok = hmac.compare_digest(actual_ct_hash, str(doc["ciphertext_sha256"]))

        signer = conn.execute(
            "SELECT ed25519_pub_b64 FROM users WHERE id = ?", (doc["signer_user_id"],)
        ).fetchone()
        if signer:
            sig_ok = verify_document_manifest(
                str(signer["ed25519_pub_b64"]),
                str(doc["manifest_signature_b64"]),
                str(doc["id"]),
                int(doc["current_version"]),
                str(doc["owner_id"]),
                str(doc["plaintext_sha256"]),
                str(doc["ciphertext_sha256"]),
            )

        verified = ct_ok and sig_ok
        append_audit_event(
            settings,
            action="DOC_INTEGRITY_VERIFIED" if verified else "DOCUMENT_INTEGRITY_FAILURE",
            outcome="SUCCESS" if verified else "ALERT",
            actor_user_id=session.user_id,
            actor_username=session.username,
            ip_address=ip_address,
            target_doc_id=doc_id,
            details={"ciphertext_hash_ok": ct_ok, "manifest_sig_ok": sig_ok},
            conn=conn,
        )

    return {
        "doc_id": doc_id,
        "verified": verified,
        "ciphertext_hash_ok": ct_ok,
        "manifest_signature_ok": sig_ok,
        "expected_ciphertext_sha256": str(doc["ciphertext_sha256"]),
        "actual_ciphertext_sha256": actual_ct_hash,
        "plaintext_sha256": str(doc["plaintext_sha256"]),
        "version": int(doc["current_version"]),
    }


def update_document_content(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    *,
    new_title: str | None = None,
    new_content: bytes,
    new_filename: str | None = None,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Update document content (owner or editor), rotating DEK and re-wrapping for active users."""
    if not new_content:
        raise ServiceError("Updated document content cannot be empty.")
    if len(new_content) > settings.max_upload_bytes:
        raise ServiceError("Updated document exceeds size limit.", status_code=413)

    with audited_transaction(settings) as conn:
        doc, perm = _authorize_document(settings, conn, session, doc_id, "edit", ip_address)
        # Ensure current blob wasn't tampered with before updating
        _verify_and_decrypt_doc(settings, conn, doc, perm, session, ip_address)

        new_version = int(doc["current_version"]) + 1
        new_blob_id = str(uuid.uuid4())
        new_dek = generate_dek()
        safe_title = sanitize_title(new_title, str(doc["title"])) if new_title else str(doc["title"])
        safe_filename = (
            sanitize_filename(new_filename) if new_filename else str(doc["original_filename"])
        )

        blob_bytes, pt_sha256, ct_sha256 = encrypt_document_blob(
            new_content, new_dek, doc_id, new_version, str(doc["owner_id"])
        )
        sig_b64 = sign_document_manifest(
            session.keys.ed25519_sk,
            doc_id,
            new_version,
            str(doc["owner_id"]),
            pt_sha256,
            ct_sha256,
        )

        # Re-wrap new DEK for every active collaborator
        active_perms = conn.execute(
            """
            SELECT p.id, p.user_id, u.x25519_pub_b64
            FROM document_permissions p
            JOIN users u ON u.id = p.user_id
            WHERE p.doc_id = ? AND p.revoked_at IS NULL
            """,
            (doc_id,),
        ).fetchall()

        new_blob_path = settings.blob_dir / f"{new_blob_id}.enc"
        new_blob_path.write_bytes(blob_bytes)
        old_blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"

        try:
            now_iso = utc_now_iso()
            conn.execute(
                """
                UPDATE documents
                SET title = ?, original_filename = ?, size_bytes = ?, blob_id = ?,
                    current_version = ?, plaintext_sha256 = ?, ciphertext_sha256 = ?,
                    manifest_signature_b64 = ?, signer_user_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    safe_title,
                    safe_filename,
                    len(new_content),
                    new_blob_id,
                    new_version,
                    pt_sha256,
                    ct_sha256,
                    sig_b64,
                    session.user_id,
                    now_iso,
                    doc_id,
                ),
            )
            for ap in active_perms:
                wrapped = wrap_dek_for_user(
                    new_dek, str(ap["x25519_pub_b64"]), doc_id, new_version, str(ap["user_id"])
                )
                conn.execute(
                    "UPDATE document_permissions SET wrapped_dek_json = ? WHERE id = ?",
                    (wrapped, ap["id"]),
                )

            append_audit_event(
                settings,
                action="DOC_UPDATE",
                outcome="SUCCESS",
                actor_user_id=session.user_id,
                actor_username=session.username,
                ip_address=ip_address,
                target_doc_id=doc_id,
                details={"new_version": new_version, "actor_role": perm["role"]},
                conn=conn,
            )
        except Exception:
            new_blob_path.unlink(missing_ok=True)
            raise

    old_blob_path.unlink(missing_ok=True)
    return {"doc_id": doc_id, "version": new_version, "plaintext_sha256": pt_sha256}


def share_document(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    *,
    target_username: str,
    role: str,
    expires_in_hours: int | None = None,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Owner-only sharing: wraps DEK under recipient's X25519 public key."""
    if role not in ("viewer", "editor"):
        raise ServiceError("Share role must be either 'viewer' or 'editor'.")

    with audited_transaction(settings) as conn:
        doc, perm = _authorize_document(settings, conn, session, doc_id, "share", ip_address)
        target = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (target_username.strip(),),
        ).fetchone()
        if not target:
            raise ServiceError("Target user does not exist or is inactive.", status_code=404)
        if str(target["id"]) == session.user_id:
            raise ServiceError("You already own this document.")

        dek = unwrap_dek_for_user(
            str(perm["wrapped_dek_json"]),
            session.keys.x25519_sk,
            doc_id,
            int(doc["current_version"]),
            session.user_id,
        )
        wrapped_for_target = wrap_dek_for_user(
            dek,
            str(target["x25519_pub_b64"]),
            doc_id,
            int(doc["current_version"]),
            str(target["id"]),
        )
        expires_at = None
        if expires_in_hours is not None and expires_in_hours > 0:
            expires_at = (
                datetime.now(timezone.utc) + timedelta(hours=expires_in_hours)
            ).isoformat()

        now_iso = utc_now_iso()
        existing = conn.execute(
            """
            SELECT id FROM document_permissions
            WHERE doc_id = ? AND user_id = ? AND revoked_at IS NULL
            """,
            (doc_id, target["id"]),
        ).fetchone()

        if existing:
            conn.execute(
                """
                UPDATE document_permissions
                SET role = ?, wrapped_dek_json = ?, granted_by = ?, granted_at = ?, expires_at = ?
                WHERE id = ?
                """,
                (role, wrapped_for_target, session.user_id, now_iso, expires_at, existing["id"]),
            )
        else:
            conn.execute(
                """
                INSERT INTO document_permissions (
                    id, doc_id, user_id, role, wrapped_dek_json,
                    granted_by, granted_at, expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    str(uuid.uuid4()),
                    doc_id,
                    target["id"],
                    role,
                    wrapped_for_target,
                    session.user_id,
                    now_iso,
                    expires_at,
                ),
            )

        append_audit_event(
            settings,
            action="DOC_SHARE_GRANTED",
            outcome="SUCCESS",
            actor_user_id=session.user_id,
            actor_username=session.username,
            ip_address=ip_address,
            target_doc_id=doc_id,
            details={
                "recipient_username": target["username"],
                "role": role,
                "expires_at": expires_at,
            },
            conn=conn,
        )

    return {
        "doc_id": doc_id,
        "recipient_username": str(target["username"]),
        "role": role,
        "expires_at": expires_at,
    }


def revoke_document_share(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    target_user_id: str,
    ip_address: str = "127.0.0.1",
) -> dict[str, Any]:
    """Revoke recipient's access, wipe wrapped DEK, and rotate document DEK/blob."""
    with audited_transaction(settings) as conn:
        doc, perm = _authorize_document(settings, conn, session, doc_id, "revoke", ip_address)
        if target_user_id == session.user_id:
            raise ServiceError("Owner cannot revoke their own ownership.")

        target_perm = conn.execute(
            """
            SELECT p.*, u.username FROM document_permissions p
            JOIN users u ON u.id = p.user_id
            WHERE p.doc_id = ? AND p.user_id = ? AND p.revoked_at IS NULL
            """,
            (doc_id, target_user_id),
        ).fetchone()
        if not target_perm:
            raise ServiceError("Active share grant not found for this user.", status_code=404)

        now_iso = utc_now_iso()
        conn.execute(
            """
            UPDATE document_permissions
            SET revoked_at = ?, wrapped_dek_json = NULL
            WHERE id = ?
            """,
            (now_iso, target_perm["id"]),
        )

        # Decrypt plaintext and rotate DEK to cryptographically isolate revoked recipient
        plaintext = _verify_and_decrypt_doc(settings, conn, doc, perm, session, ip_address)
        new_version = int(doc["current_version"]) + 1
        new_blob_id = str(uuid.uuid4())
        new_dek = generate_dek()

        blob_bytes, pt_sha256, ct_sha256 = encrypt_document_blob(
            plaintext, new_dek, doc_id, new_version, str(doc["owner_id"])
        )
        sig_b64 = sign_document_manifest(
            session.keys.ed25519_sk,
            doc_id,
            new_version,
            str(doc["owner_id"]),
            pt_sha256,
            ct_sha256,
        )

        remaining_perms = conn.execute(
            """
            SELECT p.id, p.user_id, u.x25519_pub_b64
            FROM document_permissions p
            JOIN users u ON u.id = p.user_id
            WHERE p.doc_id = ? AND p.revoked_at IS NULL
            """,
            (doc_id,),
        ).fetchall()

        new_blob_path = settings.blob_dir / f"{new_blob_id}.enc"
        new_blob_path.write_bytes(blob_bytes)
        old_blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"

        try:
            conn.execute(
                """
                UPDATE documents
                SET blob_id = ?, current_version = ?, plaintext_sha256 = ?,
                    ciphertext_sha256 = ?, manifest_signature_b64 = ?,
                    signer_user_id = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    new_blob_id,
                    new_version,
                    pt_sha256,
                    ct_sha256,
                    sig_b64,
                    session.user_id,
                    now_iso,
                    doc_id,
                ),
            )
            for rp in remaining_perms:
                wrapped = wrap_dek_for_user(
                    new_dek, str(rp["x25519_pub_b64"]), doc_id, new_version, str(rp["user_id"])
                )
                conn.execute(
                    "UPDATE document_permissions SET wrapped_dek_json = ? WHERE id = ?",
                    (wrapped, rp["id"]),
                )

            append_audit_event(
                settings,
                action="DOC_SHARE_REVOKED",
                outcome="SUCCESS",
                actor_user_id=session.user_id,
                actor_username=session.username,
                ip_address=ip_address,
                target_doc_id=doc_id,
                details={
                    "revoked_username": target_perm["username"],
                    "rotated_to_version": new_version,
                },
                conn=conn,
            )
        except Exception:
            new_blob_path.unlink(missing_ok=True)
            raise

    old_blob_path.unlink(missing_ok=True)
    return {
        "doc_id": doc_id,
        "revoked_username": str(target_perm["username"]),
        "new_version": new_version,
    }


def delete_document(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    ip_address: str = "127.0.0.1",
) -> None:
    """Owner-only deletion: revokes all DEK grants, marks deleted, deletes encrypted blob."""
    with audited_transaction(settings) as conn:
        doc, _ = _authorize_document(settings, conn, session, doc_id, "delete", ip_address)
        now_iso = utc_now_iso()
        conn.execute(
            "UPDATE documents SET is_deleted = 1, updated_at = ? WHERE id = ?",
            (now_iso, doc_id),
        )
        conn.execute(
            """
            UPDATE document_permissions
            SET revoked_at = ?, wrapped_dek_json = NULL
            WHERE doc_id = ? AND revoked_at IS NULL
            """,
            (now_iso, doc_id),
        )
        append_audit_event(
            settings,
            action="DOC_DELETE",
            outcome="SUCCESS",
            actor_user_id=session.user_id,
            actor_username=session.username,
            ip_address=ip_address,
            target_doc_id=doc_id,
            details={"title": doc["title"]},
            conn=conn,
        )

    blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"
    blob_path.unlink(missing_ok=True)


def get_document_audit_history(
    settings: Settings,
    session: AuthenticatedSession,
    doc_id: str,
    ip_address: str = "127.0.0.1",
) -> list[dict[str, Any]]:
    """Return chronological audit trail for a specific document (owner-only)."""
    with audited_transaction(settings) as conn:
        _authorize_document(settings, conn, session, doc_id, "share", ip_address)
        rows = conn.execute(
            """
            SELECT seq_no, timestamp_utc, actor_username, action, outcome, details_json
            FROM audit_logs
            WHERE target_doc_id = ?
            ORDER BY seq_no DESC
            LIMIT 25
            """,
            (doc_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_user_sessions(settings: Settings, session: AuthenticatedSession) -> list[dict[str, Any]]:
    """List active, non-revoked sessions for the authenticated user."""
    now_iso = utc_now_iso()
    conn = get_connection(settings.db_path)
    try:
        rows = conn.execute(
            """
            SELECT token_hash, created_at, expires_at, last_seen_at, ip_address, user_agent
            FROM sessions
            WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?
            ORDER BY last_seen_at DESC
            """,
            (session.user_id, now_iso),
        ).fetchall()
    finally:
        conn.close()

    items: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        d["is_current"] = hmac.compare_digest(str(r["token_hash"]), session.session_hash)
        d["token_prefix"] = str(r["token_hash"])[:12]
        items.append(d)
    return items


def revoke_other_sessions(
    settings: Settings,
    key_store: RuntimeKeyStore,
    session: AuthenticatedSession,
    ip_address: str = "127.0.0.1",
) -> int:
    """Revoke all active sessions belonging to the user except the current session."""
    now_iso = utc_now_iso()
    with db_transaction(settings.db_path) as conn:
        others = conn.execute(
            """
            SELECT token_hash FROM sessions
            WHERE user_id = ? AND revoked_at IS NULL AND token_hash != ?
            """,
            (session.user_id, session.session_hash),
        ).fetchall()
        for row in others:
            key_store.delete(str(row["token_hash"]))
        conn.execute(
            """
            UPDATE sessions SET revoked_at = ?
            WHERE user_id = ? AND revoked_at IS NULL AND token_hash != ?
            """,
            (now_iso, session.user_id, session.session_hash),
        )
        append_audit_event(
            settings,
            action="OTHER_SESSIONS_REVOKED",
            outcome="SUCCESS",
            actor_user_id=session.user_id,
            actor_username=session.username,
            ip_address=ip_address,
            details={"revoked_count": len(others)},
            conn=conn,
        )
    return len(others)
