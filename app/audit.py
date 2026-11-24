"""Tamper-evident cryptographic hash-chained & HMAC-authenticated audit logging."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import Settings
from app.crypto import hmac_sha256_hex
from app.database import db_transaction, get_connection

GENESIS_HASH = "0" * 64
SENSITIVE_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "dek",
        "wrapped_dek",
        "private_key",
        "secret",
        "token",
        "session_key",
        "recovery_code",
        "plaintext",
        "content",
    }
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_details(details: dict[str, Any] | None) -> str:
    """Ensure sensitive secrets or document contents never enter audit logs."""
    if not details:
        return "{}"
    cleaned: dict[str, Any] = {}
    for key, val in details.items():
        if key.lower() in SENSITIVE_KEYS:
            cleaned[key] = "[REDACTED]"
        elif isinstance(val, str) and len(val) > 512:
            cleaned[key] = val[:512] + "...[TRUNCATED]"
        else:
            cleaned[key] = val
    return json.dumps(cleaned, sort_keys=True, separators=(",", ":"))


def _canonical_entry_string(
    seq_no: int,
    event_id: str,
    timestamp_utc: str,
    actor_user_id: str | None,
    actor_username: str,
    ip_address: str,
    action: str,
    target_doc_id: str | None,
    outcome: str,
    details_json: str,
    prev_hash: str,
) -> str:
    return "|".join(
        [
            str(seq_no),
            event_id,
            timestamp_utc,
            actor_user_id or "",
            actor_username,
            ip_address,
            action,
            target_doc_id or "",
            outcome,
            details_json,
            prev_hash,
        ]
    )


def append_audit_event(
    settings: Settings,
    *,
    action: str,
    outcome: str,
    actor_user_id: str | None = None,
    actor_username: str = "anonymous",
    ip_address: str = "127.0.0.1",
    target_doc_id: str | None = None,
    details: dict[str, Any] | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Append an audit log entry inside an atomic hash-chain + HMAC update.

    If `conn` is provided, caller manages the IMMEDIATE transaction.
    """

    def _insert(c: sqlite3.Connection) -> dict[str, Any]:
        row = c.execute(
            "SELECT seq_no, entry_hash FROM audit_logs ORDER BY seq_no DESC LIMIT 1"
        ).fetchone()
        next_seq = (int(row["seq_no"]) + 1) if row else 1
        prev_hash = str(row["entry_hash"]) if row else GENESIS_HASH

        event_id = str(uuid.uuid4())
        ts = utc_now_iso()
        details_json = _sanitize_details(details)
        canonical = _canonical_entry_string(
            next_seq,
            event_id,
            ts,
            actor_user_id,
            actor_username,
            ip_address,
            action,
            target_doc_id,
            outcome,
            details_json,
            prev_hash,
        )
        entry_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        entry_hmac = hmac_sha256_hex(settings.audit_hmac_key, entry_hash)

        c.execute(
            """
            INSERT INTO audit_logs (
                seq_no, event_id, timestamp_utc, actor_user_id, actor_username,
                ip_address, action, target_doc_id, outcome, details_json,
                prev_hash, entry_hash, entry_hmac
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                next_seq,
                event_id,
                ts,
                actor_user_id,
                actor_username,
                ip_address,
                action,
                target_doc_id,
                outcome,
                details_json,
                prev_hash,
                entry_hash,
                entry_hmac,
            ),
        )
        _write_chain_head(settings.audit_chain_head_path, settings.audit_hmac_key, next_seq, entry_hash)
        return {
            "seq_no": next_seq,
            "event_id": event_id,
            "timestamp_utc": ts,
            "action": action,
            "outcome": outcome,
            "entry_hash": entry_hash,
        }

    if conn is not None:
        return _insert(conn)

    with db_transaction(settings.db_path) as tx_conn:
        return _insert(tx_conn)


def _write_chain_head(head_path: Path, hmac_key: bytes, seq_no: int, entry_hash: str) -> None:
    """Persist external HMAC-signed chain head anchor to catch tail row deletion."""
    payload = f"{seq_no}|{entry_hash}"
    anchor = {
        "last_seq": seq_no,
        "last_entry_hash": entry_hash,
        "head_hmac": hmac_sha256_hex(hmac_key, payload),
    }
    head_path.write_text(json.dumps(anchor, indent=2), encoding="utf-8")


def verify_audit_chain(settings: Settings) -> dict[str, Any]:
    """Verify full audit log hash chain, sequence contiguity, HMAC tags, and tail anchor."""
    conn = get_connection(settings.db_path)
    try:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY seq_no ASC").fetchall()
    finally:
        conn.close()

    anomalies: list[dict[str, Any]] = []
    expected_seq = 1
    expected_prev_hash = GENESIS_HASH
    verified_count = 0

    for row in rows:
        seq_no = int(row["seq_no"])
        if seq_no != expected_seq:
            anomalies.append(
                {
                    "seq_no": seq_no,
                    "type": "SEQUENCE_GAP",
                    "detail": f"Expected seq_no {expected_seq} but found {seq_no} (possible row deletion).",
                }
            )
            expected_seq = seq_no

        if not hmac.compare_digest(str(row["prev_hash"]), expected_prev_hash):
            anomalies.append(
                {
                    "seq_no": seq_no,
                    "type": "CHAIN_LINK_BROKEN",
                    "detail": f"prev_hash mismatch at seq_no {seq_no}.",
                }
            )

        canonical = _canonical_entry_string(
            seq_no,
            str(row["event_id"]),
            str(row["timestamp_utc"]),
            row["actor_user_id"],
            str(row["actor_username"]),
            str(row["ip_address"]),
            str(row["action"]),
            row["target_doc_id"],
            str(row["outcome"]),
            str(row["details_json"]),
            str(row["prev_hash"]),
        )
        recomputed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(recomputed_hash, str(row["entry_hash"])):
            anomalies.append(
                {
                    "seq_no": seq_no,
                    "type": "ROW_CONTENT_TAMPERED",
                    "detail": f"entry_hash mismatch at seq_no {seq_no} (record fields were altered).",
                }
            )

        expected_hmac = hmac_sha256_hex(settings.audit_hmac_key, str(row["entry_hash"]))
        if not hmac.compare_digest(expected_hmac, str(row["entry_hmac"])):
            anomalies.append(
                {
                    "seq_no": seq_no,
                    "type": "HMAC_FORGERY_DETECTED",
                    "detail": f"entry_hmac verification failed at seq_no {seq_no}.",
                }
            )

        if not any(a["seq_no"] == seq_no for a in anomalies):
            verified_count += 1

        expected_prev_hash = str(row["entry_hash"])
        expected_seq += 1

    # Check external tail anchor against DB last row to detect tail truncation
    if settings.audit_chain_head_path.exists():
        try:
            anchor = json.loads(settings.audit_chain_head_path.read_text(encoding="utf-8"))
            anchor_hmac = hmac_sha256_hex(
                settings.audit_hmac_key, f"{anchor['last_seq']}|{anchor['last_entry_hash']}"
            )
            if not hmac.compare_digest(anchor_hmac, str(anchor["head_hmac"])):
                anomalies.append(
                    {
                        "seq_no": anchor.get("last_seq"),
                        "type": "ANCHOR_HMAC_INVALID",
                        "detail": "External chain_head.json anchor HMAC is invalid.",
                    }
                )
            else:
                last_db_seq = int(rows[-1]["seq_no"]) if rows else 0
                last_db_hash = str(rows[-1]["entry_hash"]) if rows else GENESIS_HASH
                if last_db_seq != int(anchor["last_seq"]) or not hmac.compare_digest(
                    last_db_hash, str(anchor["last_entry_hash"])
                ):
                    anomalies.append(
                        {
                            "seq_no": anchor.get("last_seq"),
                            "type": "TAIL_TRUNCATION_DETECTED",
                            "detail": (
                                f"External anchor expects seq_no {anchor['last_seq']}, "
                                f"but DB ends at seq_no {last_db_seq}."
                            ),
                        }
                    )
        except (ValueError, KeyError) as exc:
            anomalies.append(
                {
                    "seq_no": None,
                    "type": "ANCHOR_CORRUPTED",
                    "detail": f"External chain_head.json is unreadable: {exc}",
                }
            )
    elif rows:
        anomalies.append(
            {
                "seq_no": None,
                "type": "ANCHOR_MISSING",
                "detail": "Audit rows exist in DB but external chain_head.json anchor is missing.",
            }
        )

    return {
        "valid": len(anomalies) == 0,
        "total_records": len(rows),
        "verified_records": verified_count,
        "anomalies": anomalies,
    }


def detect_suspicious_patterns(settings: Settings) -> list[dict[str, Any]]:
    """Analyze audit trail to flag anomalous/suspicious actor patterns."""
    conn = get_connection(settings.db_path)
    try:
        rows = conn.execute(
            """
            SELECT actor_username, ip_address, action, outcome, COUNT(*) AS hit_count,
                   MAX(timestamp_utc) AS last_seen
            FROM audit_logs
            WHERE outcome IN ('DENIED', 'ALERT')
            GROUP BY actor_username, ip_address, action, outcome
            ORDER BY hit_count DESC, last_seen DESC
            LIMIT 25
            """
        ).fetchall()
    finally:
        conn.close()

    alerts: list[dict[str, Any]] = []
    for r in rows:
        count = int(r["hit_count"])
        action = str(r["action"])
        severity = "HIGH" if r["outcome"] == "ALERT" or count >= 3 else "MEDIUM"
        alerts.append(
            {
                "actor_username": r["actor_username"],
                "ip_address": r["ip_address"],
                "action": action,
                "outcome": r["outcome"],
                "hit_count": count,
                "last_seen": r["last_seen"],
                "severity": severity,
            }
        )
    return alerts
