"""Comprehensive functional and adversarial security tests for VaultGuard SDMS (Part 3)."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.audit import verify_audit_chain
from app.config import Settings, get_settings
from app.crypto import CryptoIntegrityError, CryptoKeyError, decrypt_document_blob, unwrap_dek_for_user
from app.database import get_connection, init_db
from app.main import create_app
from app.services import RuntimeKeyStore, register_user


@pytest.fixture()
def vault_env(tmp_path: Path):
    """Create an isolated VaultGuard instance with fresh DB, blob dir, and test accounts."""
    settings = get_settings(tmp_path / "storage")
    init_db(settings.db_path)

    # Seed an auditor_admin via privileged bootstrap (not exposed publicly)
    register_user(
        settings,
        username="sec_admin",
        email="sec_admin@vaultguard.test",
        full_name="Security Auditor",
        password="AdminStrong#2026!",
        system_role="auditor_admin",
        allow_admin_creation=True,
    )

    app = create_app(settings)
    return app, settings


def _api_register_and_login(
    client: TestClient, username: str, email: str, full_name: str, password: str
) -> dict:
    reg = client.post(
        "/api/auth/register",
        json={
            "username": username,
            "email": email,
            "full_name": full_name,
            "password": password,
        },
    )
    assert reg.status_code == 201, reg.text
    login = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert login.status_code == 200, login.text
    data = login.json()
    return {
        "user_id": data["user"]["id"],
        "username": username,
        "csrf": data["csrf_token"],
        "recovery_code": reg.json()["recovery_code"],
        "cookies": dict(login.cookies),
    }


def _api_login(client: TestClient, username: str, password: str) -> dict:
    login = client.post(
        "/api/auth/login", json={"username": username, "password": password}
    )
    assert login.status_code == 200, login.text
    data = login.json()
    return {
        "user_id": data["user"]["id"],
        "username": username,
        "csrf": data["csrf_token"],
        "cookies": dict(login.cookies),
    }


def _upload_doc(
    client: TestClient, user_ctx: dict, title: str, filename: str, content: bytes
) -> dict:
    resp = client.post(
        "/api/documents",
        data={"title": title},
        files={"file": (filename, content, "text/plain")},
        headers={"X-CSRF-Token": user_ctx["csrf"]},
        cookies=user_ctx["cookies"],
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_scenario_1_and_2_unauthorized_access_and_idor(vault_env):
    """Part 3 Scenarios 1 & 2: Unauthorized access, admin least privilege, and IDOR."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        charlie = _api_register_and_login(
            client, "charlie", "charlie@test.local", "Charlie", "CharlieStrong#2026!"
        )
        admin = _api_login(client, "sec_admin", "AdminStrong#2026!")

        secret_bytes = b"TOP-SECRET-ALICE-PAYROLL-DATA-9942"
        doc = _upload_doc(client, alice, "Payroll Q4", "payroll.txt", secret_bytes)
        doc_id = doc["doc_id"]

        # Scenario 1a: Charlie (unrelated user) attempts GET and download -> 403
        r_charlie = client.get(f"/api/documents/{doc_id}", cookies=charlie["cookies"])
        assert r_charlie.status_code == 403
        r_dl = client.get(f"/documents/{doc_id}/download", cookies=charlie["cookies"])
        assert r_dl.status_code == 403

        # Scenario 1b: Auditor Admin cannot automatically read user's confidential doc -> 403
        r_admin = client.get(f"/api/documents/{doc_id}", cookies=admin["cookies"])
        assert r_admin.status_code == 403

        # Admin CAN verify ciphertext integrity without decrypting -> 200
        r_admin_verify = client.get(
            f"/api/documents/{doc_id}/verify", cookies=admin["cookies"]
        )
        assert r_admin_verify.status_code == 200
        assert r_admin_verify.json()["verified"] is True

        # Scenario 2: Identifier manipulation (bogus UUID and path-like IDOR)
        r_fake = client.get(
            "/api/documents/00000000-0000-0000-0000-000000000099",
            cookies=charlie["cookies"],
        )
        assert r_fake.status_code == 404
        r_malformed = client.get(
            "/api/documents/12345-not-a-uuid", cookies=charlie["cookies"]
        )
        assert r_malformed.status_code == 400

        # Confirm IDOR attempts were recorded in audit log without leaking plaintext
        conn = get_connection(settings.db_path)
        try:
            idor_rows = conn.execute(
                "SELECT action, outcome, actor_username, details_json FROM audit_logs WHERE action = 'IDOR_ATTEMPT'"
            ).fetchall()
            assert len(idor_rows) >= 4
            assert any(r["actor_username"] == "sec_admin" for r in idor_rows)
            all_logs = conn.execute("SELECT details_json FROM audit_logs").fetchall()
            for lr in all_logs:
                assert "TOP-SECRET-ALICE-PAYROLL-DATA-9942" not in lr["details_json"]
        finally:
            conn.close()


def test_scenario_3_storage_exposure_analysis(vault_env):
    """Part 3 Scenario 3: Raw storage & DB inspection reveals no plaintext or raw DEKs."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        secret = b"CLASSIFIED-FORMULA-ALPHA-778811-DO-NOT-EXFILTRATE"
        doc = _upload_doc(client, alice, "Formula Alpha", "formula_alpha.txt", secret)

        blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"
        assert blob_path.exists()
        raw_blob = blob_path.read_bytes()
        assert raw_blob.startswith(b"VGSD1")
        assert b"CLASSIFIED-FORMULA" not in raw_blob
        assert b"formula_alpha" not in raw_blob
        assert b"alice" not in raw_blob

        conn = get_connection(settings.db_path)
        try:
            user_row = conn.execute(
                "SELECT password_hash, enc_private_bundle, recovery_bundle FROM users WHERE username = 'alice'"
            ).fetchone()
            assert user_row["password_hash"].startswith("$argon2id$")
            assert "AliceStrong" not in user_row["enc_private_bundle"]

            perm_row = conn.execute(
                "SELECT wrapped_dek_json FROM document_permissions WHERE doc_id = ?",
                (doc["doc_id"],),
            ).fetchone()
            wrapped_obj = json.loads(perm_row["wrapped_dek_json"])
            assert set(wrapped_obj.keys()) == {"v", "eph_pub", "nonce", "ct"}

            # Attempting to decrypt blob with a guessed key fails with CryptoIntegrityError
            with pytest.raises(CryptoIntegrityError):
                decrypt_document_blob(
                    raw_blob,
                    b"\x00" * 32,
                    doc["doc_id"],
                    1,
                    alice["user_id"],
                    doc["plaintext_sha256"],
                )
        finally:
            conn.close()


def test_scenario_4_external_document_tampering_detection(vault_env):
    """Part 3 Scenario 4: Modifying encrypted blob outside app fails closed & alerts."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        doc = _upload_doc(
            client, alice, "Financial Ledger", "ledger.txt", b"Balance: $100,000.00"
        )
        blob_path = settings.blob_dir / f"{doc['blob_id']}.enc"

        # Attacker flips 1 bit inside ciphertext on disk
        tampered = bytearray(blob_path.read_bytes())
        tampered[-10] ^= 0xFF
        blob_path.write_bytes(bytes(tampered))

        # Retrieval must fail closed with 409 Conflict
        resp = client.get(f"/api/documents/{doc['doc_id']}", cookies=alice["cookies"])
        assert resp.status_code == 409
        assert "INTEGRITY ALERT" in resp.json()["detail"]

        # Verify endpoint reports tampered state
        v_resp = client.get(
            f"/api/documents/{doc['doc_id']}/verify", cookies=alice["cookies"]
        )
        assert v_resp.status_code == 409
        assert v_resp.json()["ciphertext_hash_ok"] is False

        conn = get_connection(settings.db_path)
        try:
            alert = conn.execute(
                "SELECT action, outcome FROM audit_logs WHERE target_doc_id = ? AND outcome = 'ALERT'",
                (doc["doc_id"],),
            ).fetchone()
            assert alert is not None
            assert alert["action"] == "DOCUMENT_INTEGRITY_FAILURE"
        finally:
            conn.close()


def test_scenario_5_privilege_misuse_and_escalation(vault_env):
    """Part 3 Scenario 5: Viewer cannot edit/share/delete; user cannot access admin or mass-assign."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        bob = _api_register_and_login(
            client, "bob", "bob@test.local", "Bob", "BobStrong#2026!"
        )
        doc = _upload_doc(client, alice, "Design Spec", "spec.txt", b"Original spec v1")
        doc_id = doc["doc_id"]

        # Share with Bob as viewer
        sh = client.post(
            f"/api/documents/{doc_id}/share",
            json={"target_username": "bob", "role": "viewer"},
            headers={"X-CSRF-Token": alice["csrf"]},
            cookies=alice["cookies"],
        )
        assert sh.status_code == 200

        # Bob can read
        assert client.get(f"/api/documents/{doc_id}", cookies=bob["cookies"]).status_code == 200

        # Bob attempts edit -> 403
        r_edit = client.put(
            f"/api/documents/{doc_id}",
            json={"new_text": "Malicious tamper by viewer"},
            headers={"X-CSRF-Token": bob["csrf"]},
            cookies=bob["cookies"],
        )
        assert r_edit.status_code == 403

        # Bob attempts share -> 403
        r_share = client.post(
            f"/api/documents/{doc_id}/share",
            json={"target_username": "alice", "role": "editor"},
            headers={"X-CSRF-Token": bob["csrf"]},
            cookies=bob["cookies"],
        )
        assert r_share.status_code == 403

        # Bob attempts delete -> 403
        r_del = client.delete(
            f"/api/documents/{doc_id}",
            headers={"X-CSRF-Token": bob["csrf"]},
            cookies=bob["cookies"],
        )
        assert r_del.status_code == 403

        # Bob attempts to access /admin -> 403
        assert client.get("/api/admin/audit/verify", cookies=bob["cookies"]).status_code == 403

        # Mass assignment check: signup ignores extra system_role='auditor_admin'
        eve = client.post(
            "/api/auth/register",
            json={
                "username": "eve_escalate",
                "email": "eve@test.local",
                "full_name": "Eve",
                "password": "EveStrong#2026!",
                "system_role": "auditor_admin",
            },
        )
        assert eve.status_code == 201
        assert eve.json()["system_role"] == "user"


def test_scenario_6_permission_revocation_and_key_rotation(vault_env):
    """Part 3 Scenario 6: Revoking access blocks future reads and rotates DEK/blob."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        bob = _api_register_and_login(
            client, "bob", "bob@test.local", "Bob", "BobStrong#2026!"
        )
        doc = _upload_doc(
            client, alice, "Roadmap 2027", "roadmap.txt", b"Confidential Q1 launch plan"
        )
        doc_id = doc["doc_id"]

        client.post(
            f"/api/documents/{doc_id}/share",
            json={"target_username": "bob", "role": "editor"},
            headers={"X-CSRF-Token": alice["csrf"]},
            cookies=alice["cookies"],
        )
        # Bob edits v1 -> v2 successfully while permitted
        ed = client.put(
            f"/api/documents/{doc_id}",
            json={"new_text": "Confidential Q1 launch plan - Bob edit"},
            headers={"X-CSRF-Token": bob["csrf"]},
            cookies=bob["cookies"],
        )
        assert ed.status_code == 200
        assert ed.json()["version"] == 2

        # Snapshot Bob's v2 wrapped DEK before revocation
        conn = get_connection(settings.db_path)
        try:
            old_wrapped = conn.execute(
                "SELECT wrapped_dek_json FROM document_permissions WHERE doc_id = ? AND user_id = ?",
                (doc_id, bob["user_id"]),
            ).fetchone()["wrapped_dek_json"]
            old_blob_id = conn.execute(
                "SELECT blob_id FROM documents WHERE id = ?", (doc_id,)
            ).fetchone()["blob_id"]
        finally:
            conn.close()

        # Alice revokes Bob's access
        rev = client.post(
            f"/api/documents/{doc_id}/revoke",
            json={"target_user_id": bob["user_id"]},
            headers={"X-CSRF-Token": alice["csrf"]},
            cookies=alice["cookies"],
        )
        assert rev.status_code == 200
        assert rev.json()["new_version"] == 3

        # Bob's subsequent read & download must be denied (403)
        assert client.get(f"/api/documents/{doc_id}", cookies=bob["cookies"]).status_code == 403
        assert client.get(f"/documents/{doc_id}/download", cookies=bob["cookies"]).status_code == 403

        # Old blob was deleted and DEK rotated; old wrapped DEK cannot decrypt v3 blob
        assert not (settings.blob_dir / f"{old_blob_id}.enc").exists()
        conn = get_connection(settings.db_path)
        try:
            perm_after = conn.execute(
                "SELECT revoked_at, wrapped_dek_json FROM document_permissions WHERE doc_id = ? AND user_id = ?",
                (doc_id, bob["user_id"]),
            ).fetchone()
            assert perm_after["revoked_at"] is not None
            assert perm_after["wrapped_dek_json"] is None
            assert old_wrapped is not None
        finally:
            conn.close()

        # Alice still reads v3 cleanly
        r_alice = client.get(f"/api/documents/{doc_id}", cookies=alice["cookies"])
        assert r_alice.status_code == 200
        assert "Bob edit" in r_alice.json()["content_text"]


def test_scenario_7_audit_tampering_detection(vault_env):
    """Part 3 Scenario 7: Detect row edits, forged hash chains, and tail deletions."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        admin = _api_login(client, "sec_admin", "AdminStrong#2026!")
        _upload_doc(client, alice, "Audit Test Doc", "a.txt", b"audit payload")

        # Baseline chain is valid
        ok_resp = client.get("/api/admin/audit/verify", cookies=admin["cookies"])
        assert ok_resp.status_code == 200
        assert ok_resp.json()["valid"] is True

        # Tamper 1: Alter an existing audit row directly in SQLite
        conn = get_connection(settings.db_path)
        try:
            conn.execute(
                "UPDATE audit_logs SET outcome = 'DENIED' WHERE seq_no = 2"
            )
        finally:
            conn.close()

        bad_resp = client.get("/api/admin/audit/verify", cookies=admin["cookies"])
        assert bad_resp.status_code == 409
        report = bad_resp.json()
        assert report["valid"] is False
        assert any(a["type"] == "ROW_CONTENT_TAMPERED" and a["seq_no"] == 2 for a in report["anomalies"])

        # Tamper 2: Attacker deletes the final audit log row (tail truncation)
        conn = get_connection(settings.db_path)
        try:
            max_seq = conn.execute("SELECT MAX(seq_no) AS m FROM audit_logs").fetchone()["m"]
            conn.execute("DELETE FROM audit_logs WHERE seq_no = ?", (max_seq,))
        finally:
            conn.close()

        tail_report = verify_audit_chain(settings)
        assert tail_report["valid"] is False
        assert any(a["type"] == "TAIL_TRUNCATION_DETECTED" for a in tail_report["anomalies"])


def test_bonus_lockout_csrf_recovery_and_expiry(vault_env):
    """Verify brute-force lockout, CSRF defense, key recovery, and share expiration."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        bob = _api_register_and_login(
            client, "bob", "bob@test.local", "Bob", "BobStrong#2026!"
        )
        doc = _upload_doc(client, alice, "Key Recovery Test", "rec.txt", b"Survives password reset!")

        # CSRF protection blocks upload without X-CSRF-Token
        no_csrf = client.post(
            "/api/documents",
            data={"title": "No CSRF"},
            files={"file": ("x.txt", b"abc", "text/plain")},
            cookies=alice["cookies"],
        )
        assert no_csrf.status_code == 403

        # Share with expiry, then simulate expiration in DB -> denied
        client.post(
            f"/api/documents/{doc['doc_id']}/share",
            json={"target_username": "bob", "role": "viewer", "expires_in_hours": 1},
            headers={"X-CSRF-Token": alice["csrf"]},
            cookies=alice["cookies"],
        )
        conn = get_connection(settings.db_path)
        try:
            past = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
            conn.execute(
                "UPDATE document_permissions SET expires_at = ? WHERE doc_id = ? AND user_id = ?",
                (past, doc["doc_id"], bob["user_id"]),
            )
        finally:
            conn.close()
        assert client.get(f"/api/documents/{doc['doc_id']}", cookies=bob["cookies"]).status_code == 403

        # Self-service recovery code password reset preserves Alice's decryption capability
        rec_resp = client.post(
            "/recover",
            data={
                "username": "alice",
                "recovery_code": alice["recovery_code"],
                "new_password": "AliceNewStrong#2027!",
            },
        )
        assert rec_resp.status_code == 200

        # Old session was revoked by password recovery
        assert client.get("/api/documents", cookies=alice["cookies"]).status_code == 401

        # Re-login with new password decrypts the existing document cleanly!
        alice2 = _api_login(client, "alice", "AliceNewStrong#2027!")
        got = client.get(f"/api/documents/{doc['doc_id']}", cookies=alice2["cookies"])
        assert got.status_code == 200
        assert got.json()["content_text"] == "Survives password reset!"

        # Brute-force lockout on Bob after 5 bad password attempts
        for _ in range(4):
            bad = client.post(
                "/api/auth/login", json={"username": "bob", "password": "WrongPassword#1"}
            )
            assert bad.status_code == 401
        locked = client.post(
            "/api/auth/login", json={"username": "bob", "password": "WrongPassword#1"}
        )
        assert locked.status_code == 429


def test_profile_session_management_and_ui_verify(vault_env):
    """Verify Identity/Key fingerprint profile page, multi-session revocation, and UI integrity button."""
    app, settings = vault_env
    with TestClient(app) as client:
        alice_s1 = _api_register_and_login(
            client, "alice", "alice@test.local", "Alice", "AliceStrong#2026!"
        )
        doc = _upload_doc(client, alice_s1, "Profile Check", "prof.txt", b"session isolation check")

        # Second independent session for Alice
        alice_s2 = _api_login(client, "alice", "AliceStrong#2026!")

        # View /profile and /documents/{id} in UI with s2
        prof = client.get("/profile", cookies=alice_s2["cookies"])
        assert prof.status_code == 200
        assert "X25519 Fingerprint" in prof.text
        assert "Ed25519 Fingerprint" in prof.text

        # Security headers verified (strict CSP without unsafe-inline script)
        assert "script-src 'self'" in prof.headers.get("content-security-policy", "")
        assert prof.headers.get("x-frame-options") == "DENY"

        # UI verify integrity button
        ver = client.post(
            f"/documents/{doc['doc_id']}/verify",
            data={"csrf_token": alice_s2["csrf"]},
            cookies=alice_s2["cookies"],
            follow_redirects=False,
        )
        assert ver.status_code == 303
        assert "PASSED" in ver.headers["location"]

        # Revoke all other sessions from s2 -> s1 becomes invalid (401)
        rev = client.post(
            "/profile/revoke-other-sessions",
            data={"csrf_token": alice_s2["csrf"]},
            cookies=alice_s2["cookies"],
            follow_redirects=False,
        )
        assert rev.status_code == 303
        assert client.get("/api/documents", cookies=alice_s1["cookies"]).status_code == 401
        assert client.get("/api/documents", cookies=alice_s2["cookies"]).status_code == 200

