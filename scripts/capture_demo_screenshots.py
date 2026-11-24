"""Capture live Playwright screenshots of VaultGuard SDMS and all adversarial scenarios."""

from __future__ import annotations

import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

import uvicorn
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import get_settings
from app.database import get_connection, init_db
from app.main import create_app
from scripts.seed_demo import seed_demo_environment


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _login_browser(page, base_url: str, username: str, password: str) -> None:
    page.goto(f"{base_url}/login", wait_until="networkidle")
    page.fill('input[name="username"]', username)
    page.fill('input[name="password"]', password)
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")


def main() -> None:
    demo_root = ROOT / "tmp_demo_capture"
    if demo_root.exists():
        shutil.rmtree(demo_root)
    demo_root.mkdir(parents=True)

    screenshots_dir = ROOT / "screenshots"
    screenshots_dir.mkdir(parents=True, exist_ok=True)

    settings = get_settings(demo_root)
    init_db(settings.db_path)
    seed_info = seed_demo_environment(demo_root)
    shared_doc_id = seed_info["shared_doc_id"]
    private_doc_id = seed_info["private_doc_id"]

    # Record raw storage inspection proof before tampering
    conn = get_connection(settings.db_path)
    try:
        priv_doc_row = conn.execute(
            "SELECT blob_id FROM documents WHERE id = ?", (private_doc_id,)
        ).fetchone()
        priv_blob_id = str(priv_doc_row["blob_id"])
    finally:
        conn.close()

    blob_bytes = (settings.blob_dir / f"{priv_blob_id}.enc").read_bytes()
    evidence_txt = ROOT / "docs" / "storage_exposure_evidence.txt"
    evidence_txt.parent.mkdir(parents=True, exist_ok=True)
    evidence_txt.write_text(
        "\n".join(
            [
                "=== VaultGuard SDMS Storage Exposure Inspection ===",
                f"Private Document UUID: {private_doc_id}",
                f"Opaque Blob Filename:  storage/vault_blobs/{priv_blob_id}.enc",
                f"Blob Size (bytes):     {len(blob_bytes)}",
                f"Magic Header:          {blob_bytes[:5]!r}",
                f"Nonce (12 bytes hex):  {blob_bytes[5:17].hex()}",
                f"Ciphertext+Tag (head): {blob_bytes[17:49].hex()}",
                f"Plaintext leaked?:     {b'Playbook' in blob_bytes or b'Incident' in blob_bytes}",
            ]
        ),
        encoding="utf-8",
    )

    app = create_app(settings)
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(1.0)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # 1. Login & Alice Dashboard & Document Detail
            ctx_alice = browser.new_context(viewport={"width": 1360, "height": 860})
            p_alice = ctx_alice.new_page()
            p_alice.goto(f"{base_url}/login", wait_until="networkidle")
            p_alice.screenshot(path=str(screenshots_dir / "01_login_screen.png"), full_page=True)

            _login_browser(p_alice, base_url, "alice", "AliceTest#2026!")
            p_alice.screenshot(path=str(screenshots_dir / "02_alice_dashboard.png"), full_page=True)

            p_alice.goto(f"{base_url}/documents/{shared_doc_id}", wait_until="networkidle")
            p_alice.screenshot(path=str(screenshots_dir / "03_document_detail_and_sharing.png"), full_page=True)

            p_alice.goto(f"{base_url}/profile", wait_until="networkidle")
            p_alice.screenshot(path=str(screenshots_dir / "10_identity_keys_sessions.png"), full_page=True)
            p_alice.goto(f"{base_url}/documents/{shared_doc_id}", wait_until="networkidle")

            # 2. Scenario 1 & 2: Charlie IDOR / Unauthorized access
            ctx_charlie = browser.new_context(viewport={"width": 1360, "height": 860})
            p_charlie = ctx_charlie.new_page()
            _login_browser(p_charlie, base_url, "charlie", "CharlieTest#2026!")
            p_charlie.goto(f"{base_url}/documents/{private_doc_id}", wait_until="networkidle")
            p_charlie.screenshot(path=str(screenshots_dir / "04_scenario1_2_idor_unauthorized_403.png"), full_page=True)

            # 3. Scenario 5: Bob (viewer) viewing shared document (least privilege UI + role badge)
            ctx_bob = browser.new_context(viewport={"width": 1360, "height": 860})
            p_bob = ctx_bob.new_page()
            _login_browser(p_bob, base_url, "bob", "BobTest#2026!")
            p_bob.goto(f"{base_url}/documents/{shared_doc_id}", wait_until="networkidle")
            p_bob.screenshot(path=str(screenshots_dir / "05_scenario5_viewer_privilege_boundary.png"), full_page=True)

            # 4. Scenario 6: Alice revokes Bob, Bob tries to reopen -> 403
            p_alice.locator('form[action$="/revoke"] button[type="submit"]').first.click()
            p_alice.wait_for_load_state("networkidle")
            p_bob.goto(f"{base_url}/documents/{shared_doc_id}", wait_until="networkidle")
            p_bob.screenshot(path=str(screenshots_dir / "06_scenario6_revocation_denied_403.png"), full_page=True)

            # 5. Scenario 4: Corrupt private document blob on disk -> Alice sees Integrity Violation 409
            priv_blob_path = settings.blob_dir / f"{priv_blob_id}.enc"
            tampered_blob = bytearray(priv_blob_path.read_bytes())
            tampered_blob[-8] ^= 0xAA
            priv_blob_path.write_bytes(bytes(tampered_blob))
            p_alice.goto(f"{base_url}/documents/{private_doc_id}", wait_until="networkidle")
            p_alice.screenshot(path=str(screenshots_dir / "07_scenario4_external_tamper_alert.png"), full_page=True)

            # 6. Admin Console (intact audit chain + suspicious alerts)
            ctx_admin = browser.new_context(viewport={"width": 1360, "height": 900})
            p_admin = ctx_admin.new_page()
            _login_browser(p_admin, base_url, "sec_admin", "AdminAudit#2026!")
            p_admin.screenshot(path=str(screenshots_dir / "08_admin_audit_console_intact.png"), full_page=True)

            # 7. Scenario 7: Direct SQL tamper on audit_logs -> Admin Console detects TAMPER DETECTED
            conn = get_connection(settings.db_path)
            try:
                conn.execute(
                    "UPDATE audit_logs SET outcome = 'SUCCESS', actor_username = 'forged_user' WHERE seq_no = 12"
                )
                max_seq = conn.execute("SELECT MAX(seq_no) AS m FROM audit_logs").fetchone()["m"]
                conn.execute("DELETE FROM audit_logs WHERE seq_no = ?", (max_seq,))
            finally:
                conn.close()

            p_admin.reload(wait_until="networkidle")
            p_admin.screenshot(path=str(screenshots_dir / "09_scenario7_audit_tamper_detected.png"), full_page=True)

            browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        shutil.rmtree(demo_root, ignore_errors=True)

    print("Captured 9 live demonstration screenshots in screenshots/")


if __name__ == "__main__":
    main()
