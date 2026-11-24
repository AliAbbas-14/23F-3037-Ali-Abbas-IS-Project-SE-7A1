"""Seed VaultGuard SDMS with controlled, non-secret demonstration accounts and sample documents."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import get_settings
from app.database import init_db
from app.services import RuntimeKeyStore, login_user, register_user, share_document, upload_document


def seed_demo_environment(storage_root: Path | None = None) -> dict[str, str]:
    """Create controlled test accounts and encrypted sample documents (no real secrets)."""
    settings = get_settings(storage_root)
    init_db(settings.db_path)
    key_store = RuntimeKeyStore()

    demo_accounts = [
        ("alice", "alice@vaultguard.test", "Alice Khan (Doc Owner)", "AliceTest#2026!", "user", False),
        ("bob", "bob@vaultguard.test", "Bob Ahmed (Collaborator)", "BobTest#2026!", "user", False),
        ("charlie", "charlie@vaultguard.test", "Charlie Raza (External User)", "CharlieTest#2026!", "user", False),
        ("sec_admin", "admin@vaultguard.test", "Security Auditor Admin", "AdminAudit#2026!", "auditor_admin", True),
    ]

    recovery_codes: dict[str, str] = {}
    for uname, email, full_name, pwd, role, allow_admin in demo_accounts:
        try:
            res = register_user(
                settings,
                username=uname,
                email=email,
                full_name=full_name,
                password=pwd,
                system_role=role,
                allow_admin_creation=allow_admin,
            )
            recovery_codes[uname] = res["recovery_code"]
        except Exception:
            pass

    # Upload sample documents as Alice
    alice_login = login_user(settings, key_store, username="alice", password="AliceTest#2026!")
    from app.services import resolve_session

    alice_sess = resolve_session(
        settings, key_store, alice_login["raw_session_token"], alice_login["session_key_hex"]
    )
    sample_1 = (ROOT / "sample_data" / "confidential_architecture_brief.txt").read_bytes()
    doc1 = upload_document(
        settings,
        alice_sess,
        title="CS3002 Zero-Trust Architecture Brief",
        filename="confidential_architecture_brief.txt",
        content=sample_1,
        mime_type="text/plain",
    )
    share_document(
        settings,
        alice_sess,
        doc1["doc_id"],
        target_username="bob",
        role="viewer",
    )

    sample_2 = (ROOT / "sample_data" / "incident_response_playbook.md").read_bytes()
    doc2 = upload_document(
        settings,
        alice_sess,
        title="Incident Response Playbook (Alice Only)",
        filename="incident_response_playbook.md",
        content=sample_2,
        mime_type="text/markdown",
    )

    return {
        "shared_doc_id": doc1["doc_id"],
        "private_doc_id": doc2["doc_id"],
    }


if __name__ == "__main__":
    info = seed_demo_environment()
    print("Seeded demo VaultGuard SDMS successfully:", info)
