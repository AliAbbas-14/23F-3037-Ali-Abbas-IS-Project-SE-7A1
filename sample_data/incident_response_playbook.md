# Incident Response Playbook (Synthetic Test Fixture)

- **Trigger 1 — Integrity Violation (`DOCUMENT_INTEGRITY_FAILURE`)**:
  Immediately block document retrieval, preserve ciphertext snapshot, and escalate to Security Auditor Admin.
- **Trigger 2 — Brute Force (`ACCOUNT_LOCKED`)**:
  Enforce 300-second lockout after 5 failed Argon2id authentication attempts and flag IP in audit summary.
- **Trigger 3 — Audit Tampering (`ROW_CONTENT_TAMPERED` / `SEQUENCE_GAP`)**:
  Freeze automated trust in local SQLite logs and inspect external HMAC chain anchor.
