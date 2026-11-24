# VaultGuard SDMS — Secure Document Management System

**Course:** CS3002 – Information Security (Semester Project)  
**Campus:** FAST-NUCES, Chiniot – Faisalabad Campus  
**Author:** Ali Abbas (`23F-3037`, Section `SE-7A1`)  

---

## 🌐 Live Deployed Application

- **Live URL:** [https://dad9278cb54cb6.app.lhr.life](https://dad9278cb54cb6.app.lhr.life)

### 🔑 Demo Accounts & Passwords:
| Role | Username | Password | Notes |
| :--- | :--- | :--- | :--- |
| **Owner / Editor** | `alice` | `AliceTest#2026!` | Can upload, edit, share, and rotate keys |
| **Viewer** | `bob` | `BobSecure#2026!` | Read-only view on shared documents |
| **Unauthorized User** | `charlie` | `CharlieKey#2026!` | Unshared user (triggers HTTP 403 IDOR test) |
| **Security Administrator** | `sec_admin` | `AdminAudit#2026!` | Access to Audit Console & Tamper Detection |

---

VaultGuard SDMS is a security-first prototype document management system engineered to protect document confidentiality, integrity, access boundaries, sharing lifecycles, and audit accountability using established cryptographic libraries (`PyCA cryptography` and `argon2-cffi`).

## Core Security Architecture

- **Separated Data & Metadata Storage:** Relational metadata, ACL grants, hashed session tokens, and audit chains live in SQLite WAL (`storage/db/vaultguard.db`), isolated from opaque binary ciphertext files (`storage/vault_blobs/<blob_id>.enc`).
- **Envelope Encryption & Authenticated Integrity:** Each uploaded document receives a unique 256-bit Data Encryption Key (DEK) encrypted with **AES-256-GCM** using Additional Authenticated Data (`doc_id | version | owner_id | plaintext_sha256`), plus an **Ed25519** digital signature over the document manifest.
- **Per-User Asymmetric Key Wrapping:** Every user has **X25519** and **Ed25519** key pairs wrapped at rest with an **Argon2id** Password-Derived Key Encryption Key (PD-KEK) and a one-time offline recovery key. Sharing wraps the document DEK via **ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM**.
- **Hybrid RBAC + Document DAC Authorization:** Every route verifies server-side session state, CSRF synchronizer tokens, UUID format, active non-revoked/unexpired permissions, and role capability (`owner`, `editor`, `viewer`). System `auditor_admin` accounts cannot automatically decrypt or read users' confidential documents (**Separation of Duties**).
- **Cryptographic Key Rotation on Revocation:** Revoking a collaborator destroys their `wrapped_dek_json`, marks `revoked_at`, generates a fresh 256-bit DEK and new `.enc` blob version, re-wraps only for remaining authorized collaborators, and deletes the old blob.
- **Tamper-Evident Audit Chain:** Security events commit inside `audited_transaction` even when operations fail closed, chained via SHA-256, signed with **HMAC-SHA256** (`VAULTGUARD_AUDIT_HMAC_KEY`), and anchored externally in `storage/audit/chain_head.json` to detect middle edits, deletions, forged hashes, and tail truncation.

## Repository Structure

```text
├── app/
│   ├── config.py          # Storage separation paths & security settings
│   ├── crypto.py          # PyCA cryptography & argon2-cffi primitives wrapper
│   ├── database.py        # SQLite WAL schema & atomic transaction helper
│   ├── audit.py           # SHA-256 + HMAC-SHA256 chained audit trail & anomaly checks
│   ├── services.py        # Auth, ACL gate, envelope ops, key rotation, recovery
│   ├── main.py            # FastAPI routes, security headers, CSRF, JSON & UI endpoints
│   ├── static/styles.css  # Dark-slate console stylesheet
│   └── templates/         # Jinja2 auto-escaped UI templates
├── docs/
│   ├── diagrams/          # High-DPI architecture & security diagrams
│   └── storage_exposure_evidence.txt
├── sample_data/           # Synthetic non-secret test documents
├── screenshots/           # Live Playwright screenshots of UI & adversarial scenarios
├── scripts/
│   └── seed_demo.py       # Seeds controlled non-secret demo accounts & docs
├── tests/
│   └── test_security_scenarios.py
├── run_server.py
├── requirements.txt
├── .env.example
├── SETUP.md
├── 23F-3037_IS_Project.docx
└── 23F-3037_IS_Project_Presentation.pptx
```

## Quick Start

See [SETUP.md](SETUP.md) for complete setup, seeding, server launch, and automated adversarial testing commands.
