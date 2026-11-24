# Setup and Verification Instructions — VaultGuard SDMS

## 1. Prerequisites
- Python **3.12+** (tested on Python 3.12.10 on Windows)
- Virtual environment support (`venv`)

## 2. Installation
From the project root directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 3. Environment Configuration (No Real Secrets Included)
Copy `.env.example` to `.env` if customizing values, or set environment variables directly:

```powershell
copy .env.example .env
# Generate a local 32-byte hex HMAC key for audit integrity:
python -c "import secrets; print(secrets.token_hex(32))"
```

If `VAULTGUARD_AUDIT_HMAC_KEY` is omitted, `app/config.py` generates a cryptographically random 256-bit key locally in `storage/audit/.audit_hmac_key` (excluded from Git via `.gitignore`).

## 4. Seed Controlled Test Data
Populate synthetic test accounts (`alice`, `bob`, `charlie`, `sec_admin`) and encrypted sample documents from `sample_data/`:

```powershell
.\.venv\Scripts\python.exe scripts\seed_demo.py
```

**Controlled Demo Credentials (Synthetic Test Accounts Only):**
- `alice` / `AliceTest#2026!` — Document Owner (`user`)
- `bob` / `BobTest#2026!` — Collaborator (`user`)
- `charlie` / `CharlieTest#2026!` — Unauthorized User (`user`)
- `sec_admin` / `AdminAudit#2026!` — Security Auditor (`auditor_admin`)

## 5. Run the Application Server
```powershell
.\.venv\Scripts\python.exe run_server.py
```
Open `http://127.0.0.1:8000` in your browser.

## 6. Run Automated Security & Adversarial Tests
Runs all 7 Part 3 adversarial scenarios plus brute-force lockout, CSRF, key recovery, and share expiry verification in isolated temporary storage:

```powershell
.\.venv\Scripts\python.exe -m pytest -v tests\test_security_scenarios.py
```
