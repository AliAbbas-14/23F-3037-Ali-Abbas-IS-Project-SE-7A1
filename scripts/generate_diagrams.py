"""Render 5 high-resolution architectural & security diagrams via Chromium SVG."""

from __future__ import annotations

from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DIAGRAMS_DIR = ROOT / "docs" / "diagrams"


DIAGRAMS: dict[str, str] = {
    "01_system_architecture.png": """
<svg viewBox="0 0 1300 760" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, sans-serif">
  <defs>
    <marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
    <marker id="arr-gold" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#fbbf24"/>
    </marker>
  </defs>
  <rect width="1300" height="760" fill="#0b111b" rx="14"/>
  <text x="45" y="48" fill="#f8fafc" font-size="24" font-weight="700">VaultGuard SDMS &mdash; System Architecture &amp; Data Flows</text>
  <text x="45" y="74" fill="#94a3b8" font-size="14">Separated Metadata DB, Encrypted Blob Store, Session Key Isolation, and Hash-Chained Audit Layer</text>

  <!-- Client Boundary -->
  <rect x="40" y="105" width="250" height="585" rx="12" fill="#121b2b" stroke="#38bdf8" stroke-width="2"/>
  <text x="65" y="138" fill="#7dd3fc" font-size="16" font-weight="700">Client Layer (Browser / API)</text>
  <rect x="65" y="165" width="200" height="90" rx="8" fill="#182338" stroke="#273754"/>
  <text x="165" y="196" text-anchor="middle" fill="#f8fafc" font-size="14" font-weight="600">Document Owner / Editor</text>
  <text x="165" y="218" text-anchor="middle" fill="#94a3b8" font-size="12">Upload, Share, Revoke, Edit</text>
  <text x="165" y="236" text-anchor="middle" fill="#94a3b8" font-size="11">HttpOnly Cookies + CSRF Token</text>

  <rect x="65" y="295" width="200" height="90" rx="8" fill="#182338" stroke="#273754"/>
  <text x="165" y="326" text-anchor="middle" fill="#f8fafc" font-size="14" font-weight="600">Shared Viewer</text>
  <text x="165" y="348" text-anchor="middle" fill="#94a3b8" font-size="12">Read, Verify, Download</text>
  <text x="165" y="366" text-anchor="middle" fill="#94a3b8" font-size="11">Least Privilege Role Enforcement</text>

  <rect x="65" y="430" width="200" height="105" rx="8" fill="#182338" stroke="#a855f7"/>
  <text x="165" y="460" text-anchor="middle" fill="#d8b4fe" font-size="14" font-weight="600">Security Auditor Admin</text>
  <text x="165" y="482" text-anchor="middle" fill="#94a3b8" font-size="12">Audit Chain &amp; Alerts Only</text>
  <text x="165" y="502" text-anchor="middle" fill="#fca5a5" font-size="11">NO Automatic Doc Decryption</text>
  <text x="165" y="520" text-anchor="middle" fill="#94a3b8" font-size="11">Non-decrypting Sig/Hash Check</text>

  <rect x="65" y="570" width="200" height="85" rx="8" fill="#0f172a" stroke="#334155"/>
  <text x="165" y="600" text-anchor="middle" fill="#e2e8f0" font-size="13" font-weight="600">Session Cookie Pair</text>
  <text x="165" y="622" text-anchor="middle" fill="#38bdf8" font-size="11">vg_session (Opaque 256-bit)</text>
  <text x="165" y="640" text-anchor="middle" fill="#fbbf24" font-size="11">vg_k (Ephemeral Vault Secret)</text>

  <!-- App Server Boundary -->
  <rect x="355" y="105" width="525" height="585" rx="12" fill="#121b2b" stroke="#22c55e" stroke-width="2"/>
  <text x="380" y="138" fill="#86efac" font-size="16" font-weight="700">Application &amp; Security Services (FastAPI)</text>

  <rect x="380" y="165" width="475" height="80" rx="8" fill="#182338" stroke="#273754"/>
  <text x="617" y="192" text-anchor="middle" fill="#f8fafc" font-size="15" font-weight="700">Security Headers, CSRF &amp; Session Middleware</text>
  <text x="617" y="216" text-anchor="middle" fill="#94a3b8" font-size="12">CSP | X-Frame-Options: DENY | nosniff | no-store | SHA-256 Session Hash</text>
  <text x="617" y="234" text-anchor="middle" fill="#94a3b8" font-size="12">Idle Timeout + Brute-Force Lockout (5 attempts / 300s)</text>

  <rect x="380" y="275" width="225" height="125" rx="8" fill="#182338" stroke="#38bdf8"/>
  <text x="492" y="305" text-anchor="middle" fill="#7dd3fc" font-size="14" font-weight="700">Authorization Gate</text>
  <text x="492" y="328" text-anchor="middle" fill="#e2e8f0" font-size="12">_authorize_document()</text>
  <text x="492" y="350" text-anchor="middle" fill="#94a3b8" font-size="11">UUID Format Validation</text>
  <text x="492" y="368" text-anchor="middle" fill="#94a3b8" font-size="11">Owner / Editor / Viewer Matrix</text>
  <text x="492" y="386" text-anchor="middle" fill="#94a3b8" font-size="11">Revocation &amp; Expiry Check</text>

  <rect x="630" y="275" width="225" height="125" rx="8" fill="#182338" stroke="#fbbf24"/>
  <text x="742" y="305" text-anchor="middle" fill="#fde68a" font-size="14" font-weight="700">Runtime Key Vault (RAM)</text>
  <text x="742" y="328" text-anchor="middle" fill="#e2e8f0" font-size="12">Volatile Memory Cache</text>
  <text x="742" y="350" text-anchor="middle" fill="#94a3b8" font-size="11">Holds X25519 + Ed25519 Keys</text>
  <text x="742" y="368" text-anchor="middle" fill="#94a3b8" font-size="11">Encrypted by cookie vg_k</text>
  <text x="742" y="386" text-anchor="middle" fill="#94a3b8" font-size="11">Wiped on Logout / Expiry</text>

  <rect x="380" y="430" width="475" height="115" rx="8" fill="#182338" stroke="#22c55e"/>
  <text x="617" y="460" text-anchor="middle" fill="#86efac" font-size="15" font-weight="700">Cryptographic Engine (PyCA cryptography + argon2-cffi)</text>
  <text x="617" y="485" text-anchor="middle" fill="#e2e8f0" font-size="12">Argon2id (Password Hash &amp; PD-KEK) | AES-256-GCM + AAD (Document Envelope)</text>
  <text x="617" y="507" text-anchor="middle" fill="#e2e8f0" font-size="12">Ephemeral X25519 + HKDF-SHA256 (DEK Wrapping) | Ed25519 (Manifest Signatures)</text>
  <text x="617" y="529" text-anchor="middle" fill="#94a3b8" font-size="11">Automatic DEK + Blob Rotation on Update and Permission Revocation</text>

  <rect x="380" y="570" width="475" height="90" rx="8" fill="#182338" stroke="#f59e0b"/>
  <text x="617" y="598" text-anchor="middle" fill="#fcd34d" font-size="14" font-weight="700">Tamper-Evident Audit Logger (audited_transaction)</text>
  <text x="617" y="622" text-anchor="middle" fill="#e2e8f0" font-size="12">Commits Denied/Alert Events Even After Rollback</text>
  <text x="617" y="642" text-anchor="middle" fill="#94a3b8" font-size="11">Sequential SHA-256 Chain + HMAC-SHA256 + Sanitized Details (Zero Secrets)</text>

  <!-- Storage Boundary -->
  <rect x="945" y="105" width="315" height="585" rx="12" fill="#121b2b" stroke="#f59e0b" stroke-width="2"/>
  <text x="970" y="138" fill="#fcd34d" font-size="16" font-weight="700">Separated Storage Layer</text>

  <rect x="970" y="165" width="265" height="175" rx="8" fill="#182338" stroke="#273754"/>
  <text x="1102" y="195" text-anchor="middle" fill="#f8fafc" font-size="14" font-weight="700">Metadata &amp; ACL SQLite DB</text>
  <text x="1102" y="216" text-anchor="middle" fill="#38bdf8" font-size="11">storage/db/vaultguard.db (WAL)</text>
  <text x="988" y="242" fill="#94a3b8" font-size="11">&bull; Users + Argon2id + Enc Key Bundles</text>
  <text x="988" y="262" fill="#94a3b8" font-size="11">&bull; Hashed Session Tokens</text>
  <text x="988" y="282" fill="#94a3b8" font-size="11">&bull; Document Metadata + Ed25519 Sig</text>
  <text x="988" y="302" fill="#94a3b8" font-size="11">&bull; Per-User X25519-Wrapped DEKs</text>
  <text x="988" y="322" fill="#94a3b8" font-size="11">&bull; Hash-Chained Audit Log Rows</text>

  <rect x="970" y="370" width="265" height="150" rx="8" fill="#182338" stroke="#273754"/>
  <text x="1102" y="400" text-anchor="middle" fill="#f8fafc" font-size="14" font-weight="700">Encrypted Object Blob Store</text>
  <text x="1102" y="422" text-anchor="middle" fill="#38bdf8" font-size="11">storage/vault_blobs/&lt;blob_id&gt;.enc</text>
  <text x="988" y="448" fill="#94a3b8" font-size="11">&bull; Opaque Binary: VGSD1|Nonce|CT|Tag</text>
  <text x="988" y="468" fill="#94a3b8" font-size="11">&bull; Decoupled UUID (No Filename/User)</text>
  <text x="988" y="488" fill="#94a3b8" font-size="11">&bull; Zero Keys Stored in Blob Folder</text>
  <text x="988" y="508" fill="#94a3b8" font-size="11">&bull; Purged Immediately on Delete/Rotate</text>

  <rect x="970" y="550" width="265" height="110" rx="8" fill="#182338" stroke="#a855f7"/>
  <text x="1102" y="580" text-anchor="middle" fill="#d8b4fe" font-size="14" font-weight="700">External Audit Anchor</text>
  <text x="1102" y="602" text-anchor="middle" fill="#38bdf8" font-size="11">storage/audit/chain_head.json</text>
  <text x="988" y="628" fill="#94a3b8" font-size="11">&bull; HMAC-Signed Tail Seq # &amp; Hash</text>
  <text x="988" y="646" fill="#94a3b8" font-size="11">&bull; Isolated AUDIT_HMAC_KEY</text>

  <!-- Arrows -->
  <line x1="290" y1="205" x2="375" y2="205" stroke="#38bdf8" stroke-width="2.2" marker-end="url(#arr)"/>
  <line x1="290" y1="340" x2="375" y2="340" stroke="#38bdf8" stroke-width="2.2" marker-end="url(#arr)"/>
  <line x1="290" y1="482" x2="375" y2="605" stroke="#38bdf8" stroke-width="2.2" marker-end="url(#arr)"/>
  <line x1="858" y1="330" x2="965" y2="250" stroke="#fbbf24" stroke-width="2" marker-end="url(#arr-gold)"/>
  <line x1="858" y1="485" x2="965" y2="445" stroke="#38bdf8" stroke-width="2.2" marker-end="url(#arr)"/>
  <line x1="858" y1="615" x2="965" y2="605" stroke="#fbbf24" stroke-width="2" marker-end="url(#arr-gold)"/>
</svg>
""",
    "02_threat_model.png": """
<svg viewBox="0 0 1300 760" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, sans-serif">
  <rect width="1300" height="760" fill="#0b111b" rx="14"/>
  <text x="45" y="48" fill="#f8fafc" font-size="24" font-weight="700">VaultGuard SDMS &mdash; STRIDE Threat Model &amp; Trust Boundaries</text>
  <text x="45" y="74" fill="#94a3b8" font-size="14">Protected Assets, Trust Boundaries (TB1&ndash;TB3), Adversarial Threats, and Implemented Mitigations</text>

  <!-- Trust Boundaries Header -->
  <rect x="45" y="100" width="1210" height="115" rx="10" fill="#121b2b" stroke="#38bdf8" stroke-width="1.5"/>
  <text x="65" y="128" fill="#7dd3fc" font-size="15" font-weight="700">Critical Security Assets &amp; Trust Boundaries</text>
  <text x="65" y="155" fill="#e2e8f0" font-size="12.5"><tspan font-weight="700" fill="#fbbf24">Assets:</tspan> A1: Document Plaintexts &bull; A2: Per-Doc DEKs &amp; User X25519/Ed25519 Private Keys &bull; A3: User Passwords &amp; Sessions &bull; A4: Access Control Integrity &bull; A5: Audit Trail Integrity</text>
  <text x="65" y="180" fill="#e2e8f0" font-size="12.5"><tspan font-weight="700" fill="#38bdf8">TB1 (Client &harr; FastAPI):</tspan> Untrusted HTTP requests, cookies, CSRF tokens &bull; <tspan font-weight="700" fill="#22c55e">TB2 (App &harr; Storage):</tspan> Server RAM vs Disk &bull; <tspan font-weight="700" fill="#a855f7">TB3 (User &harr; Admin):</tspan> Separation of Duties</text>
  <text x="65" y="201" fill="#94a3b8" font-size="11.5">Explicit Trust Assumption: Application server RAM is trusted only during active authenticated requests; disk storage &amp; DB backups are treated as untrusted against passive exposure.</text>

  <!-- Threat Cards Grid -->
  <!-- Row 1 -->
  <rect x="45" y="240" width="385" height="225" rx="10" fill="#121b2b" stroke="#ef4444" stroke-width="1.5"/>
  <text x="65" y="272" fill="#fca5a5" font-size="15" font-weight="700">1. Spoofing &amp; Session Hijacking (TB1)</text>
  <text x="65" y="298" fill="#cbd5e1" font-size="12">Threats: Password brute-force, credential stuffing,</text>
  <text x="65" y="315" fill="#cbd5e1" font-size="12">CSRF, session token theft via DB dump or XSS.</text>
  <line x1="65" y1="330" x2="410" y2="330" stroke="#273754"/>
  <text x="65" y="352" fill="#86efac" font-size="12" font-weight="700">Mitigations Implemented:</text>
  <text x="65" y="372" fill="#94a3b8" font-size="11.5">&bull; Argon2id (64 MiB) password hashing</text>
  <text x="65" y="390" fill="#94a3b8" font-size="11.5">&bull; Lockout after 5 failed attempts (300s)</text>
  <text x="65" y="408" fill="#94a3b8" font-size="11.5">&bull; SHA-256 hashed HttpOnly/SameSite=Lax tokens</text>
  <text x="65" y="426" fill="#94a3b8" font-size="11.5">&bull; Synchronizer CSRF token + strict CSP headers</text>
  <text x="65" y="446" fill="#7dd3fc" font-size="11">Tested: Lockout + CSRF + Session Revocation Tests</text>

  <rect x="457" y="240" width="385" height="225" rx="10" fill="#121b2b" stroke="#f59e0b" stroke-width="1.5"/>
  <text x="477" y="272" fill="#fcd34d" font-size="15" font-weight="700">2. Information Disclosure at Rest (TB2)</text>
  <text x="477" y="298" fill="#cbd5e1" font-size="12">Threats: Storage bucket compromise, SQLite DB</text>
  <text x="477" y="315" fill="#cbd5e1" font-size="12">backup theft, or curious administrator snooping.</text>
  <line x1="477" y1="330" x2="822" y2="330" stroke="#273754"/>
  <text x="477" y="352" fill="#86efac" font-size="12" font-weight="700">Mitigations Implemented:</text>
  <text x="477" y="372" fill="#94a3b8" font-size="11.5">&bull; AES-256-GCM envelope encryption per document</text>
  <text x="477" y="390" fill="#94a3b8" font-size="11.5">&bull; Opaque blob UUID filenames (no plaintext/owner)</text>
  <text x="477" y="408" fill="#94a3b8" font-size="11.5">&bull; X25519 + HKDF-SHA256 per-user DEK wrapping</text>
  <text x="477" y="426" fill="#94a3b8" font-size="11.5">&bull; Private keys locked under Argon2id PD-KEK</text>
  <text x="477" y="446" fill="#7dd3fc" font-size="11">Tested: Scenario 3 (Storage Exposure) &amp; Admin Block</text>

  <rect x="869" y="240" width="385" height="225" rx="10" fill="#121b2b" stroke="#ef4444" stroke-width="1.5"/>
  <text x="889" y="272" fill="#fca5a5" font-size="15" font-weight="700">3. Tampering: Blobs &amp; Audit Logs (TB2)</text>
  <text x="889" y="298" fill="#cbd5e1" font-size="12">Threats: Offline modification of .enc files, DB</text>
  <text x="889" y="315" fill="#cbd5e1" font-size="12">hash swapping, or erasing/editing audit rows.</text>
  <line x1="889" y1="330" x2="1234" y2="330" stroke="#273754"/>
  <text x="889" y="352" fill="#86efac" font-size="12" font-weight="700">Mitigations Implemented:</text>
  <text x="889" y="372" fill="#94a3b8" font-size="11.5">&bull; AES-GCM authentication tag + AAD metadata bind</text>
  <text x="889" y="390" fill="#94a3b8" font-size="11.5">&bull; Ed25519 digital signature over manifest hashes</text>
  <text x="889" y="408" fill="#94a3b8" font-size="11.5">&bull; SHA-256 hash chain + HMAC-SHA256 on audit logs</text>
  <text x="889" y="426" fill="#94a3b8" font-size="11.5">&bull; External chain_head.json catches tail truncation</text>
  <text x="889" y="446" fill="#7dd3fc" font-size="11">Tested: Scenarios 4 &amp; 7 (Blob &amp; Audit Tampering)</text>

  <!-- Row 2 -->
  <rect x="45" y="490" width="590" height="225" rx="10" fill="#121b2b" stroke="#a855f7" stroke-width="1.5"/>
  <text x="65" y="522" fill="#d8b4fe" font-size="15" font-weight="700">4. Elevation of Privilege &amp; IDOR (TB1 / TB3)</text>
  <text x="65" y="548" fill="#cbd5e1" font-size="12">Threats: Manipulating doc UUIDs, viewer sending PUT/DELETE/share calls, user registering</text>
  <text x="65" y="566" fill="#cbd5e1" font-size="12">with system_role=auditor_admin, or admin attempting to read confidential user files.</text>
  <line x1="65" y1="582" x2="615" y2="582" stroke="#273754"/>
  <text x="65" y="605" fill="#86efac" font-size="12" font-weight="700">Mitigations Implemented:</text>
  <text x="65" y="625" fill="#94a3b8" font-size="11.5">&bull; Unpredictable UUIDv4 doc identifiers + server-side ACL gate on every route</text>
  <text x="65" y="643" fill="#94a3b8" font-size="11.5">&bull; Hardcoded system_role='user' on public registration (zero mass assignment)</text>
  <text x="65" y="661" fill="#94a3b8" font-size="11.5">&bull; Auditor Admin separated from document decryption keys (Separation of Duties)</text>
  <text x="65" y="679" fill="#94a3b8" font-size="11.5">&bull; Every denied attempt commits IDOR_ATTEMPT / PRIVILEGE_ESCALATION_ATTEMPT</text>
  <text x="65" y="700" fill="#7dd3fc" font-size="11">Tested: Scenarios 1, 2, &amp; 5</text>

  <rect x="665" y="490" width="590" height="225" rx="10" fill="#121b2b" stroke="#38bdf8" stroke-width="1.5"/>
  <text x="685" y="522" fill="#7dd3fc" font-size="15" font-weight="700">5. Stale Share Access &amp; Link Leakage (TB1 / TB2)</text>
  <text x="685" y="548" fill="#cbd5e1" font-size="12">Threats: Accessing document after permission revocation, leaked anonymous bearer URLs,</text>
  <text x="685" y="566" fill="#cbd5e1" font-size="12">shared machine browser caching of sensitive downloads, or expired collaborator tokens.</text>
  <line x1="685" y1="582" x2="1235" y2="582" stroke="#273754"/>
  <text x="685" y="605" fill="#86efac" font-size="12" font-weight="700">Mitigations Implemented:</text>
  <text x="685" y="625" fill="#94a3b8" font-size="11.5">&bull; No anonymous bearer URLs: all reads/downloads require active authenticated session + ACL</text>
  <text x="685" y="643" fill="#94a3b8" font-size="11.5">&bull; Instant revocation sets revoked_at, wipes wrapped_dek_json, and rotates DEK + blob</text>
  <text x="685" y="661" fill="#94a3b8" font-size="11.5">&bull; Time-bound share expiration checked server-side on every request</text>
  <text x="685" y="679" fill="#94a3b8" font-size="11.5">&bull; Cache-Control: no-store + Content-Disposition: attachment + nosniff on downloads</text>
  <text x="685" y="700" fill="#7dd3fc" font-size="11">Tested: Scenario 6 + Share Expiry Test (Residual Risk: offline downloaded copies)</text>
</svg>
""",
    "03_database_storage_design.png": """
<svg viewBox="0 0 1300 760" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, sans-serif">
  <rect width="1300" height="760" fill="#0b111b" rx="14"/>
  <text x="45" y="48" fill="#f8fafc" font-size="24" font-weight="700">Database &amp; Separated Storage Schema Design</text>
  <text x="45" y="74" fill="#94a3b8" font-size="14">Relational SQLite Metadata &amp; ACL Store (vaultguard.db) Isolated from Binary Ciphertext Blobs (vault_blobs/)</text>

  <!-- Table 1: users -->
  <rect x="45" y="105" width="380" height="295" rx="10" fill="#121b2b" stroke="#38bdf8" stroke-width="1.8"/>
  <rect x="45" y="105" width="380" height="38" rx="10" fill="#182338"/>
  <text x="65" y="130" fill="#7dd3fc" font-size="15" font-weight="700">TABLE: users</text>
  <text x="65" y="164" fill="#fbbf24" font-size="12">PK  id (UUIDv4)</text>
  <text x="65" y="186" fill="#e2e8f0" font-size="12">    username, email, full_name</text>
  <text x="65" y="208" fill="#e2e8f0" font-size="12">    system_role ('user' | 'auditor_admin')</text>
  <text x="65" y="230" fill="#86efac" font-size="12">    password_hash (Argon2id)</text>
  <text x="65" y="252" fill="#e2e8f0" font-size="12">    kdf_salt_b64 (16B random)</text>
  <text x="65" y="274" fill="#e2e8f0" font-size="12">    x25519_pub_b64, ed25519_pub_b64</text>
  <text x="65" y="296" fill="#fca5a5" font-size="12">    enc_private_bundle (AES-GCM w/ PD-KEK)</text>
  <text x="65" y="318" fill="#fca5a5" font-size="12">    recovery_bundle + recovery_code_hash</text>
  <text x="65" y="340" fill="#94a3b8" font-size="12">    failed_attempts, locked_until, is_active</text>
  <text x="65" y="378" fill="#64748b" font-size="11">Never stores raw passwords or plaintext keys.</text>

  <!-- Table 2: sessions -->
  <rect x="45" y="425" width="380" height="205" rx="10" fill="#121b2b" stroke="#22c55e" stroke-width="1.8"/>
  <rect x="45" y="425" width="380" height="38" rx="10" fill="#182338"/>
  <text x="65" y="450" fill="#86efac" font-size="15" font-weight="700">TABLE: sessions</text>
  <text x="65" y="484" fill="#fbbf24" font-size="12">PK  token_hash (SHA-256 of cookie)</text>
  <text x="65" y="506" fill="#38bdf8" font-size="12">FK  user_id &rarr; users.id</text>
  <text x="65" y="528" fill="#e2e8f0" font-size="12">    csrf_token (32B hex)</text>
  <text x="65" y="550" fill="#e2e8f0" font-size="12">    created_at, expires_at, last_seen_at</text>
  <text x="65" y="572" fill="#e2e8f0" font-size="12">    ip_address, user_agent, revoked_at</text>
  <text x="65" y="608" fill="#64748b" font-size="11">DB dump cannot forge active session cookies.</text>

  <!-- Table 3: documents -->
  <rect x="460" y="105" width="390" height="295" rx="10" fill="#121b2b" stroke="#38bdf8" stroke-width="1.8"/>
  <rect x="460" y="105" width="390" height="38" rx="10" fill="#182338"/>
  <text x="480" y="130" fill="#7dd3fc" font-size="15" font-weight="700">TABLE: documents</text>
  <text x="480" y="164" fill="#fbbf24" font-size="12">PK  id (UUIDv4)</text>
  <text x="480" y="186" fill="#38bdf8" font-size="12">FK  owner_id &rarr; users.id</text>
  <text x="480" y="208" fill="#e2e8f0" font-size="12">    title, original_filename, mime_type, size</text>
  <text x="480" y="230" fill="#fbbf24" font-size="12">UQ  blob_id (Decoupled UUIDv4)</text>
  <text x="480" y="252" fill="#e2e8f0" font-size="12">    current_version (INTEGER)</text>
  <text x="480" y="274" fill="#86efac" font-size="12">    plaintext_sha256, ciphertext_sha256</text>
  <text x="480" y="296" fill="#86efac" font-size="12">    manifest_signature_b64 (Ed25519)</text>
  <text x="480" y="318" fill="#38bdf8" font-size="12">FK  signer_user_id &rarr; users.id</text>
  <text x="480" y="340" fill="#94a3b8" font-size="12">    created_at, updated_at, is_deleted</text>
  <text x="480" y="378" fill="#64748b" font-size="11">Zero document bytes or DEKs inside DB.</text>

  <!-- Table 4: document_permissions -->
  <rect x="460" y="425" width="390" height="205" rx="10" fill="#121b2b" stroke="#f59e0b" stroke-width="1.8"/>
  <rect x="460" y="425" width="390" height="38" rx="10" fill="#182338"/>
  <text x="480" y="450" fill="#fcd34d" font-size="15" font-weight="700">TABLE: document_permissions (ACL)</text>
  <text x="480" y="484" fill="#fbbf24" font-size="12">PK  id (UUIDv4)</text>
  <text x="480" y="506" fill="#38bdf8" font-size="12">FK  doc_id &rarr; documents.id | user_id &rarr; users.id</text>
  <text x="480" y="528" fill="#e2e8f0" font-size="12">    role ('owner' | 'editor' | 'viewer')</text>
  <text x="480" y="550" fill="#fca5a5" font-size="12">    wrapped_dek_json (X25519 + HKDF + GCM)</text>
  <text x="480" y="572" fill="#94a3b8" font-size="12">    granted_by, granted_at, expires_at, revoked_at</text>
  <text x="480" y="608" fill="#64748b" font-size="11">Revoke sets revoked_at, NULLs wrapped_dek, rotates DEK.</text>

  <!-- Table 5: audit_logs + Isolated Filesystem -->
  <rect x="885" y="105" width="370" height="295" rx="10" fill="#121b2b" stroke="#a855f7" stroke-width="1.8"/>
  <rect x="885" y="105" width="370" height="38" rx="10" fill="#182338"/>
  <text x="905" y="130" fill="#d8b4fe" font-size="15" font-weight="700">TABLE: audit_logs (Append-Only)</text>
  <text x="905" y="164" fill="#fbbf24" font-size="12">PK  seq_no (Strict Contiguous 1..N)</text>
  <text x="905" y="186" fill="#e2e8f0" font-size="12">    event_id (UUIDv4), timestamp_utc</text>
  <text x="905" y="208" fill="#e2e8f0" font-size="12">    actor_user_id, actor_username, ip</text>
  <text x="905" y="230" fill="#e2e8f0" font-size="12">    action, target_doc_id, outcome</text>
  <text x="905" y="252" fill="#e2e8f0" font-size="12">    details_json (Sensitive Keys Redacted)</text>
  <text x="905" y="274" fill="#86efac" font-size="12">    prev_hash (64 hex)</text>
  <text x="905" y="296" fill="#86efac" font-size="12">    entry_hash (SHA-256 of canonical row)</text>
  <text x="905" y="318" fill="#fca5a5" font-size="12">    entry_hmac (HMAC-SHA256)</text>
  <text x="905" y="378" fill="#64748b" font-size="11">Anchored externally in storage/audit/chain_head.json</text>

  <rect x="885" y="425" width="370" height="205" rx="10" fill="#182338" stroke="#22c55e" stroke-width="1.8"/>
  <text x="905" y="458" fill="#86efac" font-size="15" font-weight="700">ISOLATED BLOB STORAGE (Disk)</text>
  <text x="905" y="484" fill="#38bdf8" font-size="12">storage/vault_blobs/&lt;blob_id&gt;.enc</text>
  <text x="905" y="514" fill="#e2e8f0" font-size="12">[ 5B Magic: "VGSD1" ]</text>
  <text x="905" y="536" fill="#e2e8f0" font-size="12">[ 12B CSPRNG Nonce ]</text>
  <text x="905" y="558" fill="#e2e8f0" font-size="12">[ N-Byte AES-256-GCM Ciphertext ]</text>
  <text x="905" y="580" fill="#e2e8f0" font-size="12">[ 16B GCM Auth Tag (AAD-bound) ]</text>
  <text x="905" y="612" fill="#64748b" font-size="11">Storage theft alone leaks zero titles, users, or bytes.</text>

  <!-- Summary Footer -->
  <rect x="45" y="655" width="1210" height="68" rx="10" fill="#182338" stroke="#334155"/>
  <text x="65" y="685" fill="#f8fafc" font-size="13" font-weight="700">Why Separate Metadata DB from Encrypted Blobs?</text>
  <text x="65" y="707" fill="#94a3b8" font-size="12">1) Keeps SQLite WAL small &amp; atomic for ACL/audit queries  2) Decouples blob UUIDs from filenames/owners  3) Ensures blob compromise yields zero context &amp; DB compromise yields zero keys/plaintext.</text>
</svg>
""",
    "04_cryptographic_lifecycle.png": """
<svg viewBox="0 0 1300 760" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, sans-serif">
  <defs>
    <marker id="a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
  </defs>
  <rect width="1300" height="760" fill="#0b111b" rx="14"/>
  <text x="45" y="48" fill="#f8fafc" font-size="24" font-weight="700">Cryptographic Key Hierarchy &amp; Lifecycle</text>
  <text x="45" y="74" fill="#94a3b8" font-size="14">PyCA cryptography &amp; argon2-cffi: Envelope Encryption, Ephemeral X25519 Wrapping, Ed25519 Signatures, and Key Rotation</text>

  <!-- Top Row: User Key Lifecycle -->
  <rect x="45" y="105" width="380" height="270" rx="10" fill="#121b2b" stroke="#38bdf8" stroke-width="1.8"/>
  <text x="65" y="138" fill="#7dd3fc" font-size="16" font-weight="700">1. User Identity &amp; Key Unlock</text>
  <text x="65" y="168" fill="#e2e8f0" font-size="12.5">User Password + Random 16B kdf_salt</text>
  <text x="65" y="192" fill="#86efac" font-size="12.5">&darr; Argon2id (t=3, m=64MiB, p=2)</text>
  <text x="65" y="216" fill="#fbbf24" font-size="12.5">256-bit PD-KEK (In RAM only at login)</text>
  <text x="65" y="242" fill="#e2e8f0" font-size="12">&bull; Unlocks X25519 PrivKey (DEK Unwrap)</text>
  <text x="65" y="262" fill="#e2e8f0" font-size="12">&bull; Unlocks Ed25519 PrivKey (Manifest Sign)</text>
  <text x="65" y="288" fill="#94a3b8" font-size="11.5">&bull; Offline Recovery Code &rarr; HKDF Recovery-KEK</text>
  <text x="65" y="308" fill="#94a3b8" font-size="11.5">&bull; Session RAM Vault sealed by cookie vg_k</text>
  <text x="65" y="350" fill="#fca5a5" font-size="11">Admins do NOT hold a master decryption key.</text>

  <rect x="460" y="105" width="390" height="270" rx="10" fill="#121b2b" stroke="#22c55e" stroke-width="1.8"/>
  <text x="480" y="138" fill="#86efac" font-size="16" font-weight="700">2. Document Upload &amp; Encryption</text>
  <text x="480" y="168" fill="#e2e8f0" font-size="12.5">CSPRNG 256-bit DEK (os.urandom(32))</text>
  <text x="480" y="194" fill="#fbbf24" font-size="12.5">&darr; AES-256-GCM (96-bit Random Nonce)</text>
  <text x="480" y="218" fill="#94a3b8" font-size="11.5">AAD = doc_id | version | owner_id | pt_sha256</text>
  <text x="480" y="244" fill="#e2e8f0" font-size="12">&bull; Blob written to vault_blobs/&lt;blob_id&gt;.enc</text>
  <text x="480" y="264" fill="#e2e8f0" font-size="12">&bull; Manifest signed with Actor's Ed25519 key:</text>
  <text x="492" y="284" fill="#7dd3fc" font-size="11">VG-MANIFEST-V1|doc|ver|owner|pt_hash|ct_hash</text>
  <text x="480" y="310" fill="#e2e8f0" font-size="12">&bull; DEK wrapped for Owner's X25519 pubkey</text>
  <text x="480" y="350" fill="#94a3b8" font-size="11">Metadata swap or 1-bit disk edit fails GCM/Ed25519.</text>

  <rect x="885" y="105" width="370" height="270" rx="10" fill="#121b2b" stroke="#f59e0b" stroke-width="1.8"/>
  <text x="905" y="138" fill="#fcd34d" font-size="16" font-weight="700">3. Sharing &amp; Key Wrapping</text>
  <text x="905" y="168" fill="#e2e8f0" font-size="12.5">Owner unwraps DEK in session RAM</text>
  <text x="905" y="194" fill="#fbbf24" font-size="12.5">&darr; Ephemeral X25519 ECDH Key Exchange</text>
  <text x="905" y="218" fill="#94a3b8" font-size="11.5">shared = eph_sk.exchange(recipient_x25519_pk)</text>
  <text x="905" y="242" fill="#86efac" font-size="12.5">&darr; HKDF-SHA256 Key Derivation</text>
  <text x="905" y="264" fill="#94a3b8" font-size="11.5">info = "vaultguard-dek-wrap-v1|doc|ver|uid"</text>
  <text x="905" y="290" fill="#e2e8f0" font-size="12">&bull; wrap_key encrypts DEK via AES-256-GCM</text>
  <text x="905" y="312" fill="#e2e8f0" font-size="12">&bull; Recipient unwraps without Owner online later</text>
  <text x="905" y="350" fill="#94a3b8" font-size="11">AAD binds wrapped DEK to recipient &amp; version.</text>

  <!-- Bottom Row: Rotation & Audit -->
  <rect x="45" y="405" width="600" height="305" rx="10" fill="#121b2b" stroke="#ef4444" stroke-width="1.8"/>
  <text x="65" y="438" fill="#fca5a5" font-size="16" font-weight="700">4. Revocation, Version Update &amp; Key Rotation</text>
  <text x="65" y="468" fill="#e2e8f0" font-size="12.5">Triggered on: Share Revocation OR Authorized Editor Update</text>
  <text x="65" y="498" fill="#94a3b8" font-size="12">Step 1: Verify existing blob integrity &amp; decrypt plaintext using actor's session keys.</text>
  <text x="65" y="522" fill="#94a3b8" font-size="12">Step 2: Mark revoked user's permission revoked_at=NOW, wrapped_dek_json=NULL.</text>
  <text x="65" y="546" fill="#94a3b8" font-size="12">Step 3: Generate brand-new 256-bit DEK_v(n+1) and new opaque blob_id.</text>
  <text x="65" y="570" fill="#94a3b8" font-size="12">Step 4: Re-encrypt content under DEK_v(n+1), re-sign Ed25519 manifest.</text>
  <text x="65" y="594" fill="#94a3b8" font-size="12">Step 5: Re-wrap DEK_v(n+1) ONLY for remaining active collaborators' public keys.</text>
  <text x="65" y="618" fill="#94a3b8" font-size="12">Step 6: Atomically update DB pointer and unlink old v(n) encrypted blob file.</text>
  <text x="65" y="660" fill="#7dd3fc" font-size="12" font-weight="600">Result: Old wrapped DEKs captured before revocation cannot decrypt v(n+1) blobs.</text>
  <text x="65" y="684" fill="#fca5a5" font-size="11.5">Honest Limitation: Plaintext copies already downloaded locally prior to revocation cannot be wiped.</text>

  <rect x="670" y="405" width="585" height="305" rx="10" fill="#121b2b" stroke="#a855f7" stroke-width="1.8"/>
  <text x="690" y="438" fill="#d8b4fe" font-size="16" font-weight="700">5. Audit Integrity &amp; Trust Assumptions</text>
  <text x="690" y="468" fill="#e2e8f0" font-size="12.5">Cryptographic Chain Formulas:</text>
  <text x="690" y="494" fill="#86efac" font-size="12" font-family="Consolas, monospace">entry_hash = SHA256(seq | id | ts | actor | action | doc | out | details | prev)</text>
  <text x="690" y="518" fill="#fbbf24" font-size="12" font-family="Consolas, monospace">entry_hmac = HMAC-SHA256(AUDIT_HMAC_KEY, entry_hash)</text>
  <text x="690" y="550" fill="#e2e8f0" font-size="12.5">Key &amp; Trust Boundaries:</text>
  <text x="690" y="574" fill="#94a3b8" font-size="11.5">&bull; AUDIT_HMAC_KEY is isolated from document DEKs and user keys.</text>
  <text x="690" y="594" fill="#94a3b8" font-size="11.5">&bull; Sequence gaps (1..N) catch middle deletions; chain_head.json catches tail deletes.</text>
  <text x="690" y="614" fill="#94a3b8" font-size="11.5">&bull; Server RAM handles password/DEK ops during request (requires TLS 1.3 in prod).</text>
  <text x="690" y="634" fill="#94a3b8" font-size="11.5">&bull; Lost password + lost recovery code = cryptographic lock (no admin backdoor).</text>
  <text x="690" y="680" fill="#7dd3fc" font-size="11.5">100% Standard Libraries: PyCA cryptography 50.x + argon2-cffi 25.x + Python stdlib.</text>
</svg>
""",
    "05_access_control_flow.png": """
<svg viewBox="0 0 1300 760" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, sans-serif">
  <defs>
    <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8"/>
    </marker>
    <marker id="ar-red" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 1 L 10 5 L 0 9 z" fill="#ef4444"/>
    </marker>
  </defs>
  <rect width="1300" height="760" fill="#0b111b" rx="14"/>
  <text x="45" y="48" fill="#f8fafc" font-size="24" font-weight="700">Access-Control Model &amp; Server-Side Authorization Pipeline</text>
  <text x="45" y="74" fill="#94a3b8" font-size="14">Hybrid System-Level RBAC (user vs auditor_admin) + Per-Document DAC ACL (owner, editor, viewer)</text>

  <!-- Pipeline Boxes -->
  <rect x="45" y="110" width="210" height="95" rx="10" fill="#182338" stroke="#38bdf8" stroke-width="1.8"/>
  <text x="150" y="142" text-anchor="middle" fill="#7dd3fc" font-size="14" font-weight="700">1. Session Auth</text>
  <text x="150" y="165" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Verify vg_session hash,</text>
  <text x="150" y="182" text-anchor="middle" fill="#e2e8f0" font-size="11.5">TTL/Idle &amp; vg_k vault</text>

  <rect x="295" y="110" width="210" height="95" rx="10" fill="#182338" stroke="#38bdf8" stroke-width="1.8"/>
  <text x="400" y="142" text-anchor="middle" fill="#7dd3fc" font-size="14" font-weight="700">2. CSRF &amp; ID Check</text>
  <text x="400" y="165" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Compare CSRF token;</text>
  <text x="400" y="182" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Validate UUIDv4 doc_id</text>

  <rect x="545" y="110" width="225" height="95" rx="10" fill="#182338" stroke="#f59e0b" stroke-width="1.8"/>
  <text x="657" y="142" text-anchor="middle" fill="#fcd34d" font-size="14" font-weight="700">3. ACL &amp; Revocation</text>
  <text x="657" y="165" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Active permission row</text>
  <text x="657" y="182" text-anchor="middle" fill="#e2e8f0" font-size="11.5">revoked_at IS NULL &amp; !exp</text>

  <rect x="810" y="110" width="215" height="95" rx="10" fill="#182338" stroke="#a855f7" stroke-width="1.8"/>
  <text x="917" y="142" text-anchor="middle" fill="#d8b4fe" font-size="14" font-weight="700">4. Role Capability</text>
  <text x="917" y="165" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Action in Role Matrix?</text>
  <text x="917" y="182" text-anchor="middle" fill="#e2e8f0" font-size="11.5">(owner / editor / viewer)</text>

  <rect x="1065" y="110" width="190" height="95" rx="10" fill="#182338" stroke="#22c55e" stroke-width="1.8"/>
  <text x="1160" y="142" text-anchor="middle" fill="#86efac" font-size="14" font-weight="700">5. Crypto Unwrap</text>
  <text x="1160" y="165" text-anchor="middle" fill="#e2e8f0" font-size="11.5">Verify Sig + Unwrap DEK</text>
  <text x="1160" y="182" text-anchor="middle" fill="#e2e8f0" font-size="11.5">+ AES-GCM Decrypt</text>

  <!-- Pipeline Arrows -->
  <line x1="255" y1="157" x2="290" y2="157" stroke="#38bdf8" stroke-width="2" marker-end="url(#ar)"/>
  <line x1="505" y1="157" x2="540" y2="157" stroke="#38bdf8" stroke-width="2" marker-end="url(#ar)"/>
  <line x1="770" y1="157" x2="805" y2="157" stroke="#38bdf8" stroke-width="2" marker-end="url(#ar)"/>
  <line x1="1025" y1="157" x2="1060" y2="157" stroke="#38bdf8" stroke-width="2" marker-end="url(#ar)"/>

  <!-- Fail Closed Banner -->
  <rect x="45" y="245" width="1210" height="72" rx="10" fill="#23121b" stroke="#ef4444" stroke-width="1.5"/>
  <text x="65" y="275" fill="#fca5a5" font-size="14" font-weight="700">Fail-Closed Denial &amp; Guaranteed Audit Commit</text>
  <text x="65" y="299" fill="#e2e8f0" font-size="12">Any failure in Steps 1&ndash;4 returns HTTP 401/403/404 and immediately commits an audit record (IDOR_ATTEMPT, REVOKED_ACCESS_ATTEMPT, ACCESS_DENIED_EXPIRED, or PRIVILEGE_ESCALATION_ATTEMPT).</text>

  <!-- Role Permission Matrix Table -->
  <rect x="45" y="345" width="1210" height="365" rx="10" fill="#121b2b" stroke="#273754" stroke-width="1.8"/>
  <text x="65" y="380" fill="#f8fafc" font-size="17" font-weight="700">Authorization &amp; Least-Privilege Role Matrix</text>

  <rect x="65" y="400" width="1170" height="38" fill="#182338"/>
  <text x="85" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">ROLE / IDENTITY</text>
  <text x="330" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">READ / DOWNLOAD</text>
  <text x="510" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">VERIFY HASH/SIG</text>
  <text x="680" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">EDIT / ROTATE</text>
  <text x="845" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">SHARE / REVOKE</text>
  <text x="1020" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">DELETE DOC</text>
  <text x="1145" y="424" fill="#94a3b8" font-size="12.5" font-weight="700">AUDIT CONSOLE</text>

  <!-- Rows -->
  <line x1="65" y1="485" x2="1235" y2="485" stroke="#273754"/>
  <text x="85" y="468" fill="#7dd3fc" font-size="13" font-weight="700">Document Owner (DAC)</text>
  <text x="360" y="468" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="535" y="468" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="705" y="468" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="870" y="468" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="1038" y="468" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="1165" y="468" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>

  <line x1="65" y1="535" x2="1235" y2="535" stroke="#273754"/>
  <text x="85" y="518" fill="#fcd34d" font-size="13" font-weight="700">Shared Editor (DAC)</text>
  <text x="360" y="518" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="535" y="518" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="705" y="518" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="870" y="518" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="1038" y="518" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="1165" y="518" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>

  <line x1="65" y1="585" x2="1235" y2="585" stroke="#273754"/>
  <text x="85" y="568" fill="#cbd5e1" font-size="13" font-weight="700">Shared Viewer (DAC)</text>
  <text x="360" y="568" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="535" y="568" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>
  <text x="705" y="568" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="870" y="568" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="1038" y="568" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="1165" y="568" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>

  <line x1="65" y1="635" x2="1235" y2="635" stroke="#273754"/>
  <text x="85" y="618" fill="#d8b4fe" font-size="13" font-weight="700">Auditor Admin (RBAC)</text>
  <text x="350" y="618" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)*</text>
  <text x="515" y="618" fill="#86efac" font-size="13" font-weight="700">CIPHERTEXT</text>
  <text x="705" y="618" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="870" y="618" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="1038" y="618" fill="#fca5a5" font-size="13" font-weight="700">DENY (403)</text>
  <text x="1165" y="618" fill="#86efac" font-size="13" font-weight="700">ALLOW</text>

  <text x="85" y="668" fill="#94a3b8" font-size="12">Unauthenticated / No Grant &rarr; Always DENY (401 / 403). *Auditor Admin cannot read any user's confidential documents unless explicitly shared.</text>
  <text x="85" y="690" fill="#7dd3fc" font-size="12">Separation of Duties: Admin verifies blob SHA-256 &amp; Ed25519 signature integrity without possessing user DEKs or plaintext access.</text>
</svg>
""",
}


def main() -> None:
    DIAGRAMS_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1340, "height": 800}, device_scale_factor=2)
        for filename, svg_markup in DIAGRAMS.items():
            html = f"""<!DOCTYPE html>
            <html><body style="margin:0;padding:16px;background:#0b111b;display:flex;justify-content:center;align-items:center;">
            {svg_markup}
            </body></html>"""
            page.set_content(html)
            out_path = DIAGRAMS_DIR / filename
            page.locator("svg").screenshot(path=str(out_path))
        browser.close()
    print(f"Generated {len(DIAGRAMS)} high-DPI diagrams in {DIAGRAMS_DIR}")


if __name__ == "__main__":
    main()
