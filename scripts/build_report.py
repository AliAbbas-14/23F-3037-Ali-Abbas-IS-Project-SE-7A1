"""Generate CS3002 Semester Project Word Report: 23F-3037_IS_Project.docx."""

from __future__ import annotations

from pathlib import Path

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parent.parent
OUT_DOCX = ROOT / "23F-3037_IS_Project.docx"

NAVY = RGBColor(0x1B, 0x36, 0x5D)
TEAL = RGBColor(0x02, 0x84, 0xC7)
DARK = RGBColor(0x1E, 0x29, 0x3B)
MUTED = RGBColor(0x47, 0x55, 0x69)


def _set_cell_bg(cell, hex_color: str) -> None:
    shading = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    cell._tc.get_or_add_tcPr().append(shading)


def _set_cell_margins(cell, top=100, bottom=100, left=140, right=140) -> None:
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement("w:tcMar")
    for side, val in (("top", top), ("bottom", bottom), ("left", left), ("right", right)):
        node = OxmlElement(f"w:{side}")
        node.set(qn("w:w"), str(val))
        node.set(qn("w:type"), "dxa")
        tcMar.append(node)
    tcPr.append(tcMar)


def _add_page_number(run) -> None:
    fld1 = parse_xml(r'<w:fldChar %s w:fldCharType="begin"/>' % nsdecls("w"))
    instr = parse_xml(r'<w:instrText %s xml:space="preserve"> PAGE </w:instrText>' % nsdecls("w"))
    fld2 = parse_xml(r'<w:fldChar %s w:fldCharType="separate"/>' % nsdecls("w"))
    fld3 = parse_xml(r'<w:fldChar %s w:fldCharType="end"/>' % nsdecls("w"))
    run._r.append(fld1)
    run._r.append(instr)
    run._r.append(fld2)
    run._r.append(fld3)


def _add_h1(doc: Document, text: str) -> None:
    p = doc.add_heading(text, level=1)
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.keep_with_next = True
    for r in p.runs:
        r.font.name = "Calibri"
        r.font.size = Pt(16)
        r.font.bold = True
        r.font.color.rgb = NAVY


def _add_h2(doc: Document, text: str) -> None:
    p = doc.add_heading(text, level=2)
    p.paragraph_format.space_before = Pt(11)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    for r in p.runs:
        r.font.name = "Calibri"
        r.font.size = Pt(13)
        r.font.bold = True
        r.font.color.rgb = TEAL


def _add_h3(doc: Document, text: str) -> None:
    p = doc.add_heading(text, level=3)
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.keep_with_next = True
    for r in p.runs:
        r.font.name = "Calibri"
        r.font.size = Pt(11)
        r.font.bold = True
        r.font.color.rgb = DARK


def _add_body(doc: Document, text: str, bold_prefix: str | None = None) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(5)
    p.paragraph_format.line_spacing = 1.15
    if bold_prefix:
        rb = p.add_run(bold_prefix)
        rb.bold = True
        rb.font.name = "Calibri"
        rb.font.size = Pt(10.5)
        rb.font.color.rgb = DARK
    r = p.add_run(text)
    r.font.name = "Calibri"
    r.font.size = Pt(10.5)
    r.font.color.rgb = DARK


def _add_bullet(doc: Document, text: str, bold_prefix: str | None = None) -> None:
    p = doc.add_paragraph(style="List Bullet")
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.12
    if bold_prefix:
        rb = p.add_run(bold_prefix)
        rb.bold = True
        rb.font.name = "Calibri"
        rb.font.size = Pt(10.2)
        rb.font.color.rgb = DARK
    r = p.add_run(text)
    r.font.name = "Calibri"
    r.font.size = Pt(10.2)
    r.font.color.rgb = DARK


def _add_callout(doc: Document, title: str, body: str, bg_hex: str = "EFF6FF") -> None:
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    _set_cell_bg(cell, bg_hex)
    _set_cell_margins(cell, top=120, bottom=120, left=180, right=180)
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(2)
    rt = p.add_run(title + "\n")
    rt.bold = True
    rt.font.name = "Calibri"
    rt.font.size = Pt(10.5)
    rt.font.color.rgb = NAVY
    rb = p.add_run(body)
    rb.font.name = "Calibri"
    rb.font.size = Pt(10)
    rb.font.color.rgb = DARK
    doc.add_paragraph().paragraph_format.space_after = Pt(3)


def _add_code_block(doc: Document, lines: str) -> None:
    tbl = doc.add_table(rows=1, cols=1)
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = tbl.cell(0, 0)
    _set_cell_bg(cell, "0F172A")
    _set_cell_margins(cell, top=110, bottom=110, left=150, right=150)
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(0)
    r = p.add_run(lines)
    r.font.name = "Consolas"
    r.font.size = Pt(8.8)
    r.font.color.rgb = RGBColor(0xE2, 0xE8, 0xF0)
    doc.add_paragraph().paragraph_format.space_after = Pt(3)


def _add_styled_table(doc: Document, headers: list[str], rows: list[list[str]]) -> None:
    tbl = doc.add_table(rows=len(rows) + 1, cols=len(headers))
    tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
    tbl.style = "Table Grid"
    for j, h in enumerate(headers):
        cell = tbl.cell(0, j)
        _set_cell_bg(cell, "1B365D")
        _set_cell_margins(cell, top=90, bottom=90, left=110, right=110)
        p = cell.paragraphs[0]
        p.paragraph_format.space_after = Pt(0)
        r = p.add_run(h)
        r.bold = True
        r.font.name = "Calibri"
        r.font.size = Pt(9.5)
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
    for i, row in enumerate(rows):
        bg = "F8FAFC" if i % 2 == 0 else "FFFFFF"
        for j, val in enumerate(row):
            cell = tbl.cell(i + 1, j)
            _set_cell_bg(cell, bg)
            _set_cell_margins(cell, top=75, bottom=75, left=110, right=110)
            p = cell.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(val)
            r.font.name = "Calibri"
            r.font.size = Pt(9.2)
            r.font.color.rgb = DARK
    doc.add_paragraph().paragraph_format.space_after = Pt(4)


def _add_figure(doc: Document, img_path: Path, caption: str, width_in: float = 6.2) -> None:
    if not img_path.exists():
        _add_body(doc, f"[Missing image: {img_path.name}]")
        return
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.keep_with_next = True
    p_img.paragraph_format.space_before = Pt(4)
    p_img.paragraph_format.space_after = Pt(2)
    p_img.add_run().add_picture(str(img_path), width=Inches(width_in))

    p_cap = doc.add_paragraph()
    p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_cap.paragraph_format.space_after = Pt(8)
    rc = p_cap.add_run(caption)
    rc.italic = True
    rc.font.name = "Calibri"
    rc.font.size = Pt(9.2)
    rc.font.color.rgb = MUTED


def build_report() -> None:
    doc = Document()

    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.85)
        section.right_margin = Inches(0.85)
        section.different_first_page_header_footer = True

        hdr = section.header.paragraphs[0]
        hdr.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        hr = hdr.add_run("CS3002 Information Security | VaultGuard SDMS (23F-3037 Ali Abbas)")
        hr.font.name = "Calibri"
        hr.font.size = Pt(8.5)
        hr.font.color.rgb = MUTED

        ftr = section.footer.paragraphs[0]
        ftr.alignment = WD_ALIGN_PARAGRAPH.CENTER
        fr1 = ftr.add_run("FAST-NUCES Chiniot-Faisalabad Campus | Page ")
        fr1.font.name = "Calibri"
        fr1.font.size = Pt(8.5)
        fr1.font.color.rgb = MUTED
        fr_pg = ftr.add_run()
        fr_pg.font.name = "Calibri"
        fr_pg.font.size = Pt(8.5)
        fr_pg.font.color.rgb = MUTED
        _add_page_number(fr_pg)

    # =====================================================================
    # COVER PAGE
    # =====================================================================
    p_uni = doc.add_paragraph()
    p_uni.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_uni.paragraph_format.space_before = Pt(36)
    r_u = p_uni.add_run("NATIONAL UNIVERSITY OF COMPUTER & EMERGING SCIENCES\nChiniot – Faisalabad Campus")
    r_u.bold = True
    r_u.font.name = "Calibri"
    r_u.font.size = Pt(15)
    r_u.font.color.rgb = NAVY

    p_course = doc.add_paragraph()
    p_course.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_course.paragraph_format.space_before = Pt(24)
    r_c = p_course.add_run("CS3002 – Information Security\nSemester Project Technical Report")
    r_c.bold = True
    r_c.font.name = "Calibri"
    r_c.font.size = Pt(14)
    r_c.font.color.rgb = TEAL

    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_title.paragraph_format.space_before = Pt(28)
    p_title.paragraph_format.space_after = Pt(12)
    r_t = p_title.add_run("VaultGuard SDMS\nDesign and Implementation of a Secure Document Management System")
    r_t.bold = True
    r_t.font.name = "Calibri"
    r_t.font.size = Pt(22)
    r_t.font.color.rgb = NAVY

    p_sub = doc.add_paragraph()
    p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_sub.paragraph_format.space_after = Pt(36)
    r_s = p_sub.add_run(
        "Envelope Encryption (AES-256-GCM + Ephemeral X25519 + HKDF-SHA256) | "
        "Ed25519 Manifest Signatures | Argon2id Identity Protection | "
        "Hybrid RBAC/DAC Enforcement | Tamper-Evident HMAC-SHA256 Audit Chain"
    )
    r_s.italic = True
    r_s.font.name = "Calibri"
    r_s.font.size = Pt(10.5)
    r_s.font.color.rgb = MUTED

    _add_styled_table(
        doc,
        ["Submission Field", "Details"],
        [
            ["Student Name", "Ali Abbas (Solo Project)"],
            ["Roll Number / Section", "23F-3037 / SE-7A1"],
            ["Course Code & Title", "CS3002 – Information Security"],
            ["Project System", "VaultGuard Secure Document Management System (v1.0.0)"],
            ["Submission Deadline", "29-Nov-2026"],
            ["Cryptographic Libraries", "PyCA cryptography 50.0.2 (OpenSSL), argon2-cffi 25.1.0, Python stdlib"],
        ],
    )

    _add_callout(
        doc,
        "Executive Security Thesis",
        "The objective of VaultGuard SDMS is not to maximize feature count, but to build a cryptographically "
        "and architecturally defensible system. Every design decision—storage separation, per-document envelope "
        "encryption, password-locked user private keys, server-side object-level authorization, DEK rotation "
        "upon revocation, separation of auditor duties, and tamper-evident audit chaining—was engineered, tested "
        "against controlled adversarial attacks, and evaluated with explicit trust boundaries and residual limitations.",
    )
    doc.add_page_break()

    # =====================================================================
    # PART 1: SECURITY RESEARCH AND DESIGN (25 QUESTIONS)
    # =====================================================================
    _add_h1(doc, "Part 1: Security Research and Design")
    _add_body(
        doc,
        "Before implementing VaultGuard SDMS, each of the five security problem areas prescribed in the project "
        "specification was researched to compare viable engineering alternatives, select a defensible architecture, "
        "justify trade-offs, and document honest residual limitations.",
    )

    # Area 1
    _add_h2(doc, "1. Data Storage and Confidentiality")
    _add_body(
        doc,
        "Uploaded documents are stored as opaque encrypted binary blobs on a dedicated vault filesystem directory "
        "(storage/vault_blobs/<blob_id>.enc), completely decoupled from human-readable filenames and user identifiers.",
        "1.1 How uploaded documents are stored: ",
    )
    _add_body(
        doc,
        "Documents are NEVER stored in their original plaintext form. Only the encrypted envelope payload "
        "(magic header 'VGSD1' + 12-byte random nonce + AES-256-GCM ciphertext + 16-byte authentication tag) "
        "persists on disk, while metadata resides in SQLite WAL (storage/db/vaultguard.db). "
        "Alternatives considered: (a) storing raw files with OS permissions (vulnerable to storage leak or backup theft), "
        "(b) storing document bytes inside SQLite BLOB columns (bloats DB backups and prevents decoupled storage scaling). "
        "Selected approach: separated encrypted blob store + relational metadata DB.",
        "1.2 Original vs. protected form: ",
    )
    _add_body(
        doc,
        "Document encryption takes place immediately inside the application memory boundary upon authenticated upload "
        "(app/services.py:upload_document) before any bytes touch the storage directory. Only TLS-protected transport "
        "and transient request RAM handle plaintext during upload, authorized preview/download, or version updates.",
        "1.3 Point at which document protection takes place: ",
    )
    _add_body(
        doc,
        "The SQLite database stores user accounts, Argon2id password hashes, password-encrypted private key bundles, "
        "SHA-256 hashed session tokens, document metadata (UUIDv4 doc_id, sanitized title/filename, MIME type, size, "
        "SHA-256 hashes, Ed25519 manifest signature, decoupled blob_id), per-user wrapped DEKs, and chained audit logs. "
        "Separately, storage/vault_blobs/ holds ONLY opaque encrypted bytes, and storage/audit/ holds the external "
        "HMAC-signed chain anchor (chain_head.json) and isolated audit HMAC key.",
        "1.4 Database vs. separated storage boundary: ",
    )
    _add_body(
        doc,
        "If an attacker steals storage/vault_blobs/ alone, they learn only ciphertext byte lengths and random UUID filenames—"
        "zero document names, zero user identities, zero keys, and zero plaintext. If an attacker steals BOTH the blob directory "
        "and SQLite DB at rest, they obtain sanitized metadata (titles, sizes, ownership relationships, timestamps) and audit rows, "
        "but STILL cannot decrypt any document because every DEK is wrapped under users' X25519 keys whose private keys are locked "
        "with Argon2id password-derived KEKs. Limitation: metadata (document titles, sizes, collaboration graph) is readable in a DB leak.",
        "1.5 Compromise blast-radius analysis: ",
    )

    # Area 2
    _add_h2(doc, "2. Cryptographic Protection")
    _add_body(
        doc,
        "Confidentiality uses two-tier envelope encryption via PyCA cryptography: each document is encrypted with a fresh "
        "256-bit CSPRNG Data Encryption Key (DEK) under AES-256-GCM, and that DEK is individually wrapped for each authorized "
        "recipient using ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM. Only users holding an unlocked X25519 private key "
        "and an active non-revoked grant can unwrap the DEK. Alternative rejected: single server-wide master key (creates a single "
        "point of compromise and lets curious admins read all files).",
        "2.1 Ensuring authorized-only decryption: ",
    )
    _add_body(
        doc,
        "Unauthorized modification is detected across three complementary layers: (1) AES-256-GCM's 128-bit authentication tag "
        "with Additional Authenticated Data (AAD = doc_id|version|owner_id|plaintext_sha256) detects any ciphertext bit-flip or "
        "metadata swapping; (2) ciphertext_sha256 stored in DB detects offline disk modifications even before decryption; and "
        "(3) an Ed25519 digital signature over the canonical manifest (VG-MANIFEST-V1|doc_id|version|owner_id|pt_sha256|ct_sha256) "
        "authenticates the uploader/editor identity.",
        "2.2 Detecting unauthorized modification: ",
    )
    _add_body(
        doc,
        "Each user receives X25519 and Ed25519 key pairs at signup. Private keys are encrypted under a 256-bit PD-KEK derived from "
        "their password + per-user 16-byte kdf_salt via Argon2id (t=3, m=64 MiB, p=2). On login, unlocked keys reside strictly in volatile "
        "server memory sealed under a per-session cookie secret (vg_k) and are destroyed on logout or timeout. DEKs rotate automatically "
        "on document edits and share revocations.",
        "2.3 Cryptographic key management lifecycle: ",
    )
    _add_body(
        doc,
        "At registration, VaultGuard generates a high-entropy Offline Recovery Code whose HKDF-SHA256 derived key also wraps a backup copy "
        "of the user's private key bundle. If a user forgets their password, /recover verifies the recovery code, unwraps their keys, "
        "re-wraps them under a new Argon2id PD-KEK, rotates the recovery code, and invalidates all active sessions. If a password or key "
        "is compromised, password recovery + session revocation cuts off the attacker immediately; however, if BOTH password and recovery "
        "code are lost, documents remain cryptographically unrecoverable (honest zero-backdoor trade-off).",
        "2.4 Credential or key loss / compromise: ",
    )
    _add_body(
        doc,
        "In this prototype, cryptographic operations execute server-side inside FastAPI using audited OpenSSL/Argon2 bindings (PyCA "
        "cryptography & argon2-cffi), protected over TLS in deployment, while client browsers hold only HttpOnly session cookies and CSRF tokens. "
        "Alternative considered: pure browser WebCrypto E2EE. While client-side E2EE removes server RAM from the trust boundary, it complicates "
        "atomic multi-recipient DEK rotation on revocation, browser key storage, and server-side validation. Server-RAM envelope encryption was "
        "selected for reliability and verifiable key rotation, with explicit trust assumption that server RAM is trusted only during active requests.",
        "2.5 Client vs. server cryptographic operations: ",
    )

    # Area 3
    _add_h2(doc, "3. Authentication and Authorization")
    _add_body(
        doc,
        "Users authenticate with username and strong password (10+ characters, mixed character classes) verified against Argon2id hashes. "
        "After 5 failed attempts, accounts lock for 300 seconds and trigger an ALERT audit log. Successful login issues a 256-bit opaque "
        "session token stored in SQLite solely as a SHA-256 digest (vg_session HttpOnly/SameSite=Lax cookie) paired with vg_k and a session-bound "
        "CSRF synchronizer token.",
        "3.1 Verifying user identity: ",
    )
    _add_body(
        doc,
        "VaultGuard enforces a hybrid access-control model: system-level RBAC (user vs. auditor_admin) separates security auditing from "
        "document ownership, while per-document DAC ACL entries in document_permissions assign exact roles (owner, editor, viewer). "
        "Public /register hardcodes system_role='user' to eliminate mass-assignment privilege escalation.",
        "3.2 Distinguishing administrators, owners, editors, and viewers: ",
    )
    _add_body(
        doc,
        "Document identifiers are unpredictable UUIDv4 values rather than sequential integers, and dashboard queries filter strictly by "
        "active, unexpired permissions for session.user_id. Crucially, even if an authenticated attacker crafts a raw request to another "
        "user's UUID, _authorize_document blocks it server-side and commits an IDOR_ATTEMPT audit record.",
        "3.3 Preventing cross-user access & IDOR: ",
    )
    _add_body(
        doc,
        "Every read, download, verify, edit, share, revoke, and delete route executes _authorize_document() before touching blobs or DEKs, "
        "validating UUID syntax, non-deleted state, active permission row (revoked_at IS NULL), expiration timestamp, and role capability matrix. "
        "Hiding UI buttons is strictly cosmetic defense-in-depth, never an authorization control.",
        "3.4 Per-operation server-side checks: ",
    )
    _add_body(
        doc,
        "Yes. Only the document owner can revoke granted permissions via POST /documents/{doc_id}/revoke, which immediately sets revoked_at, "
        "nullifies the recipient's wrapped_dek_json, rotates the document DEK + encrypted blob to version + 1, and re-wraps only for remaining "
        "active collaborators.",
        "3.5 Revocation capability: ",
    )

    # Area 4
    _add_h2(doc, "4. Secure Document Sharing")
    _add_body(
        doc,
        "Owners share documents directly with registered users by username, specifying 'viewer' or 'editor' and optional expiry duration. "
        "The owner's active session unwraps the document DEK and wraps a recipient-specific copy under the target user's X25519 public key "
        "bound via HKDF context and AES-GCM AAD to (doc_id, version, recipient_user_id).",
        "4.1 How confidential sharing works: ",
    )
    _add_body(
        doc,
        "Sharing permissions are stored server-side in document_permissions and enforced by _authorize_document() on every API and UI endpoint. "
        "Viewers are blocked with HTTP 403 and PRIVILEGE_ESCALATION_ATTEMPT logs if they submit PUT/edit, POST/share, or DELETE requests.",
        "4.2 Enforcing sharing permissions: ",
    )
    _add_body(
        doc,
        "Any access attempt after revocation is denied with HTTP 403 ('You do not have permission to access this document') and logged as "
        "REVOKED_ACCESS_ATTEMPT. Because revocation also deletes the old wrapped DEK and rotates the document to a new DEK and new blob UUID, "
        "even an attacker holding an old DB snapshot cannot decrypt rotated document versions.",
        "4.3 Post-revocation access attempts: ",
    )
    _add_body(
        doc,
        "Anonymous bearer download URLs introduce severe risks: URLs leak via browser history, HTTP Referer headers, proxy logs, chat forwards, "
        "and cannot verify recipient identity or enforce per-user revocation cleanly. Therefore, VaultGuard intentionally rejects anonymous public "
        "download URLs—every download endpoint (/documents/{doc_id}/download) requires an authenticated session cookie plus server-side ACL check.",
        "4.4 Risks of download links and shared URLs: ",
    )
    _add_body(
        doc,
        "Downloads stream decrypted bytes directly from RAM without writing temporary plaintext files on the server disk, returning "
        "Cache-Control: no-store, no-cache, must-revalidate, private, X-Content-Type-Options: nosniff, and Content-Disposition: attachment "
        "with path-sanitized filenames. Honest limitation: once a user legitimately downloads plaintext to their local workstation, no web "
        "application can remotely revoke or erase that offline local file copy without invasive DRM.",
        "4.5 Handling downloads and temporary copies: ",
    )

    # Area 5
    _add_h2(doc, "5. Auditing and Accountability")
    _add_body(
        doc,
        "VaultGuard records security-relevant lifecycle and adversarial events: USER_REGISTERED, LOGIN_SUCCESS, LOGIN_FAILED, ACCOUNT_LOCKED, "
        "LOGIN_BLOCKED_LOCKED, LOGOUT, PASSWORD_RECOVERED, DOC_UPLOAD, DOC_READ, DOC_DOWNLOAD, DOC_UPDATE, DOC_SHARE_GRANTED, DOC_SHARE_REVOKED, "
        "DOC_DELETE, DOC_INTEGRITY_VERIFIED, DOCUMENT_INTEGRITY_FAILURE, IDOR_ATTEMPT, REVOKED_ACCESS_ATTEMPT, ACCESS_DENIED_EXPIRED, "
        "PRIVILEGE_ESCALATION_ATTEMPT, and CSRF_VALIDATION_FAILED. A sensitive-key sanitizer redacts passwords, keys, tokens, and document contents.",
        "5.1 Recorded activities: ",
    )
    _add_body(
        doc,
        "Each log entry includes a contiguous sequence number (seq_no), SHA-256 link to prev_hash, SHA-256 digest of all canonical fields "
        "(entry_hash), and HMAC-SHA256 tag (entry_hmac) keyed by isolated VAULTGUARD_AUDIT_HMAC_KEY, plus an external signed tail anchor "
        "(storage/audit/chain_head.json). Furthermore, audited_transaction() ensures failed/denied events commit even when domain transactions roll back.",
        "5.2 Protecting audit records from modification/deletion: ",
    )
    _add_body(
        doc,
        "An auditor_admin investigates user account status (failed_attempts, lockouts), chronological audit rows, integrity verification results "
        "(ciphertext SHA-256 + Ed25519 signature checks without decryption), and aggregated suspicious-activity alerts grouped by actor and IP.",
        "5.3 Administrator investigation scope: ",
    )
    _add_body(
        doc,
        "No. By the Principle of Least Privilege and Separation of Duties, administrators cannot automatically read users' confidential documents. "
        "Admin routes expose metadata and non-decrypting integrity verification only; attempting to open a user's document returns HTTP 403 and logs "
        "an IDOR_ATTEMPT (no_document_permission_admin_least_privilege).",
        "5.4 Should administrators read users' confidential documents?: ",
    )
    _add_body(
        doc,
        "Investigators distinguish benign activity from attacks via outcome classification (SUCCESS vs. DENIED vs. ALERT) and the Security Console's "
        "anomaly detector (detect_suspicious_patterns), which surfaces repeated LOGIN_FAILED/ACCOUNT_LOCKED bursts, repeated IDOR_ATTEMPT probes across "
        "foreign UUIDs, PRIVILEGE_ESCALATION_ATTEMPT hits, and DOCUMENT_INTEGRITY_FAILURE alerts.",
        "5.5 Distinguishing legitimate vs. suspicious activity: ",
    )

    _add_h2(doc, "Part 1 Comparative Summary (Alternatives, Decisions, Justifications, Limitations)")
    _add_styled_table(
        doc,
        ["Problem Area", "Alternatives Considered", "Selected Approach & Justification", "Key Limitations"],
        [
            [
                "1. Data Storage & Confidentiality",
                "Plaintext OS files; Full-disk encryption only; SQLite BLOBs",
                "Separated SQLite metadata DB + opaque UUID AES-256-GCM blob files; eliminates DB bloat & directory leaks.",
                "Sanitized titles/sizes in SQLite remain visible upon DB dump.",
            ],
            [
                "2. Cryptographic Protection",
                "Single server master KEK; Pure browser WebCrypto E2EE",
                "AES-256-GCM envelope + ephemeral X25519 DEK wrap + Argon2id PD-KEK + Ed25519 manifests; no admin master backdoor.",
                "Server RAM processes plaintext/keys during active sessions; losing both password & recovery code locks data.",
            ],
            [
                "3. Auth & Authorization",
                "Stateless JWTs; Coarse RBAC only; Superuser admin read",
                "Argon2id + SHA-256 hashed stateful sessions + hybrid System RBAC / Document DAC ACL; complete server-side mediation.",
                "Volatile RAM key store clears on server restart, requiring user re-login.",
            ],
            [
                "4. Secure Document Sharing",
                "Anonymous pre-signed URLs; ACL flag check without re-keying",
                "Authenticated user-to-user ACLs + X25519-wrapped DEKs + instant DEK/blob rotation upon revocation; zero bearer URLs.",
                "Offline files downloaded legitimately prior to revocation cannot be remotely wiped.",
            ],
            [
                "5. Auditing & Accountability",
                "Rotating plaintext logs; Unprotected SQL audit table",
                "Rollback-safe audited_transaction + SHA-256 hash chain + isolated HMAC-SHA256 + external chain_head.json anchor.",
                "Root host attacker with access to both SQLite and .audit_hmac_key could forge; requires remote SIEM in production.",
            ],
        ],
    )
    doc.add_page_break()

    # =====================================================================
    # PART 2 & PART 5 (SECTIONS 1-5): TECHNICAL ARCHITECTURE & DESIGN
    # =====================================================================
    _add_h1(doc, "Part 2: System Architecture and Technical Design")

    _add_h2(doc, "2.1 System Architecture and Data Flows")
    _add_body(
        doc,
        "VaultGuard SDMS separates presentation/API handling (FastAPI + Jinja2 autoescaped templates), security enforcement "
        "(_authorize_document, CSRF, security headers), cryptographic engine (app/crypto.py), volatile session key vault "
        "(RuntimeKeyStore), metadata database (SQLite WAL), encrypted blob filesystem (storage/vault_blobs/), and external audit anchor.",
    )
    _add_figure(
        doc,
        ROOT / "docs" / "diagrams" / "01_system_architecture.png",
        "Figure 1: VaultGuard SDMS System Architecture, Trust Boundaries, and Data Flows.",
    )

    _add_h2(doc, "2.2 Threat Model (Assets, Threats, Trust Boundaries, Mitigations)")
    _add_body(
        doc,
        "Using STRIDE threat modeling across three explicit trust boundaries (TB1: Client-Server HTTP, TB2: App RAM vs. Persistent Disk, "
        "TB3: Standard User vs. Auditor Admin), VaultGuard protects five primary assets: document plaintexts (A1), DEKs and asymmetric private "
        "keys (A2), user credentials/sessions (A3), access-control integrity (A4), and audit trail integrity (A5).",
    )
    _add_figure(
        doc,
        ROOT / "docs" / "diagrams" / "02_threat_model.png",
        "Figure 2: STRIDE Threat Model, Assets, Trust Boundaries, and Implemented Mitigations.",
    )
    _add_styled_table(
        doc,
        ["Asset", "STRIDE Threat", "Trust Boundary", "Implemented Mitigation & Verification"],
        [
            ["A1/A2: Plaintexts & DEKs", "Information Disclosure at Rest", "TB2 (RAM vs Disk)", "AES-256-GCM envelope + X25519 DEK wrap + Argon2id PD-KEK (Scenario 3)"],
            ["A1: Ciphertext Integrity", "Tampering Outside Workflow", "TB2 (Storage Disk)", "Ciphertext SHA-256 + AES-GCM AAD tag + Ed25519 manifest sig (Scenario 4)"],
            ["A3: Credentials & Sessions", "Spoofing / Brute Force / CSRF", "TB1 (Client-Server)", "Argon2id + 5-attempt lockout + SHA-256 HttpOnly cookie + CSRF token (Bonus Suite)"],
            ["A4: Access Control ACLs", "Elevation / IDOR / Stale Share", "TB1 & TB3 (User-Admin)", "UUIDv4 IDs + _authorize_document + DEK rotation on revoke (Scenarios 1, 2, 5, 6)"],
            ["A5: Audit Trail", "Repudiation / Log Tampering", "TB2 (DB vs Anchor)", "SHA-256 hash chain + HMAC-SHA256 + external chain_head.json (Scenario 7)"],
        ],
    )

    _add_h2(doc, "2.3 Database and Separated Storage Design")
    _add_body(
        doc,
        "Relational metadata and ACL rows reside in storage/db/vaultguard.db (with PRAGMA foreign_keys=ON and WAL concurrency), whereas "
        "binary ciphertexts reside separately in storage/vault_blobs/<blob_id>.enc. Decoupling doc_id from blob_id ensures directory "
        "listings disclose neither titles nor ownership.",
    )
    _add_styled_table(
        doc,
        ["Store / Table", "Location", "Stored Data", "Security Rationale"],
        [
            ["users", "storage/db/vaultguard.db", "UUID, role, Argon2id hash, kdf_salt, X25519/Ed25519 pubkeys, PD-KEK/recovery bundles", "Zero plaintext passwords or unlocked private keys at rest"],
            ["sessions", "storage/db/vaultguard.db", "SHA-256 token_hash, csrf_token, expiry, last_seen, ip_address", "DB leak cannot hijack sessions; supports instant revocation"],
            ["documents", "storage/db/vaultguard.db", "doc_id, decoupled blob_id, title, plaintext/ciphertext SHA-256, Ed25519 sig", "Separates metadata lookup from ciphertext storage"],
            ["document_permissions", "storage/db/vaultguard.db", "doc_id, user_id, role, X25519-wrapped DEK, expires_at, revoked_at", "Enforces least-privilege DAC & isolates DEKs per recipient"],
            ["audit_logs + anchor", "DB + storage/audit/chain_head.json", "Monotonic seq_no, prev_hash, entry_hash, entry_hmac + external head", "Prevents silent edits, row deletion, and tail truncation"],
            ["Opaque Blobs", "storage/vault_blobs/<blob_id>.enc", "b'VGSD1' + 12B nonce + AES-256-GCM ciphertext + 16B tag", "Leaked blob folder reveals zero filenames, users, or keys"],
        ],
    )
    _add_figure(
        doc,
        ROOT / "docs" / "diagrams" / "03_database_storage_design.png",
        "Figure 3: Relational Metadata Schema and Separated Encrypted Blob Storage Format.",
    )

    _add_h2(doc, "2.4 Cryptographic Design, Key Lifecycle, and Trust Assumptions")
    _add_styled_table(
        doc,
        ["Security Function", "Algorithm & Parameters", "Library / Binding", "Justification"],
        [
            ["Password Hashing", "Argon2id (t=3, m=64 MiB, p=2, 16B salt)", "argon2-cffi 25.1.0", "Memory-hard PHC winner resisting GPU/ASIC cracking"],
            ["Key Encryption Key", "Argon2id raw 256-bit PD-KEK (dedicated kdf_salt)", "argon2-cffi low_level", "Domain separation between login verification and key unlock"],
            ["Document Encryption", "AES-256-GCM (96-bit CSPRNG nonce + AAD)", "PyCA cryptography 50.0.2", "Authenticated encryption guaranteeing confidentiality & tamper detection"],
            ["DEK Key Wrapping", "Ephemeral X25519 ECDH + HKDF-SHA256 + AES-GCM", "PyCA cryptography", "Forward-secret per-recipient wrapping bound to doc/version/user"],
            ["Manifest Signatures", "Ed25519 digital signatures", "PyCA cryptography", "Fast, deterministic signer attribution over plaintext & ciphertext hashes"],
            ["Audit Integrity", "SHA-256 chain + HMAC-SHA256 + tail anchor", "Python hashlib / hmac", "Detects row tampering, deletion, hash forgery, and tail truncation"],
        ],
    )
    _add_figure(
        doc,
        ROOT / "docs" / "diagrams" / "04_cryptographic_lifecycle.png",
        "Figure 4: Cryptographic Key Hierarchy, Envelope Encryption, and Rotation Lifecycle.",
    )

    _add_h2(doc, "2.5 Access-Control Design and Authorization Pipeline")
    _add_body(
        doc,
        "Every state-changing and document-access endpoint executes a mandatory five-stage server-side gate before touching ciphertext or DEKs. "
        "System administrators (auditor_admin) hold audit-console privileges without implicit document decryption rights.",
    )
    _add_styled_table(
        doc,
        ["Role / Identity", "Scope", "Read / Download", "Verify Hash/Sig", "Edit & Rotate", "Share / Revoke / Delete", "Audit Console"],
        [
            ["Owner", "Per-Document (DAC)", "ALLOW", "ALLOW", "ALLOW", "ALLOW", "DENY (403)"],
            ["Editor", "Per-Document (DAC)", "ALLOW", "ALLOW", "ALLOW", "DENY (403)", "DENY (403)"],
            ["Viewer", "Per-Document (DAC)", "ALLOW", "ALLOW", "DENY (403)", "DENY (403)", "DENY (403)"],
            ["Auditor Admin", "System (RBAC)", "DENY (403)*", "ALLOW (No Decrypt)", "DENY (403)", "DENY (403)", "ALLOW"],
        ],
    )
    _add_figure(
        doc,
        ROOT / "docs" / "diagrams" / "05_access_control_flow.png",
        "Figure 5: Five-Stage Server-Side Authorization Pipeline and Hybrid RBAC/DAC Role Matrix.",
    )

    _add_h2(doc, "2.6 Working Prototype Interface Walkthrough")
    _add_body(
        doc,
        "The working FastAPI web interface exposes authentication, identity/key fingerprints & active session management, vault dashboard "
        "with drag-and-drop upload and live filtering, encrypted document preview/editing/sharing/revocation, and the Security Audit Console. "
        "Figures 6–9 demonstrate authenticated workflows captured from the running server via Chromium.",
    )
    _add_figure(
        doc,
        ROOT / "screenshots" / "01_login_screen.png",
        "Figure 6: VaultGuard SDMS Sign-In Screen (Argon2id authentication & session key unlock).",
        width_in=5.5,
    )
    _add_figure(
        doc,
        ROOT / "screenshots" / "02_alice_dashboard.png",
        "Figure 7: Document Owner Vault Dashboard displaying KPI cards, live filter toolbar, and drag-and-drop upload.",
        width_in=5.8,
    )
    _add_figure(
        doc,
        ROOT / "screenshots" / "03_document_detail_and_sharing.png",
        "Figure 8: Verified Document View showing AES-256-GCM + Ed25519 seal, copyable hashes, sharing, and document history.",
        width_in=5.3,
    )
    _add_figure(
        doc,
        ROOT / "screenshots" / "10_identity_keys_sessions.png",
        "Figure 9: Identity & Keys Profile displaying X25519/Ed25519 fingerprints and active session revocation.",
        width_in=5.5,
    )
    doc.add_page_break()

    # =====================================================================
    # PART 3: SECURITY TESTING AND ADVERSARIAL DEMONSTRATION
    # =====================================================================
    _add_h1(doc, "Part 3: Security Testing and Adversarial Demonstration")
    _add_body(
        doc,
        "All seven adversarial scenarios required by Part 3—plus brute-force lockout, CSRF rejection, share expiration, key recovery, "
        "and multi-session revocation—were verified both programmatically via pytest (tests/test_security_scenarios.py: 8/8 passed in 29.94s) "
        "and visually against a live Uvicorn server using Playwright Chromium.",
    )

    _add_code_block(
        doc,
        "$ .\\.venv\\Scripts\\python.exe -m pytest -v tests\\test_security_scenarios.py\n"
        "tests/test_security_scenarios.py::test_scenario_1_and_2_unauthorized_access_and_idor PASSED [ 12%]\n"
        "tests/test_security_scenarios.py::test_scenario_3_storage_exposure_analysis PASSED         [ 25%]\n"
        "tests/test_security_scenarios.py::test_scenario_4_external_document_tampering_detection PASSED [ 37%]\n"
        "tests/test_security_scenarios.py::test_scenario_5_privilege_misuse_and_escalation PASSED    [ 50%]\n"
        "tests/test_security_scenarios.py::test_scenario_6_permission_revocation_and_key_rotation PASSED [ 62%]\n"
        "tests/test_security_scenarios.py::test_scenario_7_audit_tampering_detection PASSED          [ 75%]\n"
        "tests/test_security_scenarios.py::test_bonus_lockout_csrf_recovery_and_expiry PASSED        [ 87%]\n"
        "tests/test_security_scenarios.py::test_profile_session_management_and_ui_verify PASSED      [100%]\n"
        "======================= 8 passed in 29.94s =======================",
    )

    scenarios = [
        (
            "Scenario 1: Unauthorized Document Access (User & Auditor Admin)",
            "Threat: Privilege bypass / unauthorized confidentiality breach. Assets: Alice's private document plaintext & DEK.",
            "1) Alice uploads private 'Payroll Q4' document. 2) Unshared user Charlie requests GET /api/documents/{id} and /download. 3) System auditor_admin (sec_admin) also attempts GET /api/documents/{id} and /verify.",
            "Expected & Actual: Both Charlie and sec_admin receive HTTP 403 Forbidden on read/download, while sec_admin receives HTTP 200 on non-decrypting /verify. Both denials commit IDOR_ATTEMPT rows (admin tagged with no_document_permission_admin_least_privilege).",
            "Limitation & Mitigation: Returning 403 vs 404 on valid vs missing UUIDs can reveal UUID existence to authenticated probes; mitigated via 128-bit unpredictable UUIDv4 identifiers and rate monitoring.",
        ),
        (
            "Scenario 2: Identifier Manipulation (IDOR)",
            "Threat: Insecure Direct Object Reference (IDOR) via URL/path manipulation. Assets: Foreign confidential documents.",
            "1) Bob holds access to shared doc A. 2) Authenticated attacker Charlie substitutes Alice's private doc UUID, bogus UUID 00000000-...-0099, and malformed '12345-not-a-uuid' into /documents/{doc_id}.",
            "Expected & Actual: Returns HTTP 403 (foreign UUID), 404 (nonexistent UUID), and 400 (malformed UUID). Zero document titles or bytes leak, and every probe commits an IDOR_ATTEMPT audit entry.",
            "Limitation & Mitigation: Malformed-vs-missing status codes differ slightly (400 vs 404); could be collapsed to uniform 403/404 for maximal API opacity.",
        ),
    ]
    for title, threat, steps, result, limit in scenarios:
        _add_h2(doc, title)
        _add_bullet(doc, threat, "Threat & Asset: ")
        _add_bullet(doc, steps, "Controlled Test Steps: ")
        _add_bullet(doc, result, "Expected vs. Actual Behaviour: ")
        _add_bullet(doc, limit, "Limitation & Future Mitigation: ")

    _add_figure(
        doc,
        ROOT / "screenshots" / "04_scenario1_2_idor_unauthorized_403.png",
        "Figure 9: Scenarios 1 & 2 Live Proof — Charlie blocked with HTTP 403 Access Denied when accessing Alice's private document UUID.",
        width_in=5.5,
    )

    _add_h2(doc, "Scenario 3: Storage Exposure")
    _add_bullet(doc, "Threat: Offline storage / DB backup theft. Assets: Document plaintext, filenames, DEKs, user credentials.", "Threat & Asset: ")
    _add_bullet(doc, "Inspected raw storage/vault_blobs/<blob_id>.enc bytes and SQLite rows in users, documents, and document_permissions.", "Controlled Test Steps: ")
    _add_bullet(doc, "Expected & Actual: Blob starts with b'VGSD1' + 12B nonce + AES-GCM ciphertext; zero occurrences of plaintext, filename, or username exist on disk. DB password_hash starts with $argon2id$; wrapped_dek_json holds only {v, eph_pub, nonce, ct}; decryption with forged keys raises CryptoIntegrityError.", "Expected vs. Actual Behaviour: ")
    storage_ev = (ROOT / "docs" / "storage_exposure_evidence.txt").read_text(encoding="utf-8")
    _add_code_block(doc, storage_ev)
    _add_bullet(doc, "Limitation & Mitigation: Sanitized metadata (titles, sizes, owner_id, timestamps) in SQLite remains readable if DB is stolen; future iteration could encrypt titles inside AAD-bound metadata.", "Limitation & Future Mitigation: ")

    _add_h2(doc, "Scenario 4: External Document Modification")
    _add_bullet(doc, "Threat: Silent file corruption or ciphertext tampering on disk outside app workflow. Assets: Document integrity & authenticity.", "Threat & Asset: ")
    _add_bullet(doc, "Flipped 1 byte inside storage/vault_blobs/<blob_id>.enc outside FastAPI; Alice then requested the document via browser and /verify.", "Controlled Test Steps: ")
    _add_bullet(doc, "Expected & Actual: System fails closed with HTTP 409 Integrity Alert ('Encrypted blob on disk was modified outside the application workflow!'), refuses to return plaintext, flags ciphertext_hash_ok=False, and logs HIGH-severity DOCUMENT_INTEGRITY_FAILURE.", "Expected vs. Actual Behaviour: ")
    _add_bullet(doc, "Limitation & Mitigation: Detection prevents serving tampered bytes, but does not auto-heal corrupted storage without redundant immutable backups.", "Limitation & Future Mitigation: ")
    _add_figure(
        doc,
        ROOT / "screenshots" / "07_scenario4_external_tamper_alert.png",
        "Figure 10: Scenario 4 Live Proof — 1-bit disk tamper triggers fail-closed HTTP 409 Integrity Alert.",
        width_in=5.5,
    )

    _add_h2(doc, "Scenario 5: Privilege Misuse and Escalation")
    _add_bullet(doc, "Threat: Horizontal/vertical privilege escalation. Assets: Document integrity, sharing ACLs, admin console.", "Threat & Asset: ")
    _add_bullet(doc, "1) Bob (viewer) loads shared doc UI (no edit/share/delete controls). 2) Bob crafts raw PUT, POST /share, and DELETE requests, plus GET /api/admin/audit/verify. 3) User 'eve_escalate' submits system_role='auditor_admin' on registration.", "Controlled Test Steps: ")
    _add_bullet(doc, "Expected & Actual: Every unauthorized document/admin request returns HTTP 403 Forbidden and logs PRIVILEGE_ESCALATION_ATTEMPT; public registration ignores system_role and enforces 'user'.", "Expected vs. Actual Behaviour: ")
    _add_bullet(doc, "Limitation & Mitigation: Role changes require owner action; adding multi-party approval for high-sensitivity docs would reduce single-owner risk.", "Limitation & Future Mitigation: ")
    _add_figure(
        doc,
        ROOT / "screenshots" / "05_scenario5_viewer_privilege_boundary.png",
        "Figure 11: Scenario 5 Live Proof — Bob as Viewer sees read/download only (all raw mutation calls blocked with HTTP 403).",
        width_in=5.4,
    )

    _add_h2(doc, "Scenario 6: Permission Revocation and Key Rotation")
    _add_bullet(doc, "Threat: Stale access post-revocation or replay of captured wrapped DEKs. Assets: Updated/confidential document versions.", "Threat & Asset: ")
    _add_bullet(doc, "1) Bob reads/edits shared doc while permitted (v2); test snapshots Bob's wrapped_dek_json and old blob_id. 2) Alice clicks Revoke. 3) Bob immediately requests GET /documents/{id} and /download.", "Controlled Test Steps: ")
    _add_bullet(doc, "Expected & Actual: Revocation sets revoked_at, NULLs wrapped_dek_json, rotates DEK to v3, re-encrypts into a new blob UUID, and unlinks the old blob. Bob's subsequent requests fail with HTTP 403 and log REVOKED_ACCESS_ATTEMPT.", "Expected vs. Actual Behaviour: ")
    _add_bullet(doc, "Limitation & Mitigation: Plaintext copies already downloaded locally by Bob prior to revocation cannot be deleted remotely (inherent DRM gap); mitigated operationally via short share expiries and watermarking.", "Limitation & Future Mitigation: ")
    _add_figure(
        doc,
        ROOT / "screenshots" / "06_scenario6_revocation_denied_403.png",
        "Figure 12: Scenario 6 Live Proof — Bob immediately blocked with HTTP 403 after Alice revokes share and rotates DEK.",
        width_in=5.5,
    )

    _add_h2(doc, "Scenario 7: Audit Tampering Detection")
    _add_bullet(doc, "Threat: Insider/DBA altering or deleting forensic audit logs to hide malicious activity. Assets: Audit trail non-repudiation.", "Threat & Asset: ")
    _add_bullet(doc, "1) Verified intact chain in /admin console (Figure 14). 2) Executed raw SQL UPDATE on seq_no=12 (forged actor_username='forged_user', outcome='SUCCESS') and deleted the final row seq_no=20 (tail truncation). 3) Reloaded Security Audit Console.", "Controlled Test Steps: ")
    _add_bullet(doc, "Expected & Actual: Console switches from VERIFIED INTACT (20/20) to red TAMPER DETECTED (18/19 verified), pinpointing exact violations: seq 12 ROW_CONTENT_TAMPERED and seq 20 TAIL_TRUNCATION_DETECTED.", "Expected vs. Actual Behaviour: ")
    _add_bullet(doc, "Limitation & Mitigation: An attacker possessing root OS access to BOTH SQLite and local chain_head.json/.audit_hmac_key could recompute everything; production mitigation is shipping logs asynchronously to remote WORM/append-only SIEM storage.", "Limitation & Future Mitigation: ")
    _add_figure(
        doc,
        ROOT / "screenshots" / "08_admin_audit_console_intact.png",
        "Figure 14: Security Auditor Console prior to tampering — Audit Chain VERIFIED INTACT (20/20) with threat summaries.",
        width_in=5.3,
    )
    _add_figure(
        doc,
        ROOT / "screenshots" / "09_scenario7_audit_tamper_detected.png",
        "Figure 15: Scenario 7 Live Proof — Tampered seq 12 and truncated seq 20 immediately flagged as TAMPER DETECTED.",
        width_in=5.3,
    )
    doc.add_page_break()

    # =====================================================================
    # PART 4: DESIGN DECISION RECORDS (5 DDRs)
    # =====================================================================
    _add_h1(doc, "Part 4: Design Decision Records (DDR-01 to DDR-05)")

    ddrs = [
        (
            "DDR-01: Document Storage and Protection Architecture",
            "How should uploaded confidential documents and their metadata be persisted so that neither database compromise nor file-storage theft exposes document plaintexts?",
            "1) Plaintext filesystem with OS ACLs; 2) Full-disk encryption (BitLocker/LUKS) alone; 3) Encrypted BLOBs stored directly inside SQLite rows; 4) Separated metadata SQLite DB + isolated opaque AES-256-GCM blob files.",
            "Selected Option 4: Documents are encrypted immediately in memory as opaque <blob_id>.enc files under storage/vault_blobs/, decoupled from UUID doc_id, original filename, and owner metadata stored in storage/db/vaultguard.db. This prevents DB bloat, simplifies object-storage migration (e.g., S3), and prevents filesystem directory snooping.",
            "Defense-in-Depth, Storage Isolation, Data-at-Rest Confidentiality, Metadata Minimization.",
            "Filename/title metadata in SQLite remains visible on DB dump; orphaned blobs could occur on abrupt power failure without cleanup sweeps (mitigated by try/except unlink rollback in upload/update/revoke).",
        ),
        (
            "DDR-02: Cryptographic Approach and Key Management",
            "How should documents be encrypted, signed, and shared without storing plaintext keys or enabling an administrator master backdoor?",
            "1) Single server-side symmetric KEK encrypting all DEKs; 2) Pure client-side browser WebCrypto E2EE; 3) Server-assisted Envelope Encryption (AES-256-GCM DEKs + Ephemeral X25519 + HKDF-SHA256 wrapping + Argon2id PD-KEK + Ed25519 manifest signatures).",
            "Selected Option 3: Eliminates single master-key blast radius, ensures administrators cannot read user documents without user passwords, supports offline-recipient sharing via X25519 public keys, and guarantees atomic DEK rotation on revocation and Ed25519 tamper attribution.",
            "Envelope Encryption, Authenticated Encryption with Associated Data (AAD), Diffie-Hellman Key Agreement (X25519), Key Derivation (Argon2id & HKDF), Digital Signatures (Ed25519).",
            "Server RAM handles plaintext/keys during active sessions (requiring TLS 1.3 and memory protection in production); losing both password and offline recovery code causes permanent cryptographic data loss.",
        ),
        (
            "DDR-03: Authentication and Access-Control Model",
            "How should user identities be authenticated and permissions enforced across owners, editors, viewers, and security administrators?",
            "1) Stateless JWTs with coarse RBAC roles; 2) Basic session cookies with superuser Admin read access; 3) Argon2id authentication + SHA-256 hashed server-side sessions + Hybrid System RBAC (user vs auditor_admin) & Per-Document DAC ACL.",
            "Selected Option 3: Server-side hashed sessions support instant logout/recovery invalidation, brute-force lockout, and idle timeouts; hybrid RBAC+DAC enforces least privilege so auditor_admin audits logs and verifies blob integrity without reading user plaintexts.",
            "Principle of Least Privilege, Separation of Duties, Fail-Closed Mediation, Stateful Session Revocation, Brute-Force Throttling.",
            "Stateful DB session checks add one fast indexed query per request; RuntimeKeyStore is volatile in-memory so server restarts require user re-login (a deliberate security trade-off over writing unwrapped keys to disk).",
        ),
        (
            "DDR-04: Document Sharing and Permission Revocation",
            "How should users share confidential documents while guaranteeing immediate post-revocation enforcement and preventing link leakage?",
            "1) Signed bearer download URLs (time-limited anonymous links); 2) ACL database flag check only without rotating DEKs; 3) Authenticated user-to-user ACL grants with X25519-wrapped DEKs + immediate revocation with DEK & blob rotation.",
            "Selected Option 3: Eliminates anonymous URL leakage via logs/referrers, checks active/unexpired ACL grants server-side, wipes the revoked user's wrapped DEK, and rotates DEK + blob UUID so prior wrapped DEKs cannot decrypt rotated versions.",
            "Complete Mediation, Cryptographic Erasure/Key Rotation, Time-Bounded Authorization, Non-Cacheable Transport Headers (no-store).",
            "Sharing requires recipients to hold registered accounts; legitimate copies downloaded locally before revocation remain outside server control.",
        ),
        (
            "DDR-05: Audit Logging and Protection of Audit Records",
            "How can security events remain accountable and tamper-evident even if an attacker or rogue DBA modifies SQLite audit rows?",
            "1) Standard rotating plaintext log files; 2) Unprotected SQL audit table; 3) Atomic SHA-256 hash chain + isolated HMAC-SHA256 authentication + external chain_head.json anchor + rollback-safe audited_transaction.",
            "Selected Option 3: Ensures denied attacks still commit when operations fail closed, catches middle edits/deletions (sequence gaps & hash mismatch), blocks hash-recalculation forgery via isolated HMAC key, and detects tail truncation via external anchor.",
            "Non-Repudiation, Integrity Chaining, Message Authentication (HMAC), Secret Sanitization (PII/Key Redaction).",
            "If an attacker gains root host access to both SQLite and .audit_hmac_key, they could forge both; production deployment should mirror audit events to remote append-only WORM/SIEM infrastructure.",
        ),
    ]

    for title, prob, alts, sel, concepts, trade in ddrs:
        _add_h2(doc, title)
        _add_styled_table(
            doc,
            ["DDR Dimension", "Decision Specification"],
            [
                ["1. Problem Being Addressed", prob],
                ["2. Alternatives Considered", alts],
                ["3. Selected Approach & Justification", sel],
                ["4. Supporting IS Concepts", concepts],
                ["5. Limitations, Risks & Trade-Offs", trade],
            ],
        )

    # =====================================================================
    # REFERENCES
    # =====================================================================
    _add_h1(doc, "References and External Libraries")
    refs = [
        "Python Cryptographic Authority (PyCA). cryptography v50.0.2 (OpenSSL-backed AESGCM, X25519, Ed25519, HKDF). https://cryptography.io/",
        "Schernthaner, H. argon2-cffi v25.1.0 (RFC 9106 Argon2id Password Hashing & Low-Level KDF). https://argon2-cffi.readthedocs.io/",
        "Tiangolo, S. FastAPI v0.165.0, Starlette v1.10.0, Uvicorn v0.54.0, Jinja2 v3.1.6 (Web Framework & Security Middleware). https://fastapi.tiangolo.com/",
        "SQLite 3.49.1 (Python stdlib sqlite3 with WAL mode & foreign key enforcement). https://www.sqlite.org/",
        "Microsoft Playwright v1.65.2 & pytest v9.2.0 (Automated Security & Browser Verification). https://playwright.dev/python/",
        "python-docx v1.2.0 & python-pptx v1.0.2 (Automated Technical Documentation Generation).",
        "NIST Special Publication 800-63B: Digital Identity Guidelines — Authentication and Lifecycle Management.",
        "NIST Special Publication 800-57 Part 1 Rev. 5: Recommendation for Key Management.",
        "OWASP Cheat Sheet Series: Cryptographic Storage, Access Control, Session Management, and Cross-Site Request Forgery Prevention.",
        "IETF RFC 7748 (X25519), RFC 8032 (Ed25519), RFC 5869 (HKDF), and RFC 9106 (Argon2).",
    ]
    for r in refs:
        _add_bullet(doc, r)

    doc.save(str(OUT_DOCX))
    print(f"Generated Word report: {OUT_DOCX}")


if __name__ == "__main__":
    build_report()
