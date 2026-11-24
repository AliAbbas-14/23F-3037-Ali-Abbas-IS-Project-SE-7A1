"""Generate CS3002 Project Presentation: 23F-3037_IS_Project_Presentation.pptx."""

from __future__ import annotations

from pathlib import Path

from PIL import Image
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parent.parent
OUT_PPTX = ROOT / "23F-3037_IS_Project_Presentation.pptx"

BG = RGBColor(0x0B, 0x11, 0x1B)
CARD = RGBColor(0x12, 0x1B, 0x2B)
ACCENT = RGBColor(0x38, 0xBD, 0xF8)
GREEN = RGBColor(0x4A, 0xDE, 0x80)
WHITE = RGBColor(0xF8, 0xFA, 0xFC)
MUTED = RGBColor(0x94, 0xA3, 0xB8)


def _new_slide(prs: Presentation, title: str, subtitle: str = ""):
    slide = prs.slides.add_slide(prs.slide_layouts[6])
    bg = slide.background.fill
    bg.solid()
    bg.fore_color.rgb = BG

    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.08))
    bar.fill.solid()
    bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background()

    tb = slide.shapes.add_textbox(Inches(0.55), Inches(0.25), Inches(12.2), Inches(0.85))
    tf = tb.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = title
    p.font.name = "Segoe UI"
    p.font.size = Pt(24)
    p.font.bold = True
    p.font.color.rgb = WHITE
    if subtitle:
        p2 = tf.add_paragraph()
        p2.text = subtitle
        p2.font.name = "Segoe UI"
        p2.font.size = Pt(12.5)
        p2.font.color.rgb = ACCENT
    return slide


def _add_bullets(slide, left, top, width, height, items: list[tuple[str, str]], font_size=14):
    card = slide.shapes.add_shape(
        MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height)
    )
    card.fill.solid()
    card.fill.fore_color.rgb = CARD
    card.line.color.rgb = RGBColor(0x27, 0x37, 0x54)

    tb = slide.shapes.add_textbox(
        Inches(left + 0.25), Inches(top + 0.22), Inches(width - 0.5), Inches(height - 0.44)
    )
    tf = tb.text_frame
    tf.word_wrap = True
    for idx, (head, body) in enumerate(items):
        p = tf.paragraphs[0] if idx == 0 else tf.add_paragraph()
        p.space_after = Pt(12)
        r1 = p.add_run()
        r1.text = f"• {head}: "
        r1.font.bold = True
        r1.font.name = "Segoe UI"
        r1.font.size = Pt(font_size)
        r1.font.color.rgb = ACCENT
        r2 = p.add_run()
        r2.text = body
        r2.font.name = "Segoe UI"
        r2.font.size = Pt(font_size)
        r2.font.color.rgb = WHITE


def _fit_picture(slide, img_path: Path, box_left: float, box_top: float, max_w: float, max_h: float) -> None:
    if not img_path.exists():
        return
    with Image.open(img_path) as im:
        iw, ih = im.size
    ratio = min(max_w / iw, max_h / ih)
    w_in = iw * ratio
    h_in = ih * ratio
    x_in = box_left + (max_w - w_in) / 2
    y_in = box_top + (max_h - h_in) / 2
    slide.shapes.add_picture(str(img_path), Inches(x_in), Inches(y_in), width=Inches(w_in), height=Inches(h_in))


def _add_image_slide(prs: Presentation, title: str, subtitle: str, img_path: Path, note: str):
    slide = _new_slide(prs, title, subtitle)
    _fit_picture(slide, img_path, 0.55, 1.2, 12.23, 5.65)
    tb = slide.shapes.add_textbox(Inches(0.6), Inches(6.95), Inches(12.1), Inches(0.4))
    p = tb.text_frame.paragraphs[0]
    p.text = note
    p.font.name = "Segoe UI"
    p.font.size = Pt(11)
    p.font.color.rgb = MUTED


def build_presentation() -> None:
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)

    # Slide 1: Title
    s1 = prs.slides.add_slide(prs.slide_layouts[6])
    bg1 = s1.background.fill
    bg1.solid()
    bg1.fore_color.rgb = BG
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(0.1))
    bar.fill.solid()
    bar.fill.fore_color.rgb = ACCENT
    bar.line.fill.background()

    tb = s1.shapes.add_textbox(Inches(0.9), Inches(1.4), Inches(11.5), Inches(4.8))
    tf = tb.text_frame
    tf.word_wrap = True
    p0 = tf.paragraphs[0]
    p0.text = "FAST-NUCES CHINIOT-FAISALABAD | CS3002 INFORMATION SECURITY"
    p0.font.name = "Segoe UI"
    p0.font.size = Pt(14)
    p0.font.bold = True
    p0.font.color.rgb = ACCENT

    p1 = tf.add_paragraph()
    p1.space_before = Pt(18)
    p1.text = "VaultGuard SDMS\nSecure Document Management System"
    p1.font.name = "Segoe UI"
    p1.font.size = Pt(38)
    p1.font.bold = True
    p1.font.color.rgb = WHITE

    p2 = tf.add_paragraph()
    p2.space_before = Pt(22)
    p2.text = "Envelope Encryption (AES-256-GCM + X25519 + Ed25519) | Argon2id | Hybrid RBAC/DAC | HMAC Audit Chain"
    p2.font.name = "Segoe UI"
    p2.font.size = Pt(15)
    p2.font.color.rgb = MUTED

    p3 = tf.add_paragraph()
    p3.space_before = Pt(36)
    p3.text = "Submitted by: Ali Abbas (23F-3037)  |  Section: SE-7A1  |  Solo Project"
    p3.font.name = "Segoe UI"
    p3.font.size = Pt(16)
    p3.font.bold = True
    p3.font.color.rgb = GREEN

    # Slide 2: Security Objectives
    s2 = _new_slide(prs, "1. Security Objectives & Design Philosophy", "Building a Defensible System rather than Feature Bloat")
    _add_bullets(
        s2, 0.55, 1.35, 12.2, 5.6,
        [
            ("Storage Separation", "Metadata & ACLs stored in SQLite WAL; opaque AES-256-GCM blobs stored separately by decoupled UUID."),
            ("No Admin Master Key", "User X25519/Ed25519 private keys are encrypted under Argon2id PD-KEK; auditor_admin cannot read user documents."),
            ("Standard Audited Crypto", "100% PyCA cryptography (OpenSSL) and argon2-cffi — zero custom cryptographic algorithms."),
            ("Complete Mediation", "Server-side _authorize_document() validates session, CSRF, UUID, non-revoked grant, expiry, and role capability."),
            ("Cryptographic Revocation", "Revoking a collaborator deletes their wrapped DEK, rotates to a new 256-bit DEK + blob, and unlinks old ciphertext."),
            ("Tamper-Evident Accountability", "Rollback-safe audit commits chained with SHA-256, HMAC-SHA256, and an external tail anchor."),
        ],
        font_size=15,
    )

    # Slides 3-7: Diagrams
    _add_image_slide(
        prs,
        "2. System Architecture & Data Flows",
        "Client Layer -> FastAPI Security Gate -> Runtime Key Vault -> Separated DB & Blob Store",
        ROOT / "docs" / "diagrams" / "01_system_architecture.png",
        "Diagram 01: Full VaultGuard SDMS architectural topology and trust boundaries.",
    )
    _add_image_slide(
        prs,
        "3. STRIDE Threat Model & Mitigations",
        "Explicit Assets, Trust Boundaries (TB1-TB3), and Verified Defenses",
        ROOT / "docs" / "diagrams" / "02_threat_model.png",
        "Diagram 02: Mapped directly to automated adversarial tests in tests/test_security_scenarios.py.",
    )
    _add_image_slide(
        prs,
        "4. Database & Separated Storage Design",
        "Relational SQLite Metadata Isolated from Binary Ciphertext Blobs",
        ROOT / "docs" / "diagrams" / "03_database_storage_design.png",
        "Diagram 03: Zero raw passwords, DEKs, or plaintexts stored in either database or blob storage.",
    )
    _add_image_slide(
        prs,
        "5. Cryptographic Key Hierarchy & Lifecycle",
        "Argon2id PD-KEK -> X25519/Ed25519 Keys -> AES-256-GCM Envelope -> DEK Rotation",
        ROOT / "docs" / "diagrams" / "04_cryptographic_lifecycle.png",
        "Diagram 04: Includes offline self-service Recovery Code path preserving key access without admin backdoors.",
    )
    _add_image_slide(
        prs,
        "6. Access-Control Model & Authorization Pipeline",
        "Hybrid System RBAC (user vs auditor_admin) + Document DAC (owner, editor, viewer)",
        ROOT / "docs" / "diagrams" / "05_access_control_flow.png",
        "Diagram 05: Server-side object-level authorization guarantees all denials commit audit entries.",
    )

    # Slide 8: Working Prototype (Auth + Identity/Keys)
    s8a = _new_slide(prs, "7. Authentication & Identity Key Management", "Argon2id Session Unlock, X25519/Ed25519 Fingerprints & Session Revocation")
    _fit_picture(s8a, ROOT / "screenshots" / "01_login_screen.png", 0.55, 1.35, 5.95, 5.65)
    _fit_picture(s8a, ROOT / "screenshots" / "10_identity_keys_sessions.png", 6.8, 1.35, 5.95, 5.65)

    # Slide 9: Working Prototype (Vault + Document Detail)
    s8 = _new_slide(prs, "8. Working Application Prototype", "Encrypted Vault Dashboard, Integrity Verification, Sharing & Activity History")
    _fit_picture(s8, ROOT / "screenshots" / "02_alice_dashboard.png", 0.55, 1.3, 5.9, 5.7)
    _fit_picture(s8, ROOT / "screenshots" / "03_document_detail_and_sharing.png", 6.75, 1.3, 6.0, 5.7)

    # Slide 10: Scenarios 1-4
    s9 = _new_slide(prs, "9. Adversarial Demos: IDOR (Scen 1-2) & Blob Tampering (Scen 4)", "Fail-Closed HTTP 403 / 409 Responses with Guaranteed Audit Logging")
    _fit_picture(s9, ROOT / "screenshots" / "04_scenario1_2_idor_unauthorized_403.png", 0.55, 1.35, 5.95, 5.6)
    _fit_picture(s9, ROOT / "screenshots" / "07_scenario4_external_tamper_alert.png", 6.8, 1.35, 5.95, 5.6)

    # Slide 11: Scenarios 5-6
    s10 = _new_slide(prs, "10. Adversarial Demos: Privilege Boundary (Scen 5) & Revocation (Scen 6)", "Least Privilege Enforcement and Post-Revocation DEK Rotation")
    _fit_picture(s10, ROOT / "screenshots" / "05_scenario5_viewer_privilege_boundary.png", 0.55, 1.35, 5.95, 5.6)
    _fit_picture(s10, ROOT / "screenshots" / "06_scenario6_revocation_denied_403.png", 6.8, 1.35, 5.95, 5.6)

    # Slide 12: Scenario 7
    s11 = _new_slide(prs, "11. Adversarial Demo: Audit Log Tampering (Scenario 7)", "Intact Hash Chain (20/20) vs. SQL Row Edit (Seq 12) + Tail Truncation (Seq 20)")
    _fit_picture(s11, ROOT / "screenshots" / "08_admin_audit_console_intact.png", 0.55, 1.3, 5.95, 5.7)
    _fit_picture(s11, ROOT / "screenshots" / "09_scenario7_audit_tamper_detected.png", 6.8, 1.3, 5.95, 5.7)

    # Slide 13: Summary
    s12 = _new_slide(prs, "12. Verification Summary & Residual Limitations", "8/8 Automated Security Tests Passed (29.94s) — Honest Engineering Trade-offs")
    _add_bullets(
        s12, 0.55, 1.35, 12.2, 5.6,
        [
            ("All 7 Part 3 Scenarios Verified", "Unauthorized access, IDOR, storage exposure, disk tamper, privilege escalation, revocation, and audit tampering all passed."),
            ("Additional Protections Verified", "Brute-force 5-attempt lockout (HTTP 429), CSRF token rejection (403), share expiry, and recovery-code password reset."),
            ("Limitation 1 — Offline Downloaded Copies", "Locally downloaded plaintext files cannot be remotely wiped after share revocation (DRM boundary)."),
            ("Limitation 2 — Server RAM Trust Boundary", "Keys unlock in ephemeral server memory during active sessions; requires TLS 1.3 in production."),
            ("Limitation 3 — Host-Root Audit Risk", "Local SQLite + HMAC key on one host should ship logs asynchronously to remote WORM/SIEM storage in production."),
        ],
        font_size=15,
    )

    prs.save(str(OUT_PPTX))
    print(f"Generated presentation: {OUT_PPTX}")


if __name__ == "__main__":
    build_presentation()
