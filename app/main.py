"""VaultGuard SDMS FastAPI Application — UI routes, JSON API, security headers, and CSRF."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.audit import append_audit_event, detect_suspicious_patterns, verify_audit_chain
from app.config import Settings, get_settings
from app.database import get_connection, init_db
from app.services import (
    AccessDeniedError,
    AuthenticatedSession,
    AuthError,
    IntegrityFailureError,
    RuntimeKeyStore,
    ServiceError,
    delete_document,
    get_document_audit_history,
    get_user_sessions,
    list_accessible_documents,
    login_user,
    logout_user,
    recover_user_password,
    register_user,
    resolve_session,
    retrieve_document,
    revoke_document_share,
    revoke_other_sessions,
    share_document,
    update_document_content,
    upload_document,
    verify_document_integrity_status,
)

APP_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = APP_DIR / "templates"
STATIC_DIR = APP_DIR / "static"

SESSION_COOKIE = "vg_session"
VAULT_KEY_COOKIE = "vg_k"


class RegisterPayload(BaseModel):
    username: str
    email: str
    full_name: str
    password: str


class LoginPayload(BaseModel):
    username: str
    password: str


class SharePayload(BaseModel):
    target_username: str
    role: str
    expires_in_hours: int | None = None


class RevokePayload(BaseModel):
    target_user_id: str


class EditTextPayload(BaseModel):
    new_title: str | None = None
    new_text: str


def create_app(custom_settings: Settings | None = None) -> FastAPI:
    """Application factory enabling isolated test instances and production startup."""
    settings = custom_settings or get_settings()
    init_db(settings.db_path)
    key_store = RuntimeKeyStore()

    app = FastAPI(title="VaultGuard SDMS", version="1.0.0", docs_url=None, redoc_url=None)
    app.state.settings = settings
    app.state.key_store = key_store

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def add_security_headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'"
        )
        if request.url.path not in ("/login", "/register", "/recover") and not request.url.path.startswith(
            "/static"
        ):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
        return response

    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "127.0.0.1"

    def _get_session(request: Request) -> AuthenticatedSession:
        return resolve_session(
            settings,
            key_store,
            request.cookies.get(SESSION_COOKIE),
            request.cookies.get(VAULT_KEY_COOKIE),
        )

    def _verify_csrf(session: AuthenticatedSession, provided: str | None) -> None:
        if not provided or not hmac.compare_digest(session.csrf_token, provided):
            append_audit_event(
                settings,
                action="CSRF_VALIDATION_FAILED",
                outcome="DENIED",
                actor_user_id=session.user_id,
                actor_username=session.username,
            )
            raise AccessDeniedError("Invalid or missing CSRF security token.", status_code=403)

    def _set_auth_cookies(response: Response, auth_result: dict[str, Any]) -> None:
        cookie_opts = {
            "httponly": True,
            "samesite": "lax",
            "secure": settings.cookie_secure,
            "path": "/",
            "max_age": settings.session_ttl_seconds,
        }
        response.set_cookie(SESSION_COOKIE, auth_result["raw_session_token"], **cookie_opts)
        response.set_cookie(VAULT_KEY_COOKIE, auth_result["session_key_hex"], **cookie_opts)

    def _clear_auth_cookies(response: Response) -> None:
        response.delete_cookie(SESSION_COOKIE, path="/")
        response.delete_cookie(VAULT_KEY_COOKIE, path="/")

    def _require_admin(request: Request, session: AuthenticatedSession) -> None:
        if session.system_role != "auditor_admin":
            append_audit_event(
                settings,
                action="PRIVILEGE_ESCALATION_ATTEMPT",
                outcome="DENIED",
                actor_user_id=session.user_id,
                actor_username=session.username,
                ip_address=_client_ip(request),
                details={"target_route": request.url.path, "system_role": session.system_role},
            )
            raise AccessDeniedError(
                "Administrator privileges required for security audit console.", status_code=403
            )

    def _is_probably_text(content: bytes, filename: str, mime: str) -> tuple[bool, str | None]:
        text_exts = {".txt", ".md", ".json", ".csv", ".log", ".xml", ".yaml", ".yml", ".py"}
        ext = Path(filename).suffix.lower()
        if mime.startswith("text/") or ext in text_exts:
            try:
                return True, content.decode("utf-8")
            except UnicodeDecodeError:
                return False, None
        return False, None

    # ------------------------------------------------------------------
    # HTML UI Routes
    # ------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def root_redirect(request: Request) -> Response:
        try:
            sess = _get_session(request)
            target = "/admin" if sess.system_role == "auditor_admin" else "/dashboard"
            return RedirectResponse(url=target, status_code=303)
        except AuthError:
            return RedirectResponse(url="/login", status_code=303)

    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request, msg: str | None = None, err: str | None = None) -> Response:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"session": None, "error": err, "info": msg, "username": ""},
        )

    @app.post("/login", response_class=HTMLResponse)
    def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ) -> Response:
        try:
            res = login_user(
                settings,
                key_store,
                username=username,
                password=password,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent", "browser"),
            )
            dest = "/admin" if res["user"]["system_role"] == "auditor_admin" else "/dashboard"
            resp = RedirectResponse(url=dest, status_code=303)
            _set_auth_cookies(resp, res)
            return resp
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "login.html",
                {"session": None, "error": exc.message, "info": None, "username": username},
                status_code=exc.status_code,
            )

    @app.get("/register", response_class=HTMLResponse)
    def register_page(request: Request) -> Response:
        return templates.TemplateResponse(
            request,
            "register.html",
            {"session": None, "error": None, "recovery_code": None, "registered_username": None},
        )

    @app.post("/register", response_class=HTMLResponse)
    def register_submit(
        request: Request,
        username: str = Form(...),
        email: str = Form(...),
        full_name: str = Form(...),
        password: str = Form(...),
    ) -> Response:
        try:
            res = register_user(
                settings,
                username=username,
                email=email,
                full_name=full_name,
                password=password,
                system_role="user",
                allow_admin_creation=False,
                ip_address=_client_ip(request),
            )
            return templates.TemplateResponse(
                request,
                "register.html",
                {
                    "session": None,
                    "error": None,
                    "recovery_code": res["recovery_code"],
                    "registered_username": res["username"],
                },
                status_code=201,
            )
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "register.html",
                {
                    "session": None,
                    "error": exc.message,
                    "recovery_code": None,
                    "registered_username": None,
                },
                status_code=exc.status_code,
            )

    @app.get("/recover", response_class=HTMLResponse)
    def recover_page(request: Request) -> Response:
        return templates.TemplateResponse(
            request,
            "recover.html",
            {"session": None, "error": None, "new_recovery_code": None},
        )

    @app.post("/recover", response_class=HTMLResponse)
    def recover_submit(
        request: Request,
        username: str = Form(...),
        recovery_code: str = Form(...),
        new_password: str = Form(...),
    ) -> Response:
        try:
            new_code = recover_user_password(
                settings,
                key_store,
                username=username,
                recovery_code=recovery_code,
                new_password=new_password,
                ip_address=_client_ip(request),
            )
            return templates.TemplateResponse(
                request,
                "recover.html",
                {"session": None, "error": None, "new_recovery_code": new_code},
            )
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "recover.html",
                {"session": None, "error": exc.message, "new_recovery_code": None},
                status_code=exc.status_code,
            )

    @app.post("/logout")
    def logout_submit(request: Request, csrf_token: str = Form(...)) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            logout_user(settings, key_store, request.cookies.get(SESSION_COOKIE), _client_ip(request))
        except ServiceError:
            logout_user(settings, key_store, request.cookies.get(SESSION_COOKIE), _client_ip(request))
        resp = RedirectResponse(url="/login?msg=Signed+out+and+session+keys+wiped", status_code=303)
        _clear_auth_cookies(resp)
        return resp

    @app.get("/dashboard", response_class=HTMLResponse)
    def dashboard_page(
        request: Request, msg: str | None = None, err: str | None = None
    ) -> Response:
        try:
            sess = _get_session(request)
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)

        docs = list_accessible_documents(settings, sess)
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {
                "session": sess,
                "documents": docs,
                "flash_msg": msg,
                "flash_err": err,
                "max_upload_mb": settings.max_upload_bytes // (1024 * 1024),
            },
        )

    @app.post("/documents/upload")
    async def upload_submit(
        request: Request,
        csrf_token: str = Form(...),
        title: str = Form(""),
        file: UploadFile = File(...),
    ) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            content = await file.read()
            res = upload_document(
                settings,
                sess,
                title=title,
                filename=file.filename or "document.bin",
                content=content,
                mime_type=file.content_type,
                ip_address=_client_ip(request),
            )
            return RedirectResponse(
                url=f"/documents/{res['doc_id']}?msg=Document+encrypted+with+AES-256-GCM+and+Ed25519+signed",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return RedirectResponse(url=f"/dashboard?err={quote_plus(exc.message)}", status_code=303)

    @app.get("/documents/{doc_id}", response_class=HTMLResponse)
    def document_detail_page(
        request: Request, doc_id: str, msg: str | None = None, err: str | None = None
    ) -> Response:
        try:
            sess = _get_session(request)
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)

        try:
            data = retrieve_document(
                settings, sess, doc_id, is_download=False, ip_address=_client_ip(request)
            )
        except IntegrityFailureError as exc:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "session": sess,
                    "status_code": exc.status_code,
                    "title": "Cryptographic Integrity Violation Detected",
                    "message": exc.message,
                    "doc_id": doc_id,
                },
                status_code=exc.status_code,
            )
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "session": sess,
                    "status_code": exc.status_code,
                    "title": "Access Denied" if exc.status_code == 403 else "Document Error",
                    "message": exc.message,
                    "doc_id": doc_id,
                },
                status_code=exc.status_code,
            )

        is_text, preview_text = _is_probably_text(
            data["plaintext"],
            data["doc"]["original_filename"],
            data["doc"]["mime_type"],
        )

        # Fetch active users for share dropdown if owner + owner document audit history
        share_candidates: list[str] = []
        doc_history: list[dict[str, Any]] = []
        if data["my_role"] == "owner":
            conn = get_connection(settings.db_path)
            try:
                rows = conn.execute(
                    "SELECT username FROM users WHERE id != ? AND is_active = 1 ORDER BY username",
                    (sess.user_id,),
                ).fetchall()
                share_candidates = [str(r["username"]) for r in rows]
            finally:
                conn.close()
            doc_history = get_document_audit_history(
                settings, sess, doc_id, ip_address=_client_ip(request)
            )

        return templates.TemplateResponse(
            request,
            "document_detail.html",
            {
                "session": sess,
                "doc": data["doc"],
                "owner_username": data["owner_username"],
                "signer_username": data["signer_username"],
                "my_role": data["my_role"],
                "is_text": is_text,
                "preview_text": preview_text,
                "shares": data["shares"],
                "share_candidates": share_candidates,
                "doc_history": doc_history,
                "verify_result": None,
                "flash_msg": msg,
                "flash_err": err,
            },
        )

    @app.post("/documents/{doc_id}/verify")
    def document_verify_submit(request: Request, doc_id: str, csrf_token: str = Form(...)) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            res = verify_document_integrity_status(
                settings, sess, doc_id, ip_address=_client_ip(request)
            )
            if res["verified"]:
                return RedirectResponse(
                    url=f"/documents/{doc_id}?msg=Live+Cryptographic+Check+PASSED:+Ciphertext+SHA-256+%26+Ed25519+Signature+Match",
                    status_code=303,
                )
            return RedirectResponse(
                url=f"/documents/{doc_id}?err=INTEGRITY+ALERT:+Ciphertext+hash+or+Ed25519+signature+mismatch!",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return RedirectResponse(url=f"/documents/{doc_id}?err={quote_plus(exc.message)}", status_code=303)

    @app.get("/profile", response_class=HTMLResponse)
    def profile_page(request: Request, msg: str | None = None, err: str | None = None) -> Response:
        try:
            sess = _get_session(request)
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)

        x25519_fp = hashlib.sha256(sess.x25519_pub_b64.encode("ascii")).hexdigest()
        ed25519_fp = hashlib.sha256(sess.ed25519_pub_b64.encode("ascii")).hexdigest()
        sessions = get_user_sessions(settings, sess)
        return templates.TemplateResponse(
            request,
            "profile.html",
            {
                "session": sess,
                "x25519_fp": x25519_fp,
                "ed25519_fp": ed25519_fp,
                "active_sessions": sessions,
                "flash_msg": msg,
                "flash_err": err,
            },
        )

    @app.post("/profile/revoke-other-sessions")
    def profile_revoke_others(request: Request, csrf_token: str = Form(...)) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            count = revoke_other_sessions(
                settings, key_store, sess, ip_address=_client_ip(request)
            )
            return RedirectResponse(
                url=f"/profile?msg=Revoked+{count}+other+active+session(s)+and+wiped+their+runtime+keys",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return RedirectResponse(url=f"/profile?err={quote_plus(exc.message)}", status_code=303)

    @app.get("/documents/{doc_id}/download")
    def document_download(request: Request, doc_id: str) -> Response:
        try:
            sess = _get_session(request)
            data = retrieve_document(
                settings, sess, doc_id, is_download=True, ip_address=_client_ip(request)
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "session": sess,
                    "status_code": exc.status_code,
                    "title": "Download Blocked",
                    "message": exc.message,
                    "doc_id": doc_id,
                },
                status_code=exc.status_code,
            )

        doc = data["doc"]
        return Response(
            content=data["plaintext"],
            media_type=doc["mime_type"],
            headers={
                "Content-Disposition": f'attachment; filename="{doc["original_filename"]}"',
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.post("/documents/{doc_id}/edit")
    async def document_edit_submit(
        request: Request,
        doc_id: str,
        csrf_token: str = Form(...),
        new_title: str = Form(""),
        new_text: str | None = Form(None),
        file: UploadFile | None = File(None),
    ) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            content_bytes = b""
            new_filename = None
            if file and file.filename:
                content_bytes = await file.read()
                new_filename = file.filename
            elif new_text is not None:
                content_bytes = new_text.encode("utf-8")

            res = update_document_content(
                settings,
                sess,
                doc_id,
                new_title=new_title or None,
                new_content=content_bytes,
                new_filename=new_filename,
                ip_address=_client_ip(request),
            )
            return RedirectResponse(
                url=f"/documents/{doc_id}?msg=Updated+to+version+{res['version']}+and+re-encrypted",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "session": sess,
                    "status_code": exc.status_code,
                    "title": "Edit Denied",
                    "message": exc.message,
                    "doc_id": doc_id,
                },
                status_code=exc.status_code,
            )

    @app.post("/documents/{doc_id}/share")
    def document_share_submit(
        request: Request,
        doc_id: str,
        csrf_token: str = Form(...),
        target_username: str = Form(...),
        role: str = Form(...),
        expires_in_hours: str = Form(""),
    ) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            exp_hours = int(expires_in_hours) if expires_in_hours.strip() else None
            res = share_document(
                settings,
                sess,
                doc_id,
                target_username=target_username,
                role=role,
                expires_in_hours=exp_hours,
                ip_address=_client_ip(request),
            )
            return RedirectResponse(
                url=f"/documents/{doc_id}?msg=DEK+wrapped+and+shared+with+{quote_plus(res['recipient_username'])}+as+{res['role']}",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return RedirectResponse(
                url=f"/documents/{doc_id}?err={quote_plus(exc.message)}", status_code=303
            )

    @app.post("/documents/{doc_id}/revoke")
    def document_revoke_submit(
        request: Request,
        doc_id: str,
        csrf_token: str = Form(...),
        target_user_id: str = Form(...),
    ) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            res = revoke_document_share(
                settings, sess, doc_id, target_user_id, ip_address=_client_ip(request)
            )
            return RedirectResponse(
                url=f"/documents/{doc_id}?msg=Revoked+{quote_plus(res['revoked_username'])}+and+rotated+DEK+to+v{res['new_version']}",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return RedirectResponse(
                url=f"/documents/{doc_id}?err={quote_plus(exc.message)}", status_code=303
            )

    @app.post("/documents/{doc_id}/delete")
    def document_delete_submit(
        request: Request,
        doc_id: str,
        csrf_token: str = Form(...),
    ) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, csrf_token)
            delete_document(settings, sess, doc_id, ip_address=_client_ip(request))
            return RedirectResponse(
                url="/dashboard?msg=Document+deleted+and+encrypted+blob+purged",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "session": sess,
                    "status_code": exc.status_code,
                    "title": "Deletion Denied",
                    "message": exc.message,
                    "doc_id": doc_id,
                },
                status_code=exc.status_code,
            )

    @app.get("/admin", response_class=HTMLResponse)
    def admin_console(request: Request, msg: str | None = None, err: str | None = None) -> Response:
        try:
            sess = _get_session(request)
            _require_admin(request, sess)
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except AccessDeniedError as exc:
            return templates.TemplateResponse(
                request,
                "error.html",
                {
                    "session": sess,
                    "status_code": 403,
                    "title": "Administrator Access Required",
                    "message": exc.message,
                    "doc_id": None,
                },
                status_code=403,
            )

        conn = get_connection(settings.db_path)
        try:
            users = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT id, username, email, full_name, system_role,
                           failed_attempts, locked_until, is_active, created_at
                    FROM users ORDER BY created_at DESC
                    """
                ).fetchall()
            ]
            docs_meta = [
                dict(r)
                for r in conn.execute(
                    """
                    SELECT d.id, d.title, u.username AS owner_username, d.current_version,
                           d.size_bytes, d.ciphertext_sha256, d.updated_at, d.is_deleted
                    FROM documents d JOIN users u ON u.id = d.owner_id
                    ORDER BY d.updated_at DESC
                    """
                ).fetchall()
            ]
            audit_rows = [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM audit_logs ORDER BY seq_no DESC LIMIT 100"
                ).fetchall()
            ]
        finally:
            conn.close()

        chain_status = verify_audit_chain(settings)
        suspicious = detect_suspicious_patterns(settings)

        return templates.TemplateResponse(
            request,
            "admin.html",
            {
                "session": sess,
                "users": users,
                "docs_meta": docs_meta,
                "audit_rows": audit_rows,
                "chain_status": chain_status,
                "suspicious": suspicious,
                "flash_msg": msg,
                "flash_err": err,
            },
        )

    @app.post("/admin/documents/{doc_id}/verify")
    def admin_verify_doc(
        request: Request, doc_id: str, csrf_token: str = Form(...)
    ) -> Response:
        try:
            sess = _get_session(request)
            _require_admin(request, sess)
            _verify_csrf(sess, csrf_token)
            res = verify_document_integrity_status(
                settings, sess, doc_id, ip_address=_client_ip(request)
            )
            if res["verified"]:
                return RedirectResponse(
                    url=f"/admin?msg=Document+{doc_id[:8]}+ciphertext+%26+Ed25519+signature+VERIFIED",
                    status_code=303,
                )
            return RedirectResponse(
                url=f"/admin?err=TAMPER+DETECTED+on+document+{doc_id[:8]}",
                status_code=303,
            )
        except AuthError as exc:
            return RedirectResponse(url=f"/login?err={quote_plus(exc.message)}", status_code=303)
        except ServiceError as exc:
            return RedirectResponse(url=f"/admin?err={quote_plus(exc.message)}", status_code=303)

    # ------------------------------------------------------------------
    # JSON API Routes (for programmatic & adversarial security tests)
    # ------------------------------------------------------------------
    @app.get("/api/health")
    def api_health() -> dict[str, str]:
        return {"status": "ok", "service": "VaultGuard SDMS"}

    @app.post("/api/auth/register")
    def api_register(request: Request, payload: RegisterPayload) -> JSONResponse:
        try:
            res = register_user(
                settings,
                username=payload.username,
                email=payload.email,
                full_name=payload.full_name,
                password=payload.password,
                system_role="user",
                allow_admin_creation=False,
                ip_address=_client_ip(request),
            )
            return JSONResponse(res, status_code=201)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.post("/api/auth/login")
    def api_login(request: Request, payload: LoginPayload) -> Response:
        try:
            res = login_user(
                settings,
                key_store,
                username=payload.username,
                password=payload.password,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent", "api-client"),
            )
            resp = JSONResponse(
                {"user": res["user"], "csrf_token": res["csrf_token"]}, status_code=200
            )
            _set_auth_cookies(resp, res)
            return resp
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.post("/api/auth/logout")
    def api_logout(request: Request) -> Response:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, request.headers.get("x-csrf-token"))
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)
        logout_user(settings, key_store, request.cookies.get(SESSION_COOKIE), _client_ip(request))
        resp = JSONResponse({"detail": "logged_out"}, status_code=200)
        _clear_auth_cookies(resp)
        return resp

    @app.get("/api/documents")
    def api_list_documents(request: Request) -> JSONResponse:
        try:
            sess = _get_session(request)
            return JSONResponse({"documents": list_accessible_documents(settings, sess)})
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.post("/api/documents")
    async def api_upload_document(
        request: Request,
        title: str = Form(""),
        file: UploadFile = File(...),
    ) -> JSONResponse:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, request.headers.get("x-csrf-token"))
            content = await file.read()
            res = upload_document(
                settings,
                sess,
                title=title,
                filename=file.filename or "upload.bin",
                content=content,
                mime_type=file.content_type,
                ip_address=_client_ip(request),
            )
            return JSONResponse(res, status_code=201)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.get("/api/documents/{doc_id}")
    def api_get_document(request: Request, doc_id: str) -> JSONResponse:
        try:
            sess = _get_session(request)
            data = retrieve_document(
                settings, sess, doc_id, is_download=False, ip_address=_client_ip(request)
            )
            is_text, preview = _is_probably_text(
                data["plaintext"],
                data["doc"]["original_filename"],
                data["doc"]["mime_type"],
            )
            return JSONResponse(
                {
                    "document": data["doc"],
                    "my_role": data["my_role"],
                    "is_text": is_text,
                    "content_text": preview,
                    "shares": data["shares"],
                }
            )
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.get("/api/documents/{doc_id}/verify")
    def api_verify_document(request: Request, doc_id: str) -> JSONResponse:
        try:
            sess = _get_session(request)
            res = verify_document_integrity_status(
                settings, sess, doc_id, ip_address=_client_ip(request)
            )
            return JSONResponse(res, status_code=200 if res["verified"] else 409)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.put("/api/documents/{doc_id}")
    def api_edit_document(
        request: Request, doc_id: str, payload: EditTextPayload
    ) -> JSONResponse:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, request.headers.get("x-csrf-token"))
            res = update_document_content(
                settings,
                sess,
                doc_id,
                new_title=payload.new_title,
                new_content=payload.new_text.encode("utf-8"),
                ip_address=_client_ip(request),
            )
            return JSONResponse(res)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.post("/api/documents/{doc_id}/share")
    def api_share_document(
        request: Request, doc_id: str, payload: SharePayload
    ) -> JSONResponse:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, request.headers.get("x-csrf-token"))
            res = share_document(
                settings,
                sess,
                doc_id,
                target_username=payload.target_username,
                role=payload.role,
                expires_in_hours=payload.expires_in_hours,
                ip_address=_client_ip(request),
            )
            return JSONResponse(res)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.post("/api/documents/{doc_id}/revoke")
    def api_revoke_document(
        request: Request, doc_id: str, payload: RevokePayload
    ) -> JSONResponse:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, request.headers.get("x-csrf-token"))
            res = revoke_document_share(
                settings, sess, doc_id, payload.target_user_id, ip_address=_client_ip(request)
            )
            return JSONResponse(res)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.delete("/api/documents/{doc_id}")
    def api_delete_document(request: Request, doc_id: str) -> JSONResponse:
        try:
            sess = _get_session(request)
            _verify_csrf(sess, request.headers.get("x-csrf-token"))
            delete_document(settings, sess, doc_id, ip_address=_client_ip(request))
            return JSONResponse({"detail": "deleted"})
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    @app.get("/api/admin/audit/verify")
    def api_admin_verify_audit(request: Request) -> JSONResponse:
        try:
            sess = _get_session(request)
            _require_admin(request, sess)
            report = verify_audit_chain(settings)
            return JSONResponse(report, status_code=200 if report["valid"] else 409)
        except ServiceError as exc:
            return JSONResponse({"detail": exc.message}, status_code=exc.status_code)

    return app


app = create_app()
