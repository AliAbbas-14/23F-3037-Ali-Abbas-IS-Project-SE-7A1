"""Established cryptographic primitives wrapper using PyCA cryptography and argon2-cffi.

No cryptographic algorithm is implemented from scratch; all primitives delegate to
audited libraries (OpenSSL via PyCA cryptography, Argon2 via argon2-cffi, and Python
stdlib hashlib/hmac/secrets).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
from dataclasses import dataclass

from argon2 import PasswordHasher, low_level
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BLOB_MAGIC = b"VGSD1"

_PASSWORD_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


class CryptoIntegrityError(Exception):
    """Raised when authenticated decryption, signature, or hash verification fails."""


class CryptoKeyError(Exception):
    """Raised when user key unlocking or DEK unwrapping fails."""


@dataclass
class UnlockedKeyBundle:
    """In-memory unlocked asymmetric keys for an authenticated user session."""

    x25519_sk: x25519.X25519PrivateKey
    ed25519_sk: ed25519.Ed25519PrivateKey

    def serialize(self) -> bytes:
        payload = {
            "x25519": base64.b64encode(
                self.x25519_sk.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ).decode("ascii"),
            "ed25519": base64.b64encode(
                self.ed25519_sk.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ).decode("ascii"),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    @classmethod
    def deserialize(cls, raw: bytes) -> "UnlockedKeyBundle":
        data = json.loads(raw.decode("utf-8"))
        return cls(
            x25519_sk=x25519.X25519PrivateKey.from_private_bytes(
                base64.b64decode(data["x25519"])
            ),
            ed25519_sk=ed25519.Ed25519PrivateKey.from_private_bytes(
                base64.b64decode(data["ed25519"])
            ),
        )


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def hash_password(password: str) -> str:
    """Hash a password with Argon2id (salted, memory-hard)."""
    return _PASSWORD_HASHER.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify an Argon2id password hash safely."""
    try:
        return _PASSWORD_HASHER.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def derive_kek_from_password(password: str, kdf_salt: bytes) -> bytes:
    """Derive a 256-bit Key Encryption Key from user password via Argon2id."""
    return low_level.hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=kdf_salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=low_level.Type.ID,
    )


def derive_kek_from_recovery_code(recovery_code: str, kdf_salt: bytes) -> bytes:
    """Derive a 256-bit recovery KEK from a high-entropy recovery code via HKDF-SHA256."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=kdf_salt,
        info=b"vaultguard-recovery-kek-v1",
    ).derive(recovery_code.strip().encode("utf-8"))


def generate_recovery_code() -> str:
    """Generate a high-entropy formatted recovery code shown once at signup."""
    raw = secrets.token_hex(16).upper()
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def hash_token(raw_token: str) -> str:
    """SHA-256 digest for storing session/recovery tokens without raw secrets at rest."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def hmac_sha256_hex(key: bytes, message: str) -> str:
    """Compute hex HMAC-SHA256 tag."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_user_keypairs() -> tuple[UnlockedKeyBundle, str, str]:
    """Generate fresh X25519 (encryption wrap) and Ed25519 (signing) key pairs."""
    x_sk = x25519.X25519PrivateKey.generate()
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    x_pub = b64e(
        x_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    ed_pub = b64e(
        ed_sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    return UnlockedKeyBundle(x25519_sk=x_sk, ed25519_sk=ed_sk), x_pub, ed_pub


def encrypt_key_bundle(bundle: UnlockedKeyBundle, kek: bytes, user_id: str, purpose: str) -> str:
    """Encrypt user private keys using AES-256-GCM with AAD bound to user_id and purpose."""
    nonce = os.urandom(12)
    aad = f"vaultguard-keybundle|{user_id}|{purpose}".encode("utf-8")
    ct = AESGCM(kek).encrypt(nonce, bundle.serialize(), aad)
    return json.dumps({"v": 1, "nonce": b64e(nonce), "ct": b64e(ct)}, separators=(",", ":"))


def decrypt_key_bundle(enc_json: str, kek: bytes, user_id: str, purpose: str) -> UnlockedKeyBundle:
    """Decrypt user private keys using AES-256-GCM; fails closed on wrong key/tamper."""
    try:
        obj = json.loads(enc_json)
        nonce = b64d(obj["nonce"])
        ct = b64d(obj["ct"])
        aad = f"vaultguard-keybundle|{user_id}|{purpose}".encode("utf-8")
        raw = AESGCM(kek).decrypt(nonce, ct, aad)
        return UnlockedKeyBundle.deserialize(raw)
    except (KeyError, ValueError, InvalidTag) as exc:
        raise CryptoKeyError("Failed to unlock private key bundle.") from exc


def wrap_runtime_bundle(bundle: UnlockedKeyBundle, session_key: bytes, session_hash: str) -> bytes:
    """Encrypt unlocked session keys in ephemeral server memory under cookie-held secret."""
    nonce = os.urandom(12)
    aad = f"vaultguard-runtime|{session_hash}".encode("utf-8")
    return nonce + AESGCM(session_key).encrypt(nonce, bundle.serialize(), aad)


def unwrap_runtime_bundle(wrapped: bytes, session_key: bytes, session_hash: str) -> UnlockedKeyBundle:
    """Unwrap ephemeral session private keys using cookie-held secret."""
    if len(wrapped) < 28:
        raise CryptoKeyError("Corrupted runtime session vault.")
    try:
        nonce, ct = wrapped[:12], wrapped[12:]
        aad = f"vaultguard-runtime|{session_hash}".encode("utf-8")
        raw = AESGCM(session_key).decrypt(nonce, ct, aad)
        return UnlockedKeyBundle.deserialize(raw)
    except (InvalidTag, ValueError) as exc:
        raise CryptoKeyError("Session vault key mismatch or expired.") from exc


def generate_dek() -> bytes:
    """Generate a random 256-bit Data Encryption Key (DEK)."""
    return os.urandom(32)


def encrypt_document_blob(
    plaintext: bytes,
    dek: bytes,
    doc_id: str,
    version: int,
    owner_id: str,
) -> tuple[bytes, str, str]:
    """Encrypt document bytes with AES-256-GCM and bind metadata via AAD.

    Returns (blob_bytes, plaintext_sha256_hex, ciphertext_sha256_hex).
    """
    plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()
    nonce = os.urandom(12)
    aad = f"{doc_id}|v{version}|{owner_id}|{plaintext_sha256}".encode("utf-8")
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    blob_bytes = BLOB_MAGIC + nonce + ciphertext
    ciphertext_sha256 = hashlib.sha256(blob_bytes).hexdigest()
    return blob_bytes, plaintext_sha256, ciphertext_sha256


def decrypt_document_blob(
    blob_bytes: bytes,
    dek: bytes,
    doc_id: str,
    version: int,
    owner_id: str,
    expected_plaintext_sha256: str,
) -> bytes:
    """Decrypt and authenticate document blob; fails closed on any tamper."""
    if not blob_bytes.startswith(BLOB_MAGIC) or len(blob_bytes) < len(BLOB_MAGIC) + 12 + 16:
        raise CryptoIntegrityError("Encrypted blob header or length is invalid.")
    nonce = blob_bytes[len(BLOB_MAGIC) : len(BLOB_MAGIC) + 12]
    ciphertext = blob_bytes[len(BLOB_MAGIC) + 12 :]
    aad = f"{doc_id}|v{version}|{owner_id}|{expected_plaintext_sha256}".encode("utf-8")
    try:
        plaintext = AESGCM(dek).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise CryptoIntegrityError("AES-256-GCM authentication tag verification failed.") from exc

    actual_sha256 = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_plaintext_sha256):
        raise CryptoIntegrityError("Decrypted plaintext SHA-256 checksum mismatch.")
    return plaintext


def wrap_dek_for_user(
    dek: bytes,
    recipient_x25519_pub_b64: str,
    doc_id: str,
    version: int,
    recipient_user_id: str,
) -> str:
    """Wrap a 256-bit DEK for a specific recipient using ephemeral X25519 + HKDF-SHA256 + AES-GCM."""
    recipient_pk = x25519.X25519PublicKey.from_public_bytes(b64d(recipient_x25519_pub_b64))
    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pub_raw = eph_sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    shared = eph_sk.exchange(recipient_pk)
    context = f"vaultguard-dek-wrap-v1|{doc_id}|v{version}|{recipient_user_id}".encode("utf-8")
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context,
    ).derive(shared)

    nonce = os.urandom(12)
    aad = f"{doc_id}|v{version}|{recipient_user_id}".encode("utf-8")
    ct = AESGCM(wrap_key).encrypt(nonce, dek, aad)
    return json.dumps(
        {
            "v": 1,
            "eph_pub": b64e(eph_pub_raw),
            "nonce": b64e(nonce),
            "ct": b64e(ct),
        },
        separators=(",", ":"),
    )


def unwrap_dek_for_user(
    wrapped_json: str,
    recipient_x25519_sk: x25519.X25519PrivateKey,
    doc_id: str,
    version: int,
    recipient_user_id: str,
) -> bytes:
    """Unwrap a recipient's DEK using their unlocked X25519 private key."""
    try:
        data = json.loads(wrapped_json)
        eph_pk = x25519.X25519PublicKey.from_public_bytes(b64d(data["eph_pub"]))
        nonce = b64d(data["nonce"])
        ct = b64d(data["ct"])
        shared = recipient_x25519_sk.exchange(eph_pk)
        context = f"vaultguard-dek-wrap-v1|{doc_id}|v{version}|{recipient_user_id}".encode("utf-8")
        wrap_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context,
        ).derive(shared)
        aad = f"{doc_id}|v{version}|{recipient_user_id}".encode("utf-8")
        return AESGCM(wrap_key).decrypt(nonce, ct, aad)
    except (KeyError, ValueError, InvalidTag) as exc:
        raise CryptoKeyError("Unable to unwrap document encryption key.") from exc


def sign_document_manifest(
    ed25519_sk: ed25519.Ed25519PrivateKey,
    doc_id: str,
    version: int,
    owner_id: str,
    plaintext_sha256: str,
    ciphertext_sha256: str,
) -> str:
    """Create an Ed25519 signature over document identity, version, and cryptographic hashes."""
    manifest = f"VG-MANIFEST-V1|{doc_id}|v{version}|{owner_id}|{plaintext_sha256}|{ciphertext_sha256}".encode(
        "utf-8"
    )
    return b64e(ed25519_sk.sign(manifest))


def verify_document_manifest(
    ed25519_pub_b64: str,
    signature_b64: str,
    doc_id: str,
    version: int,
    owner_id: str,
    plaintext_sha256: str,
    ciphertext_sha256: str,
) -> bool:
    """Verify Ed25519 signature over document manifest."""
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(b64d(ed25519_pub_b64))
        manifest = f"VG-MANIFEST-V1|{doc_id}|v{version}|{owner_id}|{plaintext_sha256}|{ciphertext_sha256}".encode(
            "utf-8"
        )
        pub.verify(b64d(signature_b64), manifest)
        return True
    except (ValueError, InvalidSignature):
        return False
