from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time

from sqlalchemy.orm import Session

from app.config import Settings
from app.models.user import User, UserRole

TOKEN_LIFETIME_SECONDS = 8 * 60 * 60
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_SALT_BYTES = 16
_SCRYPT_KEY_BYTES = 32


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_SCRYPT_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_KEY_BYTES,
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, n, r, p, salt_text, digest_text = encoded.split("$")
        if algorithm != "scrypt":
            return False
        expected = _unb64(digest_text)
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=_unb64(salt_text),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


def issue_access_token(username: str, secret_key: str) -> str:
    if len(secret_key) < 32:
        raise ValueError("AUTH_SECRET_KEY must contain at least 32 characters")
    now = int(time.time())
    payload = _b64(
        json.dumps(
            {"sub": username, "iat": now, "exp": now + TOKEN_LIFETIME_SECONDS},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    signed = f"v1.{payload}"
    signature = hmac.new(secret_key.encode("utf-8"), signed.encode("ascii"), hashlib.sha256)
    return f"{signed}.{_b64(signature.digest())}"


def verify_access_token(token: str, secret_key: str) -> str | None:
    if len(secret_key) < 32:
        return None
    try:
        version, payload, signature_text = token.split(".")
        if version != "v1":
            return None
        signed = f"{version}.{payload}"
        expected = hmac.new(
            secret_key.encode("utf-8"), signed.encode("ascii"), hashlib.sha256
        ).digest()
        if not hmac.compare_digest(expected, _unb64(signature_text)):
            return None
        claims = json.loads(_unb64(payload))
        username = claims["sub"]
        if not isinstance(username, str) or int(claims["exp"]) <= int(time.time()):
            return None
        return username
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def ensure_bootstrap_admin(db: Session, settings: Settings) -> None:
    username = settings.auth_admin_username.strip()
    password = settings.auth_admin_password
    if not username or not password:
        if settings.environment.lower() in {"production", "prod"}:
            raise RuntimeError(
                "AUTH_ADMIN_USERNAME and AUTH_ADMIN_PASSWORD must be configured in production"
            )
        return
    if len(password) < 12:
        raise RuntimeError("AUTH_ADMIN_PASSWORD must contain at least 12 characters")
    if len(settings.auth_secret_key) < 32:
        raise RuntimeError("AUTH_SECRET_KEY must contain at least 32 characters")

    existing = db.query(User).filter(User.username == username).first()
    if existing is not None:
        return
    db.add(
        User(
            username=username,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
            is_active=True,
        )
    )
    db.commit()


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
