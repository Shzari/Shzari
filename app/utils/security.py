from __future__ import annotations

import hashlib
import os
import re
from base64 import urlsafe_b64decode, urlsafe_b64encode

from app.config import SECRET_KEY


def _hash_password(password: str, salt_hex: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), 200000
    ).hex()


def _crypto_key() -> bytes:
    return hashlib.sha256(SECRET_KEY.encode("utf-8")).digest()


def _keystream(length: int, nonce: bytes) -> bytes:
    key = _crypto_key()
    stream = b""
    counter = 0
    while len(stream) < length:
        stream += hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        counter += 1
    return stream[:length]


def encrypt_secret(value: str) -> str:
    if value == "":
        return ""
    raw = value.encode("utf-8")
    nonce = os.urandom(16)
    cipher = bytes(a ^ b for a, b in zip(raw, _keystream(len(raw), nonce)))
    return f"enc:v1:{urlsafe_b64encode(nonce).decode('ascii')}:{urlsafe_b64encode(cipher).decode('ascii')}"


def decrypt_secret(value: str) -> str:
    text = str(value or "")
    if not text.startswith("enc:v1:"):
        return text
    parts = text.split(":", 3)
    if len(parts) != 4:
        return ""
    try:
        nonce = urlsafe_b64decode(parts[2].encode("ascii"))
        cipher = urlsafe_b64decode(parts[3].encode("ascii"))
    except Exception:
        return ""
    plain = bytes(a ^ b for a, b in zip(cipher, _keystream(len(cipher), nonce)))
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def is_valid_ipv4(value: str) -> bool:
    text = str(value or "").strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", text):
        return False
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if len(part) == 0 or len(part) > 3:
            return False
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True
