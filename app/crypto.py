"""
SENTINEL Security Module - Authenticated Encryption at Rest for Sensitive Integrations
Implements authenticated encryption (AES-128-CBC + HMAC-SHA256 via Fernet / Cryptography)
for webhook URLs, tokens, and third-party integration secrets.
Keys are strictly stored outside SQLite and excluded from Git.
"""
import os
import base64
import logging
from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from app.config import settings

logger = logging.getLogger(__name__)

KEY_FILE_NAME = ".webhook_encryption.key"

def get_encryption_key() -> bytes:
    """
    Retrieves or derives the authenticated Fernet encryption key.
    Key hierarchy:
    1. Environment variable WEBHOOK_ENCRYPTION_KEY (highest priority).
    2. Secure key file (.webhook_encryption.key on disk, strictly gitignored).
    3. HKDF derivation from settings.SECRET_KEY with domain-separated salt.
    """
    # 1. Environment variable
    env_key = os.environ.get("WEBHOOK_ENCRYPTION_KEY", "").strip()
    if env_key:
        try:
            Fernet(env_key.encode("utf-8"))
            return env_key.encode("utf-8")
        except Exception:
            pass

    # 2. Local key file
    if os.path.exists(KEY_FILE_NAME):
        try:
            with open(KEY_FILE_NAME, "rb") as f:
                f_key = f.read().strip()
                if f_key:
                    Fernet(f_key)
                    return f_key
        except Exception:
            pass

    # 3. Deterministic HKDF derivation from operator-configured SECRET_KEY
    # Provides authenticated encryption at rest without storing raw symmetric keys in SQLite or Git
    secret_material = getattr(settings, "SECRET_KEY", "sentinel-soc-default-secret-seed").encode("utf-8")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"sentinel-webhook-at-rest-v1",
        info=b"webhook-fernet-encryption-key",
    )
    derived_bytes = hkdf.derive(secret_material)
    fernet_key = base64.urlsafe_b64encode(derived_bytes)
    return fernet_key

def encrypt_webhook_url(url: str) -> str:
    """
    Encrypts a sensitive webhook URL at rest.
    Returns ciphertext prefixed with 'enc:'.
    """
    if not url:
        return ""
    clean = url.strip()
    try:
        key = get_encryption_key()
        f = Fernet(key)
        encrypted_bytes = f.encrypt(clean.encode("utf-8"))
        return f"enc:{encrypted_bytes.decode('utf-8')}"
    except Exception as e:
        logger.error("Failed to encrypt webhook secret at rest")
        return ""

def decrypt_webhook_url(token_or_url: str) -> str:
    """
    Decrypts an encrypted webhook URL token.
    Gracefully handles existing plaintext URLs for backwards-compatible migration.
    """
    if not token_or_url:
        return ""
    val = token_or_url.strip()
    
    # Safe migration: if not encrypted, return existing legacy URL
    if not val.startswith("enc:"):
        return val

    ciphertext = val[4:]
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted_bytes = f.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except InvalidToken:
        logger.error("Decryption failed: Token is invalid or encryption key has changed.")
        return ""
    except Exception:
        logger.error("Decryption error occurred.")
        return ""

def get_active_webhook_url() -> str:
    """
    Retrieves and decrypts the currently active webhook URL.
    Supports:
    1. Encrypted string in settings.ALERT_WEBHOOK_URL_ENCRYPTED or env var
    2. Legacy or encrypted string in settings.ALERT_WEBHOOK_URL or env var
    """
    enc_val = (getattr(settings, "ALERT_WEBHOOK_URL_ENCRYPTED", "") or os.environ.get("ALERT_WEBHOOK_URL_ENCRYPTED", "")).strip()
    if enc_val:
        decrypted = decrypt_webhook_url(enc_val)
        if decrypted:
            return decrypted

    val = (getattr(settings, "ALERT_WEBHOOK_URL", "") or os.environ.get("ALERT_WEBHOOK_URL", "")).strip()
    if val:
        return decrypt_webhook_url(val)

    return ""


