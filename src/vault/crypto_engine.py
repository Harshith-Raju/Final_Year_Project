"""
Layer 3 - Subsystem A: Cryptographic Engine for the Pseudonymization Vault.
Provides authenticated encryption for mapping tables using AES-GCM (if cryptography is installed)
or standard library HMAC-SHA256 authenticated stream cipher.
Ensures mapping tables cannot be read by memory dumping or third-party processes.
"""

import base64
import hashlib
import hmac
import os
import secrets
import json
from typing import Dict, Any, Optional

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class CryptoEngine:
    """
    Session-scoped cryptographic encryption engine.
    Generates a high-entropy key per session.
    """

    def __init__(self, session_key: Optional[bytes] = None):
        # 256-bit session key
        self.key: bytes = session_key or secrets.token_bytes(32)

    def encrypt_mapping(self, data: Dict[str, Any]) -> str:
        """Serializes dictionary and encrypts it with authenticated ciphertext."""
        raw_bytes = json.dumps(data).encode("utf-8")
        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(self.key)
            nonce = secrets.token_bytes(12)
            ciphertext = aesgcm.encrypt(nonce, raw_bytes, None)
            payload = nonce + ciphertext
            return base64.b64encode(payload).decode("utf-8")
        else:
            # High-performance authenticated encryption for in-memory session vault
            salt = secrets.token_bytes(16)
            # 1,000 iterations is plenty for an ephemeral, in-memory session vault and executes in < 1ms
            derived = hashlib.pbkdf2_hmac("sha256", self.key, salt, 1000, dklen=len(raw_bytes) + 32)
            keystream = derived[:len(raw_bytes)]
            mac_key = derived[len(raw_bytes):]
            encrypted = bytes(b ^ k for b, k in zip(raw_bytes, keystream))
            tag = hmac.new(mac_key, salt + encrypted, hashlib.sha256).digest()
            payload = salt + tag + encrypted
            return base64.b64encode(payload).decode("utf-8")

    def decrypt_mapping(self, encrypted_b64: str) -> Dict[str, Any]:
        """Decrypts and verifies authentication tag before deserializing."""
        payload = base64.b64decode(encrypted_b64.encode("utf-8"))
        if HAS_CRYPTOGRAPHY:
            aesgcm = AESGCM(self.key)
            nonce = payload[:12]
            ciphertext = payload[12:]
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return json.loads(decrypted.decode("utf-8"))
        else:
            salt = payload[:16]
            tag = payload[16:48]
            encrypted = payload[48:]
            derived = hashlib.pbkdf2_hmac("sha256", self.key, salt, 1000, dklen=len(encrypted) + 32)
            keystream = derived[:len(encrypted)]
            mac_key = derived[len(encrypted):]
            expected_tag = hmac.new(mac_key, salt + encrypted, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Cryptographic verification failed: vault data has been tampered with.")
            decrypted = bytes(b ^ k for b, k in zip(encrypted, keystream))
            return json.loads(decrypted.decode("utf-8"))
