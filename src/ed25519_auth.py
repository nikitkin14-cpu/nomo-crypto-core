"""
Ed25519 аутентификация для Nomo Messenger.
Генерация ключей, подпись, проверка, отпечаток.
"""

import hashlib
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)


def generate_keypair() -> tuple[str, str]:
    """Генерирует пару ключей Ed25519.
    
    Returns:
        (private_pem, public_pem) — ключи в PEM-формате
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


def sign_message(private_pem: str, message: bytes) -> bytes:
    """Подписывает сообщение приватным ключом.
    
    Args:
        private_pem: приватный ключ в PEM
        message: сообщение для подписи
    
    Returns:
        подпись (64 байта)
    """
    private_key = Ed25519PrivateKey.from_private_bytes(
        _pem_to_raw_private(private_pem)
    )
    return private_key.sign(message)


def verify_signature(public_pem: str, message: bytes, signature: bytes) -> bool:
    """Проверяет подпись сообщения.
    
    Args:
        public_pem: публичный ключ в PEM
        message: исходное сообщение
        signature: подпись для проверки
    
    Returns:
        True если подпись валидна
    """
    try:
        public_key = Ed25519PublicKey.from_public_bytes(
            _pem_to_raw_public(public_pem)
        )
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def get_key_fingerprint(public_pem: str) -> str:
    """Возвращает отпечаток публичного ключа.
    
    Args:
        public_pem: публичный ключ в PEM
    
    Returns:
        первые 16 символов SHA256 хеша ключа
    """
    raw = _pem_to_raw_public(public_pem)
    return hashlib.sha256(raw).hexdigest()[:16]


def get_public_key_base64(public_pem: str) -> str:
    """Возвращает публичный ключ в base64 (32 байта)."""
    raw = _pem_to_raw_public(public_pem)
    return base64.b64encode(raw).decode('utf-8')


def get_private_key_base64(private_pem: str) -> str:
    """Возвращает приватный ключ в base64 (32 байта)."""
    raw = _pem_to_raw_private(private_pem)
    return base64.b64encode(raw).decode('utf-8')


def _pem_to_raw_private(pem: str) -> bytes:
    """Извлекает сырые байты приватного ключа из PEM."""
    key = serialization.load_pem_private_key(
        pem.encode('utf-8'), password=None
    )
    return key.private_bytes_raw()


def _pem_to_raw_public(pem: str) -> bytes:
    """Извлекает сырые байты публичного ключа из PEM."""
    key = serialization.load_pem_public_key(
        pem.encode('utf-8')
    )
    return key.public_bytes_raw()
