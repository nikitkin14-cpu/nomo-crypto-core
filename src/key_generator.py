"""
Генератор случайных ключей для Nomo Messenger.
Использует secrets (Python stdlib) для криптографически безопасной генерации.
"""

import secrets


def generate_random_key(length: int = 32) -> bytes:
    """Генерирует криптографически безопасный случайный ключ.
    
    Args:
        length: длина ключа в байтах (по умолчанию 32)
    
    Returns:
        случайный ключ
    """
    return secrets.token_bytes(length)


def generate_key_from_seed(seed: bytes, length: int = 32) -> bytes:
    """Детерминированно генерирует ключ из seed.
    
    Args:
        seed: исходный seed
        length: длина выходного ключа
    
    Returns:
        ключ, сгенерированный из seed
    """
    import hashlib
    return hashlib.sha256(seed).digest()[:length]


def generate_prekeys(count: int = 100) -> list[bytes]:
    """Генерирует пул одноразовых pre-ключей для X3DH.
    
    Args:
        count: количество ключей
    
    Returns:
        список случайных ключей по 32 байта
    """
    return [generate_random_key(32) for _ in range(count)]


def generate_signed_prekey_seed() -> bytes:
    """Генерирует seed для подписанного pre-ключа."""
    return generate_random_key(32)
