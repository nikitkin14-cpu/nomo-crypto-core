"""
Nomo Messenger — Ed25519 Authentication Module

This module provides:
- Generation of Ed25519 key pairs
- Signing and verification of messages
- Key serialization (PEM format)

No phone number. No email. No password. Your key IS your identity.
"""

import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend


def generate_key_pair():
    """
    Generate a new Ed25519 key pair.

    Returns:
        tuple: (private_key_pem, public_key_pem) — both as strings in PEM format.
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


def sign_message(private_key_pem: str, message: bytes) -> str:
    """
    Sign a message using the private key.

    Args:
        private_key_pem: Private key in PEM format.
        message: Message to sign (bytes).

    Returns:
        str: Base64-encoded signature.
    """
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    signature = private_key.sign(message)
    return base64.b64encode(signature).decode('utf-8')


def verify_signature(public_key_pem: str, message: bytes, signature_b64: str) -> bool:
    """
    Verify a message signature using the public key.

    Args:
        public_key_pem: Public key in PEM format.
        message: Original message (bytes).
        signature_b64: Base64-encoded signature.

    Returns:
        bool: True if signature is valid, False otherwise.
    """
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


def get_public_key_fingerprint(public_key_pem: str) -> str:
    """
    Generate a human-readable fingerprint from a public key.

    Args:
        public_key_pem: Public key in PEM format.

    Returns:
        str: First 16 characters of SHA256 fingerprint.
    """
    import hashlib
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return hashlib.sha256(key_bytes).hexdigest()[:16]
