"""
E2E-шифрование Nomo Messenger.
X3DH (Extended Triple Diffie-Hellman) + Double Ratchet.
"""

import hashlib
import hmac
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ─── Утилиты ───────────────────────────────────────────

def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-деривация ключа."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(ikm)


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac.new(key, data, hashlib.sha256).digest()


def _aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes, bytes]:
    """AES-256-GCM шифрование.
    
    Returns:
        (iv, ciphertext, tag)
    """
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag


def _aes_gcm_decrypt(key: bytes, iv: bytes, ciphertext: bytes, tag: bytes, associated_data: bytes = b"") -> bytes:
    """AES-256-GCM расшифрование."""
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()


# ─── X3DH ──────────────────────────────────────────────

def generate_x3dh_bundle(identity_key: bytes, signed_prekey: bytes, one_time_prekeys: list[bytes]) -> dict:
    """Генерирует PreKey Bundle для X3DH."""
    return {
        "identity_key": identity_key,
        "signed_prekey": signed_prekey,
        "one_time_prekey": one_time_prekeys[0] if one_time_prekeys else None,
    }


def initiate_x3dh(sender_identity_priv: bytes, sender_ephemeral_priv: bytes,
                  recipient_identity_pub: bytes, recipient_signed_prekey: bytes,
                  recipient_one_time_prekey: bytes | None = None) -> bytes:
    """Инициация X3DH со стороны отправителя.
    
    Returns:
        shared_secret (32 байта)
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    
    # Преобразуем Ed25519 ключи в X25519 (упрощение: используем первые 32 байта)
    sender_identity_x25519 = X25519PrivateKey.from_private_bytes(sender_identity_priv[:32])
    sender_ephemeral_x25519 = X25519PrivateKey.from_private_bytes(sender_ephemeral_priv[:32])
    
    # DH1: sender_identity * recipient_signed_prekey
    dh1 = sender_identity_x25519.exchange(
        X25519PublicKey.from_public_bytes(recipient_signed_prekey[:32])
    )
    
    # DH2: sender_ephemeral * recipient_identity
    dh2 = sender_ephemeral_x25519.exchange(
        X25519PublicKey.from_public_bytes(recipient_identity_pub[:32])
    )
    
    # DH3: sender_ephemeral * recipient_signed_prekey
    dh3 = sender_ephemeral_x25519.exchange(
        X25519PublicKey.from_public_bytes(recipient_signed_prekey[:32])
    )
    
    # DH4: sender_ephemeral * recipient_one_time_prekey (опционально)
    dh4 = b""
    if recipient_one_time_prekey:
        dh4 = sender_ephemeral_x25519.exchange(
            X25519PublicKey.from_public_bytes(recipient_one_time_prekey[:32])
        )
    
    # Общий секрет: HKDF(DH1 || DH2 || DH3 || DH4)
    combined = dh1 + dh2 + dh3 + dh4
    return _hkdf(combined, salt=b"nomo-x3dh-v1", info=b"shared-secret")


def process_x3dh_initiation(recipient_identity_priv: bytes, recipient_signed_prekey_priv: bytes,
                            recipient_one_time_prekey_priv: bytes | None,
                            sender_identity_pub: bytes, sender_ephemeral_pub: bytes) -> bytes:
    """Обработка X3DH инициации со стороны получателя.
    
    Returns:
        shared_secret (32 байта)
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    
    recipient_identity_x25519 = X25519PrivateKey.from_private_bytes(recipient_identity_priv[:32])
    recipient_signed_prekey_x25519 = X25519PrivateKey.from_private_bytes(recipient_signed_prekey_priv[:32])
    
    # DH1: recipient_signed_prekey * sender_identity
    dh1 = recipient_signed_prekey_x25519.exchange(
        X25519PublicKey.from_public_bytes(sender_identity_pub[:32])
    )
    
    # DH2: recipient_identity * sender_ephemeral
    dh2 = recipient_identity_x25519.exchange(
        X25519PublicKey.from_public_bytes(sender_ephemeral_pub[:32])
    )
    
    # DH3: recipient_signed_prekey * sender_ephemeral
    dh3 = recipient_signed_prekey_x25519.exchange(
        X25519PublicKey.from_public_bytes(sender_ephemeral_pub[:32])
    )
    
    # DH4: recipient_one_time_prekey * sender_ephemeral (опционально)
    dh4 = b""
    if recipient_one_time_prekey_priv:
        recipient_one_time_x25519 = X25519PrivateKey.from_private_bytes(recipient_one_time_prekey_priv[:32])
        dh4 = recipient_one_time_x25519.exchange(
            X25519PublicKey.from_public_bytes(sender_ephemeral_pub[:32])
        )
    
    combined = dh1 + dh2 + dh3 + dh4
    return _hkdf(combined, salt=b"nomo-x3dh-v1", info=b"shared-secret")


# ─── Double Ratchet ────────────────────────────────────

class RatchetState:
    """Состояние Double Ratchet для одного направления."""
    
    def __init__(self, shared_secret: bytes):
        # Root Key и Chain Key
        self.root_key = _hkdf(shared_secret, salt=b"nomo-ratchet-v1", info=b"root-key")
        self.sending_chain_key = _hkdf(self.root_key, salt=b"", info=b"sending-chain")
        self.receiving_chain_key = None
        
        # Ключи DH
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        self.dh_private = X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        self.remote_dh_public = None
        
        # Номера сообщений и пропущенные ключи
        self.sent_count = 0
        self.received_count = 0
        self.skipped_keys: dict[int, bytes] = {}
    
    def encrypt(self, plaintext: bytes) -> dict:
        """Зашифровать сообщение.
        
        Returns:
            dict с 'ciphertext', 'iv', 'tag', 'dh_public', 'message_number'
        """
        # Message Key из Chain Key
        message_key = _hmac_sha256(self.sending_chain_key, b"message-key")
        self.sending_chain_key = _hmac_sha256(self.sending_chain_key, b"chain-key")
        
        iv, ciphertext, tag = _aes_gcm_encrypt(message_key, plaintext)
        self.sent_count += 1
        
        return {
            "ciphertext": ciphertext,
            "iv": iv,
            "tag": tag,
            "dh_public": self.dh_public.public_bytes_raw(),
            "message_number": self.sent_count - 1,
        }
    
    def decrypt(self, message: dict) -> bytes:
        """Расшифровать сообщение.
        
        Args:
            message: dict с 'ciphertext', 'iv', 'tag', 'dh_public', 'message_number'
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        
        # Если новый DH-ключ от отправителя — делаем ratchet-шаг
        if message["dh_public"] != self.remote_dh_public:
            self._ratchet_step(message["dh_public"])
        
        # Получаем Message Key
        message_key = self._get_message_key(message["message_number"])
        
        return _aes_gcm_decrypt(
            message_key, message["iv"], message["ciphertext"], message["tag"]
        )
    
    def _ratchet_step(self, remote_dh_bytes: bytes):
        """Выполнить ratchet-шаг при получении нового DH-ключа."""
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
        
        remote_dh = X25519PublicKey.from_public_bytes(remote_dh_bytes)
        dh_output = self.dh_private.exchange(remote_dh)
        
        # Новый Root Key и Chain Key
        self.root_key = _hkdf(dh_output, salt=self.root_key, info=b"ratchet-step")
        self.receiving_chain_key = _hkdf(self.root_key, salt=b"", info=b"receiving-chain")
        
        # Генерируем новую пару DH
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        self.dh_private = X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key()
        
        # Новый Root Key для отправки
        dh_output2 = self.dh_private.exchange(remote_dh)
        self.root_key = _hkdf(dh_output2, salt=self.root_key, info=b"ratchet-step-2")
        self.sending_chain_key = _hkdf(self.root_key, salt=b"", info=b"sending-chain")
        
        self.remote_dh_public = remote_dh_bytes
        self.received_count = 0
    
    def _get_message_key(self, message_number: int) -> bytes:
        """Получить Message Key для расшифровки (с учётом пропущенных)."""
        # Промотать цепочку до нужного номера
        while self.received_count < message_number:
            skipped_key = _hmac_sha256(self.receiving_chain_key, b"message-key")
            self.skipped_keys[self.received_count] = skipped_key
            self.receiving_chain_key = _hmac_sha256(self.receiving_chain_key, b"chain-key")
            self.received_count += 1
        
        message_key = _hmac_sha256(self.receiving_chain_key, b"message-key")
        self.receiving_chain_key = _hmac_sha256(self.receiving_chain_key, b"chain-key")
        self.received_count += 1
        
        return message_key
