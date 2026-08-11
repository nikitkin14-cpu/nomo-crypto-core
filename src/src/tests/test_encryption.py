"""
Тесты криптографического ядра Nomo.
"""

import pytest
from src.ed25519_auth import (
    generate_keypair, sign_message, verify_signature, 
    get_key_fingerprint, get_public_key_base64
)
from src.key_generator import (
    generate_random_key, generate_prekeys, generate_key_from_seed
)
from src.e2e_protocol import (
    initiate_x3dh, process_x3dh_initiation,
    RatchetState
)


class TestEd25519:
    """Тесты Ed25519 аутентификации."""
    
    def test_generate_keypair(self):
        priv, pub = generate_keypair()
        assert "BEGIN PRIVATE KEY" in priv
        assert "BEGIN PUBLIC KEY" in pub
    
    def test_sign_and_verify(self):
        priv, pub = generate_keypair()
        message = b"Hello, Nomo!"
        
        signature = sign_message(priv, message)
        assert verify_signature(pub, message, signature)
    
    def test_wrong_signature(self):
        priv, pub = generate_keypair()
        message = b"Hello"
        
        signature = sign_message(priv, message)
        assert not verify_signature(pub, b"Wrong message", signature)
    
    def test_wrong_key(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        message = b"Hello"
        
        signature = sign_message(priv1, message)
        assert not verify_signature(pub2, message, signature)
    
    def test_fingerprint(self):
        _, pub = generate_keypair()
        fp = get_key_fingerprint(pub)
        assert len(fp) == 16
    
    def test_base64_export(self):
        _, pub = generate_keypair()
        b64 = get_public_key_base64(pub)
        assert len(b64) == 44  # 32 байта в base64


class TestKeyGenerator:
    """Тесты генератора ключей."""
    
    def test_random_key_length(self):
        key = generate_random_key(32)
        assert len(key) == 32
    
    def test_random_key_unique(self):
        keys = [generate_random_key(32) for _ in range(10)]
        assert len(set(keys)) == 10
    
    def test_key_from_seed(self):
        seed = b"test-seed"
        key1 = generate_key_from_seed(seed)
        key2 = generate_key_from_seed(seed)
        assert key1 == key2
    
    def test_prekeys_count(self):
        prekeys = generate_prekeys(50)
        assert len(prekeys) == 50
        assert all(len(k) == 32 for k in prekeys)


class TestX3DH:
    """Тесты X3DH протокола."""
    
    def test_x3dh_exchange(self):
        # Алиса
        alice_identity = generate_random_key(32)
        alice_ephemeral = generate_random_key(32)
        
        # Боб
        bob_identity = generate_random_key(32)
        bob_signed_prekey = generate_random_key(32)
        bob_one_time = generate_random_key(32)
        
        # Алиса инициирует
        shared_alice = initiate_x3dh(
            alice_identity, alice_ephemeral,
            bob_identity, bob_signed_prekey, bob_one_time
        )
        
        # Боб обрабатывает
        shared_bob = process_x3dh_initiation(
            bob_identity, bob_signed_prekey, bob_one_time,
            alice_identity, alice_ephemeral
        )
        
        assert shared_alice == shared_bob
    
    def test_x3dh_without_one_time_prekey(self):
        alice_identity = generate_random_key(32)
        alice_ephemeral = generate_random_key(32)
        bob_identity = generate_random_key(32)
        bob_signed_prekey = generate_random_key(32)
        
        shared_alice = initiate_x3dh(
            alice_identity, alice_ephemeral,
            bob_identity, bob_signed_prekey, None
        )
        
        shared_bob = process_x3dh_initiation(
            bob_identity, bob_signed_prekey, None,
            alice_identity, alice_ephemeral
        )
        
        assert shared_alice == shared_bob


class TestDoubleRatchet:
    """Тесты Double Ratchet."""
    
    def test_encrypt_decrypt(self):
        shared_secret = generate_random_key(32)
        alice = RatchetState(shared_secret)
        bob = RatchetState(shared_secret)
        
        # Алиса шифрует
        msg = alice.encrypt(b"Hello Bob!")
        
        # Боб расшифровывает
        plaintext = bob.decrypt(msg)
        assert plaintext == b"Hello Bob!"
    
    def test_multiple_messages(self):
        shared_secret = generate_random_key(32)
        alice = RatchetState(shared_secret)
        bob = RatchetState(shared_secret)
        
        for i in range(10):
            msg = alice.encrypt(f"Message {i}".encode())
            plaintext = bob.decrypt(msg)
            assert plaintext == f"Message {i}".encode()
    
    def test_two_way_communication(self):
        shared_secret = generate_random_key(32)
        alice = RatchetState(shared_secret)
        bob = RatchetState(shared_secret)
        
        # Alice → Bob
        msg1 = alice.encrypt(b"Hello from Alice")
        assert bob.decrypt(msg1) == b"Hello from Alice"
        
        # Bob → Alice (меняем направление)
        msg2 = bob.encrypt(b"Hello from Bob")
        assert alice.decrypt(msg2) == b"Hello from Bob"
        
        # Alice → Bob снова
        msg3 = alice.encrypt(b"Back to Bob")
        assert bob.decrypt(msg3) == b"Back to Bob"
    
    def test_full_cycle(self):
        """Полный цикл: X3DH → Double Ratchet."""
        # X3DH
        alice_id = generate_random_key(32)
        alice_eph = generate_random_key(32)
        bob_id = generate_random_key(32)
        bob_spk = generate_random_key(32)
        
        shared = initiate_x3dh(alice_id, alice_eph, bob_id, bob_spk)
        shared_bob = process_x3dh_initiation(bob_id, bob_spk, None, alice_id, alice_eph)
        assert shared == shared_bob
        
        # Double Ratchet
        alice = RatchetState(shared)
        bob = RatchetState(shared_bob)
        
        msg = alice.encrypt(b"Secure message after X3DH")
        plaintext = bob.decrypt(msg)
        assert plaintext == b"Secure message after X3DH"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
