# Nomo Crypto Core

**Verify, don't trust.**

This repository contains the cryptographic heart of [Nomo Messenger](https://github.com/nikitkin14-cpu/nomo-transparency):
- **Authentication:** Ed25519 key pairs — no phone number, no email, no password.
- **Encryption:** End-to-end protocol based on X3DH and Double Ratchet (Signal-grade).

Everything here is open-source so you can audit it yourself. Nomo cannot read your messages. Here's the proof.

---

## What's inside

| File | Purpose |
|------|---------|
| `src/ed25519_auth.py` | Generate key pairs, sign and verify messages |
| `src/e2e_protocol.py` | X3DH key agreement + Double Ratchet encryption |
| `src/key_generator.py` | Secure random key generation |
| `tests/test_encryption.py` | Tests to verify encryption works correctly |

---

## How to verify

```bash
git clone https://github.com/nikitkin14-cpu/nomo-crypto-core.git
cd nomo-crypto-core
pip install -r requirements.txt
pytest tests/
