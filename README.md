# Nomo Crypto Core

Криптографическое ядро мессенджера [Nomo Messenger](https://nomo-messenger.com).

## Что внутри

- **Ed25519** — генерация ключей, подпись, проверка
- **X3DH** — Extended Triple Diffie-Hellman (ключевое соглашение)
- **Double Ratchet** — пошаговое шифрование с forward secrecy

## Установка

```bash
pip install -r requirements.txt
