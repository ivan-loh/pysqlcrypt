# pysqlcrypt

Python implementation of SQL Server's `ENCRYPTBYPASSPHRASE` and `DECRYPTBYPASSPHRASE` functions.

## Quick Start

```bash
pip install pysqlcrypt
```

```python
from pysqlcrypt import encrypt_by_passphrase, decrypt_by_passphrase, SQLCryptVersion

# Encrypt
ciphertext = encrypt_by_passphrase("passphrase", "plaintext", SQLCryptVersion.V2)

# Decrypt
plaintext = decrypt_by_passphrase("passphrase", ciphertext, encoding="utf-8")
```

## API

### `encrypt_by_passphrase(passphrase, plaintext, version=V1, authenticator=None, *, encoding="utf-8")`

Returns encrypted bytes. Use `SQLCryptVersion.V1` for SQL Server 2008-2016, `SQLCryptVersion.V2` for 2017+.

### `decrypt_by_passphrase(passphrase, ciphertext, *, authenticator=None, encoding=None)`

Returns decrypted bytes, or str if `encoding` is specified. Accepts bytes or hex string (with or without `0x` prefix).

## Version Reference

| Version | SQL Server | Algorithm |
|---------|------------|-----------|
| V1 | 2008-2016 | 3DES-CBC, SHA1 |
| V2 | 2017+ | AES-256-CBC, SHA256 |

## Notes

- For NVARCHAR compatibility, use `encoding="utf-16-le"`
- The `authenticator` parameter embeds additional context data for verification
- Decryption auto-detects the version from the ciphertext header

## License

MIT

🍌
