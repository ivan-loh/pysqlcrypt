"""SQL Server ENCRYPTBYPASSPHRASE/DECRYPTBYPASSPHRASE for Python."""

from .crypto import SQLCryptVersion, decrypt_by_passphrase, encrypt_by_passphrase

__version__ = "0.2.0"
__all__ = ["encrypt_by_passphrase", "decrypt_by_passphrase", "SQLCryptVersion"]
